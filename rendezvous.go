/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since Feburary 05, 2020                        *
 **************************************************/

// you must do 'go get github.com/docker/docker@master' before 'go build'

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/forestgiant/sliceutil"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	// https://docs.docker.com/develop/sdk/examples/
	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"

	pshost "github.com/shirou/gopsutil/host"
	goLog "github.com/withmandalA/go-log"

	// https://godoc.org/gopkg.in/alecthomas/kingpin.v2
	"gopkg.in/alecthomas/kingpin.v2"

	// https://godoc.org/github.com/GlenDC/go-external-ip
	"github.com/glendc/go-external-ip"
)

type Config struct {
	ServerMode   bool         `yaml:"ServerMode"`
	Verbose      bool         `yaml:"Verbose"`
	ServerConfig []ServerSpec `yaml:"ServerConfig" json:"ServerConfig,omitempty"`
	ClientConfig []ClientSpec `yaml:"ClientConfig" json:"ClientConfig,omitempty"`
}

type ServerSpec struct {
	Address string   `yaml:"Address,omitempty"`
	Ports   []string `yaml:"Ports"`
}

type ClientSpec struct {
	ServerAddress     string   `yaml:"ServerAddress"`
	Ports             []string `yaml:"Ports"`
	RendezvousRunning bool     `yaml:"RendezvousRunning"`
	CheckDockerImages []string `yaml:"CheckDockerImages"`
	ListDockerImages  bool     `yaml:"ListDockerImages"`
}

type ServerResponse struct {
	OutboundIP string          `json:"outboundIP"`
	ExternalIP string          `json:"externalIP"`
	HostInfo   pshost.InfoStat `json:"hostInfo"`
	Hash       string          `json:"hash,omitempty"`
}

const (
	responseTimeout  = 3 * time.Second
	consensusTimeout = 300 * time.Millisecond
)

var (
	httpClient   *http.Client
	dockerClient *docker.Client
	consensus    *externalip.Consensus
	log          *goLog.Logger = goLog.New(os.Stderr).WithColor().WithDebug().WithoutTimestamp()

	appVersion       = os.Args[0] + " version 1.0.0\n" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	verboseMode bool = false
	errorOccur  bool = false
)

func main() {
	var (
		config *Config
		err    error
	)

	config, err = readConfig()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	err = initClients(config)

	if err != nil {
		fmt.Println(err.Error())
	}

	if config.ServerMode {
		err = processServerMode(config)
	} else {
		err = processClientMode(config)
	}

	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	if errorOccur {
		os.Exit(1)
	}

	return
}

func initClients(config *Config) error {
	var (
		err error
	)

	consensusConfig := externalip.ConsensusConfig{Timeout: consensusTimeout}
	consensus = externalip.DefaultConsensus(&consensusConfig, nil)

	httpClient = &http.Client{Timeout: responseTimeout}

	if config.ServerMode {
		err = dockerClientInit()
	}

	return err
}

func dockerClientInit() error {
	var (
		err error
	)

	dockerClient, err = docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return err
	}

	dockerClient.NegotiateAPIVersion(context.Background())

	fmt.Println("Docker client API version:", dockerClient.ClientVersion())
	return nil
}

func readConfig() (*Config, error) {
	var (
		config = &Config{}

		app     = kingpin.New(os.Args[0], "Port & container scanner")
		verbose = app.Flag("verbose", "Verbose information").Short('v').Bool()

		// file subcommand
		fileCmd    = app.Command("file", "Read config file").Default()
		configFile = fileCmd.Flag("file", "Config yaml file").Short('f').Required().File()

		// server subcommand
		serverCmd   = app.Command("server", "Server mode")
		addresses   = serverCmd.Flag("address", "Address to listen").Short('a').Default("127.0.0.1").Strings()
		serverPorts = serverCmd.Flag("port", "Port to listen").Short('p').Required().Strings()

		// client subcommand
		clientCmd         = app.Command("client", "Client mode")
		serverAddresses   = clientCmd.Flag("address", "Server address to scan").Short('a').Required().Strings()
		clientPorts       = clientCmd.Flag("port", "Port to scan").Short('p').Required().Strings()
		checkDockerImages = clientCmd.Flag("image", "Find Docker images in server").Short('i').Strings()
		rendezvousRunning = clientCmd.Flag("run", "Server is running in target node").Short('r').Bool()
		listDockerImages  = clientCmd.Flag("list", "List Docker images").Short('l').Bool()
	)

	if len(os.Args) < 2 {
		kingpin.Usage()
		return nil, fmt.Errorf("insufficient paramter")
	}

	app.Version(appVersion)
	app.HelpFlag.Short('h')

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	case fileCmd.FullCommand():
		yamlData, err := ioutil.ReadAll(*configFile)

		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(yamlData, config)
		if err != nil {
			return nil, err
		}

	case serverCmd.FullCommand():
		config.ServerMode = true
		config.Verbose = *verbose
		config.ClientConfig = nil
		for _, address := range *addresses {
			serverConfig := ServerSpec{
				Address: address,
				Ports:   *serverPorts,
			}
			config.ServerConfig = append(config.ServerConfig, serverConfig)
		}

	case clientCmd.FullCommand():
		config.ServerMode = false
		config.Verbose = *verbose
		config.ServerConfig = nil
		for _, serverAddress := range *serverAddresses {
			clientConfig := ClientSpec{
				ServerAddress:     serverAddress,
				Ports:             *clientPorts,
				RendezvousRunning: *rendezvousRunning,
				CheckDockerImages: *checkDockerImages,
				ListDockerImages:  *listDockerImages,
			}
			config.ClientConfig = append(config.ClientConfig, clientConfig)
		}

	default:
		return nil, fmt.Errorf("unexpected parameter parsing")
	}

	verboseMode = config.Verbose

	if verboseMode {
		jsonAsBytes, _ := json.MarshalIndent(*config, "", "  ")

		fmt.Println("------------------------------")
		fmt.Println("Config:\n", string(jsonAsBytes))
		fmt.Println("------------------------------\n")
	}

	return config, nil
}

func processServerMode(config *Config) error {
	var (
		serverConfig ServerSpec
	)

	outboundIp := getOutboundIP().String()
	externalIp := getExternalIP().String()

	fmt.Println("Outbound IP: ", outboundIp)
	fmt.Println("External IP: ", externalIp)

	found := false
	for _, serverConfig = range config.ServerConfig {
		serverIp, _ := getAddressIP4(serverConfig.Address)

		if outboundIp == serverIp.String() ||
			externalIp == serverIp.String() ||
			serverIp.String() == "127.0.0.1" {
			found = true
			break
		}
	}

	if found == false {
		return fmt.Errorf("server address is not found")
	}

	ports := serverConfig.Ports

	if len(ports) == 0 {
		return fmt.Errorf("port should be designated")
	}

	wg := sync.WaitGroup{}
	for idx, port := range ports {
		mux := http.NewServeMux()
		mux.HandleFunc("/", portCheckHandler)
		mux.HandleFunc("/dockerImages", dockerImagesHandler)

		fmt.Printf("[%02d] Listen on http://%s:%s/ ...\n", idx+1, serverConfig.Address, port)

		wg.Add(1)
		go func(openPort string) {
			defer wg.Done()
			err := http.ListenAndServe(":"+openPort, mux)
			if err != nil {
				log.Fatal(err.Error())
			}
		}(port)
	}
	wg.Wait()

	return nil
}

func processClientMode(config *Config) error {
	if len(config.ClientConfig) == 0 {
		return fmt.Errorf("target address should be designated")
	}

	// for each target
	for tIdx, clientConfig := range config.ClientConfig {
		serverAddr := clientConfig.ServerAddress
		ports := clientConfig.Ports

		fmt.Println("\n\n   ======== [", tIdx+1, "] Target Server:", serverAddr, "========")

		address, err := getAddressIP4(serverAddr)

		if err != nil {
			log.Error(err.Error())
			errorOccur = true
			continue
		}

		if address.String() != serverAddr {
			fmt.Println("\n\tLookup host:", serverAddr, "-->", address)
		}

		if len(ports) == 0 {
			log.Error("port should be designated")
			errorOccur = true
			continue
		}

		// for each port
		var successPort string
		for _, port := range ports {
			err = processPortProbe(address, port, clientConfig.RendezvousRunning)

			if err != nil {
				log.Error(err.Error())
				errorOccur = true
				continue
			}

			successPort = port
		}

		// docker images
		if clientConfig.RendezvousRunning && successPort != "" &&
			(clientConfig.ListDockerImages || len(clientConfig.CheckDockerImages) > 0) {
			err = processDockerImages(address, successPort, clientConfig.ListDockerImages, clientConfig.CheckDockerImages)

			if err != nil {
				log.Error(err.Error())
				errorOccur = true
				continue
			}
		}
	}

	return nil
}

func processPortProbe(address net.IP, port string, serverRunning bool) error {
	fmt.Println("\n\t********** [Port " + port + "] **********")

	// port check
	target := address.String() + ":" + port

	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", target, responseTimeout)
	responseTime := time.Since(startTime)

	if err != nil {
		return err
	}

	defer conn.Close()

	fmt.Println("\tPort open OK")

	if serverRunning == false {
		return nil
	}

	url := "http://" + target + "/"
	request, _ := http.NewRequest(http.MethodGet, url, nil)

	startTime = time.Now()
	response, err := httpClient.Do(request)
	responseTime = time.Since(startTime)

	if err != nil {
		return err
	}

	defer response.Body.Close()

	// get response
	resposeAsBytes, _ := ioutil.ReadAll(response.Body)

	// retreive hash from response
	var serverResponse ServerResponse
	_ = json.Unmarshal(resposeAsBytes, &serverResponse)
	receivedHash := serverResponse.Hash

	// calculate hash
	serverResponse.Hash = ""
	respAsBytes, _ := json.MarshalIndent(serverResponse, "", "  ")

	calcHashAsBytes := sha256.Sum256(respAsBytes)
	calcHashAsHexString := hex.EncodeToString(calcHashAsBytes[:])

	if receivedHash != calcHashAsHexString {
		if verboseMode {
			fmt.Println(string(resposeAsBytes))
			fmt.Println("\treceived hash: ", receivedHash)
			fmt.Println("\texpected hash: ", calcHashAsHexString)
		}
		return fmt.Errorf("http content hash mismatch")
	}

	if address.String() != serverResponse.OutboundIP &&
		address.String() != serverResponse.ExternalIP {
		fmt.Println("\trequest IP: ", address)
		fmt.Println("\tresponse outbound IP: ", serverResponse.OutboundIP)
		fmt.Println("\tresponse external IP: ", serverResponse.ExternalIP)

		return fmt.Errorf("address mismatch")
	}

	if verboseMode {
		fmt.Println("\t" + strings.ReplaceAll(string(resposeAsBytes), "\n", "\n\t"))
		fmt.Println("\tResponse time:", responseTime)
	} else {
		fmt.Println("\tHTTP response OK")
	}

	return nil
}

func processDockerImages(address net.IP, port string, list bool, checkImages []string) error {
	url := "http://" + address.String() + ":" + port + "/dockerImages"
	request, _ := http.NewRequest(http.MethodGet, url, nil)

	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	resposeAsBytes, _ := ioutil.ReadAll(response.Body)

	if len(checkImages) > 0 {
		var (
			allImages   []types.ImageSummary
			allRepoTags []string
			allImageId  []string
		)

		_ = json.Unmarshal(resposeAsBytes, &allImages)

		// get info from target server docker images
		for _, image := range allImages {
			allRepoTags = append(allRepoTags, image.RepoTags...)

			idx := strings.Index(image.ID, ":")
			allImageId = append(allImageId, image.ID[idx+1:idx+13])
		}

		fmt.Println("\n\n\t********** [ Docker Check Images ] **********")
		notFound := false
		for _, image := range checkImages {
			idx := strings.LastIndex(image, ":")
			imageTag := image[:idx]
			imageId := image[idx+1:]

			if verboseMode {
				fmt.Println("\tTag:", imageTag)
				fmt.Println("\tID :", imageId)
			}

			if sliceutil.Contains(allRepoTags, imageTag) &&
				sliceutil.Contains(allImageId, imageId) {
				fmt.Println("\t"+image, "--> found")
			} else {
				fmt.Println("\t"+image, "--> not found")
				notFound = true
			}
		}

		if notFound {
			err = fmt.Errorf("some docker image is not installed")
		}
	}

	if list {
		fmt.Println("\n\n\t********** [ Docker Images ] **********")
		fmt.Println(string(resposeAsBytes))
	}

	return err
}

func portCheckHandler(response http.ResponseWriter, request *http.Request) {
	var (
		responseData ServerResponse
		hashAsBytes  [sha256.Size]byte
	)

	responseData.OutboundIP = getOutboundIP().String()
	responseData.ExternalIP = getExternalIP().String()

	hostInfo, _ := pshost.Info()
	responseData.HostInfo = *hostInfo

	// calculate hash
	responseData.Hash = ""
	responseAsBytes, _ := json.MarshalIndent(responseData, "", "  ")
	hashAsBytes = sha256.Sum256(responseAsBytes)
	hashAsHexString := hex.EncodeToString(hashAsBytes[:])

	// add hash to responseData
	responseData.Hash = hashAsHexString

	responseAsBytes, _ = json.MarshalIndent(responseData, "", "  ")

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	response.Write(responseAsBytes)
}

func dockerImagesHandler(response http.ResponseWriter, request *http.Request) {
	var (
		imagesAsBytes []byte
	)

	images, err := dockerClient.ImageList(context.Background(), types.ImageListOptions{})

	if err != nil {
		imagesAsBytes = []byte("Docker API ImageList() error")
	} else {
		imagesAsBytes, _ = json.MarshalIndent(&images, "", "  ")
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	response.Write(imagesAsBytes)
}

func getAddressIP4(address string) (net.IP, error) {
	if validIP4(address) {
		return net.ParseIP(address), nil
	}

	// lookup host
	addr, err := net.LookupIP(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address \"%s\"", address)
	}

	return addr[0], nil
}

//https://socketloop.com/tutorials/golang-validate-ip-address
func validIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")

	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func getExternalIP() net.IP {
	ip, err := consensus.ExternalIP()

	if err != nil {
		log.Error(err.Error())
		return net.IPv4(0, 0, 0, 0)
	}

	return ip
}
