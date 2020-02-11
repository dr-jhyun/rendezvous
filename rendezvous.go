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
	"flag"
	"fmt"
	"github.com/forestgiant/sliceutil"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	// https://docs.docker.com/develop/sdk/examples/
	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"

	pshost "github.com/shirou/gopsutil/host"
	goLog "github.com/withmandalA/go-log"
)

type Config struct {
	ServerMode   bool         `yaml:"ServerMode"`
	Verbose      bool         `yaml:"Verbose"`
	ServerConfig ServerSpec   `yaml:"ServerConfig" json:"ServerConfig,omitempty"`
	ClientConfig []ClientSpec `yaml:"ClientConfig" json:"ClientConfig,omitempty"`
}

type ServerSpec struct {
	Ports []string `yaml:"Ports" json:"Ports,omitempty"`
}

type ClientSpec struct {
	TargetAddress      string   `yaml:"TargetAddress"`
	Ports              []string `yaml:"Ports"`
	ProbeServerRunning bool     `yaml:"ProbeServerRunning"`
	CheckDockerImages  []string `yaml:"CheckDockerImages"`
	ListDockerImages   bool     `yaml:"ListDockerImages"`
}

type ServerResponse struct {
	HostIP   string          `json:"hostIP"`
	HostInfo pshost.InfoStat `json:"hostInfo"`
	Hash     string          `json:"hash,omitempty"`
}

type stringSliceFlag []string

const (
	responseTimeout = 2 * time.Second
	appVersion      = "Probe version 1.0.0"
)

var (
	httpClient   *http.Client
	dockerClient *docker.Client
	log          *goLog.Logger = goLog.New(os.Stderr).WithColor().WithDebug().WithoutTimestamp()

	verbose    bool = false
	errorOccur bool = false
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
		log.Warn("error occurs during execution")
		os.Exit(1)
	}

	return
}

func readConfig() (*Config, error) {
	var (
		targetAddress     stringSliceFlag
		ports             stringSliceFlag
		checkDockerImages stringSliceFlag
		config            = new(Config)
	)

	genFlag := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	configFilePtr := genFlag.String("f", "", "Config yaml file")
	serverModePtr := genFlag.Bool("s", false, "Server mode")
	genFlag.Var(&targetAddress, "c", "Target address list")
	genFlag.Var(&ports, "p", "Port to scan")
	probeServerRunningPtr := genFlag.Bool("r", true, "Server is running in target node")
	verbosePtr := genFlag.Bool("v", false, "Print verbose information")
	genFlag.Var(&checkDockerImages, "i", "Find docker images in server")
	listDockerImagesPtr := genFlag.Bool("l", false, "Print docker image list")
	versionPtr := genFlag.Bool("version", false, "Print current version")

	_ = genFlag.Parse(os.Args[1:])

	if genFlag.NFlag() < 1 {
		genFlag.Usage()
		os.Exit(1)
	}

	if *versionPtr {
		fmt.Println(appVersion)
		os.Exit(0)
	}

	configFile := *configFilePtr

	// read config from file
	if configFile != "" {
		filename, _ := filepath.Abs(configFile)
		yamlData, err := ioutil.ReadFile(filename)

		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(yamlData, config)
		if err != nil {
			return nil, err
		}
	} else {
		config.ServerMode = *serverModePtr
		config.Verbose = *verbosePtr

		if config.ServerMode {
			config.ServerConfig.Ports = ports
			config.ClientConfig = nil
		} else {
			config.ServerConfig = ServerSpec{}
			for _, targetAddr := range targetAddress {
				clientConfig := ClientSpec{
					TargetAddress:      targetAddr,
					ProbeServerRunning: *probeServerRunningPtr,
					Ports:              ports,
					CheckDockerImages:  checkDockerImages,
					ListDockerImages:   *listDockerImagesPtr,
				}
				config.ClientConfig = append(config.ClientConfig, clientConfig)
			}
		}
	}

	verbose = config.Verbose

	if verbose {
		jsonAsBytes, _ := json.MarshalIndent(*config, "", "  ")

		fmt.Println("------------------------------")
		fmt.Println("Config:\n", string(jsonAsBytes))
		fmt.Println("------------------------------\n")
	}

	return config, nil
}

func processServerMode(config *Config) error {
	ports := config.ServerConfig.Ports

	if len(ports) == 0 {
		return fmt.Errorf("port should be designated")
	}

	err := dockerClientInit()
	if err != nil {
		fmt.Println(err.Error())
	}

	wg := sync.WaitGroup{}
	for idx, port := range ports {
		mux := http.NewServeMux()
		mux.HandleFunc("/", portCheckHandler)
		mux.HandleFunc("/dockerImages", dockerImagesHandler)

		fmt.Println("[", idx, "] Listen on http://127.0.0.1:"+port+"/ ...")

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
	httpClient = &http.Client{Timeout: responseTimeout}

	if len(config.ClientConfig) == 0 {
		return fmt.Errorf("target address should be designated")
	}

	// for each target
	for tIdx, clientConfig := range config.ClientConfig {
		targetAddr := clientConfig.TargetAddress
		ports := clientConfig.Ports

		fmt.Println("\n\n\n=============== [", tIdx, "] Target server:", targetAddr, "===============")

		if validIP4(targetAddr) == false {
			log.Error("Invalid target IP address:", targetAddr)
			errorOccur = true
			continue
		}

		if len(ports) == 0 {
			log.Error("Port should be designated")
			errorOccur = true
			continue
		}

		// for each port
		var successPort string
		for _, port := range ports {
			err := processPortProbe(targetAddr, port, clientConfig.ProbeServerRunning)

			if err != nil {
				log.Error(err.Error())
				errorOccur = true
				continue
			}

			successPort = port
		}

		// docker images
		if clientConfig.ProbeServerRunning && successPort != "" &&
			(clientConfig.ListDockerImages || len(clientConfig.CheckDockerImages) > 0) {
			err := processDockerImages(targetAddr, successPort, clientConfig.ListDockerImages, clientConfig.CheckDockerImages)

			if err != nil {
				log.Error(err.Error())
				errorOccur = true
				continue
			}
		}
	}

	return nil
}

func processPortProbe(targetAddr, port string, serverRunning bool) error {
	fmt.Println("\n\t********** [Port " + port + "] **********")

	// port check
	target := targetAddr + ":" + port

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

	url := "http://" + targetAddr + ":" + port + "/"
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
		if verbose {
			fmt.Println(string(resposeAsBytes))
			fmt.Println("\treceived hash: ", receivedHash)
			fmt.Println("\tcalculated hash: ", calcHashAsHexString)
		}
		return fmt.Errorf("hash mismatch")
	}

	if targetAddr != serverResponse.HostIP {
		if verbose {
			fmt.Println("\trequest address: ", targetAddr)
			fmt.Println("\tresponse aderess: ", serverResponse.HostIP)
		}
		return fmt.Errorf("address mismatch")
	}

	if verbose {
		fmt.Println("\t" + strings.ReplaceAll(string(resposeAsBytes), "\n", "\n\t"))
		fmt.Println("\tResponse time:", responseTime)
	} else {
		fmt.Println("\tHTTP response OK")
	}

	return nil
}

func processDockerImages(targetAddr, port string, list bool, checkImages []string) error {
	url := "http://" + targetAddr + ":" + port + "/dockerImages"
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

			if verbose {
				fmt.Println("\tTag:", imageTag)
				fmt.Println("\tID :", imageId)
			}

			if sliceutil.Contains(allRepoTags, imageTag) &&
				sliceutil.Contains(allImageId, imageId) {
				fmt.Println("\t"+image, "--> found\n")
			} else {
				fmt.Println("\t"+image, "--> not found\n")
				notFound = true
			}
		}

		if notFound {
			err = fmt.Errorf("docker image is not installed")
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

	responseData.HostIP = GetOutboundIP().String()

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

func dockerClientInit() error {
	var (
		err error
	)

	dockerClient, err = docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return err
	}

	// docker client API 버전과 일치시킴
	dockerClient.NegotiateAPIVersion(context.Background())

	fmt.Println("Docker client API version:", dockerClient.ClientVersion())
	return nil
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

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func (stringSlice *stringSliceFlag) String() string {
	return "string slice argument"
}

func (stringSlice *stringSliceFlag) Set(value string) error {
	*stringSlice = append(*stringSlice, value)
	return nil
}
