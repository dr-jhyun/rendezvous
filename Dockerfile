FROM centos:7.6.1810
MAINTAINER Jihyuck Yun <dr.jhyun@sk.com>

WORKDIR /root
ENV PATH $PATH:.:/root

#######################
### Copy files
########################
COPY . .

