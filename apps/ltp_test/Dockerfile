FROM ubuntu:latest

MAINTAINER Jihyeok Yang <flash3470@gmail.com>

RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install build-essential ssh -y
RUN apt-get install python -y
RUN apt-get install vim -y
RUN apt-get install net-tools -y
RUN apt-get install python-pip -y
RUN apt-get install python3-pip -y
RUN apt-get install autotools-dev automake unzip autoconf -y
RUN apt-get install git -y
ENV PYTHONIOENCODING utf-8

RUN apt-get install netperf -y

RUN git clone https://github.com/linux-test-project/ltp.git

WORKDIR /ltp/
RUN make autotools
RUN ./configure
RUN make
RUN make install

COPY test_script.sh test_script.sh
COPY syscall_test_script.sh syscall_test_script.sh
RUN chmod 755 test_script.sh
RUN chmod 755 syscall_test_script.sh

RUN apt-get update -y
RUN apt-get install -y build-essential
RUN apt-get install -y checkinstall
RUN apt-get install -y libreadline-gplv2-dev
RUN apt-get install -y libncursesw5-dev
RUN apt-get install -y libssl-dev
RUN apt-get install -y libsqlite3-dev
#RUN apt-get install -y tk-dev
RUN apt-get install -y libgdbm-dev
RUN apt-get install -y libc6-dev
RUN apt-get install -y libbz2-dev
RUN apt-get install -y zlib1g-dev
RUN apt-get install -y openssl
RUN apt-get install -y libffi-dev
RUN apt-get install -y wget

RUN mkdir /tmp/Python38
WORKDIR /tmp/Python38
RUN wget https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tar.xz
RUN tar xvf Python-3.8.2.tar.xz
WORKDIR /tmp/Python38/Python-3.8.2
RUN ./configure
RUN make altinstall
RUN update-alternatives --install /usr/bin/python3 python /usr/local/bin/python3.8 1
#RUN mv /usr/bin/lsb_release /usr/bin/lsb_release_back
RUN apt-get install -y python3-dev
RUN apt-get install -y python3-setuptools

RUN python3 -m pip install strace-parser

