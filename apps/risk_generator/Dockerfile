FROM ubuntu:latest

MAINTAINER Jihyeok Yang <flash3470@gmail.com>

ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

RUN apt-get update -y
RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install build-essential ssh -y
RUN apt-get install python -y
RUN apt-get install vim -y
RUN apt-get install net-tools -y
RUN apt-get install python-pip -y
RUN apt-get install python3-pip -y
RUN apt-get install git -y

RUN apt-get update -y
RUN apt-get upgrade -y

RUN pip3 --default-timeout=10000 install pandas
RUN pip3 --default-timeout=10000 install numpy
RUN pip3 --default-timeout=10000 install bs4
WORKDIR /opt/exploitdb

COPY RiskGenerator.py /root/RiskGenerator.py
ENV PYTHONIOENCODING utf-8


ENTRYPOINT ["python3", "/root/RiskGenerator.py"]
