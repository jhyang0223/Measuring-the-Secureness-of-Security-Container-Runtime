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
RUN pip3 install bs4
RUN apt-get install git -y


RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploit-database
RUN ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit
RUN cp -n /opt/exploit-database/.searchsploit_rc ~/

RUN apt-get update -y
RUN apt-get upgrade -y

RUN pip3 --default-timeout=10000 install pandas
RUN pip3 --default-timeout=10000 install numpy

WORKDIR /opt/exploitdb

COPY Crawl.py /root/Crawl.py
ENV PYTHONIOENCODING utf-8


ENTRYPOINT ["python3", "/root/Crawl.py"]
