FROM python:3.8

MAINTAINER Jihyeok Yang <flash3470@gmail.com>

ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

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

RUN git clone https://github.com/linux-test-project/ltp.git

WORKDIR /ltp/
RUN make autotools
RUN ./configure
RUN make
RUN make install

RUN apt-get install strace -y

COPY test_script.sh test_script.sh
COPY test_script_strace.sh test_script_strace.sh
COPY test_ipc.sh test_ipc.sh
COPY test_ipc_strace.sh test_ipc_strace.sh
COPY syscall_list.sh syscall_list.sh
COPY avail_syscall.py avail_syscall.py
COPY grammar.txt grammar.txt
RUN chmod 755 test_script.sh
RUN chmod 755 test_script_strace.sh
RUN chmod 755 syscall_list.sh
RUN chmod 755 test_ipc.sh
RUN chmod 755 test_ipc_strace.sh
CMD ["/bin/bash"]
