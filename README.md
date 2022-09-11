# sandboxcore

## essential package
install automake, build-essential, python3.5, trace-cmd

## [shell command] install ltp in your host linux
$git clone https://github.com/linux-test-project/ltp.git /opt/ltp

$cd /opt/ltp

$make autotools

$./configure

$make

$make install

# [JKSCI2020] Security Assessment Technique of a Container Runtime Using System Call Weights
## Abstract
In this paper, we propose quantitative evaluation method that enable security comparison between
Security Container Runtimes. security container runtime technologies have been developed to address
security issues such as Container escape caused by containers sharing the host kernel. However, most
literature provides only a analysis of the security of container technologies using rough metrics such as
the number of available system calls, making it difficult to compare the secureness of container
runtimes quantitatively. While the proposed model uses a new method of combining the degree of
exposure of host system calls with various external vulnerability metrics. With the proposed technique,
we measure and compare the security of runC (Docker default Runtime) and two representative Security
Container Runtimes, gVisor, and Kata container.
