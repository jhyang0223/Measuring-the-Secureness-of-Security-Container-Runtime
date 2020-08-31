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
