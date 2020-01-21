#/bin/bash


help_usage() {
    echo "./test_script.sh [I/O Type]"
    echo "./test_script.sh fs"
    echo "IO Type : fs, net"
}
if [ $# -lt 1 ]; then
    help_usage
    exit
fi

IOTYPE=$1

sleep 2s

if [ ${IOTYPE} = "fs" ]; then
    testcases/kernel/fs/fs_inod/fs_inod /home 3 5 1
    testcases/kernel/fs/ftest/ftest02
    testcases/kernel/fs/ftest/ftest03
    testcases/kernel/fs/ftest/ftest05
    testcases/kernel/fs/stream/stream01
    testcases/kernel/fs/stream/stream02
    testcases/kernel/fs/stream/stream03
    testcases/kernel/fs/stream/stream04
    testcases/kernel/fs/stream/stream05
    testcases/kernel/fs/read_all/read_all -d /etc
    testcases/kernel/fs/read_all/read_all -d /sys
else
    netserver
    netperf -t TCP_STREAM -H 127.0.0.1
    netperf -t UDP_STREAM -H 127.0.0.1
    service netperf stop
fi
