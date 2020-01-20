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
    testcases/kernel/fs/ftest/ftest02
    testcases/kernel/fs/ftest/ftest03
    testcases/kernel/fs/ftest/ftest05
else
    echo "TBA"
fi
