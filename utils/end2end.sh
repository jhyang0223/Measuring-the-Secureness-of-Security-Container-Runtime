!/bin/bash

echo "start crawling"
./crawling_run.sh

echo "start network test"
./ltp_run.sh net

echo "start fs test"
./ltp_run.sh fs

./calculator_run.sh
