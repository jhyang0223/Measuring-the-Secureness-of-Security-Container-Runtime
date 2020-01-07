#!/bin/bash

program=crawling

help_usage() {
    echo "./crawling_run.sh"
    echo "./crawling_run.sh"
}

if [ $# -lt 0 ]; then
    help_usage
    exit
fi

###parameter variable zone ###



############

echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . )#>> /dev/null)

sudo docker run -i -t -h ${program} --rm --name ${program} ${program}
