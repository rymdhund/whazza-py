#!/bin/sh

docker run --rm -it -v $PWD/client:/app -v $PWD:/data --link status2server status2 python3 client.py $@
