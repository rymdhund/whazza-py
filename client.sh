#!/bin/sh

docker run --rm -it -v $PWD/client:/app -v $PWD:/data --link whazzaserver status2 python3 client.py $@
