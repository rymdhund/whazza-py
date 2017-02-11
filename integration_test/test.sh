#!/bin/bash

set -x

/app/bin/server &
/app/bin/checker &

sleep 5
if `/app/bin/client status | grep -q good`; then
    echo "All good"
else
    /app/bin/client status
    echo "Fail!"
fi

exit
