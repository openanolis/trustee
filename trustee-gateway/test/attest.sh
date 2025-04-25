#!/usr/bin/bash

curl -k -X POST http://$1/api/kbs/v0/attest \
     -i \
     -b 'kbs-session-id='$2'' \
     -H 'Content-Type: application/json' \
     -d @attest.json
