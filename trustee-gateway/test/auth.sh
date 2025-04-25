#!/usr/bin/bash

curl -k -X POST http://$1/api/kbs/v0/auth \
     -i \
     -H 'Content-Type: application/json' \
     -d @auth.json
