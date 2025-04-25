curl -k -X POST http://$1/api/rvps/register \
     -i \
     -H 'Content-Type: application/json' \
     -d @rvps.json

curl -k -X GET http://$1/api/rvps/query \
     -i \
     -H 'Content-Type: application/json' 
