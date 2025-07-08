#!/bin/bash

GATEWAY_URL=$1

echo "=== 测试注册参考值 ==="
curl -k -X POST http://$GATEWAY_URL/api/rvps/register \
     -i \
     -H 'Content-Type: application/json' \
     -d @rvps.json

echo -e "\n\n=== 测试查询参考值 ==="
curl -k -X GET http://$GATEWAY_URL/api/rvps/query \
     -i \
     -H 'Content-Type: application/json'

echo -e "\n\n=== 测试删除参考值 ==="
echo "删除参考值 'test-binary-1':"
curl -k -X DELETE http://$GATEWAY_URL/api/rvps/delete/test-binary-1 \
     -i \
     -H 'Content-Type: application/json'

echo -e "\n\n=== 再次查询参考值验证删除结果 ==="
curl -k -X GET http://$GATEWAY_URL/api/rvps/query \
     -i \
     -H 'Content-Type: application/json' 
