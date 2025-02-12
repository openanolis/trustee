check_result(){
    if [[ $2 -ne 0 ]];then
        echo -e "\n$1: Fail"
    docker exec $3 sh -c "kubectl delete namespace $4"
    docker stop $3 && docker rm $3
        exit 0
    else
        echo -e "\n$1: Pass"
    fi
}
connection_test(){
    output=$(docker exec $c_id sh -c "curl -k -X POST ${TRUSTEE_URL}/kbs/v0/auth -H 'Content-Type: application/json' -d '{\"version\": \"0.1.0\", \"tee\": \"tdx\", \"extra-params\": \"foo\"}'")
    echo $output
    status=1
    if echo "$output" | grep -q "nonce" && echo "$output" | grep -q "extra-params"; then
        status=0
    fi
    check_result connection_check $status $c_id $INSTANCE_NAME
}

set_config_test(){
    output=$(docker exec $c_id sh -c "trustee-client --url $TRUSTEE_URL \
    config \
    --auth-private-key /opt/trustee-kbs-auth.key \
    set-resource --path default/test/test \
    --resource-file test_resource")
    echo $output
    status=1
    if echo "$output" | grep -q "Set resource success"; then
        status=0
    fi
    check_result set_resource_check $status $c_id $INSTANCE_NAME
    resource=$(echo "$output" | grep "resource:" | awk '{print $2}')

    output=$(docker exec $c_id sh -c "trustee-client --url $TRUSTEE_URL \
    config \
    --auth-private-key /opt/trustee-kbs-auth.key \
    set-attestation-policy \
    --type rego \
    --id default \
    --policy-file /root/test_policy.rego")
    echo $output
    status=1
    if echo "$output" | grep -q "Set attestation policy success"; then
        status=0
    fi
    check_result set_attestation_policy_check $status $c_id $INSTANCE_NAME

    policy=$(docker exec $c_id sh -c "cat /root/test_policy.rego | base64 | tr '+/' '-_' | tr -d '='")
  docker exec $c_id sh -c "echo '{
        \"policy\": \"$policy\",
        \"policy_id\": \"default\"
    }'  > /root/restful-set-policy.json"
    output=$(docker exec $c_id sh -c "curl -k -X POST ${TRUSTEE_URL}/as/policy \
    -i \
    -H 'Content-Type: application/json' \
    -d @restful-set-policy.json")
    echo $output
    status=1
    if echo "$output" | grep -q "HTTP/1.1 200 OK"; then
        status=0
    fi
    check_result set_no_attestation_policy_check $status $c_id $INSTANCE_NAME

    output=$(docker exec $c_id sh -c "trustee-client --url $TRUSTEE_URL \
    config \
    --auth-private-key /opt/trustee-kbs-auth.key \
    set-resource-policy \
    --policy-file /root/test_policy.rego")
    echo $output
    status=1
    if echo "$output" | grep -q "Set resource policy success"; then
        status=0
    fi
    check_result set_resource_policy_check $status $c_id $INSTANCE_NAME
}

attestation_test(){
    output=$(docker exec $c_id sh -c "curl -k -X POST ${TRUSTEE_URL}/as/attestation \
    -i \
    -H 'Content-Type: application/json' \
    -d @/root/sample_attestation_request.json")
    echo $output
    status=1
    if echo "$output" | grep -q "HTTP/1.1 200 OK"; then
        status=0
    fi
    check_result no_attestation_check $status $c_id $INSTANCE_NAME

    output=$(docker exec $c_id sh -c "trustee-client --url ${TRUSTEE_URL} \
    get-resource \
    --path default/test/test")
    echo $output
    status=1
    if echo "$output" | grep -q $resource; then
        status=0
    fi
    check_result attestation_check $status $c_id $INSTANCE_NAME
}

image="trustee-registry.cn-hangzhou.cr.aliyuncs.com/daily/ci:latest"

docker pull $image
kubeconfig_path="/root/.kube/config"
trustee_guest_path="/root/trustee"
c_id=$(docker run -d -v $(pwd)/trustee:$trustee_guest_path -v $kubeconfig_path:$kubeconfig_path -v /sys:/sys -v /proc:/proc -v /boot:/boot -v /tmp:/tmp -v /etc/os-release:/etc/os-release --net host $image sleep infinity)
echo c_id:$c_id
INSTANCE_NAME=trustee-function-test
docker exec $c_id sh -c "kubectl create namespace $INSTANCE_NAME; \
  helm repo add trustee acr://trustee-chart.cn-hangzhou.cr.aliyuncs.com/trustee/trustee; \
  helm repo update; \
  helm install $INSTANCE_NAME /root/trustee/helm-chart/trustee --namespace $INSTANCE_NAME"
status=$?
check_result k8s_deployed_check $status $c_id $INSTANCE_NAME

AlbConfig=$(docker exec $c_id sh -c "kubectl get AlbConfig alb -o jsonpath='{.status.loadBalancer.dnsname}'")
TRUSTEE_URL=http://$AlbConfig/$INSTANCE_NAME
sleep 300
docker exec $c_id sh -c "kubectl get pods -n $INSTANCE_NAME"
docker exec $c_id sh -c "kubectl get secret kbs-auth-keypair -n $INSTANCE_NAME -o jsonpath='{.data.private\.key}' | base64 --decode > /opt/trustee-kbs-auth.key"
status=$?
check_result get_kbs-auth-keypair_check $status $c_id $INSTANCE_NAME

connection_test
set_config_test
attestation_test

docker exec $c_id sh -c "kubectl delete namespace $INSTANCE_NAME"
docker stop $c_id && docker rm $c_id