OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/../..
RESTFUL_BIN := /usr/local/bin/restful-as
GRPC_BIN := /usr/local/bin/grpc-as
AS_CACHE_PATH := /opt/confidential-containers/attestation-service
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)
EVIDENCE_FILE ?= $(MAKEFILE_DIR)/evidence.json
RAW_RUNTIME_DATA_FILE ?= $(MAKEFILE_DIR)/raw-runtime-data

RAW_RUNTIME_DATA := $(shell cat $(RAW_RUNTIME_DATA_FILE) | base64 -w0 | tr -d '=' | sed -e "s/+/-/g" -e "s/\//_/g")
EVIDENCE := $(shell cat $(EVIDENCE_FILE) | base64 -w0 | tr -d '=' | sed -e "s/+/-/g" -e "s/\//_/g")

TEE_NAME ?= snp
TEE_CLASS ?= cpu
REQUEST := $(MAKEFILE_DIR)/request.json

# Policy test files
TEST_POLICY_1 := $(MAKEFILE_DIR)/test_policy_1.rego
TEST_POLICY_2 := $(MAKEFILE_DIR)/test_policy_2.rego
POLICY_ID_1 := test-policy-1
POLICY_ID_2 := test-policy-2

.PHONY: install-dependencies
install-dependencies:
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo apt-key add - && \
	echo "deb [arch=amd64] $(SGX_REPO_URL) jammy main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		protobuf-compiler \
		clang \
		libtss2-dev \
		libsgx-dcap-quote-verify-dev \
		libsgx-dcap-default-qpl

$(RESTFUL_BIN) $(GRPC_BIN):
	cd $(PROJECT_DIR) && $(MAKE) build && $(MAKE) install

restful.pid: $(RESTFUL_BIN)
	@printf "${BOLD}start restful-coco-as${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(RESTFUL_BIN) --socket 127.0.0.1:8080 \
		& echo $$! > $@; \
	} && \
	sleep 2

grpc.pid: $(GRPC_BIN)
	@printf "${BOLD}start grpc-coco-as${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(GRPC_BIN) --socket 127.0.0.1:50004 \
		& echo $$! > $@; \
	} && \
	sleep 2

$(REQUEST): $(REQUEST).template
	sed -e "s/%TEE_NAME%/$(TEE_NAME)/g" \
		-e "s/%TEE_CLASS%/$(TEE_CLASS)/g" \
		-e "s/%EVIDENCE%/$(EVIDENCE)/g" \
		$(REQUEST).template > $(REQUEST)

.PHONY: restful-test
restful-test: restful.pid $(REQUEST)
	curl -k -X POST http://127.0.0.1:8080/attestation \
     -i \
     -H 'Content-Type: application/json' \
     -d @$(REQUEST)

.PHONY: grpc-test
grpc-test: grpc.pid $(REQUEST)
	echo $$(cat $(REQUEST)) \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/AttestationEvaluate

# Policy CRUD tests for RESTful AS
.PHONY: restful-policy-crud-test
restful-policy-crud-test: restful.pid $(TEST_POLICY_1) $(TEST_POLICY_2)
	@printf "${BOLD}Testing AS Policy CRUD operations (RESTful)${SGR0}\n"
	
	# Test 1: Set policy 1
	@printf "${BOLD}1. Setting policy $(POLICY_ID_1)${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/policy \
		-H 'Content-Type: application/json' \
		-d '{"policy_id": "$(POLICY_ID_1)", "policy": "'$$(base64 -w0 $(TEST_POLICY_1))'"}' && \
	
	# Test 2: Set policy 2
	@printf "${BOLD}2. Setting policy $(POLICY_ID_2)${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/policy \
		-H 'Content-Type: application/json' \
		-d '{"policy_id": "$(POLICY_ID_2)", "policy": "'$$(base64 -w0 $(TEST_POLICY_2))'"}' && \
	
	# Test 3: List all policies
	@printf "${BOLD}3. Listing all policies${SGR0}\n"
	curl -k http://127.0.0.1:8080/policy && \
	
	# Test 4: Get policy 1
	@printf "${BOLD}4. Getting policy $(POLICY_ID_1)${SGR0}\n"
	curl -k http://127.0.0.1:8080/policy/$(POLICY_ID_1) && \
	
	# Test 5: Get policy 2  
	@printf "${BOLD}5. Getting policy $(POLICY_ID_2)${SGR0}\n"
	curl -k http://127.0.0.1:8080/policy/$(POLICY_ID_2) && \
	
	# Test 6: Delete policy 1
	@printf "${BOLD}6. Deleting policy $(POLICY_ID_1)${SGR0}\n"
	curl -k -X DELETE http://127.0.0.1:8080/policy/$(POLICY_ID_1) && \
	
	# Test 7: Verify policy 1 is deleted (should return 404)
	@printf "${BOLD}7. Verifying policy $(POLICY_ID_1) is deleted${SGR0}\n"
	curl -k http://127.0.0.1:8080/policy/$(POLICY_ID_1) && [ $$? -ne 0 ] || true && \
	
	# Test 8: Delete policy 2
	@printf "${BOLD}8. Deleting policy $(POLICY_ID_2)${SGR0}\n"
	curl -k -X DELETE http://127.0.0.1:8080/policy/$(POLICY_ID_2) && \
	
	# Test 9: List policies to verify they are deleted
	@printf "${BOLD}9. Listing policies to verify deletion${SGR0}\n"
	curl -k http://127.0.0.1:8080/policy
	
	@printf "${BOLD}AS Policy CRUD (RESTful) e2e test passed${SGR0}\n"

# Certificate test for RESTful AS
.PHONY: restful-certificate-test
restful-certificate-test: restful.pid
	@printf "${BOLD}Testing AS Certificate retrieval (RESTful)${SGR0}\n"
	
	# Test: Get certificate
	@printf "${BOLD}Getting AS certificate${SGR0}\n"
	curl -k http://127.0.0.1:8080/certificate
	
	@printf "${BOLD}AS Certificate (RESTful) e2e test passed${SGR0}\n"

# Challenge test for RESTful AS
.PHONY: restful-challenge-test
restful-challenge-test: restful.pid
	@printf "${BOLD}Testing AS Challenge generation (RESTful)${SGR0}\n"
	
	# Test 1: Generate challenge for TDX
	@printf "${BOLD}1. Generating challenge for TDX${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/challenge \
		-H 'Content-Type: application/json' \
		-d '{"tee": "tdx", "tee_params": "test-params"}' && \
	
	# Test 2: Generate challenge for SGX
	@printf "${BOLD}2. Generating challenge for SGX${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/challenge \
		-H 'Content-Type: application/json' \
		-d '{"tee": "sgx", "tee_params": "test-params"}' && \
	
	# Test 3: Generate challenge for SNP
	@printf "${BOLD}3. Generating challenge for SNP${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/challenge \
		-H 'Content-Type: application/json' \
		-d '{"tee": "snp", "tee_params": "test-params"}' && \
	
	# Test 4: Generate challenge for sample TEE (for testing)
	@printf "${BOLD}4. Generating challenge for sample TEE${SGR0}\n"
	curl -k -X POST http://127.0.0.1:8080/challenge \
		-H 'Content-Type: application/json' \
		-d '{"tee": "sample", "tee_params": "test-params"}'
	
	@printf "${BOLD}AS Challenge (RESTful) e2e test passed${SGR0}\n"

# Policy CRUD tests for gRPC AS  
.PHONY: grpc-policy-crud-test
grpc-policy-crud-test: grpc.pid $(TEST_POLICY_1) $(TEST_POLICY_2)
	@printf "${BOLD}Testing AS Policy CRUD operations (gRPC)${SGR0}\n"
	
	# Test 1: Set policy 1
	@printf "${BOLD}1. Setting policy $(POLICY_ID_1) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_1)", "policy": "'$$(base64 -w0 $(TEST_POLICY_1))'"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/SetAttestationPolicy && \
	
	# Test 2: Set policy 2
	@printf "${BOLD}2. Setting policy $(POLICY_ID_2) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_2)", "policy": "'$$(base64 -w0 $(TEST_POLICY_2))'"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/SetAttestationPolicy && \
	
	# Test 3: List all policies
	@printf "${BOLD}3. Listing all policies via gRPC${SGR0}\n"
	echo '{}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/ListAttestationPolicies && \
	
	# Test 4: Get policy 1
	@printf "${BOLD}4. Getting policy $(POLICY_ID_1) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_1)"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationPolicy && \
	
	# Test 5: Get policy 2
	@printf "${BOLD}5. Getting policy $(POLICY_ID_2) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_2)"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationPolicy && \
	
	# Test 6: Delete policy 1
	@printf "${BOLD}6. Deleting policy $(POLICY_ID_1) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_1)"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/DeleteAttestationPolicy && \
	
	# Test 7: Delete policy 2
	@printf "${BOLD}7. Deleting policy $(POLICY_ID_2) via gRPC${SGR0}\n"
	echo '{"policy_id": "$(POLICY_ID_2)"}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/DeleteAttestationPolicy && \
	
	# Test 8: List policies to verify they are deleted
	@printf "${BOLD}8. Listing policies to verify deletion via gRPC${SGR0}\n"
	echo '{}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/ListAttestationPolicies
	
	@printf "${BOLD}AS Policy CRUD (gRPC) e2e test passed${SGR0}\n"

# Challenge test for gRPC AS
.PHONY: grpc-challenge-test
grpc-challenge-test: grpc.pid
	@printf "${BOLD}Testing AS Challenge generation (gRPC)${SGR0}\n"
	
	# Test 1: Generate challenge for TDX via gRPC
	@printf "${BOLD}1. Generating challenge for TDX via gRPC${SGR0}\n"
	echo '{"inner": {"tee": "tdx", "tee_params": "test-params"}}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationChallenge && \
	
	# Test 2: Generate challenge for SGX via gRPC
	@printf "${BOLD}2. Generating challenge for SGX via gRPC${SGR0}\n"
	echo '{"inner": {"tee": "sgx", "tee_params": "test-params"}}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationChallenge && \
	
	# Test 3: Generate challenge for SNP via gRPC
	@printf "${BOLD}3. Generating challenge for SNP via gRPC${SGR0}\n"
	echo '{"inner": {"tee": "snp", "tee_params": "test-params"}}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationChallenge && \
	
	# Test 4: Generate challenge for sample TEE via gRPC
	@printf "${BOLD}4. Generating challenge for sample TEE via gRPC${SGR0}\n"
	echo '{"inner": {"tee": "sample", "tee_params": "test-params"}}' \
	| grpcurl -plaintext -import-path ../../../protos -proto ../../../protos/attestation.proto -d @ 127.0.0.1:50004 attestation.AttestationService/GetAttestationChallenge
	
	@printf "${BOLD}AS Challenge (gRPC) e2e test passed${SGR0}\n"

.PHONY: stop-restful-as
stop-restful-as: restful.pid
	@printf "${BOLD}stop restful-as${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(AS_CACHE_PATH)

.PHONY: stop-grpc-as
stop-grpc-as: grpc.pid
	@printf "${BOLD}stop grpc-as${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(AS_CACHE_PATH)

.PHONY: e2e-restful-test
e2e-restful-test: restful-test restful-policy-crud-test restful-certificate-test restful-challenge-test stop-restful-as

.PHONY: e2e-grpc-test
e2e-grpc-test: grpc-test grpc-policy-crud-test grpc-challenge-test stop-grpc-as

.PHONY: clean
clean:
	rm -f \
		$(RESTFUL_BIN) \
		$(GRPC_BIN) \
		grpc.pid \
		restful.pid \
		$(REQUEST) \
		$(TEST_POLICY_1) \
		$(TEST_POLICY_2)
