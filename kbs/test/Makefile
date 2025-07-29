OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
CODENAME := $(shell lsb_release -sc)
SGX_REPO_URL := https://download.01.org/intel-sgx/sgx_repo/ubuntu
SGX_COLLATERAL_URL := https://api.trustedservices.intel.com/sgx/certification/v4/
SGX_QCNL_CONFIG := /etc/sgx_default_qcnl.conf
KBS_CONFIG_PATH := ./config
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/..
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)
TEE ?= sample
WORK_DIR := $(MAKEFILE_DIR)/work
KBS_REPO_PATH := $(WORK_DIR)/repository
ATTESTATION_TOKEN := $(WORK_DIR)/attestation_token
ROUNDTRIP_FILE := $(WORK_DIR)/secret
REPOSITORY_SECRET := one/two/three
SECRET_FILE := $(KBS_REPO_PATH)/$(REPOSITORY_SECRET)

# Test resource files
TEST_RESOURCE_1 := $(WORK_DIR)/test_resource_1
TEST_RESOURCE_2 := $(WORK_DIR)/test_resource_2
TEST_RESOURCE_PATH_1 := test_repo/secret/key1
TEST_RESOURCE_PATH_2 := test_repo/config/setting1

# Test attestation policy files
TEST_ATTESTATION_POLICY_1 := $(MAKEFILE_DIR)/test_attestation_policy_1.rego
TEST_ATTESTATION_POLICY_2 := $(MAKEFILE_DIR)/test_attestation_policy_2.rego
ATTESTATION_POLICY_ID_1 := test-attestation-policy-1
ATTESTATION_POLICY_ID_2 := test-attestation-policy-2

# match those with the entries in the config/*.toml files
CA_KEY := $(WORK_DIR)/ca.key
CA_CSR := $(WORK_DIR)/ca-req.csr
CA_CERT := $(WORK_DIR)/ca-cert.pem
TOKEN_KEY := $(WORK_DIR)/token.key
TOKEN_CSR := $(WORK_DIR)/token-req.csr
TOKEN_CERT := $(WORK_DIR)/token-cert.pem
TOKEN_CERT_CHAIN := $(WORK_DIR)/token-cert-chain.pem
KBS_KEY := $(WORK_DIR)/kbs.key
KBS_PEM := $(WORK_DIR)/kbs.pem
TEE_KEY := $(WORK_DIR)/tee.key
HTTPS_KEY := $(WORK_DIR)/https.key
HTTPS_CERT := $(WORK_DIR)/https.crt
KBS_POLICY := $(WORK_DIR)/kbs-policy.rego

SHELL := bash
ifneq ($(OS),Ubuntu)
    $(error "This Makefile requires Ubuntu")
endif

define TEE_POLICY_REGO
package policy

default allow = false

allow {
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["$(TEE)"]
}
endef
export TEE_POLICY_REGO

.PHONY: install-dev-dependencies
install-dev-dependencies: install-dependencies
	sudo apt-get update && \
	sudo apt-get install -y \
		build-essential \
		clang \
		libsgx-dcap-quote-verify-dev \
		libssl-dev \
		libtss2-dev \
		libudev-dev \
		pkg-config \
		protobuf-compiler

.PHONY: install-dependencies
install-dependencies:
	curl -L "$(SGX_REPO_URL)/intel-sgx-deb.key" | sudo gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
	echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] $(SGX_REPO_URL) $(CODENAME) main" \
		| sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
	sudo apt-get update && \
	sudo apt-get install -y \
		libsgx-dcap-default-qpl \
		libsgx-dcap-quote-verify \
		libsgx-urts \
		libtss2-esys-3.0.2-0 \
		libtss2-tctildr0 \
		openssl && \
	echo '{"collateral_service": "$(SGX_COLLATERAL_URL)"}' | sudo tee $(SGX_QCNL_CONFIG)

kbs:
	cd $(PROJECT_DIR) && \
	make background-check-kbs && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs $(CURDIR)/kbs

resource-kbs:
	cd $(PROJECT_DIR) && \
	make passport-resource-kbs && \
	install -D --compare $(PROJECT_DIR)/../target/release/resource-kbs $(CURDIR)/resource-kbs

client:
	cd $(PROJECT_DIR) && \
	cargo build -p kbs-client --release && \
	install -D --compare $(PROJECT_DIR)/../target/release/kbs-client $(CURDIR)/client

.PHONY: bins
bins: kbs resource-kbs client

$(CA_KEY):
	openssl genrsa -traditional -out $(CA_KEY) 2048

$(CA_CERT): $(CA_KEY)
	openssl req -new -key "$(CA_KEY)" -out "$(CA_CSR)" \
		-subj "/O=CNCF/OU=CoCo/CN=KBS-test-root" && \
	openssl req -x509 -days 3650 -key "$(CA_KEY)" -in "$(CA_CSR)" -out "$(CA_CERT)"

$(TOKEN_KEY):
	openssl ecparam -name prime256v1 -genkey -noout -out "$@"

$(TOKEN_CERT): $(TOKEN_KEY) $(CA_CERT) $(CA_KEY)
	openssl req -new -key "$(TOKEN_KEY)" -out "$(TOKEN_CSR)" \
		-subj "/O=CNCF/OU=CoCo/CN=CoCo-AS" && \
	openssl x509 -req -in "$(TOKEN_CSR)" -CA "$(CA_CERT)" -CAkey "$(CA_KEY)" \
		-CAcreateserial -out $(TOKEN_CERT) -extensions req_ext

$(TOKEN_CERT_CHAIN): $(TOKEN_CERT) $(CA_CERT)
	cat "$(TOKEN_CERT)" "$(CA_CERT)" > "$(TOKEN_CERT_CHAIN)"

.PHONY: generate-attestation-token-signer
generate-attestation-token-signer: $(TOKEN_CERT_CHAIN)

$(HTTPS_KEY) $(HTTPS_CERT):
	openssl req -x509 -out "$(HTTPS_CERT)" -keyout "$(HTTPS_KEY)" \
		-newkey rsa:2048 -nodes -sha256 \
		-subj '/CN=kbs.coco' \
		--addext "subjectAltName=IP:127.0.0.1" \
		--addext "basicConstraints=CA:FALSE"

$(KBS_KEY):
	openssl genpkey -algorithm ed25519 > "$(KBS_KEY)"

$(KBS_PEM): $(KBS_KEY)
	openssl pkey -in "$(KBS_KEY)" -pubout -out "$(KBS_PEM)"

$(TEE_KEY):
	openssl genrsa -traditional -out "$(TEE_KEY)" 2048

$(SECRET_FILE):
	mkdir -p $$(dirname "$(SECRET_FILE)") && \
	openssl rand 16 > "$(SECRET_FILE)"

$(TEST_RESOURCE_1):
	mkdir -p $$(dirname "$(TEST_RESOURCE_1)") && \
	echo "test-resource-content-1" > "$(TEST_RESOURCE_1)"

$(TEST_RESOURCE_2):
	mkdir -p $$(dirname "$(TEST_RESOURCE_2)") && \
	echo "test-resource-content-2" > "$(TEST_RESOURCE_2)"

.PHONY: start-kbs
start-kbs: kbs.PID

.PHONY: start-resource-kbs
start-resource-kbs: resource-kbs.PID

kbs-keys: $(KBS_KEY) $(TOKEN_KEY) $(HTTPS_KEY)

kbs-certs: $(KBS_PEM) $(TOKEN_CERT_CHAIN) $(HTTPS_CERT)

kbs.PID: kbs kbs-keys kbs-certs $(SECRET_FILE)
	@printf "${BOLD}start kbs${SGR0}\n"
	{ \
		"$(CURDIR)/kbs" --config-file "$(KBS_CONFIG_PATH)/kbs.toml" \
		& echo $$! > kbs.PID; \
	} && \
	sleep 1

resource-kbs.PID: resource-kbs $(KBS_PEM) $(CA_CERT) $(SECRET_FILE)
	@printf "${BOLD}start resource-kbs${SGR0}\n"
	{ \
		./resource-kbs --config-file "$(KBS_CONFIG_PATH)/resource-kbs.toml" \
		& echo $$! > resource-kbs.PID; \
	} && \
	sleep 1

.PHONY: stop-kbs
stop-kbs: kbs.PID
	@printf "${BOLD}stop kbs${SGR0}\n"
	kill $$(cat $<) && rm $<

.PHONY: stop-resource-kbs
stop-resource-kbs: resource-kbs.PID
	@printf "${BOLD}stop resource-kbs${SGR0}\n"
	kill $$(cat $<) && rm $<

test-bgcheck: client start-kbs
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		get-resource \
		--path "$(REPOSITORY_SECRET)" \
		| base64 -d > "$(ROUNDTRIP_FILE)" && \
	diff "$(ROUNDTRIP_FILE)" "$(SECRET_FILE)"
	@printf "${BOLD}background-check e2e test passed${SGR0}\n"

.PHONY: $(ATTESTATION_TOKEN)
$(ATTESTATION_TOKEN): client $(TEE_KEY) start-kbs
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		attest \
		--tee-key-file "$(TEE_KEY)" \
		> "$(ATTESTATION_TOKEN)"

test-passport: client $(ATTESTATION_TOKEN) start-resource-kbs
	./client --url http://127.0.0.1:50002 \
		config --auth-private-key "$(KBS_KEY)" \
		set-resource-policy --policy-file <(echo "$$TEE_POLICY_REGO") && \
	./client --url http://127.0.0.1:50002 get-resource \
		--attestation-token "$(ATTESTATION_TOKEN)" \
		--tee-key-file "$(TEE_KEY)" \
		--path $(REPOSITORY_SECRET) \
		| base64 -d > "$(ROUNDTRIP_FILE)" && \
	diff "$(SECRET_FILE)" "$(ROUNDTRIP_FILE)"
	@printf "${BOLD}passport e2e test passed${SGR0}\n"

test-resource-crud: client start-kbs $(TEST_RESOURCE_1) $(TEST_RESOURCE_2)
	@printf "${BOLD}Testing KBS Resource CRUD operations${SGR0}\n"
	
	# Set resource policy first
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource-policy \
		--policy-file <(echo "$$TEE_POLICY_REGO") && \
	
	# Test 1: Set resource 1
	@printf "${BOLD}1. Setting resource $(TEST_RESOURCE_PATH_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource \
		--path "$(TEST_RESOURCE_PATH_1)" \
		--resource-file "$(TEST_RESOURCE_1)" && \
	
	# Test 2: Set resource 2
	@printf "${BOLD}2. Setting resource $(TEST_RESOURCE_PATH_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-resource \
		--path "$(TEST_RESOURCE_PATH_2)" \
		--resource-file "$(TEST_RESOURCE_2)" && \
	
	# Test 3: List all resources
	@printf "${BOLD}3. Listing all resources${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-resources && \
	
	# Test 4: List resources by repository
	@printf "${BOLD}4. Listing resources by repository (test_repo)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-resources \
		--repository "test_repo" && \
	
	# Test 5: List resources by type
	@printf "${BOLD}5. Listing resources by type (secret)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-resources \
		--type "secret" && \
	
	# Test 6: Get resource 1
	@printf "${BOLD}6. Getting resource $(TEST_RESOURCE_PATH_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		get-resource \
		--path "$(TEST_RESOURCE_PATH_1)" \
		| base64 -d > "$(WORK_DIR)/retrieved_resource_1" && \
	diff "$(TEST_RESOURCE_1)" "$(WORK_DIR)/retrieved_resource_1" && \
	
	# Test 7: Get resource 2
	@printf "${BOLD}7. Getting resource $(TEST_RESOURCE_PATH_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		get-resource \
		--path "$(TEST_RESOURCE_PATH_2)" \
		| base64 -d > "$(WORK_DIR)/retrieved_resource_2" && \
	diff "$(TEST_RESOURCE_2)" "$(WORK_DIR)/retrieved_resource_2" && \
	
	# Test 8: Delete resource 1
	@printf "${BOLD}8. Deleting resource $(TEST_RESOURCE_PATH_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		delete-resource \
		--path "$(TEST_RESOURCE_PATH_1)" && \
	
	# Test 9: Verify resource 1 is deleted (should fail)
	@printf "${BOLD}9. Verifying resource $(TEST_RESOURCE_PATH_1) is deleted${SGR0}\n"
	! ./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		get-resource \
		--path "$(TEST_RESOURCE_PATH_1)" 2>/dev/null && \
	
	# Test 10: Delete resource 2
	@printf "${BOLD}10. Deleting resource $(TEST_RESOURCE_PATH_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		delete-resource \
		--path "$(TEST_RESOURCE_PATH_2)" && \
	
	# Test 11: List resources to verify they are deleted
	@printf "${BOLD}11. Verifying all test resources are deleted${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-resources \
		--repository "test_repo" | grep -q '[]' || true
	
	@printf "${BOLD}KBS Resource CRUD e2e test passed${SGR0}\n"

test-attestation-policy-crud: client start-kbs $(TEST_ATTESTATION_POLICY_1) $(TEST_ATTESTATION_POLICY_2)
	@printf "${BOLD}Testing KBS Attestation Policy CRUD operations${SGR0}\n"
	
	# Test 1: Set attestation policy 1
	@printf "${BOLD}1. Setting attestation policy $(ATTESTATION_POLICY_ID_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-attestation-policy \
		--type "rego" \
		--id "$(ATTESTATION_POLICY_ID_1)" \
		--policy-file "$(TEST_ATTESTATION_POLICY_1)" && \
	
	# Test 2: Set attestation policy 2
	@printf "${BOLD}2. Setting attestation policy $(ATTESTATION_POLICY_ID_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		set-attestation-policy \
		--type "rego" \
		--id "$(ATTESTATION_POLICY_ID_2)" \
		--policy-file "$(TEST_ATTESTATION_POLICY_2)" && \
	
	# Test 3: List all attestation policies
	@printf "${BOLD}3. Listing all attestation policies${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-attestation-policies && \
	
	# Test 4: Get attestation policy 1
	@printf "${BOLD}4. Getting attestation policy $(ATTESTATION_POLICY_ID_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		get-attestation-policy \
		--id "$(ATTESTATION_POLICY_ID_1)" && \
	
	# Test 5: Get attestation policy 2
	@printf "${BOLD}5. Getting attestation policy $(ATTESTATION_POLICY_ID_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		get-attestation-policy \
		--id "$(ATTESTATION_POLICY_ID_2)" && \
	
	# Test 6: Delete attestation policy 1
	@printf "${BOLD}6. Deleting attestation policy $(ATTESTATION_POLICY_ID_1)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		delete-attestation-policy \
		--id "$(ATTESTATION_POLICY_ID_1)" && \
	
	# Test 7: Verify attestation policy 1 is deleted (should fail)
	@printf "${BOLD}7. Verifying attestation policy $(ATTESTATION_POLICY_ID_1) is deleted${SGR0}\n"
	! ./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		get-attestation-policy \
		--id "$(ATTESTATION_POLICY_ID_1)" 2>/dev/null && \
	
	# Test 8: Delete attestation policy 2
	@printf "${BOLD}8. Deleting attestation policy $(ATTESTATION_POLICY_ID_2)${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		delete-attestation-policy \
		--id "$(ATTESTATION_POLICY_ID_2)" && \
	
	# Test 9: List attestation policies to verify they are deleted
	@printf "${BOLD}9. Listing attestation policies to verify deletion${SGR0}\n"
	./client \
		--url https://127.0.0.1:8080 \
		--cert-file "$(HTTPS_CERT)" \
		config \
		--auth-private-key "$(KBS_KEY)" \
		list-attestation-policies
	
	@printf "${BOLD}KBS Attestation Policy CRUD e2e test passed${SGR0}\n"

.PHONY: stop
stop: stop-kbs stop-resource-kbs

.PHONY: e2e-test
e2e-test: test-bgcheck test-passport test-resource-crud test-attestation-policy-crud stop

.PHONY: clean
clean:
	rm -rf \
		kbs \
		client \
		resource-kbs \
		work/* \
		$(TEST_ATTESTATION_POLICY_1) \
		$(TEST_ATTESTATION_POLICY_2)
