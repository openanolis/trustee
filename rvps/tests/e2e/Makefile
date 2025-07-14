OS := $(shell lsb_release -si)
RELEASE := $(shell lsb_release -sr)
MAKEFILE_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(MAKEFILE_DIR)/../..
RVPS_BIN := /usr/local/bin/rvps
RVPS_TOOL_BIN := /usr/local/bin/rvps-tool
RVPS_CACHE_PATH := /tmp/rvps-test-cache
BOLD := $(shell tput bold)
SGR0 := $(shell tput sgr0)

# Test configuration
TEST_CONFIG_LOCALFS := $(MAKEFILE_DIR)/config_localfs.json
TEST_CONFIG_LOCALJSON := $(MAKEFILE_DIR)/config_localjson.json

# Test message files
TEST_MESSAGE_1 := $(MAKEFILE_DIR)/test_message_1.json
TEST_MESSAGE_2 := $(MAKEFILE_DIR)/test_message_2.json
TEST_MESSAGE_INVALID := $(MAKEFILE_DIR)/test_message_invalid.json

# Policy test files
TEST_POLICY_1 := $(MAKEFILE_DIR)/test_policy_1.rego
TEST_POLICY_2 := $(MAKEFILE_DIR)/test_policy_2.rego

# Test data names
TEST_REF_VALUE_1 := test-binary-1
TEST_REF_VALUE_2 := test-binary-2
TEST_REF_VALUE_3 := test-package-1

# Default RVPS test address
RVPS_TEST_ADDR := 127.0.0.1:50003
RVPS_TEST_URL := http://$(RVPS_TEST_ADDR)

.PHONY: install-dependencies
install-dependencies:
	sudo apt-get update && \
	sudo apt-get install -y \
		protobuf-compiler \
		clang \
		curl \
		jq

# Build RVPS binaries
$(RVPS_BIN) $(RVPS_TOOL_BIN):
	cd $(PROJECT_DIR) && $(MAKE) build && sudo $(MAKE) install

# Create test configuration files
$(TEST_CONFIG_LOCALFS):
	mkdir -p $(RVPS_CACHE_PATH)/localfs && \
	echo '{"storage": {"type": "LocalFs", "file_path": "$(RVPS_CACHE_PATH)/localfs"}}' > $(TEST_CONFIG_LOCALFS)

$(TEST_CONFIG_LOCALJSON):
	mkdir -p $(RVPS_CACHE_PATH)/localjson && \
	echo '{"storage": {"type": "LocalJson", "file_path": "$(RVPS_CACHE_PATH)/localjson/reference_values.json"}}' > $(TEST_CONFIG_LOCALJSON)

# Create test message files
$(TEST_MESSAGE_1):
	@echo '{"version": "0.1.0", "type": "sample", "payload": "'$$(echo '{"$(TEST_REF_VALUE_1)": ["ref-value-1", "ref-value-2"], "$(TEST_REF_VALUE_2)": ["ref-value-3", "ref-value-4"]}' | base64 -w0)'"}' > $(TEST_MESSAGE_1)

$(TEST_MESSAGE_2):
	@echo '{"version": "0.1.0", "type": "sample", "payload": "'$$(echo '{"$(TEST_REF_VALUE_3)": ["ref-value-5", "ref-value-6"]}' | base64 -w0)'"}' > $(TEST_MESSAGE_2)

$(TEST_MESSAGE_INVALID):
	@echo '{"version": "999.0.0", "type": "unknown", "payload": "invalid-payload"}' > $(TEST_MESSAGE_INVALID)

# Start RVPS with LocalFS storage
rvps-localfs.pid: $(RVPS_BIN) $(TEST_CONFIG_LOCALFS)
	@printf "${BOLD}Starting RVPS with LocalFS storage${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(RVPS_BIN) --config $(TEST_CONFIG_LOCALFS) --address $(RVPS_TEST_ADDR) \
		& echo $$! > rvps-localfs.pid; \
	} && \
	sleep 2

# Start RVPS with LocalJSON storage
rvps-localjson.pid: $(RVPS_BIN) $(TEST_CONFIG_LOCALJSON)
	@printf "${BOLD}Starting RVPS with LocalJSON storage${SGR0}\n"
	{ \
		RUST_LOG=info \
		$(RVPS_BIN) --config $(TEST_CONFIG_LOCALJSON) --address $(RVPS_TEST_ADDR) \
		& echo $$! > rvps-localjson.pid; \
	} && \
	sleep 2

# Basic CRUD test with LocalFS storage
.PHONY: test-localfs-crud
test-localfs-crud: rvps-localfs.pid $(RVPS_TOOL_BIN) $(TEST_MESSAGE_1) $(TEST_MESSAGE_2)
	@printf "${BOLD}Testing RVPS CRUD operations with LocalFS storage${SGR0}\n"
	
	# Test 1: Register first message
	@printf "${BOLD}1. Registering test message 1${SGR0}\n"
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_1) && \
	
	# Test 2: Query reference values after first registration
	@printf "${BOLD}2. Querying reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_2)" && \
	
	# Test 3: Register second message
	@printf "${BOLD}3. Registering test message 2${SGR0}\n"
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_2) && \
	
	# Test 4: Query all reference values
	@printf "${BOLD}4. Querying all reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_3)" && \
	
	# Test 5: Delete a reference value
	@printf "${BOLD}5. Deleting reference value $(TEST_REF_VALUE_1)${SGR0}\n"
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_1) && \
	
	# Test 6: Verify deletion
	@printf "${BOLD}6. Verifying deletion${SGR0}\n"
	! $(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_2)" && \
	
	# Test 7: Delete remaining reference values
	@printf "${BOLD}7. Cleaning up remaining reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_2) && \
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_3)
	
	@printf "${BOLD}RVPS LocalFS CRUD test passed${SGR0}\n"

# Basic CRUD test with LocalJSON storage
.PHONY: test-localjson-crud
test-localjson-crud: rvps-localjson.pid $(RVPS_TOOL_BIN) $(TEST_MESSAGE_1) $(TEST_MESSAGE_2)
	@printf "${BOLD}Testing RVPS CRUD operations with LocalJSON storage${SGR0}\n"
	
	# Test 1: Register first message
	@printf "${BOLD}1. Registering test message 1${SGR0}\n"
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_1) && \
	
	# Test 2: Query reference values after first registration
	@printf "${BOLD}2. Querying reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_2)" && \
	
	# Test 3: Register second message
	@printf "${BOLD}3. Registering test message 2${SGR0}\n"
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_2) && \
	
	# Test 4: Query all reference values
	@printf "${BOLD}4. Querying all reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_3)" && \
	
	# Test 5: Delete a reference value
	@printf "${BOLD}5. Deleting reference value $(TEST_REF_VALUE_1)${SGR0}\n"
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_1) && \
	
	# Test 6: Verify deletion
	@printf "${BOLD}6. Verifying deletion${SGR0}\n"
	! $(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_2)" && \
	
	# Test 7: Delete remaining reference values
	@printf "${BOLD}7. Cleaning up remaining reference values${SGR0}\n"
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_2) && \
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_3)
	
	@printf "${BOLD}RVPS LocalJSON CRUD test passed${SGR0}\n"

# Test error handling
.PHONY: test-error-handling
test-error-handling: rvps-localfs.pid $(RVPS_TOOL_BIN) $(TEST_MESSAGE_INVALID)
	@printf "${BOLD}Testing RVPS error handling${SGR0}\n"
	
	# Test 1: Try to register invalid message (should fail)
	@printf "${BOLD}1. Testing invalid message registration (should fail)${SGR0}\n"
	! $(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_INVALID) && \
	
	# Test 2: Try to delete non-existent reference value
	@printf "${BOLD}2. Testing deletion of non-existent reference value${SGR0}\n"
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name non-existent-value && \
	
	# Test 3: Try to connect to invalid address
	@printf "${BOLD}3. Testing connection to invalid address (should fail)${SGR0}\n"
	! $(RVPS_TOOL_BIN) query --addr http://127.0.0.1:99999 2>/dev/null
	
	@printf "${BOLD}RVPS error handling test passed${SGR0}\n"

# Test gRPC API directly using grpcurl
.PHONY: test-grpc-api
test-grpc-api: rvps-localfs.pid $(TEST_MESSAGE_1)
	@printf "${BOLD}Testing RVPS gRPC API directly${SGR0}\n"
	
	# Test 1: Register reference value via gRPC
	@printf "${BOLD}1. Registering via gRPC${SGR0}\n"
	echo '{"message": "'$$(cat $(TEST_MESSAGE_1) | tr -d '\n' | sed 's/"/\\"/g')'"}' \
	| grpcurl -plaintext -import-path ../../protos -proto ../../protos/reference.proto -d @ $(RVPS_TEST_ADDR) reference.ReferenceValueProviderService/RegisterReferenceValue && \
	
	# Test 2: Query reference values via gRPC
	@printf "${BOLD}2. Querying via gRPC${SGR0}\n"
	echo '{}' \
	| grpcurl -plaintext -import-path ../../protos -proto ../../protos/reference.proto -d @ $(RVPS_TEST_ADDR) reference.ReferenceValueProviderService/QueryReferenceValue && \
	
	# Test 3: Delete reference value via gRPC
	@printf "${BOLD}3. Deleting via gRPC${SGR0}\n"
	echo '{"name": "$(TEST_REF_VALUE_1)"}' \
	| grpcurl -plaintext -import-path ../../protos -proto ../../protos/reference.proto -d @ $(RVPS_TEST_ADDR) reference.ReferenceValueProviderService/DeleteReferenceValue
	
	@printf "${BOLD}RVPS gRPC API test passed${SGR0}\n"

# Test concurrent operations
.PHONY: test-concurrent-operations
test-concurrent-operations: rvps-localfs.pid $(RVPS_TOOL_BIN) $(TEST_MESSAGE_1) $(TEST_MESSAGE_2)
	@printf "${BOLD}Testing RVPS concurrent operations${SGR0}\n"
	
	# Test concurrent registrations
	@printf "${BOLD}1. Testing concurrent registrations${SGR0}\n"
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_1) & \
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_2) & \
	wait && \
	
	# Test concurrent queries
	@printf "${BOLD}2. Testing concurrent queries${SGR0}\n"
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) & \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) & \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) & \
	wait && \
	
	# Cleanup
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_1) && \
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_2) && \
	$(RVPS_TOOL_BIN) delete --addr $(RVPS_TEST_URL) --name $(TEST_REF_VALUE_3)
	
	@printf "${BOLD}RVPS concurrent operations test passed${SGR0}\n"

# Test storage backend switching
.PHONY: test-storage-backend-switching
test-storage-backend-switching: $(RVPS_TOOL_BIN) $(TEST_MESSAGE_1)
	@printf "${BOLD}Testing RVPS storage backend switching${SGR0}\n"
	
	# Test 1: Start with LocalFS, add data
	@printf "${BOLD}1. Testing LocalFS storage${SGR0}\n"
	$(MAKE) rvps-localfs.pid && \
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_1) && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(MAKE) stop-rvps-localfs && \
	
	# Test 2: Switch to LocalJSON, verify isolation
	@printf "${BOLD}2. Testing LocalJSON storage isolation${SGR0}\n"
	$(MAKE) rvps-localjson.pid && \
	! $(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(RVPS_TOOL_BIN) register --addr $(RVPS_TEST_URL) --path $(TEST_MESSAGE_1) && \
	$(RVPS_TOOL_BIN) query --addr $(RVPS_TEST_URL) | grep -q "$(TEST_REF_VALUE_1)" && \
	$(MAKE) stop-rvps-localjson
	
	@printf "${BOLD}RVPS storage backend switching test passed${SGR0}\n"

.PHONY: stop-rvps-localfs
stop-rvps-localfs: rvps-localfs.pid
	@printf "${BOLD}Stopping RVPS with LocalFS storage${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(RVPS_CACHE_PATH)/localfs

.PHONY: stop-rvps-localjson
stop-rvps-localjson: rvps-localjson.pid
	@printf "${BOLD}Stopping RVPS with LocalJSON storage${SGR0}\n"
	kill $$(cat $<) && rm $<
	rm -rf $(RVPS_CACHE_PATH)/localjson

.PHONY: stop
stop: 
	-$(MAKE) stop-rvps-localfs 2>/dev/null || true
	-$(MAKE) stop-rvps-localjson 2>/dev/null || true

# Run all E2E tests
.PHONY: e2e-test
e2e-test: test-localfs-crud stop test-localjson-crud stop test-error-handling stop test-grpc-api stop test-concurrent-operations stop test-storage-backend-switching

.PHONY: clean
clean: stop
	rm -f \
		$(RVPS_BIN) \
		$(RVPS_TOOL_BIN) \
		rvps-localfs.pid \
		rvps-localjson.pid \
		$(TEST_CONFIG_LOCALFS) \
		$(TEST_CONFIG_LOCALJSON) \
		$(TEST_MESSAGE_1) \
		$(TEST_MESSAGE_2) \
		$(TEST_MESSAGE_INVALID) && \
	rm -rf $(RVPS_CACHE_PATH) 