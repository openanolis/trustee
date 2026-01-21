package policy

import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 35

##### Common Helper Functions

# Generic function to validate measurements for any platform and algorithm
validate_boot_measurements(measurements_data) if {
	some algorithm in {"SHA-1", "SHA-256", "SHA-384"}
	components := ["grub", "shim", "initrd", "kernel"]
	every component in components {
		measurement_key := sprintf("measurement.%s.%s", [component, algorithm])
		measurements_data[measurement_key] in data.reference[measurement_key]
	}
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline(measurements_data, cmdline_data) if {
	some algorithm in {"SHA-1", "SHA-256", "SHA-384"}
	measurement_key := sprintf("measurement.kernel_cmdline.%s", [algorithm])
	measurements_data[measurement_key] in data.reference[measurement_key]
}

### The following functions are for parsing UEFI event logs
### These functions are chosen when the related verifier is using `deps/eventlog`
### crate

# Parse grub algorithm and digest
parse_grub(uefi_event_logs) := grub if {
	some i, j
	uefi_event_logs[i].type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	contains(uefi_event_logs[i].details.device_paths[j], "grub")
	grub := {
		"alg": uefi_event_logs[i].digests[0].alg,
		"value": uefi_event_logs[i].digests[0].digest,
	}
}

# Parse shim algorithm and digest
parse_shim(uefi_event_logs) := shim if {
	some i, j
	uefi_event_logs[i].type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
	contains(uefi_event_logs[i].details.device_paths[j], "shim")
	shim := {
		"alg": uefi_event_logs[i].digests[0].alg,
		"value": uefi_event_logs[i].digests[0].digest,
	}
}

# Parse kernel algorithm and digest
parse_kernel(uefi_event_logs) := kernel if {
	some i
	uefi_event_logs[i].type_name == "EV_IPL"
	contains(uefi_event_logs[i].details.string, "Kernel")
	kernel := {
		"alg": uefi_event_logs[i].digests[0].alg,
		"value": uefi_event_logs[i].digests[0].digest,
	}
}

# Parse initrd algorithm and digest
parse_initrd(uefi_event_logs) := initrd if {
	some i
	uefi_event_logs[i].type_name == "EV_IPL"
	contains(uefi_event_logs[i].details.string, "Initrd")
	initrd := {
		"alg": uefi_event_logs[i].digests[0].alg,
		"value": uefi_event_logs[i].digests[0].digest,
	}
}

# Generic function to validate measurements for any platform and algorithm
# that recorded via uefi eventlog format
validate_boot_measurements_uefi_event_log(uefi_event_logs) if {
	grub := parse_grub(uefi_event_logs)
	shim := parse_shim(uefi_event_logs)
	initrd := parse_initrd(uefi_event_logs)
	kernel := parse_kernel(uefi_event_logs)
	components := [
		{"name": "grub", "value": grub.value, "alg": grub.alg},
		{"name": "shim", "value": shim.value, "alg": shim.alg},
		{"name": "initrd", "value": initrd.value, "alg": initrd.alg},
		{"name": "kernel", "value": kernel.value, "alg": kernel.alg},
	]
	every component in components {
		measurement_key := sprintf("measurement.%s.%s", [component.name, component.alg])
		component.value in data.reference[measurement_key]
	}
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline_uefi(uefi_event_logs) if {
	some prefix in ["grub_cmd linux", "kernel_cmdline", "grub_kernel_cmdline"]
	some i
	uefi_event_logs[i].type_name == "EV_IPL"
	startswith(uefi_event_logs[i].details.string, prefix)
	measurement_key := sprintf("measurement.kernel_cmdline.%s", [uefi_event_logs[i].digests[0].alg])
	uefi_event_logs[i].digests[0].digest in data.reference[measurement_key]
}

# Function to check the cryptpilot load config
validate_cryptpilot_config(uefi_event_logs) if {
	some i
	uefi_event_logs[i].type_name == "EV_EVENT_TAG"
	uefi_event_logs[i].details.unicode_name == "AAEL"
	uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
	uefi_event_logs[i].details.data.operation == "load_config"
	uefi_event_logs[i].details.data.content in data.reference["AA.eventlog.cryptpilot.alibabacloud.com.load_config"]
}

# Function to check the cryptpilot fde rootfs integrity
validate_cryptpilot_fde(uefi_event_logs) if {
	some i
	uefi_event_logs[i].type_name == "EV_EVENT_TAG"
	uefi_event_logs[i].details.unicode_name == "AAEL"
	uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
	uefi_event_logs[i].details.data.operation == "fde_rootfs_hash"
	uefi_event_logs[i].details.data.content in data.reference["AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash"]
}

# Function to check the file measurements from Measurement_tool integrity
validate_aael_file_measurements(uefi_event_logs) if {
	aael := [e |
		e := uefi_event_logs[_]
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "file"
	]
	every e in aael {
		key := sprintf("measurement.%s.%s", [e.details.data.domain, e.details.data.operation])
		e.details.data.content in data.reference[key]
	}
}

# Function to check the /bin file measurements from Measurement_tool integrity
validate_aael_bin_measurements(uefi_event_logs) if {
	aael := [e |
		e := uefi_event_logs[_]
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "file"
		contains(e.details.data.operation, "/bin")
	]
	every e in aael {
		key := sprintf("measurement.%s.%s", [e.details.data.domain, e.details.data.operation])
		e.details.data.content in data.reference[key]
	}
}

# Function to check the /etc file measurements from Measurement_tool integrity
validate_aael_etc_measurements(uefi_event_logs) if {
	aael := [e |
		e := uefi_event_logs[_]
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "file"
		contains(e.details.data.operation, "/etc")
	]
	every e in aael {
		key := sprintf("measurement.%s.%s", [e.details.data.domain, e.details.data.operation])
		e.details.data.content in data.reference[key]
	}
}

# Function to check the system/lib/include file measurements from Measurement_tool integrity
validate_aael_system_measurements(uefi_event_logs) if {
	aael := [e |
		e := uefi_event_logs[_]
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "file"
		some fragment in {"/system", "/lib", "/include"}
		contains(e.details.data.operation, fragment)
	]
	every e in aael {
		key := sprintf("measurement.%s.%s", [e.details.data.domain, e.details.data.operation])
		e.details.data.content in data.reference[key]
	}
}

# Function to check the AI model measurements in UEFI eventlog
validate_aael_model_measurements(uefi_event_logs) if {
	aael := [e |
		e := uefi_event_logs[_]
		e.type_name == "EV_EVENT_TAG"
		e.details.unicode_name == "AAEL"
		e.details.data.domain == "trustiflux.alibaba.com"
		contains(e.details.data.operation, "load-model")
	]
	every e in aael {
		model_measurement := json.unmarshal(e.details.data.content)
		model_id := model_measurement["model-id"]
		hash := model_measurement["hash"]
		key := sprintf("measurement.model.%s", [model_id])
		hash in data.reference[key]
	}
}

##### TDX

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	# validate_boot_measurements_uefi_event_log(input.tdx.uefi_event_logs)

	# Check AI model measurement
	# validate_aael_model_measurements(input.tdx.uefi_event_logs)

	# Check /bin measurements
	validate_aael_bin_measurements(input.tdx.uefi_event_logs)
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in data.reference["tdx.mr_seam"]
	# input.tdx.quote.body.tcb_svn in data.reference["tdx.tcb_svn"]
	# input.tdx.quote.body.mr_td in data.reference["tdx.mr_td"]
}

configuration := 2 if {
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	# input.tdx.td_attributes.debug == false
	# input.tdx.quote.body.xfam in data.reference["tdx.xfam"]

	# Check kernel command line parameters have the expected value for any supported algorithm
	# validate_kernel_cmdline_uefi(input.tdx.uefi_event_logs)

	# Check /etc measurements
	validate_aael_etc_measurements(input.tdx.uefi_event_logs)
}

file_system := 2 if {
	input.tdx

	# Check /system, /lib, /include measurements
	validate_aael_system_measurements(input.tdx.uefi_event_logs)

	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tdx.uefi_event_logs)
}

##### TPM

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	# validate_boot_measurements(input.tpm)

	# Check AI model measurement
	# validate_aael_model_measurements(input.tdx.uefi_event_logs)

	# Check /bin measurements
	validate_aael_bin_measurements(input.tpm.uefi_event_logs)
}

hardware := 2 if {
	# Placeholder to avoid empty body. Remove when enabling checks below.
	input.tpm
	# Check TPM EK cert issuer
	# input.tpm.EK_cert_issuer.OU in data.reference["tpm_ek_issuer_ou"]

	# Check TPM firmware version
	# input.tpm["quote.firmware_version"] in data.reference["tpm.firmware_version"]
}

configuration := 2 if {
	# Check kernel command line parameters have the expected value for any supported algorithm
	# validate_kernel_cmdline(input.tpm, input.tpm.kernel_cmdline)

	# Check /etc measurements
	validate_aael_etc_measurements(input.tpm.uefi_event_logs)
}

file_system := 2 if {
	input.tpm

	# Check /system, /lib, /include measurements
	validate_aael_system_measurements(input.tpm.uefi_event_logs)

	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tpm.uefi_event_logs)
}

##### Hygon CSV

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements
	validate_boot_measurements_uefi_event_log(input.csv.uefi_event_logs)

	# Check AI model measurement
	# validate_aael_model_measurements(input.tdx.uefi_event_logs)

	# Check /bin measurements
	validate_aael_bin_measurements(input.csv.uefi_event_logs)
}

# Check cryptpilot config. Uncomment this due to your need
hardware := 2 if {
	input.csv.version in ["2", "1"]
	# input.csv.vm_id in data.reference["csv.vm_id"]
	# input.csv.vm_version in data.reference["csv.vm_version"]
	# input.csv.serial_number in data.reference["csv.serial_number"]
	# input.csv.measurement in data.reference["csv.measurement"]
}

# Check cryptpilot config. Uncomment this due to your need
configuration := 2 if {
	# input.csv.policy.nodbg in data.reference["csv.policy.nodbg"]
	# input.csv.policy.noks in data.reference["csv.policy.noks"]
	# input.csv.policy.es in data.reference["csv.policy.es"]
	# input.csv.policy.nosend in data.reference["csv.policy.nosend"]
	# input.csv.policy.domain in data.reference["csv.policy.domain"]
	# input.csv.policy.csv in data.reference["csv.policy.csv"]
	# input.csv.policy.csv3 in data.reference["csv.policy.csv3"]
	# input.csv.policy.asid_reuse in data.reference["csv.policy.asid_reuse"]
	# input.csv.policy.hsk_version in data.reference["csv.policy.hsk_version"]
	# input.csv.policy.cek_version in data.reference["csv.policy.cek_version"]
	# input.csv.policy.api_major in data.reference["csv.policy.api_major"]
	# input.csv.policy.api_minor in data.reference["csv.policy.api_minor"]
	# input.csv.user_pubkey_digest in data.reference["csv.user_pubkey_digest"]

	# Check kernel command line parameters have the expected value for any supported algorithm
	# validate_kernel_cmdline_uefi(input.csv.uefi_event_logs)

	# Check /etc measurements
	validate_aael_etc_measurements(input.csv.uefi_event_logs)
}

file_system := 2 if {
	input.csv

	# Check /system, /lib, /include measurements
	validate_aael_system_measurements(input.csv.uefi_event_logs)

	# Check rootfs integrity
	# validate_cryptpilot_fde(input.tpm.uefi_event_logs)
	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tpm.uefi_event_logs)
}