package policy

import rego.v1

# This policy validates multiple TEE platforms
# The policy is meant to capture the TCB requirements
# for confidential containers.

# This policy is used to generate an EAR Appraisal.
# Specifically it generates an AR4SI result.
# More informatino on AR4SI can be found at
# <https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/>

# For the `executables` trust claim, the value 33 stands for
# "Runtime memory includes executables, scripts, files, and/or
#  objects which are not recognized."
default executables := 33

# For the `hardware` trust claim, the value 97 stands for
# "A Verifier does not recognize an Attester's hardware or
#  firmware, but it should be recognized."
default hardware := 97

# For the `configuration` trust claim the value 36 stands for
# "Elements of the configuration relevant to security are
#  unavailable to the Verifier."
default configuration := 36

# For the `filesystem` trust claim, the value 35 stands for
# "File system integrity cannot be verified or is compromised."
default file_system := 35

##### Common Helper Functions

# Generic function to validate measurements for any platform and algorithm
validate_boot_measurements(measurements_data) if {
	some algorithm in {"SHA1", "SHA256", "SHA384", "SM3", "SM-3"}
	components := ["grub", "shim", "initrd", "kernel"]
	every component in components {
		measurement_key := sprintf("measurement.%s.%s", [component, algorithm])
		measurements_data[measurement_key] in query_reference_value(measurement_key)
	}
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline(measurements_data, cmdline_data) if {
	some algorithm in {"SHA1", "SHA256", "SHA384", "SM3", "SM-3"}
	measurement_key := sprintf("measurement.kernel_cmdline.%s", [algorithm])
	measurements_data[measurement_key] in query_reference_value(measurement_key)
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
		component.value in query_reference_value(measurement_key)
	}
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline_uefi(uefi_event_logs) if {
	some prefix in ["grub_cmd linux", "kernel_cmdline", "grub_kernel_cmdline"]
	some i
	uefi_event_logs[i].type_name == "EV_IPL"
	startswith(uefi_event_logs[i].details.string, prefix)
	measurement_key := sprintf("measurement.kernel_cmdline.%s", [uefi_event_logs[i].digests[0].alg])
	uefi_event_logs[i].digests[0].digest in query_reference_value(measurement_key)
}

# Function to check the cryptpilot load config
validate_cryptpilot_config(uefi_event_logs) if {
	some i
	uefi_event_logs[i].type_name == "EV_EVENT_TAG"
	uefi_event_logs[i].details.unicode_name == "AAEL"
	uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
	uefi_event_logs[i].details.data.operation == "load_config"
	uefi_event_logs[i].details.data.content in query_reference_value("AA.eventlog.cryptpilot.alibabacloud.com.load_config")
}

# Function to check the cryptpilot fde rootfs integrity
validate_cryptpilot_fde(uefi_event_logs) if {
	some i
	uefi_event_logs[i].type_name == "EV_EVENT_TAG"
	uefi_event_logs[i].details.unicode_name == "AAEL"
	uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
	uefi_event_logs[i].details.data.operation == "fde_rootfs_hash"
	uefi_event_logs[i].details.data.content in query_reference_value("AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash")
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
		e.details.data.content in query_reference_value(key)
	}
}

##### AMD SEV-SNP

# Reference-value checks are deployment-specific. Uncomment the checks needed
# by the relying party after provisioning the corresponding RVPS values.
executables := 3 if {
	input.snp
	# input.snp.measurement in query_reference_value("snp.measurement")
}

hardware := 2 if {
	input.snp
	# input.snp.reported_tcb_bootloader in query_reference_value("snp.reported_tcb_bootloader")
	# input.snp.reported_tcb_tee in query_reference_value("snp.reported_tcb_tee")
	# input.snp.reported_tcb_snp in query_reference_value("snp.reported_tcb_snp")
	# input.snp.reported_tcb_microcode in query_reference_value("snp.reported_tcb_microcode")
	# Turin and later only:
	# input.snp.reported_tcb_fmc in query_reference_value("snp.reported_tcb_fmc")
}

configuration := 2 if {
	input.snp.policy_debug_allowed == "0"
	input.snp.policy_migrate_ma == "0"
}

# Base SNP evidence does not authenticate runtime filesystem state.
file_system := 0 if {
	input.snp
}

##### TDX

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	validate_boot_measurements_uefi_event_log(input.tdx.uefi_event_logs)
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	# Check TDX Module version and its hash. Also check OVMF code hash.
	# input.tdx.quote.body.mr_seam in query_reference_value("tdx.mr_seam")
	# input.tdx.quote.body.tcb_svn in query_reference_value("tdx.tcb_svn")
	# input.tdx.quote.body.mr_td in query_reference_value("tdx.mr_td")
}

configuration := 2 if {
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	# input.tdx.td_attributes.debug == false
	input.tdx.quote.body.xfam in query_reference_value("tdx.xfam")

	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline_uefi(input.tdx.uefi_event_logs)
	# Check cryptpilot config
	# validate_cryptpilot_config(input.tdx.uefi_event_logs)
}

file_system := 2 if {
	input.tdx

	# Placeholder to avoid empty body being treated as true. Remove when enabling checks below.
	false
	# Check rootfs integrity
	# validate_cryptpilot_fde(input.tdx.uefi_event_logs)

	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tdx.uefi_event_logs)
}

##### TPM

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	validate_boot_measurements(input.tpm)
}

hardware := 2 if {
	# Placeholder to avoid empty body. Remove when enabling checks below.
	input.tpm
	# Check TPM EK cert issuer
	# input.tpm.EK_cert_issuer.OU in query_reference_value("tpm_ek_issuer_ou")

	# Check TPM firmware version
	# input.tpm["quote.firmware_version"] in query_reference_value("tpm.firmware_version")
}

configuration := 2 if {
	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline(input.tpm, input.tpm.kernel_cmdline)
	# Check cryptpilot config
	# validate_cryptpilot_config(input.tpm.uefi_event_logs)
}

file_system := 2 if {
	input.tpm

	# Placeholder to avoid empty body being treated as true. Remove when enabling checks below.
	false
	# Check rootfs integrity
	# validate_cryptpilot_fde(input.tpm.uefi_event_logs)

	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tpm.uefi_event_logs)
}

##### Hygon TPM

executables := 3 if {
	validate_boot_measurements(input.hygontpm)
}

hardware := 2 if {
	input.hygontpm
	# input.hygontpm.EK_cert_issuer.OU in query_reference_value("hygontpm.ek_cert_issuer_ou")
	# input.hygontpm["quote.firmware_version"] in query_reference_value("hygontpm.firmware_version")
}

configuration := 2 if {
	validate_kernel_cmdline(input.hygontpm, input.hygontpm.kernel_cmdline)
}

file_system := 2 if {
	input.hygontpm

	# Placeholder to avoid empty body being treated as true. Remove when enabling checks below.
	false
	# validate_cryptpilot_fde(input.hygontpm.uefi_event_logs)
	# validate_aael_file_measurements(input.hygontpm.uefi_event_logs)
}

##### Sample TEE (for testing)

executables := 2 if {
	input.sample
}

hardware := 2 if {
	input.sample
}

configuration := 2 if {
	input.sample
}

file_system := 2 if {
	input.sample
}

##### Hygon CSV

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements
	validate_boot_measurements_uefi_event_log(input.csv.uefi_event_logs)
}

# Check cryptpilot config. Uncomment this due to your need
hardware := 2 if {
	input.csv.version in ["2", "1"]
	# input.csv.vm_id in query_reference_value("csv.vm_id")
	# input.csv.vm_version in query_reference_value("csv.vm_version")
	# input.csv.serial_number in query_reference_value("csv.serial_number")
	# input.csv.measurement in query_reference_value("csv.measurement")
}

# Check cryptpilot config. Uncomment this due to your need
configuration := 2 if {
	# input.csv.policy.nodbg in query_reference_value("csv.policy.nodbg")
	# input.csv.policy.noks in query_reference_value("csv.policy.noks")
	# input.csv.policy.es in query_reference_value("csv.policy.es")
	# input.csv.policy.nosend in query_reference_value("csv.policy.nosend")
	# input.csv.policy.domain in query_reference_value("csv.policy.domain")
	# input.csv.policy.csv in query_reference_value("csv.policy.csv")
	# input.csv.policy.csv3 in query_reference_value("csv.policy.csv3")
	# input.csv.policy.asid_reuse in query_reference_value("csv.policy.asid_reuse")
	# input.csv.policy.hsk_version in query_reference_value("csv.policy.hsk_version")
	# input.csv.policy.cek_version in query_reference_value("csv.policy.cek_version")
	# input.csv.policy.api_major in query_reference_value("csv.policy.api_major")
	# input.csv.policy.api_minor in query_reference_value("csv.policy.api_minor")
	# input.csv.user_pubkey_digest in query_reference_value("csv.user_pubkey_digest")

	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline_uefi(input.csv.uefi_event_logs)
	# Check cryptpilot config. Uncomment this due to your need
	# validate_cryptpilot_config(input.csv.uefi_event_logs)
}

file_system := 2 if {
	input.csv

	# Placeholder to avoid empty body being treated as true. Remove when enabling checks below.
	false
	# Check rootfs integrity
	# validate_cryptpilot_fde(input.tpm.uefi_event_logs)
	# Check measured files - iterate through all file measurements
	# validate_aael_file_measurements(input.tpm.uefi_event_logs)
}

default allow := false

allow := true if {
	executables <= 32
	hardware <= 32
	configuration <= 32
	file_system <= 32
}
