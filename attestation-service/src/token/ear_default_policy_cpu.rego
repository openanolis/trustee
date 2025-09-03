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
# FIXME: now the `file_system` claim returned by rego is not well
# handled by EAR token broker, as it expects `file-system`.
default file_system := 35

##### Common Helper Functions

# Generic function to validate measurements for any platform and algorithm
validate_boot_measurements(measurements_data) if {
	some algorithm in {"SHA1", "SHA256", "SHA384"}
	components := ["grub", "shim", "initrd", "kernel"]
	every component in components {
		measurement_key := sprintf("measurement.%s.%s", [component, algorithm])
		measurements_data[measurement_key] in data.reference[measurement_key]
	}
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline(measurements_data, cmdline_data) if {
	cmdline_data in data.reference.kernel_cmdline

	some algorithm in {"SHA1", "SHA256", "SHA384"}
	measurement_key := sprintf("measurement.kernel_cmdline.%s", [algorithm])
	measurements_data[measurement_key] in data.reference[measurement_key]
}

# Generic funtion to validate all file measurements in AA Eventlog
file_measurements_valid(measurements_data) if {
	every file_key, file_value in measurements_data {
		startswith(file_key, "AA.eventlog.file")
		file_path := substring(file_key, 16, -1)
		file_value in data.reference[sprintf("measurement.file%s", [file_path])]
	}
}

##### TDX

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	validate_boot_measurements(input.tdx.ccel)
}

hardware := 2 if {
	# Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

	# Check TDX Module version and its hash. Also check OVMF code hash.
	input.tdx.quote.body.mr_seam in data.reference["tdx.mr_seam"]
	input.tdx.quote.body.tcb_svn in data.reference["tdx.tcb_svn"]
	input.tdx.quote.body.mr_td in data.reference["tdx.mr_td"]
}

configuration := 2 if {
	# Check the TD has the expected attributes (e.g., debug not enabled) and features.
	# input.tdx.td_attributes.debug == false
	input.tdx.quote.body.xfam in data.reference["tdx.xfam"]

	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline(input.tdx.ccel, input.tdx.ccel.kernel_cmdline)
	# Check cryptpilot config
	# input.tdx["AA.eventlog.cryptpilot.alibabacloud.com.load_config"] in data.reference["cryptpilot.load_config"]
}

file_system := 2 if {
	# Check rootfs integrity
	input.tdx["AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash"] in data.reference["measurement.rootfs"]

	# Check measured files - iterate through all file measurements
	file_measurements_valid(input.tdx)
}

##### TPM

executables := 3 if {
	# Check the kernel, initrd, shim and grub measurements for any supported algorithm
	validate_boot_measurements(input.tpm)
}

hardware := 2 if {
	# Check TPM EK cert issuer
	# input.tpm.EK_cert_issuer.OU in data.reference["tpm_ek_issuer_ou"]

	# Check TPM firmware version
	input.tpm["quote.firmware_version"] in data.reference["tpm.firmware_version"]
}

configuration := 2 if {
	# Check kernel command line parameters have the expected value for any supported algorithm
	validate_kernel_cmdline(input.tpm, input.tpm.kernel_cmdline)
	# Check cryptpilot config
	# input.tpm["AA.eventlog.cryptpilot.alibabacloud.com.load_config"] in data.reference["cryptpilot.load_config"]
}

file_system := 2 if {
	# Check rootfs integrity
	input.tpm["AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash"] in data.reference["measurement.rootfs"]

	# Check measured files - iterate through all file measurements
	file_measurements_valid(input.tpm)
}
