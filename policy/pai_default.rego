package policy

import rego.v1

default executables := 33
default hardware := 97
default configuration := 36
default file_system := 35

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
	validate_aael_model_measurements(input.tdx.uefi_event_logs)
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
    input.tdx
}

file_system := 2 if {
    input.tdx
}

##### SYSTEM

executables := 3 if {
	# Check AI model measurement
	validate_aael_model_measurements(input.system.uefi_event_logs)
}

hardware := 2 if {
	input.system
}

configuration := 2 if {
	input.system
}

file_system := 2 if {
	input.system
}