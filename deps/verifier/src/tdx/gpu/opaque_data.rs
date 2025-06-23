use anyhow::{anyhow, Result};
use log::debug;
use std::collections::HashMap;

#[derive(Debug)]
pub struct OpaqueData {
    pub fields: HashMap<String, Vec<u8>>,
}

impl OpaqueData {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut fields = HashMap::new();
        let mut offset = 0;

        while offset + 4 <= data.len() {
            // Read data type (2 bytes, little endian)
            let data_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            // Read data size (2 bytes, little endian)
            let data_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + data_size > data.len() {
                break;
            }

            // Read data content
            let field_data = data[offset..offset + data_size].to_vec();
            offset += data_size;

            // Map field name based on data type
            let field_name = Self::get_field_name(data_type);
            debug!(
                "Opaque field: {} (type={}, size={})",
                field_name, data_type, data_size
            );

            fields.insert(field_name, field_data);
        }

        Ok(OpaqueData { fields })
    }

    pub fn get_string_field(&self, field_name: &str) -> Result<String> {
        match self.fields.get(field_name) {
            Some(data) => {
                // Remove trailing null characters
                let trimmed_data: Vec<u8> = data.iter().cloned().take_while(|&b| b != 0).collect();
                String::from_utf8(trimmed_data)
                    .map_err(|e| anyhow!("Cannot convert field {} to string: {}", field_name, e))
            }
            None => Err(anyhow!("Field {} does not exist", field_name)),
        }
    }

    #[allow(dead_code)]
    pub fn get_binary_field(&self, field_name: &str) -> Result<&[u8]> {
        self.fields
            .get(field_name)
            .map(|v| v.as_slice())
            .ok_or_else(|| anyhow!("Field {} does not exist", field_name))
    }

    fn get_field_name(data_type: u16) -> String {
        match data_type {
            1 => "CERT_ISSUER_NAME".to_string(),
            2 => "CERT_AUTHORITY_KEY_IDENTIFIER".to_string(),
            3 => "DRIVER_VERSION".to_string(),
            4 => "GPU_INFO".to_string(),
            5 => "SKU".to_string(),
            6 => "VBIOS_VERSION".to_string(),
            7 => "MANUFACTURER_ID".to_string(),
            8 => "TAMPER_DETECTION".to_string(),
            9 => "SMC".to_string(),
            10 => "VPR".to_string(),
            11 => "NVDEC0_STATUS".to_string(),
            12 => "MSRSCNT".to_string(),
            13 => "CPRINFO".to_string(),
            14 => "BOARD_ID".to_string(),
            15 => "CHIP_SKU".to_string(),
            16 => "CHIP_SKU_MOD".to_string(),
            17 => "PROJECT".to_string(),
            18 => "PROJECT_SKU".to_string(),
            19 => "PROJECT_SKU_MOD".to_string(),
            20 => "FWID".to_string(),
            21 => "PROTECTED_PCIE_STATUS".to_string(),
            22 => "SWITCH_PDI".to_string(),
            23 => "FLOORSWEPT_PORTS".to_string(),
            24 => "POSITION_ID".to_string(),
            25 => "LOCK_SWITCH_STATUS".to_string(),
            32 => "GPU_LINK_CONN".to_string(),
            33 => "SYS_ENABLE_STATUS".to_string(),
            34 => "OPAQUE_DATA_VERSION".to_string(),
            35 => "CHIP_INFO".to_string(),
            255 => "INVALID".to_string(),
            _ => format!("UNKNOWN_{}", data_type),
        }
    }
}
