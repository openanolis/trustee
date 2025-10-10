// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside a TDX Quote and CCEL and
//! serialize them into a JSON. The format will look lile
//! ```json
//! {
//!  "ccel": {
//!    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
//!    "kernel_parameters": {
//!      "console": "hvc0",
//!      "root": "/dev/vda1",
//!      "rw": null
//!    }
//!  },
//!  "quote": {
//!    "header":{
//!        "version": "0400",
//!        "att_key_type": "0200",
//!        "tee_type": "81000000",
//!        "reserved": "00000000",
//!        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
//!        "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
//!    },
//!    "body":{
//!        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
//!        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
//!        "seam_attributes": "0000000000000000",
//!        "td_attributes": "0100001000000000",
//!        "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
//!        "tcb_svn": "03000500000000000000000000000000",
//!        "xfam": "e742060000000000",
//!        "rtmr_0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_1": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//!    }
//!  }
//!}
//! ```

use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use eventlog::CcEventLog;
use log::debug;
use serde_json::{Map, Value};

use crate::{tdx::quote::QuoteV5Body, TeeEvidenceParsedClaim};

use super::quote::Quote;

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

pub fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    match &quote {
        Quote::V4 { header, body } => {
            parse_claim!(quote_header, "version", b"\x04\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
            parse_claim!(quote_body, "mr_seam", body.mr_seam);
            parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
            parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
            parse_claim!(quote_body, "td_attributes", body.td_attributes);
            parse_claim!(quote_body, "xfam", body.xfam);
            parse_claim!(quote_body, "mr_td", body.mr_td);
            parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
            parse_claim!(quote_body, "mr_owner", body.mr_owner);
            parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
            parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
            parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
            parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
            parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
            parse_claim!(quote_body, "report_data", body.report_data);

            parse_claim!(quote_map, "header", quote_header);
            parse_claim!(quote_map, "body", quote_body);
        }
        Quote::V5 {
            header,
            r#type,
            size,
            body,
        } => {
            parse_claim!(quote_header, "version", b"\x05\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_map, "type", r#type.as_bytes());
            parse_claim!(quote_map, "size", &size[..]);
            match body {
                QuoteV5Body::Tdx10(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
                QuoteV5Body::Tdx15(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_body, "tee_tcb_svn2", body.tee_tcb_svn2);
                    parse_claim!(quote_body, "mr_servicetd", body.mr_servicetd);
                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
            }
        }
    }

    let mut claims = Map::new();

    // Claims from CC EventLog.
    if let Some(ccel) = cc_eventlog {
        let result = serde_json::to_value(ccel.clone().log)?;
        claims.insert("uefi_event_logs".to_string(), result);
    }

    parse_claim!(claims, "quote", quote_map);

    parse_claim!(claims, "report_data", quote.report_data());
    parse_claim!(claims, "init_data", quote.mr_config_id());

    let claims_str = serde_json::to_string_pretty(&claims)?;
    debug!("Parsed Evidence claims map: \n{claims_str}\n");

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

const ERR_INVALID_HEADER: &str = "invalid header";
const ERR_NOT_ENOUGH_DATA: &str = "not enough data after header";

type Descriptor = [u8; 16];
type InfoLength = u32;

/// Kernel Commandline Event inside Eventlog
#[derive(Debug, PartialEq)]
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: Descriptor,
    pub info_length: InfoLength,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = anyhow::Error;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let descriptor_size = core::mem::size_of::<Descriptor>();

        let info_size = core::mem::size_of::<InfoLength>();

        let header_size = descriptor_size + info_size;

        if data.len() < header_size {
            bail!(ERR_INVALID_HEADER);
        }

        let descriptor = data[0..descriptor_size].try_into()?;

        let info_length = (&data[descriptor_size..header_size]).read_u32::<LittleEndian>()?;

        let total_size = header_size + info_length as usize;

        let data = data
            .get(header_size..total_size)
            .ok_or(ERR_NOT_ENOUGH_DATA)
            .map_err(|e| anyhow!(e))?;

        Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

#[allow(dead_code)]
fn parse_kernel_parameters(kernel_parameters: &[u8]) -> Result<Map<String, Value>> {
    let parameters_str = String::from_utf8(kernel_parameters.to_vec())?;
    debug!("kernel parameters: {parameters_str}");

    let parameters = parameters_str
        .split(&[' ', '\n', '\r', '\0'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }

            let it = item.split_once('=');

            match it {
                Some((k, v)) => Some((k.into(), v.into())),
                None => Some((item.to_string(), Value::Null)),
            }
        })
        .collect();

    Ok(parameters)
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use assert_json_diff::assert_json_eq;
    use eventlog::CcEventLog;
    use serde_json::{json, to_value, Map, Value};

    use crate::tdx::quote::parse_tdx_quote;

    use super::{generate_parsed_claim, parse_kernel_parameters};

    use rstest::rstest;

    // This is used with anyhow!() to create an actual error. However, we
    // don't care about the type of error: it's simply used to denote that
    // some sort of Err() occurred.
    const SOME_ERROR: &str = "an error of some sort occurred";

    #[test]
    fn parse_tdx_claims() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let ccel_bin = std::fs::read("./test_data/CCEL_data").expect("read ccel failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse ccel");
        let claims = generate_parsed_claim(quote, Some(ccel)).expect("parse claim failed");
        let expected = json!({
            "uefi_event_logs": [
                {
                    "details": {
                        "string": ""
                    },
                    "digests": [
                        {
                            "alg": "SHA-384",
                            "digest": "c6e6d33de4104b8196acfb57a9866ef6a85d413e86c1be96486e857b464591f4e2d252414346e9b98960246d2219a0eb"
                        }
                    ],
                    "event": "dGRfaG9iAAAAAAAAAAAAAIAUAAABADgAAAAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAFIAAAAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAHAAAAAAAAAAAAAAAAAABAAAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAE/wAAAAAAEAAAAAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAACAE/wAAAAAAAAIAAAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAACAG/wAAAAAAAAIAAAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADBAAAAAAAwAAAAAAAAOA+AAAAAAMAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAADBAAAAAAAAAEAAAD//+7//j8AAAQACBEAAAAAcFgMau3U9EShNd0ji28MjURTRFTsEAAABihDTE9VREhDSERTRFQgIAEAAABDTERIAAAAAFuCQQ4uX1NCX1BIUFIIX0hJRAxB0AoGCF9TVEEKCwhfVUlEDVBDSSBIb3RwbHVnIENvbnRyb2xsZXIAWwFCTENLAAhfQ1JTETMKMIorAAAMAQAAAAAAAAAAAPD+//8/AAAP8P7//z8AAAAAAAAAAAAAEAAAAAAAAAB5AFuAUENTVAAOAPD+//8/AAAKEFuBGlBDU1RDUENJVSBQQ0lEIEIwRUogUFNFRyAUI1BDRUoKWyNCTENL//9waVBTRUd5AWhCMEVKWydCTENLpAAUFVBTQ04IXC8DX1NCX1BDSTBQQ05UW4JK1C5fU0JfUENJMAhfSElEDEHQCggIX0NJRAxB0AoDCF9BRFIACF9TRUcLAAAIX1VJRAAIX0NDQQEIU1VQUAAUDF9QWE0ApAwAAAAAFDdfRFNNBKAqk2gREwoQ0DfJ5VM1ek2RF+pNGcNDTaAKk2oApBEECgEhoAeTagoFpACkEQQKAQAIX0NSUxFGCAqCiA0AAgwAAAAAAAAAAAABAEcB+Az4DAEIhxcAAAwBAAAAAAAAAMD////nAAAAAAAAACiKKwAADAEAAAAAAAAAAAAAAAABAAAA//////4/AAAAAAAAAAAAAAAAAAD+PwAAiA0AAQwDAAAAAPcMAAD4DIgNAAEMAwAAAA3//wAAAPN5AFuCNFMwMDAIX1NVTgoACF9BRFIMAAAAABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDEIX1NVTgoBCF9BRFIMAAABABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDIIX1NVTgoCCF9BRFIMAAACABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDMIX1NVTgoDCF9BRFIMAAADABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDQIX1NVTgoECF9BRFIMAAAEABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDUIX1NVTgoFCF9BRFIMAAAFABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDYIX1NVTgoGCF9BRFIMAAAGABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDcIX1NVTgoHCF9BRFIMAAAHABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDgIX1NVTgoICF9BRFIMAAAIABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMDkIX1NVTgoJCF9BRFIMAAAJABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTAIX1NVTgoKCF9BRFIMAAAKABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTEIX1NVTgoLCF9BRFIMAAALABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTIIX1NVTgoMCF9BRFIMAAAMABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTMIX1NVTgoNCF9BRFIMAAANABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTQIX1NVTgoOCF9BRFIMAAAOABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTUIX1NVTgoPCF9BRFIMAAAPABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTYIX1NVTgoQCF9BRFIMAAAQABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTcIX1NVTgoRCF9BRFIMAAARABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTgIX1NVTgoSCF9BRFIMAAASABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMTkIX1NVTgoTCF9BRFIMAAATABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjAIX1NVTgoUCF9BRFIMAAAUABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjEIX1NVTgoVCF9BRFIMAAAVABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjIIX1NVTgoWCF9BRFIMAAAWABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjMIX1NVTgoXCF9BRFIMAAAXABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjQIX1NVTgoYCF9BRFIMAAAYABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjUIX1NVTgoZCF9BRFIMAAAZABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjYIX1NVTgoaCF9BRFIMAAAaABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjcIX1NVTgobCF9BRFIMAAAbABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjgIX1NVTgocCF9BRFIMAAAcABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMjkIX1NVTgodCF9BRFIMAAAdABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMzAIX1NVTgoeCF9BRFIMAAAeABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFR1uCNFMwMzEIX1NVTgofCF9BRFIMAAAfABQdX0VKMAlcLwNfU0JfUEhQUlBDRUpfU1VOX1NFRxRHLkRWTlQKe2gMAQAAAGCgDpNgDAEAAACGUzAwMGl7aAwCAAAAYKAOk2AMAgAA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",
                    "index": 1,
                    "type_name": "EV_PLATFORM_CONFIG_FLAGS"
                },
                {
                    "details": {},
                    "digests": [
                        {
                            "alg": "SHA-384",
                            "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0"
                        }
                    ],
                    "event": "AAAAAA==",
                    "index": 1,
                    "type_name": "EV_SEPARATOR"
                },
                {
                    "details": {},
                    "digests": [
                        {
                            "alg": "SHA-384",
                            "digest": "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0"
                        }
                    ],
                    "event": "AAAAAA==",
                    "index": 2,
                    "type_name": "EV_SEPARATOR"
                },
                {
                    "details": {
                        "string": "td_payload"
                    },
                    "digests": [
                        {
                            "alg": "SHA-384",
                            "digest": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa"
                        }
                    ],
                    "event": "C3RkX3BheWxvYWQAABCQAAAAAAAAAAAQAAAAAA==",
                    "index": 2,
                    "type_name": "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
                },
                {
                    "details": {
                        "string": "td_payload_info root=/dev/vda1 console=hvc0 rw"
                    },
                    "digests": [
                        {
                            "alg": "SHA-384",
                            "digest": "64ed1e5a47e8632f80faf428465bd987af3e8e4ceb10a5a9f387b6302e30f4993bded2331f0691c4a38ad34e4cbbc627"
                        }
                    ],
                    "event": "dGRfcGF5bG9hZF9pbmZvAAAQAAByb290PS9kZXYvdmRhMSBjb25zb2xlPWh2YzAgcncAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "index": 2,
                    "type_name": "EV_PLATFORM_CONFIG_FLAGS"
                }
            ],
            "quote": {
                "header": {
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body": {
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000",
                    "rtmr_0": "e940da7c2712d2790e2961e00484f4fa8e6f9eed71361655ae22699476b14f9e63867eb41edd4b480fef0c59f496b288",
                    "rtmr_1": "559cfcf42716ed6c40a48a73d5acb7da255435012f0a9f00fbe8c1c57612ede486a5684c4c9ff3ddf52315fcdca3a596",
                    "rtmr_2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "rtmr_3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
            },
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429"
        });

        assert_json_eq!(expected, claims);
    }

    #[rstest]
    #[trace]
    #[case(b"", Ok(Map::from_iter(vec![].into_iter())))]
    // Invalid UTF8 data
    #[case(b"\xff\xff", Err(anyhow!(SOME_ERROR)))]
    // Invalid UTF8 data
    #[case(b"foo=\xff\xff", Err(anyhow!(SOME_ERROR)))]
    #[case(b"name_only", Ok(Map::from_iter(vec![
                ("name_only".to_string(), Value::Null)
    ].into_iter())))]
    #[case(b"a=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"\ra=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"\na=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"a=b\nc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\n\nc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\r\rc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d\ne=foo", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap()),
                ("e".to_string(), to_value("foo").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d\nname_only\0e=foo", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap()),
                ("name_only".to_string(), Value::Null),
                ("e".to_string(), to_value("foo").unwrap())
    ].into_iter())))]
    #[case(b"foo='bar'", Ok(Map::from_iter(vec![
                ("foo".to_string(), to_value("'bar'").unwrap())
    ].into_iter())))]
    #[case(b"foo=\"bar\"", Ok(Map::from_iter(vec![
                ("foo".to_string(), to_value("\"bar\"").unwrap())
    ].into_iter())))]
    // Spaces in parameter values are not supported.
    // XXX: Note carefully the apostrophe values below!
    #[case(b"params_with_spaces_do_not_work='a b c'", Ok(Map::from_iter(vec![
                ("b".to_string(), Value::Null),
                ("c'".to_string(), Value::Null),
                ("params_with_spaces_do_not_work".to_string(), to_value("'a").unwrap()),
    ].into_iter())))]
    #[case(b"params_with_spaces_do_not_work=\"a b c\"", Ok(Map::from_iter(vec![
                ("b".to_string(), Value::Null),
                ("c\"".to_string(), Value::Null),
                ("params_with_spaces_do_not_work".to_string(), to_value("\"a").unwrap()),
    ].into_iter())))]
    #[case(b"a==", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=").unwrap())
    ].into_iter())))]
    #[case(b"a==b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b").unwrap())
    ].into_iter())))]
    #[case(b"a==b=", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b=").unwrap())
    ].into_iter())))]
    #[case(b"a=b=c", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b=c").unwrap())
    ].into_iter())))]
    #[case(b"a==b==c", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b==c").unwrap())
    ].into_iter())))]
    #[case(b"module_foo=bar=baz,wibble_setting=2", Ok(Map::from_iter(vec![
                ("module_foo".to_string(), to_value("bar=baz,wibble_setting=2").unwrap())
    ].into_iter())))]
    #[case(b"a=b c== d=e", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("=").unwrap()),
                ("d".to_string(), to_value("e").unwrap()),
    ].into_iter())))]
    fn test_parse_kernel_parameters(
        #[case] params: &[u8],
        #[case] result: Result<Map<String, Value>>,
    ) {
        let msg = format!(
            "test: params: {:?}, result: {result:?}",
            String::from_utf8_lossy(&params.to_vec())
        );

        let actual_result = parse_kernel_parameters(params);

        let msg = format!("{msg}: actual result: {actual_result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {msg}");
        }

        if result.is_err() {
            assert!(actual_result.is_err(), "{msg}");
            return;
        }

        let expected_result_str = format!("{result:?}");
        let actual_result_str = format!("{actual_result:?}");

        assert_eq!(expected_result_str, actual_result_str, "{msg}");

        let result = result.unwrap();
        let actual_result = actual_result.unwrap();

        let expected_count = result.len();

        let actual_count = actual_result.len();

        let msg = format!("{msg}: expected_count: {expected_count}, actual_count: {actual_count}");

        assert_eq!(expected_count, actual_count, "{msg}");

        for expected_kv in &result {
            let key = expected_kv.0.to_string();
            let value = expected_kv.1.to_string();

            let value_found = actual_result.get(&key);

            let kv_msg = format!("{msg}: key: {key:?}, value: {value:?}");

            if std::env::var("DEBUG").is_ok() {
                println!("DEBUG: {kv_msg}");
            }

            assert!(value_found.is_some(), "{kv_msg}");

            let value_found = value_found.unwrap().to_string();

            assert_eq!(value_found, value, "{kv_msg}");
        }
    }
}
