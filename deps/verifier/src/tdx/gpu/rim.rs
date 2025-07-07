use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use log::{debug, info};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use regex::Regex;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

const DEFAULT_RIM_SERVICE_BASE_URL: &str =
    "https://attest.cn-beijing.aliyuncs.com/nvcc/certification/v1/rim/";
const MAX_NETWORK_TIME_DELAY: u64 = 30;
// Aliyun metadata service URL
const ALIYUN_METADATA_URL: &str = "http://100.100.100.200/latest/meta-data/region-id";
const METADATA_TIMEOUT: u64 = 5;

// Global RIM cache
static RIM_CACHE: OnceCell<Arc<Mutex<HashMap<String, String>>>> = OnceCell::const_new();

// Initialize cache
async fn get_rim_cache() -> &'static Arc<Mutex<HashMap<String, String>>> {
    RIM_CACHE
        .get_or_init(|| async { Arc::new(Mutex::new(HashMap::new())) })
        .await
}

/// Get region_id from Aliyun metadata service
async fn get_region_id() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(METADATA_TIMEOUT))
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    let response = client.get(ALIYUN_METADATA_URL).send().await.map_err(|e| {
        anyhow!(
            "Cannot get region_id: please check if in aliyun environment: {}",
            e
        )
    })?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to get region_id: HTTP status {}",
            response.status()
        ));
    }

    let region_id = response
        .text()
        .await
        .map_err(|e| anyhow!("Unknown error to get region_id: {}", e))?
        .trim()
        .to_string();

    if region_id.is_empty() {
        return Err(anyhow!("Empty region_id received from metadata service"));
    }

    info!("Retrieved region_id from aliyun metadata: {}", region_id);
    Ok(region_id)
}

/// Get RIM service URL
async fn get_rim_service_url() -> Result<String> {
    // First check environment variable
    if let Ok(url) = env::var("NV_RIM_URL") {
        debug!("Using RIM URL from environment variable: {}", url);
        return Ok(url);
    }

    // Try to get region_id from Aliyun metadata service
    match get_region_id().await {
        Ok(region_id) => {
            let url = format!(
                "https://attest-vpc.{}.aliyuncs.com/nvcc/certification/v1/rim/",
                region_id
            );
            info!("Constructed RIM service URL: {}", url);

            // Send a HEAD request to the URL for testing
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(METADATA_TIMEOUT))
                .build()
                .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

            let resp = client.head(&url).send().await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    info!("RIM service URL is accessible: {}", url);
                    Ok(url)
                }
                Ok(r) => {
                    debug!("RIM service URL returned non-success status: {}, falling back to default URL", r.status());
                    Ok(DEFAULT_RIM_SERVICE_BASE_URL.to_string())
                }
                Err(e) => {
                    debug!(
                        "RIM service URL is not accessible: {}, falling back to default URL",
                        e
                    );
                    Ok(DEFAULT_RIM_SERVICE_BASE_URL.to_string())
                }
            }
        }
        Err(e) => {
            debug!(
                "Failed to get region_id from aliyun metadata: {}, falling back to default URL",
                e
            );
            Ok(DEFAULT_RIM_SERVICE_BASE_URL.to_string())
        }
    }
}

pub fn parse_rim_content(content: &str, rim_type: &str) -> Result<RimInfo> {
    let parser = RimParser::new();
    parser.parse(content, rim_type)
}

#[derive(Debug, Clone)]
pub struct GoldenMeasurement {
    pub name: String,
    pub index: usize,
    pub active: bool,
    pub alternatives: usize,
    pub values: Vec<String>,
    pub size: usize,
}

#[derive(Debug)]
pub struct RimInfo {
    pub name: String,
    pub version: String,
    pub manufacturer: String,
    pub product: String,
    pub measurements: HashMap<usize, GoldenMeasurement>,
}

pub struct RimParser;

impl RimParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, content: &str, _rim_type: &str) -> Result<RimInfo> {
        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        let mut rim_info = RimInfo {
            name: String::new(),
            version: String::new(),
            manufacturer: String::new(),
            product: String::new(),
            measurements: HashMap::new(),
        };

        let mut buf = Vec::new();
        let mut in_payload = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    let name = e.name();

                    match name.as_ref() {
                        b"SoftwareIdentity" => {
                            self.parse_software_identity(e, &mut rim_info)?;
                        }
                        b"Meta" => {
                            self.parse_meta(e, &mut rim_info)?;
                        }
                        b"Payload" => {
                            in_payload = true;
                        }
                        b"Resource" if in_payload => {
                            self.parse_resource(e, &mut rim_info)?;
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"Payload" {
                        in_payload = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow!("XML parsing error: {}", e)),
                _ => {}
            }
            buf.clear();
        }

        // Verify if necessary information is parsed
        if rim_info.version.is_empty() {
            return Err(anyhow!("RIM version information not found"));
        }

        debug!("Parsed RIM information: {:?}", rim_info);
        Ok(rim_info)
    }

    fn parse_software_identity(
        &self,
        element: &quick_xml::events::BytesStart,
        rim_info: &mut RimInfo,
    ) -> Result<()> {
        for attr in element.attributes() {
            let attr = attr.map_err(|e| anyhow!("Attribute parsing error: {}", e))?;
            match attr.key.as_ref() {
                b"name" => {
                    rim_info.name = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"version" => {
                    rim_info.version = String::from_utf8_lossy(&attr.value).to_string();
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn parse_meta(
        &self,
        element: &quick_xml::events::BytesStart,
        rim_info: &mut RimInfo,
    ) -> Result<()> {
        for attr in element.attributes() {
            let attr = attr.map_err(|e| anyhow!("Attribute parsing error: {}", e))?;
            match attr.key.as_ref() {
                b"colloquialVersion" => {
                    rim_info.version = String::from_utf8_lossy(&attr.value).to_string();
                }
                b"product" => {
                    rim_info.product = String::from_utf8_lossy(&attr.value).to_string();
                }
                _ => {
                    // Handle attributes with namespaces
                    let key_str = String::from_utf8_lossy(attr.key.as_ref());
                    if key_str.contains("FirmwareManufacturer") && !key_str.contains("Id") {
                        rim_info.manufacturer = String::from_utf8_lossy(&attr.value).to_string();
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_resource(
        &self,
        element: &quick_xml::events::BytesStart,
        rim_info: &mut RimInfo,
    ) -> Result<()> {
        let mut measurement = GoldenMeasurement {
            name: String::new(),
            index: 0,
            active: false,
            alternatives: 1,
            values: Vec::new(),
            size: 0,
        };

        // 在循环外部定义正则表达式
        let hash_regex = Regex::new(r"Hash(\d+)$").unwrap();

        // Parse basic attributes
        for attr in element.attributes() {
            let attr = attr.map_err(|e| anyhow!("Attribute parsing error: {}", e))?;
            let value_str = String::from_utf8_lossy(&attr.value);

            match attr.key.as_ref() {
                b"type" => {
                    if value_str != "Measurement" {
                        return Ok(()); // Skip non-measurement resources
                    }
                }
                b"index" => {
                    measurement.index = value_str
                        .parse()
                        .map_err(|e| anyhow!("Invalid index value: {}", e))?;
                }
                b"name" => {
                    measurement.name = value_str.to_string();
                }
                b"active" => {
                    measurement.active = value_str.to_lowercase() == "true";
                }
                b"alternatives" => {
                    measurement.alternatives = value_str
                        .parse()
                        .map_err(|e| anyhow!("Invalid alternative count: {}", e))?;
                }
                b"size" => {
                    measurement.size = value_str
                        .parse()
                        .map_err(|e| anyhow!("Invalid size value: {}", e))?;
                }
                _ => {
                    // Check if it's a hash value attribute
                    let key_str = String::from_utf8_lossy(attr.key.as_ref());
                    
                    if let Some(caps) = hash_regex.captures(&key_str) {
                        let hash_index: usize = caps[1]
                            .parse()
                            .map_err(|e| anyhow!("Invalid hash index: {}", e))?;

                        // Ensure values vector is large enough
                        while measurement.values.len() <= hash_index {
                            measurement.values.push(String::new());
                        }

                        measurement.values[hash_index] = value_str.to_string();
                    }
                }
            }
        }

        // Remove empty hash values
        measurement.values.retain(|v| !v.is_empty());

        // Verify alternative count matches actual hash value count
        if measurement.values.len() != measurement.alternatives {
            debug!(
                "Warning: measurement {} alternative count ({}) doesn't match actual hash value count ({})",
                measurement.name,
                measurement.alternatives,
                measurement.values.len()
            );
            measurement.alternatives = measurement.values.len();
        }

        if !measurement.name.is_empty() {
            debug!(
                "Parsed measurement: index={}, name={}, active={}, alternatives={}",
                measurement.index, measurement.name, measurement.active, measurement.alternatives
            );
            rim_info.measurements.insert(measurement.index, measurement);
        }

        Ok(())
    }
}

pub async fn get_driver_rim(driver_version: &str) -> Result<String> {
    // Get RIM service URL
    let rim_service_url = get_rim_service_url().await?;

    // Construct RIM file ID based on driver version and architecture
    let gpu_arch = env::var("GPU_ARCH_NAME").unwrap_or_else(|_| "HOPPER".to_string());

    let rim_id = match gpu_arch.as_str() {
        "HOPPER" => format!("NV_GPU_DRIVER_GH100_{}", driver_version),
        "BLACKWELL" => format!("NV_GPU_CC_DRIVER_GB100_{}", driver_version),
        _ => format!("NV_GPU_DRIVER_GH100_{}", driver_version), // Default to HOPPER
    };

    info!("Driver RIM ID: {}", rim_id);

    // Check cache first
    let cache = get_rim_cache().await;
    {
        let cache_guard = cache.lock().unwrap();
        if let Some(cached_content) = cache_guard.get(&rim_id) {
            info!("Found Driver RIM in cache: {}", rim_id);
            return Ok(cached_content.clone());
        }
    }

    // Get RIM content from service
    let content = fetch_rim_file(&rim_service_url, &rim_id).await?;

    // Cache the result
    {
        let mut cache_guard = cache.lock().unwrap();
        cache_guard.insert(rim_id, content.clone());
    }

    Ok(content)
}

pub async fn get_vbios_rim(
    project: &str,
    project_sku: &str,
    chip_sku: &str,
    vbios_version: &str,
) -> Result<String> {
    // Get RIM service URL
    let rim_service_url = get_rim_service_url().await?;

    // Construct VBIOS RIM file ID
    let vbios_version_formatted = vbios_version.replace(".", "").to_uppercase();
    let project_upper = project.to_uppercase();
    let project_sku_upper = project_sku.to_uppercase();
    let chip_sku_upper = chip_sku.to_uppercase();

    let rim_id = format!(
        "NV_GPU_VBIOS_{}_{}_{}_{}",
        project_upper, project_sku_upper, chip_sku_upper, vbios_version_formatted
    );

    info!("VBIOS RIM ID: {}", rim_id);

    // Check cache first
    let cache = get_rim_cache().await;
    {
        let cache_guard = cache.lock().unwrap();
        if let Some(cached_content) = cache_guard.get(&rim_id) {
            info!("Found VBIOS RIM in cache: {}", rim_id);
            return Ok(cached_content.clone());
        }
    }

    // Get RIM content from service
    let content = fetch_rim_file(&rim_service_url, &rim_id).await?;

    // Cache the result
    {
        let mut cache_guard = cache.lock().unwrap();
        cache_guard.insert(rim_id, content.clone());
    }

    Ok(content)
}

async fn fetch_rim_file(base_url: &str, file_id: &str) -> Result<String> {
    // Construct complete URL
    let url = if base_url.ends_with('/') {
        format!("{}{}", base_url, file_id)
    } else {
        format!("{}/{}", base_url, file_id)
    };

    info!("Fetching from RIM service: {}", url);

    // Prepare HTTP headers
    let mut headers = HashMap::new();

    // Add authentication header if service key is set
    if let Ok(service_key) = env::var("NVIDIA_ATTESTATION_SERVICE_KEY") {
        let auth_value = format!("nv-sak {}", service_key);
        headers.insert("Authorization".to_string(), auth_value);
        debug!("Using service key for authentication");
    } else {
        debug!("NVIDIA_ATTESTATION_SERVICE_KEY environment variable not set");
    }

    // Create async HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(MAX_NETWORK_TIME_DELAY))
        .build()
        .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

    // Build request
    let mut request_builder = client.get(&url);

    // Add headers
    for (key, value) in headers {
        request_builder = request_builder.header(&key, &value);
    }

    // Send request
    debug!("Sending HTTP GET request...");
    let response = request_builder.send().await.map_err(|e| {
        anyhow!(
            "HTTP request failed: {} - Please check network connection and RIM service status",
            e
        )
    })?;

    let status = response.status();
    debug!("HTTP response status: {}", status);

    // Check response status
    if !status.is_success() {
        let error_msg = match status.as_u16() {
            404 => format!("RIM file not found: {} - Please check if version information is correct", file_id),
            401 => "Authentication failed - Please check NVIDIA_ATTESTATION_SERVICE_KEY environment variable".to_string(),
            403 => "Access denied - Please check service key permissions".to_string(),
            500..=599 => "RIM service internal error - Please try again later".to_string(),
            _ => format!("HTTP error: {}", status),
        };
        return Err(anyhow!("{}", error_msg));
    }

    // Parse response
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow!("Failed to read response content: {}", e))?;

    debug!("Response content length: {} bytes", response_text.len());

    let json_object: Value = serde_json::from_str(&response_text).map_err(|e| {
        anyhow!(
            "Failed to parse JSON response: {} - Response may not be valid JSON format",
            e
        )
    })?;

    // Extract base64 encoded RIM content
    let base64_data = json_object["rim"].as_str().ok_or_else(|| {
        anyhow!("'rim' field not found in response - RIM service response format may have changed")
    })?;

    debug!(
        "Base64 encoded RIM content length: {} characters",
        base64_data.len()
    );

    // Decode base64
    let decoded_bytes = general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| anyhow!("Base64 decode failed: {} - RIM content may be corrupted", e))?;

    // Convert to UTF-8 string
    let rim_content = String::from_utf8(decoded_bytes).map_err(|e| {
        anyhow!(
            "UTF-8 decode failed: {} - RIM content contains non-UTF-8 characters",
            e
        )
    })?;

    info!(
        "Successfully fetched RIM file, content length: {} bytes",
        rim_content.len()
    );
    debug!(
        "RIM content first 100 characters: {}",
        if rim_content.len() > 100 {
            &rim_content[..100]
        } else {
            &rim_content
        }
    );

    Ok(rim_content)
}
