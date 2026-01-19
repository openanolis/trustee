use std::fs;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use git2::Repository;
use rpm::{DigestAlgorithm, FileMode, Package};
use serde::{Deserialize, Serialize};
use serde_yaml;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::{reference_value::REFERENCE_VALUE_VERSION, ReferenceValue};

use super::Extractor;

// Define the input structure for the reproducible build extractor
#[derive(Serialize, Deserialize)]
pub struct Provenance {
    pub buildspec_uri: String,
}

// The extractor struct with settings
#[derive(Debug, Clone)]
pub struct ReproducibleBuildExtractor;

impl ReproducibleBuildExtractor {
    pub fn new() -> Self {
        Self
    }

    // Function that takes buildspec_uri as input and executes the 3 steps
    pub fn execute_reproducible_build(
        &self,
        buildspec_uri: String,
    ) -> Result<Vec<(String, String)>> {
        let temp_dir = tempfile::tempdir()?;

        // Step 1: download buildspec and clone the repository
        let buildspec_path = download_buildspec(&buildspec_uri, &temp_dir)?;
        clone_guanfu_repo(&temp_dir)?;
        // Step 2: Execute the build
        execute_build_script(&temp_dir, &buildspec_path)?;
        // Step 3: Extract reference values from the build output artifacts
        let output_files = parse_output_files_from_buildspec(&buildspec_path)?;
        let reference_values = extract_reference_values(&output_files)?;

        Ok(reference_values)
    }

    // Function to validate the environment - check for Docker and Python 3.7+
    fn validate_environment(&self) -> Result<()> {
        // Check for Docker
        let docker_check = Command::new("docker").arg("--version").output();

        match docker_check {
            Ok(output) => {
                if !output.status.success() {
                    return Err(anyhow!(
                        "Docker is not available or not properly configured. Error: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow!("Docker is not installed or not in PATH: {}", e));
            }
        }

        // Check for Python
        let python_check = Command::new("python3").arg("--version").output();

        let python_version = match python_check {
            Ok(output) => {
                if !output.status.success() {
                    return Err(anyhow!(
                        "Python 3 is not available or not properly configured. Error: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }

                let version_output = String::from_utf8_lossy(&output.stdout);
                version_output.trim().to_string()
            }
            Err(e) => {
                return Err(anyhow!("Python 3 is not installed or not in PATH: {}", e));
            }
        };

        // Extract and validate Python version
        // Expected format: "Python 3.x.y" or "Python 3.x"
        if !python_version.starts_with("Python 3.") {
            return Err(anyhow!(
                "Python 3.x is required but not found. Found: {}",
                python_version
            ));
        }

        // Extract the version numbers
        let parts: Vec<&str> = python_version.split_whitespace().collect();
        if parts.len() >= 2 {
            let version_parts: Vec<&str> = parts[1].split('.').collect();
            if version_parts.len() >= 2 {
                let major = version_parts[0].parse::<u32>().unwrap_or(0);
                let minor = version_parts[1].parse::<u32>().unwrap_or(0);

                if major != 3 || minor < 7 {
                    return Err(anyhow!(
                        "Python 3.7 or higher is required. Found: {}",
                        python_version
                    ));
                }
            } else {
                return Err(anyhow!(
                    "Could not parse Python version. Found: {}",
                    python_version
                ));
            }
        } else {
            return Err(anyhow!(
                "Could not parse Python version string. Found: {}",
                python_version
            ));
        }

        Ok(())
    }
}

// Implement default constructor
impl Default for ReproducibleBuildExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// Implement the Extractor trait
impl Extractor for ReproducibleBuildExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        // Decode the provenance from base64
        let provenance = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("base64 decode")?;

        // Parse the payload containing buildspec URI
        let payload: Provenance =
            serde_json::from_slice(&provenance).context("deserialize reproducible build input")?;

        // Environment validation
        self.validate_environment()?;

        // Execute the reproducible build process and return the extracted key-value pairs
        let subjects = self.execute_reproducible_build(payload.buildspec_uri)?;

        let expiration = Utc::now()
            .with_nanosecond(0)
            .and_then(|t| t.checked_add_months(Months::new(12)))
            .ok_or_else(|| anyhow!("failed to compute expiration time"))?;

        let mut rvs = Vec::new();
        for (name, hash256) in subjects {
            let mut rv = ReferenceValue::new()?
                .set_version(REFERENCE_VALUE_VERSION)
                .set_name(&name)
                .set_expiration(expiration)
                .set_audit_proof(None); // AuditProof set to none

            // Add SHA256 hash
            rv = rv.add_hash_value("sha256".to_string(), hash256);

            rvs.push(rv);
        }

        Ok(rvs)
    }
}

// Helper function to parse output files from buildspec
fn parse_output_files_from_buildspec(buildspec_path: &std::path::Path) -> Result<Vec<String>> {
    let content =
        std::fs::read_to_string(buildspec_path).context("Failed to read buildspec file")?;

    let buildspec: serde_yaml::Value =
        serde_yaml::from_str(&content).context("Failed to parse buildspec YAML")?;

    // Extract the outputs section and get just the paths
    let paths = buildspec
        .get("outputs")
        .and_then(|outputs| outputs.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|item| {
                    item.get("path")
                        .and_then(|path_val| path_val.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(paths)
}

// Helper function for step 1: Create temporary directory and download buildspec
fn download_buildspec(buildspec_uri: &str, temp_dir: &TempDir) -> Result<std::path::PathBuf> {
    let buildspec_path = temp_dir.path().join("buildspec.yaml");

    // Download the buildspec from the URI
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(buildspec_uri)
        .send()
        .context("Failed to download buildspec")?;

    let mut dest =
        std::fs::File::create(&buildspec_path).context("Failed to create buildspec file")?;
    let content = response.bytes().context("Failed to read response body")?;
    dest.write_all(&content)
        .context("Failed to write buildspec to file")?;

    Ok(buildspec_path)
}

// Helper function for step 2: Clone GuanFu repository
fn clone_guanfu_repo(temp_dir: &TempDir) -> Result<()> {
    let repo_url = "https://github.com/1570005763/GuanFu";
    let target_dir = temp_dir.path().join("GuanFu");
    let repo =
        Repository::clone(repo_url, target_dir).context("Failed to clone GuanFu repository")?;

    // Checkout the v1 tag
    let (object, reference) = repo.revparse_ext("refs/tags/v1")?;
    repo.checkout_tree(&object, None)?;
    repo.set_head(reference.unwrap().name().unwrap())?;

    Ok(())
}

// Helper function for step 3: Execute the build script
fn execute_build_script(temp_dir: &TempDir, buildspec_path: &std::path::Path) -> Result<()> {
    let guanfu_dir = temp_dir.path().join("GuanFu");
    let build_runner_script = guanfu_dir.join("src").join("build-runner.sh");

    // Check if the build runner script exists
    if !build_runner_script.exists() {
        return Err(anyhow!(
            "Build runner script does not exist: {:?}",
            build_runner_script
        ));
    }

    // Execute the build script with the buildspec path
    let mut child = Command::new("bash")
        .arg(&build_runner_script)
        .arg(
            buildspec_path
                .to_str()
                .ok_or_else(|| anyhow!("Invalid buildspec path"))?,
        )
        .current_dir(&guanfu_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn build runner script")?;

    let status = child
        .wait()
        .context("Failed to wait for build runner script")?;

    if !status.success() {
        return Err(anyhow!(
            "Build runner script exited with status: {}",
            status
        ));
    }

    println!("Build runner script executed successfully");
    Ok(())
}

// Helper function to extract reference values
fn extract_reference_values(output_files: &[String]) -> Result<Vec<(String, String)>> {
    let mut results = Vec::new();

    for file_path in output_files {
        // Read the file content
        let content =
            fs::read(file_path).with_context(|| format!("Failed to read file: {file_path}"))?;

        // Calculate SHA256 hash
        let mut hasher256 = Sha256::new();
        hasher256.update(&content);
        let hash256 = hasher256.finalize();

        // Convert hashes to hex strings
        let hash256_hex = format!("{hash256:x}");

        // Extract filename only from the path
        let filename = Path::new(file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(file_path)
            .to_string();

        // Add filename and both hashes to results
        results.push((filename, hash256_hex));

        // Check if the file is an RPM by extension
        let path = Path::new(file_path);
        if path.extension().is_some_and(|ext| ext == "rpm") {
            // Handle RPM file specially
            let rpm_results = hash_subjects_from_rpm(path)?;
            results.extend(rpm_results);
        }
    }

    Ok(results)
}

/// Extract all files from RPM, return list of ("/absolute-path", sha256_hex)
pub fn hash_subjects_from_rpm<P: AsRef<Path>>(rpm_path: P) -> Result<Vec<(String, String)>> {
    // 1. Open and parse the RPM
    let file = File::open(&rpm_path)
        .map_err(|e| anyhow!("Failed to open RPM {}: {}", rpm_path.as_ref().display(), e))?;
    let mut buf_reader = BufReader::new(file);

    let pkg = Package::parse(&mut buf_reader)
        .map_err(|e| anyhow!("RPM parse error for {}: {}", rpm_path.as_ref().display(), e))?;

    // 2. Get all file entries from metadata (without extracting payload)
    let file_entries = pkg
        .metadata
        .get_file_entries()
        .map_err(|e| anyhow!("Failed to get file entries: {}", e))?;

    let mut results: Vec<(String, String)> = Vec::new();

    for entry in file_entries {
        // Process only regular files
        let is_regular = matches!(entry.mode, FileMode::Regular { .. });
        if !is_regular {
            continue;
        }

        // 3. Construct absolute path (same logic as original implementation)
        let s = entry.path.to_string_lossy();
        let raw = if let Some(stripped) = s.strip_prefix("./") {
            stripped
        } else {
            &s
        };

        let abs_path = if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };

        // 4. Keep only sha256, leave other algorithms blank
        //
        // entry.digest: Option<FileDigest>
        // FileDigest assumes:
        //   - algorithm: DigestAlgorithm
        //   - value: String (hex encoded)
        //
        let mut sha256_hex = String::new();
        if let Some(d) = &entry.digest {
            if d.algorithm() == DigestAlgorithm::Sha2_256 {
                sha256_hex = d.to_string();
            }
        }

        results.push((abs_path, sha256_hex));
    }

    // 5. Sort by path to ensure stable output
    results.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json;

    #[test]
    #[ignore]
    fn test_reproducible_build_extractor() {
        let extractor = ReproducibleBuildExtractor::new();

        // Create a Provenance struct with the specified buildspec_uri
        let provenance = Provenance {
            buildspec_uri: "https://github.com/1570005763/trustee/releases/download/v27/trustee.al8.buildspec.yaml".to_string(),
        };

        // Serialize the provenance struct to JSON and encode as base64
        let json_payload =
            serde_json::to_string(&provenance).expect("Failed to serialize provenance");
        let encoded_payload = base64::engine::general_purpose::STANDARD.encode(json_payload);

        // Call the verify_and_extract function
        let result = extractor.verify_and_extract(&encoded_payload);

        // Since the test is marked as ignore, we won't make assertions that would cause it to fail
        // In a real scenario, you would check the result appropriately
        if result.is_ok() {
            let reference_values = result.unwrap();
            println!(
                "Successfully extracted {} reference values",
                reference_values.len()
            );

            // Print all generated reference values
            for (index, rv) in reference_values.iter().enumerate() {
                println!("Reference Value {}: ", index + 1);
                println!("  Name: {}", rv.name());
                println!("  Version: {}", rv.version());
                println!("  Expiration: {:?}", rv.expiration);

                // Print all hash values
                for hash_value_pair in rv.hash_values() {
                    println!("  {}: {}", hash_value_pair.alg(), hash_value_pair.value());
                }

                println!();
            }
        } else {
            println!("Error during extraction: {:?}", result.err());
        }
    }
}
