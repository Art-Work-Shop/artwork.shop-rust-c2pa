use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use p256::ecdsa::Signature as P256Signature;
use ciborium::Value as CborValue;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use c2pa::{Context, ValidationState};
use std::fs;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::BTreeMap;
use std::sync::Mutex;
use uuid::Uuid;
use x509_parser::{
    certificate::X509Certificate,
    extensions::ParsedExtension,
    pem::Pem,
    prelude::FromDer,
};

static VERSION: &str = "artwork-c2pa-rust-http-signer@0.1.0";
static LAST_SIGNATURE_FORENSICS: Lazy<Mutex<SignatureForensics>> =
    Lazy::new(|| Mutex::new(SignatureForensics::default()));

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http: reqwest::Client,
    signer: Arc<SignerMaterial>,
    cert_policy_status: Arc<CertPolicyStatus>,
}

#[derive(Clone)]
struct Config {
    token: String,
    self_test_image_url: String,
    max_source_image_bytes: usize,
    source_fetch_timeout_ms: u64,
    fail_open_post_sign_verify: bool,
}

#[derive(Clone)]
struct SignerMaterial {
    cert_pem: String,
    key_pem: String,
    credential_source: String,
}

#[derive(Clone, Debug)]
struct CertPolicyConfig {
    enforced: bool,
    min_chain_count: usize,
    allow_self_issued_leaf: bool,
    require_leaf_digital_signature: bool,
    required_eku_oids: Vec<String>,
    disallowed_leaf_common_name_substrings: Vec<String>,
    allowed_leaf_fingerprints_sha256: Vec<String>,
    rotation_policy: Option<RotationPolicyDerived>,
}

#[derive(Clone, Debug, Serialize)]
struct RotationPolicySummary {
    source: String,
    #[serde(rename = "sha256")]
    file_sha256: String,
    #[serde(rename = "policyId")]
    policy_id: String,
    version: String,
    #[serde(rename = "generatedAt")]
    generated_at: String,
    #[serde(rename = "currentKeyId")]
    current_key_id: String,
    #[serde(rename = "nextKeyId")]
    next_key_id: Option<String>,
    #[serde(rename = "eligibleKeyIds")]
    eligible_key_ids: Vec<String>,
    #[serde(rename = "matchedKeyId")]
    matched_key_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CertPolicyStatus {
    enforced: bool,
    pass: bool,
    #[serde(rename = "reasonCodes")]
    reason_codes: Vec<String>,
    summary: String,
    #[serde(rename = "chainCount")]
    chain_count: usize,
    #[serde(rename = "leafFingerprintSha256")]
    leaf_fingerprint_sha256: Option<String>,
    #[serde(rename = "leafCommonName")]
    leaf_common_name: Option<String>,
    #[serde(rename = "leafKeyCongruent")]
    leaf_key_congruent: bool,
    #[serde(rename = "credentialSource")]
    credential_source: String,
    #[serde(rename = "rotationPolicy")]
    rotation_policy: Option<RotationPolicySummary>,
}

#[derive(Clone, Debug)]
struct RotationPolicyDerived {
    source: String,
    file_sha256: String,
    policy_id: String,
    version: String,
    generated_at: String,
    current_key_id: String,
    next_key_id: Option<String>,
    eligible_key_ids: Vec<String>,
    eligible_fingerprints_sha256: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RotationPolicyFile {
    version: String,
    #[serde(rename = "policyId")]
    policy_id: String,
    #[serde(rename = "generatedAt")]
    generated_at: String,
    promotion: RotationPolicyPromotion,
    #[serde(rename = "signerKeys")]
    signer_keys: Vec<RotationPolicySignerKey>,
}

#[derive(Clone, Debug, Deserialize)]
struct RotationPolicyPromotion {
    #[serde(rename = "currentKeyId")]
    current_key_id: String,
    #[serde(rename = "nextKeyId")]
    next_key_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RotationPolicySignerKey {
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "fingerprintSha256")]
    fingerprint_sha256: String,
    status: String,
}

struct LowSNormalizerSigner {
    inner: c2pa::BoxedSigner,
}

impl c2pa::Signer for LowSNormalizerSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        capture_signer_input_forensics(data);
        let signature = self.inner.sign(data)?;

        if self.inner.alg() == c2pa::SigningAlg::Es256 && signature.len() == 64 {
            if let Ok(parsed) = P256Signature::try_from(signature.as_slice()) {
                if let Some(normalized) = parsed.normalize_s() {
                    return Ok(normalized.to_vec());
                }
            }
        }

        Ok(signature)
    }

    fn alg(&self) -> c2pa::SigningAlg {
        self.inner.alg()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        let certs = self.inner.certs()?;
        if certs.is_empty() {
            return Err(c2pa::Error::BadParam("Signer returned an empty cert chain".to_string()));
        }

        let require_full_chain = std::env::var("C2PA_SIGNER_REQUIRE_FULL_CHAIN")
            .map(|v| {
                let lowered = v.trim().to_ascii_lowercase();
                lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on"
            })
            .unwrap_or(false);

        if require_full_chain && certs.len() < 2 {
            return Err(c2pa::Error::BadParam(
                "C2PA_SIGNER_REQUIRE_FULL_CHAIN is enabled but cert chain has fewer than 2 certificates".to_string(),
            ));
        }

        Ok(certs)
    }

    fn reserve_size(&self) -> usize {
        // Safe floor for a 2–3 cert ES256 chain with RFC 3161 timestamp material.
        // Real-world credential envelopes run 12–22 KB; 50 KB gives headroom
        // without bloating the JUMBF sigbox in signed images.
        // Do NOT raise beyond ~65 KB without measuring actual envelope sizes.
        const SAFE_FLOOR: usize = 50_000;
        self.inner.reserve_size().max(SAFE_FLOOR)
    }
}

#[derive(Debug, Deserialize)]
struct SignRequest {
    #[serde(alias = "sourceImageUrl")]
    #[serde(alias = "source_image_url")]
    source_image_url: Option<String>,
    #[serde(alias = "manifestGuid")]
    #[serde(alias = "manifest_guid")]
    manifest_guid: Option<String>,
    manifest: Option<Value>,
}

#[derive(Serialize)]
struct HealthLeafKeyCongruence {
    congruent: bool,
    detail: String,
}

#[derive(Serialize)]
struct HealthResponse {
    success: bool,
    ready: bool,
    algorithm: String,
    #[serde(rename = "leafKeyCongruence")]
    leaf_key_congruence: HealthLeafKeyCongruence,
    #[serde(rename = "certPolicy")]
    cert_policy: Option<CertPolicyStatus>,
}

#[derive(Serialize)]
struct SelfTestVerificationResult {
    validation_state: String,
    validation_status: Vec<Value>,
}

#[derive(Serialize)]
struct SelfTestResponse {
    success: bool,
    message: String,
    #[serde(rename = "durationMs")]
    duration_ms: u64,
    #[serde(rename = "leafKeyCongruence")]
    leaf_key_congruence: HealthLeafKeyCongruence,
    #[serde(rename = "verificationResult")]
    verification_result: SelfTestVerificationResult,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    message: String,
    code: Option<String>,
    #[serde(rename = "validationState")]
    validation_state: Option<String>,
    #[serde(rename = "gateMode")]
    gate_mode: Option<String>,
    #[serde(rename = "failureCode")]
    failure_code: Option<String>,
    #[serde(rename = "failureExplanation")]
    failure_explanation: Option<String>,
    #[serde(rename = "failureUrl")]
    failure_url: Option<String>,
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
}

impl HttpError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            success: false,
            message: self.message,
            code: None,
            validation_state: None,
            gate_mode: None,
            failure_code: None,
            failure_explanation: None,
            failure_url: None,
        });
        (self.status, body).into_response()
    }
}

#[derive(Debug, Clone)]
struct PostSignVerification {
    validation_state: String,
    validation_status: Vec<Value>,
    failure_code: Option<String>,
    failure_explanation: Option<String>,
    failure_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct SignatureForensicsSignerInput {
    tbs_sha256: String,
    tbs_hex: String,
    tbs_len: usize,
    protected_header_hex: Option<String>,
    claim_hex: Option<String>,
    claim_sha256: Option<String>,
    claim_len: Option<usize>,
    uri_samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct SignatureForensicsVerifierView {
    validation_state: Option<String>,
    manifest_label: Option<String>,
    cose_sign1_hex: Option<String>,
    cose_sign1_len: Option<usize>,
    protected_header_hex: Option<String>,
    protected_header_len: Option<usize>,
    manifest_store_blob_hex: Option<String>,
    manifest_store_blob_sha256: Option<String>,
    manifest_store_blob_len: Option<usize>,
    uri_samples: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct SignatureForensics {
    signer_input: Option<SignatureForensicsSignerInput>,
    verifier_view: Option<SignatureForensicsVerifierView>,
}

static DEFAULT_SELF_TEST_IMAGE_URL: Lazy<String> = Lazy::new(|| "https://httpbin.org/image/webp".to_string());

fn read_env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| {
            let lowered = v.trim().to_ascii_lowercase();
            matches!(lowered.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(default)
}

fn read_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn read_env_csv(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.to_ascii_lowercase())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
}

fn read_env_optional_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn load_rotation_policy_from_file() -> Result<Option<RotationPolicyDerived>, Box<dyn std::error::Error>> {
    let policy_path = match read_env_optional_string("C2PA_SIGNER_ROTATION_POLICY_FILE") {
        Some(path) => path,
        None => return Ok(None),
    };

    let raw = fs::read_to_string(&policy_path)
        .map_err(|e| format!("failed to read rotation policy file {}: {}", policy_path, e))?;
    let parsed: RotationPolicyFile = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse rotation policy JSON {}: {}", policy_path, e))?;

    if parsed.signer_keys.is_empty() {
        return Err("rotation policy has no signerKeys entries".into());
    }

    let mut by_key_id = BTreeMap::<String, (&RotationPolicySignerKey, String)>::new();
    for key in &parsed.signer_keys {
        let fingerprint = key.fingerprint_sha256.trim().to_ascii_lowercase();
        if fingerprint.len() != 64 || !fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(format!(
                "rotation policy key {} has invalid fingerprintSha256",
                key.key_id
            )
            .into());
        }
        by_key_id.insert(key.key_id.trim().to_string(), (key, fingerprint));
    }

    let current_key_id = parsed.promotion.current_key_id.trim().to_string();
    let (current_key, current_fp) = by_key_id
        .get(&current_key_id)
        .ok_or_else(|| format!("rotation policy currentKeyId {} is missing", current_key_id))?;

    let current_status = current_key.status.trim().to_ascii_lowercase();
    if !(current_status == "active" || current_status == "current") {
        return Err(format!(
            "rotation policy currentKeyId {} must have status active/current",
            current_key_id
        )
        .into());
    }

    let next_key_id = parsed
        .promotion
        .next_key_id
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut eligible_key_ids = vec![current_key_id.clone()];
    let mut eligible_fingerprints_sha256 = vec![current_fp.clone()];

    if let Some(next_id) = &next_key_id {
        let (next_key, next_fp) = by_key_id
            .get(next_id)
            .ok_or_else(|| format!("rotation policy nextKeyId {} is missing", next_id))?;
        let next_status = next_key.status.trim().to_ascii_lowercase();
        if !(next_status == "next" || next_status == "pending" || next_status == "active") {
            return Err(format!(
                "rotation policy nextKeyId {} must have status next/pending/active",
                next_id
            )
            .into());
        }
        eligible_key_ids.push(next_id.clone());
        eligible_fingerprints_sha256.push(next_fp.clone());
    }

    Ok(Some(RotationPolicyDerived {
        source: policy_path,
        file_sha256: sha256_hex(raw.as_bytes()),
        policy_id: parsed.policy_id,
        version: parsed.version,
        generated_at: parsed.generated_at,
        current_key_id,
        next_key_id,
        eligible_key_ids,
        eligible_fingerprints_sha256,
    }))
}

fn load_cert_policy_config() -> Result<CertPolicyConfig, Box<dyn std::error::Error>> {
    Ok(CertPolicyConfig {
        enforced: read_env_bool("C2PA_SIGNER_CERT_POLICY_ENFORCED", true),
        min_chain_count: read_env_usize("C2PA_SIGNER_CERT_POLICY_MIN_CHAIN_COUNT", 2),
        allow_self_issued_leaf: read_env_bool("C2PA_SIGNER_CERT_POLICY_ALLOW_SELF_ISSUED_LEAF", false),
        require_leaf_digital_signature: read_env_bool("C2PA_SIGNER_CERT_POLICY_REQUIRE_LEAF_DIGITAL_SIGNATURE", true),
        required_eku_oids: {
            let configured = read_env_csv("C2PA_SIGNER_CERT_POLICY_REQUIRED_EKU_OIDS");
            if configured.is_empty() {
                vec![
                    "1.3.6.1.5.5.7.3.4".to_string(),
                    "1.3.6.1.4.1.311.10.3.12".to_string(),
                ]
            } else {
                configured
            }
        },
        disallowed_leaf_common_name_substrings: {
            let configured = read_env_csv("C2PA_SIGNER_CERT_POLICY_DISALLOWED_LEAF_CN_SUBSTRINGS")
                .into_iter()
                .map(|entry| entry.to_ascii_lowercase())
                .collect::<Vec<String>>();
            if configured.is_empty() {
                vec!["local c2pa test signer".to_string()]
            } else {
                configured
            }
        },
        allowed_leaf_fingerprints_sha256: read_env_csv("C2PA_SIGNER_CERT_POLICY_ALLOWED_LEAF_FINGERPRINTS_SHA256"),
        rotation_policy: load_rotation_policy_from_file()?,
    })
}

fn evaluate_cert_policy(
    signer: &SignerMaterial,
    policy: &CertPolicyConfig,
) -> Result<CertPolicyStatus, Box<dyn std::error::Error>> {
    let cert_der_chain = parse_cert_chain_der(&signer.cert_pem)
        .map_err(|e| format!("Cert chain parse failed: {}", e))?;

    let chain_count = cert_der_chain.len();
    let mut reason_codes = Vec::<String>::new();
    let leaf_fingerprint_sha256 = cert_der_chain.first().map(|der| sha256_hex(der));
    let mut matched_key_id = None::<String>;

    let leaf_der = cert_der_chain
        .first()
        .ok_or_else(|| "missing leaf certificate in parsed chain".to_string())?;
    let (_rem, leaf_cert) = X509Certificate::from_der(leaf_der)
        .map_err(|_| "failed to parse leaf certificate DER".to_string())?;

    let leaf_subject = leaf_cert
        .subject()
        .iter_attributes()
        .filter_map(|attr| attr.as_str().ok().map(str::to_string))
        .collect::<Vec<String>>();
    let leaf_common_name = leaf_cert
        .subject()
        .iter_common_name()
        .find_map(|cn| cn.as_str().ok().map(str::to_string));
    let leaf_issuer = leaf_cert
        .issuer()
        .iter_attributes()
        .filter_map(|attr| attr.as_str().ok().map(str::to_string))
        .collect::<Vec<String>>();

    if chain_count < policy.min_chain_count {
        reason_codes.push(format!(
            "chain_too_short:min_required={} actual={}",
            policy.min_chain_count, chain_count
        ));
    }

    if !policy.allow_self_issued_leaf && leaf_subject == leaf_issuer {
        reason_codes.push("leaf_self_issued_not_allowed".to_string());
    }

    if let Some(cn) = &leaf_common_name {
        let lowered = cn.to_ascii_lowercase();
        for banned in &policy.disallowed_leaf_common_name_substrings {
            if !banned.is_empty() && lowered.contains(banned) {
                reason_codes.push(format!("leaf_common_name_disallowed:{}", cn));
                break;
            }
        }
    }

    let mut leaf_key_usage_digital_signature = None::<bool>;
    let mut leaf_eku_oids = Vec::<String>::new();

    for ext in leaf_cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::KeyUsage(ku) => {
                leaf_key_usage_digital_signature = Some(ku.digital_signature());
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                if eku.any {
                    leaf_eku_oids.push("2.5.29.37.0".to_string());
                }
                if eku.server_auth {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.1".to_string());
                }
                if eku.client_auth {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.2".to_string());
                }
                if eku.code_signing {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.3".to_string());
                }
                if eku.email_protection {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.4".to_string());
                }
                if eku.time_stamping {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.8".to_string());
                }
                if eku.ocsp_signing {
                    leaf_eku_oids.push("1.3.6.1.5.5.7.3.9".to_string());
                }
                for oid in &eku.other {
                    leaf_eku_oids.push(oid.to_id_string());
                }
            }
            _ => {}
        }
    }

    if policy.require_leaf_digital_signature && leaf_key_usage_digital_signature != Some(true) {
        reason_codes.push("leaf_key_usage_digital_signature_missing".to_string());
    }

    for required in &policy.required_eku_oids {
        if !leaf_eku_oids.iter().any(|present| present == required) {
            reason_codes.push(format!("leaf_eku_missing:{}", required));
        }
    }

    let mut allowed_leaf_fingerprints_sha256 = policy.allowed_leaf_fingerprints_sha256.clone();
    let mut rotation_policy_summary = None::<RotationPolicySummary>;
    if let Some(rotation_policy) = &policy.rotation_policy {
        for fingerprint in &rotation_policy.eligible_fingerprints_sha256 {
            if !allowed_leaf_fingerprints_sha256
                .iter()
                .any(|entry| entry == fingerprint)
            {
                allowed_leaf_fingerprints_sha256.push(fingerprint.clone());
            }
        }
        if let Some(leaf_fp) = &leaf_fingerprint_sha256 {
            for (index, candidate) in rotation_policy
                .eligible_fingerprints_sha256
                .iter()
                .enumerate()
            {
                if leaf_fp.eq_ignore_ascii_case(candidate) {
                    matched_key_id = rotation_policy.eligible_key_ids.get(index).cloned();
                    break;
                }
            }
            if matched_key_id.is_none() {
                reason_codes.push("leaf_fingerprint_not_in_rotation_slots".to_string());
            }
        }
        rotation_policy_summary = Some(RotationPolicySummary {
            source: rotation_policy.source.clone(),
            file_sha256: rotation_policy.file_sha256.clone(),
            policy_id: rotation_policy.policy_id.clone(),
            version: rotation_policy.version.clone(),
            generated_at: rotation_policy.generated_at.clone(),
            current_key_id: rotation_policy.current_key_id.clone(),
            next_key_id: rotation_policy.next_key_id.clone(),
            eligible_key_ids: rotation_policy.eligible_key_ids.clone(),
            matched_key_id: matched_key_id.clone(),
        });
    }

    if !allowed_leaf_fingerprints_sha256.is_empty() {
        let fingerprint_allowed = leaf_fingerprint_sha256
            .as_ref()
            .map(|fp| {
                allowed_leaf_fingerprints_sha256
                    .iter()
                    .any(|allowed| allowed == &fp.to_ascii_lowercase())
            })
            .unwrap_or(false);
        if !fingerprint_allowed {
            reason_codes.push("leaf_fingerprint_not_allowlisted".to_string());
        }
    }

    let leaf_key_congruent = c2pa::create_signer::from_keys(
        signer.cert_pem.as_bytes(),
        signer.key_pem.as_bytes(),
        c2pa::SigningAlg::Es256,
        None,
    )
    .is_ok();

    if !leaf_key_congruent {
        reason_codes.push("leaf_key_not_congruent".to_string());
    }

    let pass = if policy.enforced {
        reason_codes.is_empty()
    } else {
        true
    };

    let summary = if reason_codes.is_empty() {
        if policy.enforced {
            "cert policy pass".to_string()
        } else {
            "cert policy checks clean (enforcement disabled)".to_string()
        }
    } else if policy.enforced {
        format!("cert policy fail: {}", reason_codes.join(";"))
    } else {
        format!("cert policy warnings: {}", reason_codes.join(";"))
    };

    Ok(CertPolicyStatus {
        enforced: policy.enforced,
        pass,
        reason_codes,
        summary,
        chain_count,
        leaf_fingerprint_sha256,
        leaf_common_name,
        leaf_key_congruent,
        credential_source: signer.credential_source.clone(),
        rotation_policy: rotation_policy_summary,
    })
}

fn signer_git_sha() -> String {
    let value = std::env::var("SIGNER_GIT_SHA").unwrap_or_else(|_| "unknown".to_string());
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// C2PA-compliant cert chain generation
// ---------------------------------------------------------------------------
// Generates a 2-cert chain: Root CA → Leaf signer.
// The leaf has:
//   - KU: digitalSignature (critical)
//   - EKU: emailProtection (1.3.6.1.5.5.7.3.4) + documentSigning (1.3.6.1.4.1.311.10.3.12)
//   - Subject != Issuer (not self-issued)
//   - is_ca: false
// These are exactly the requirements the cert policy enforcer checks at startup.
struct GeneratedChain {
    root_ca_cert_pem: String,
    leaf_cert_pem: String,
    leaf_key_pem: String,
    chain_pem: String, // leaf + root CA concatenated — use this as C2PA_SIGNER_CERT_CHAIN_PEM
    leaf_fingerprint_sha256: String,
}

fn generate_c2pa_cert_chain(
    common_name: &str,
    org: &str,
    country: &str,
    not_before_ymd: (i32, u8, u8),
    not_after_ymd: (i32, u8, u8),
) -> Result<GeneratedChain, Box<dyn std::error::Error>> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyUsagePurpose, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    // ---- Root CA ----
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, format!("{} Root CA", common_name));
    ca_params.distinguished_name.push(DnType::OrganizationName, org);
    ca_params.distinguished_name.push(DnType::CountryName, country);
    ca_params.use_authority_key_identifier_extension = true;
    ca_params.not_before = rcgen::date_time_ymd(not_before_ymd.0, not_before_ymd.1, not_before_ymd.2);
    ca_params.not_after = rcgen::date_time_ymd(not_after_ymd.0, not_after_ymd.1, not_after_ymd.2);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // ---- Leaf signer ----
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params.distinguished_name.push(DnType::CommonName, common_name);
    leaf_params.distinguished_name.push(DnType::OrganizationName, org);
    leaf_params.distinguished_name.push(DnType::CountryName, country);
    leaf_params.use_authority_key_identifier_extension = true;
    leaf_params.not_before = rcgen::date_time_ymd(not_before_ymd.0, not_before_ymd.1, not_before_ymd.2);
    leaf_params.not_after = rcgen::date_time_ymd(not_after_ymd.0, not_after_ymd.1, not_after_ymd.2);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::EmailProtection,         // 1.3.6.1.5.5.7.3.4
        ExtendedKeyUsagePurpose::Other(                   // documentSigning 1.3.6.1.4.1.311.10.3.12
            vec![1, 3, 6, 1, 4, 1, 311, 10, 3, 12]
                .into_iter()
                .map(|v: u64| v)
                .collect::<Vec<_>>()
                .into(),
        ),
    ];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

    let leaf_der = leaf_cert.der().to_vec();
    let leaf_fingerprint_sha256 = sha256_hex(&leaf_der);

    // Chain PEM: leaf first, then CA — matches C2PA convention
    let chain_pem = format!("{}{}", leaf_cert.pem(), ca_cert.pem());

    Ok(GeneratedChain {
        root_ca_cert_pem: ca_cert.pem(),
        leaf_cert_pem: leaf_cert.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
        chain_pem,
        leaf_fingerprint_sha256,
    })
}

fn cmd_gen_certs() -> Result<(), Box<dyn std::error::Error>> {
    let common_name = std::env::var("SIGNER_CERT_CN")
        .unwrap_or_else(|_| "artwork.shop C2PA Signer".to_string());
    let org = std::env::var("SIGNER_CERT_ORG")
        .unwrap_or_else(|_| "artwork.shop".to_string());
    let country = std::env::var("SIGNER_CERT_COUNTRY")
        .unwrap_or_else(|_| "US".to_string());

    let chain = generate_c2pa_cert_chain(
        &common_name,
        &org,
        &country,
        (2026, 5, 4),
        (2028, 5, 4),
    )?;

    // Machine-readable JSON output so the ops upload script can parse it directly.
    let out = serde_json::json!({
        "generated": true,
        "leafFingerprintSha256": chain.leaf_fingerprint_sha256,
        "certChainPem": chain.chain_pem,
        "leafCertPem": chain.leaf_cert_pem,
        "rootCaCertPem": chain.root_ca_cert_pem,
        "privateKeyPem": chain.leaf_key_pem,
        "envVars": {
            "C2PA_SIGNER_CERT_CHAIN_PEM": chain.chain_pem.trim(),
            "C2PA_SIGNER_PRIVATE_KEY_PEM": chain.leaf_key_pem.trim(),
        },
        "note": "Store privateKeyPem and certChainPem as secrets. Do not commit them."
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --gen-certs: generate a C2PA-compliant 2-cert chain and print JSON to stdout, then exit.
    // Used by scripts/gen-signer-cert.ps1 to provision real credentials.
    if std::env::args().any(|arg| arg == "--gen-certs") {
        return cmd_gen_certs();
    }

    let bind_addr = std::env::var("RUST_SIGNER_HTTP_BIND").unwrap_or_else(|_| "127.0.0.1:8789".to_string());
    let token = std::env::var("SIGNER_SERVICE_TOKEN").unwrap_or_default();
    let self_test_image_url = std::env::var("C2PA_SIGNER_SELF_TEST_IMAGE_URL")
        .unwrap_or_else(|_| DEFAULT_SELF_TEST_IMAGE_URL.clone());
    let max_source_image_bytes = std::env::var("MAX_SOURCE_IMAGE_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20 * 1024 * 1024);
    let source_fetch_timeout_ms = std::env::var("SOURCE_FETCH_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(20_000);
    let fail_open_post_sign_verify = read_env_bool("C2PA_SIGNER_FAIL_OPEN_POST_SIGN_VERIFY", false);

    let config = Arc::new(Config {
        token,
        self_test_image_url,
        max_source_image_bytes,
        source_fetch_timeout_ms,
        fail_open_post_sign_verify,
    });

    let signer = Arc::new(resolve_signer_material()?);
    let cert_policy_config = load_cert_policy_config()?;
    let cert_policy_status = Arc::new(evaluate_cert_policy(&signer, &cert_policy_config)?);
    if cert_policy_config.enforced && !cert_policy_status.pass {
        return Err(format!(
            "Startup blocked by cert policy: {}",
            cert_policy_status.summary
        )
        .into());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(config.source_fetch_timeout_ms))
        .build()?;

    let state = AppState {
        config,
        http: client,
        signer,
        cert_policy_status,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/health/abi", get(health_abi))
        .route("/debug/cert-policy", get(debug_cert_policy))
        .route("/debug/cert-profile", get(debug_cert_profile))
        .route("/debug/signature-forensics", get(debug_signature_forensics))
        .route("/health/self-test", post(self_test))
        .route("/sign", post(sign))
        .with_state(state);

    let addr: SocketAddr = bind_addr.parse()?;
    println!("rust-http-signer listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn resolve_signer_material() -> Result<SignerMaterial, Box<dyn std::error::Error>> {
    let cert = std::env::var("C2PA_SIGNER_CERT_CHAIN_PEM")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("C2PA_SIGNER_CERT_PEM").ok())
        .filter(|value| !value.trim().is_empty());

    let key = std::env::var("C2PA_SIGNER_PRIVATE_KEY_PEM")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if let (Some(cert_pem), Some(key_pem)) = (cert.as_ref(), key.as_ref()) {
        return Ok(SignerMaterial {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            credential_source: "env".to_string(),
        });
    }

    if cert.is_some() || key.is_some() {
        return Err(
            "Incomplete signer credentials: both C2PA_SIGNER_PRIVATE_KEY_PEM and C2PA_SIGNER_CERT_CHAIN_PEM (or C2PA_SIGNER_CERT_PEM) are required."
                .into(),
        );
    }

    Err(
        "Signer credentials are missing. Set C2PA_SIGNER_PRIVATE_KEY_PEM and C2PA_SIGNER_CERT_CHAIN_PEM (or C2PA_SIGNER_CERT_PEM)."
            .into(),
    )
}

fn require_auth(headers: &HeaderMap, config: &Config) -> Result<(), HttpError> {
    if config.token.trim().is_empty() {
        return Ok(());
    }

    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer_token)
        .unwrap_or_default();

    if token == config.token {
        Ok(())
    } else {
        Err(HttpError::new(StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}

fn parse_bearer_token(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let prefix = "bearer ";
    if trimmed.len() > prefix.len() && trimmed.to_ascii_lowercase().starts_with(prefix) {
        Some(trimmed[prefix.len()..].trim().to_string())
    } else {
        None
    }
}

async fn fetch_source_image_bytes(
    state: &AppState,
    source_image_url: &str,
) -> Result<(Vec<u8>, String), HttpError> {
    let parsed = reqwest::Url::parse(source_image_url)
        .map_err(|_| HttpError::new(StatusCode::BAD_REQUEST, "sourceImageUrl must be a valid URL."))?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            "sourceImageUrl must use http or https.",
        ));
    }

    let response = state
        .http
        .get(parsed)
        .send()
        .await
        .map_err(|error| HttpError::new(StatusCode::BAD_REQUEST, format!("Source image fetch failed: {}", error)))?;

    if !response.status().is_success() {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            format!("Source image fetch failed ({}).", response.status().as_u16()),
        ));
    }

    let mime = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("image/jpeg")
        .to_string();

    let bytes = response
        .bytes()
        .await
        .map_err(|error| HttpError::new(StatusCode::BAD_REQUEST, format!("Failed to read source bytes: {}", error)))?;

    if bytes.is_empty() {
        return Err(HttpError::new(StatusCode::BAD_REQUEST, "Source image payload is empty."));
    }

    if bytes.len() > state.config.max_source_image_bytes {
        return Err(HttpError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "Source image exceeds max bytes ({}).",
                state.config.max_source_image_bytes
            ),
        ));
    }

    Ok((bytes.to_vec(), mime))
}

fn normalize_supported_image_mime(mime: &str) -> Option<&'static str> {
    let normalized = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    match normalized.as_str() {
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/webp" => Some("image/webp"),
        "video/mp4" | "application/mp4" => Some("video/mp4"),
        "audio/mpeg" | "audio/mp3" | "audio/x-mp3" | "audio/x-mpeg" => Some("audio/mpeg"),
        _ => None,
    }
}

fn require_supported_image_mime(mime: &str) -> Result<&'static str, HttpError> {
    normalize_supported_image_mime(mime).ok_or_else(|| {
        HttpError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "Unsupported source content type {mime:?}. Supported formats are image/jpeg, image/webp, video/mp4, and audio/mpeg."
            ),
        )
    })
}

fn build_manifest_definition(
    request_manifest: Option<Value>,
    manifest_guid: &str,
    signer: &SignerMaterial,
) -> Value {
    let payload = request_manifest.unwrap_or_else(|| json!({}));
    let claim_generator = payload
        .get("claim_generator")
        .and_then(Value::as_str)
        .unwrap_or("artwork.shop/1.0");

    let assertions = normalize_assertions_for_actions_and_signer_set(&payload, manifest_guid, signer);

    json!({
        "claim_generator": claim_generator,
        "claim_generator_info": [{ "name": "artwork.shop", "version": "1.0" }],
        "assertions": assertions
    })
}

fn normalize_assertions_for_actions_and_signer_set(
    payload: &Value,
    manifest_guid: &str,
    signer: &SignerMaterial,
) -> Value {
    let mut assertions = payload
        .get("assertions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    assertions.retain(|assertion| {
        assertion
            .get("label")
            .and_then(Value::as_str)
            .map(|label| label != "org.artworkshop.signer_set.v1")
            .unwrap_or(true)
    });

    let mut actions_assertion_index: Option<usize> = None;

    for (index, assertion) in assertions.iter_mut().enumerate() {
        let label = assertion
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if label != "c2pa.actions" && label != "c2pa.actions.v2" {
            continue;
        }

        actions_assertion_index = Some(index);

        let actions = assertion
            .get_mut("data")
            .and_then(Value::as_object_mut)
            .and_then(|data| data.get_mut("actions"))
            .and_then(Value::as_array_mut);

        if let Some(actions) = actions {
            let first_action = actions
                .first()
                .and_then(|item| item.get("action"))
                .and_then(Value::as_str)
                .unwrap_or_default();

            if first_action != "c2pa.created" && first_action != "c2pa.opened" {
                actions.insert(0, json!({ "action": "c2pa.created" }));
            }
        }

        break;
    }

    if actions_assertion_index.is_none() {
        assertions.push(json!({
            "label": "c2pa.actions.v2",
            "data": {
                "actions": [
                    { "action": "c2pa.created" }
                ]
            }
        }));
    }

    // Platform signer-set assertion is required and platform-authored.
    assertions.push(build_signer_set_assertion(manifest_guid, signer));

    Value::Array(assertions)
}

fn build_signer_set_assertion(manifest_guid: &str, signer: &SignerMaterial) -> Value {
    let git_sha = signer_git_sha();
    let cert_fingerprints = signer
        .cert_pem
        .split("-----END CERTIFICATE-----")
        .map(str::trim)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| {
            let normalized = format!("{}\n-----END CERTIFICATE-----", chunk);
            sha256_hex(normalized.as_bytes())
        })
        .collect::<Vec<_>>();

    let mut canonical = BTreeMap::new();
    canonical.insert("assertion_version".to_string(), json!("signer-set@1.0"));
    canonical.insert("manifest_guid".to_string(), json!(manifest_guid));
    canonical.insert("signing_alg".to_string(), json!("es256"));
    canonical.insert("signer_version".to_string(), json!(VERSION));
    canonical.insert("signer_git_sha".to_string(), json!(git_sha));
    canonical.insert("cert_chain_fingerprints_sha256".to_string(), json!(cert_fingerprints));

    let canonical_json = serde_json::to_string(&canonical).unwrap_or_else(|_| "{}".to_string());
    let signer_set_hash = sha256_hex(canonical_json.as_bytes());

    json!({
        "label": "org.artworkshop.signer_set.v1",
        "data": {
            "schema_version": "signer-set-assertion@1.0",
            "hash_alg": "sha256",
            "hash_scope": "org.artworkshop.signer_set.v1/default",
            "signer_set_hash": format!("sha256:{}", signer_set_hash),
            "canonicalization": "json-btreemap-utf8",
            "source": "c2pa-platform-final-signer",
            "manifest_guid": manifest_guid,
            "signer_version": VERSION,
            "signer_git_sha": canonical
                .get("signer_git_sha")
                .cloned()
                .unwrap_or_else(|| json!("unknown")),
            "signing_alg": "es256",
            "cert_chain_fingerprints_sha256": canonical
                .get("cert_chain_fingerprints_sha256")
                .cloned()
                .unwrap_or_else(|| json!([]))
        }
    })
}

fn sign_image(
    source_bytes: &[u8],
    source_mime: &str,
    manifest_definition: &Value,
    signer: &SignerMaterial,
) -> Result<Vec<u8>, HttpError> {
    let signer_impl = c2pa::create_signer::from_keys(
        signer.cert_pem.as_bytes(),
        signer.key_pem.as_bytes(),
        c2pa::SigningAlg::Es256,
        None,
    )
    .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Signer init failed: {}", error)))?;

    let signer_impl = LowSNormalizerSigner { inner: signer_impl };

    let mut builder = c2pa::Builder::from_json(&manifest_definition.to_string())
        .map_err(|error| HttpError::new(StatusCode::BAD_REQUEST, format!("Manifest parse failed: {}", error)))?;

    let mut source = Cursor::new(source_bytes);
    let mut destination = Cursor::new(Vec::<u8>::new());

    builder
        .sign(&signer_impl, source_mime, &mut source, &mut destination)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Signing failed: {}", error)))?;

    let output = destination.into_inner();
    if output.is_empty() {
        return Err(HttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Signing failed: empty output.",
        ));
    }

    // Optional self-verification can be disabled for faster container cold paths.
    if !read_env_bool("C2PA_SIGNER_SKIP_SELF_VERIFY", false) {
        // Forensics assertion: signer output must be verifiable by local c2pa reader.
        // If this fails, signing credentials/config are not internally coherent.
        assert_signer_self_verification(&output, source_mime)?;
    }

    Ok(output)
}

fn assert_signer_self_verification(signed_bytes: &[u8], source_mime: &str) -> Result<(), HttpError> {
    let ignore_cert_profile = read_env_bool("C2PA_SIGNER_SELF_VERIFY_IGNORE_CERT_PROFILE", false);
    let verify_after_reading = read_env_bool("C2PA_SIGNER_VERIFY_AFTER_READING", true) && !ignore_cert_profile;

    let mut stream = Cursor::new(signed_bytes.to_vec());
    let verify_settings = format!(
        r#"{{
            "version": 1,
            "verify": {{
                "verify_after_reading": {},
                "verify_after_sign": false,
                "verify_trust": false,
                "verify_timestamp_trust": false
            }}
        }}"#,
        if verify_after_reading { "true" } else { "false" }
    );

    let context = Context::new()
        .with_settings(verify_settings)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Self-verify context failed: {}", error)))?;

    let reader = c2pa::Reader::from_context(context)
        .with_stream(source_mime, &mut stream)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Self-verify read failed: {}", error)))?;

    capture_verifier_forensics(&reader, signed_bytes, source_mime);

    if ignore_cert_profile {
        return Ok(());
    }

    let validation_state = reader.validation_state();
    if validation_state == ValidationState::Invalid {
        let parsed = serde_json::from_str::<Value>(&reader.json()).unwrap_or_else(|_| json!({}));
        let explanations = parsed
            .get("validation_status")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("explanation").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let details = if explanations.is_empty() {
            "(no validation_status explanations available)".to_string()
        } else {
            explanations.join(" | ")
        };

        return Err(HttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Signer self-verification failed: {}", details),
        ));
    }

    Ok(())
}

fn with_forensics_mut<F>(mutator: F)
where
    F: FnOnce(&mut SignatureForensics),
{
    if let Ok(mut guard) = LAST_SIGNATURE_FORENSICS.lock() {
        mutator(&mut guard);
    }
}

fn capture_signer_input_forensics(tbs_bytes: &[u8]) {
    let mut record = SignatureForensicsSignerInput {
        tbs_sha256: sha256_hex(tbs_bytes),
        tbs_hex: hex::encode(tbs_bytes),
        tbs_len: tbs_bytes.len(),
        protected_header_hex: None,
        claim_hex: None,
        claim_sha256: None,
        claim_len: None,
        uri_samples: Vec::new(),
    };

    if let Ok(decoded) = ciborium::from_reader::<CborValue, _>(Cursor::new(tbs_bytes)) {
        if let CborValue::Array(values) = decoded {
            if values.len() >= 4 {
                if let CborValue::Bytes(protected) = &values[1] {
                    record.protected_header_hex = Some(hex::encode(protected));
                }
                if let CborValue::Bytes(payload) = &values[3] {
                    record.claim_len = Some(payload.len());
                    record.claim_sha256 = Some(sha256_hex(payload));
                    record.claim_hex = Some(hex::encode(payload));
                    record.uri_samples = collect_uri_samples(payload);
                }
            }
        }
    }

    with_forensics_mut(|f| {
        f.signer_input = Some(record);
    });
}

fn capture_verifier_forensics(reader: &c2pa::Reader, signed_bytes: &[u8], source_mime: &str) {
    let mut view = SignatureForensicsVerifierView {
        validation_state: Some(format!("{:?}", reader.validation_state())),
        manifest_label: reader.active_label().map(str::to_string),
        cose_sign1_hex: None,
        cose_sign1_len: None,
        protected_header_hex: None,
        protected_header_len: None,
        manifest_store_blob_hex: None,
        manifest_store_blob_sha256: None,
        manifest_store_blob_len: None,
        uri_samples: Vec::new(),
        notes: Vec::new(),
    };

    if let Some(active) = reader.active_manifest() {
        if let Some(signature) = active.signature() {
            view.cose_sign1_len = Some(signature.len());
            view.cose_sign1_hex = Some(hex::encode(signature));

            if let Ok(decoded) = ciborium::from_reader::<CborValue, _>(Cursor::new(signature)) {
                if let CborValue::Array(values) = decoded {
                    if let Some(CborValue::Bytes(protected)) = values.first() {
                        view.protected_header_len = Some(protected.len());
                        view.protected_header_hex = Some(hex::encode(protected));
                    }
                }
            }
        } else {
            view.notes.push("active_manifest.signature() unavailable".to_string());
        }
    } else {
        view.notes.push("reader.active_manifest() unavailable".to_string());
    }

    let mut uri_samples = collect_uri_samples(signed_bytes);
    uri_samples.extend(collect_uri_samples(reader.detailed_json().as_bytes()));
    uri_samples.sort();
    uri_samples.dedup();
    view.uri_samples = uri_samples;

    if let Some(store_blob) = extract_manifest_store_blob(signed_bytes, source_mime) {
        view.manifest_store_blob_len = Some(store_blob.len());
        view.manifest_store_blob_sha256 = Some(sha256_hex(&store_blob));
        view.manifest_store_blob_hex = Some(hex::encode(&store_blob));
        let mut blob_uri_samples = collect_uri_samples(&store_blob);
        view.uri_samples.append(&mut blob_uri_samples);
        view.uri_samples.sort();
        view.uri_samples.dedup();
    } else {
        view.notes.push("manifest store blob unavailable via jumbf_io".to_string());
    }

    with_forensics_mut(|f| {
        f.verifier_view = Some(view);
    });
}

fn collect_uri_samples(bytes: &[u8]) -> Vec<String> {
    let needles = ["c2pa.signature", "self#jumbf=", "/c2pa/", "urn:c2pa:"];
    let mut samples = Vec::<String>::new();

    for needle in needles {
        for offset in find_subsequence_offsets(bytes, needle.as_bytes()) {
            let start = offset.saturating_sub(40);
            let end = (offset + needle.len() + 80).min(bytes.len());
            let snippet = String::from_utf8_lossy(&bytes[start..end])
                .chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect::<String>();
            samples.push(format!("{}@{}:{}", needle, offset, snippet));
            if samples.len() >= 32 {
                return samples;
            }
        }
    }

    samples
}

fn find_subsequence_offsets(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }

    let mut offsets = Vec::<usize>::new();
    let last_start = haystack.len() - needle.len();
    for i in 0..=last_start {
        if &haystack[i..(i + needle.len())] == needle {
            offsets.push(i);
        }
    }

    offsets
}

fn extract_manifest_store_blob(signed_bytes: &[u8], source_mime: &str) -> Option<Vec<u8>> {
    c2pa::jumbf_io::load_jumbf_from_memory(source_mime, signed_bytes).ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn verify_signed_bytes(signed_bytes: &[u8], source_mime: &str) -> Result<PostSignVerification, HttpError> {
    let mut stream = Cursor::new(signed_bytes.to_vec());
    let verify_after_reading = read_env_bool("C2PA_SIGNER_VERIFY_AFTER_READING", true);
    let verify_settings = format!(
        r#"{{
        "version": 1,
        "verify": {{
            "verify_after_reading": {},
            "verify_after_sign": false,
            "verify_trust": false,
            "verify_timestamp_trust": false
        }}
    }}"#,
        if verify_after_reading { "true" } else { "false" }
    );

    let context = Context::new()
        .with_settings(verify_settings)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Verification context failed: {}", error)))?;

    let reader = c2pa::Reader::from_context(context)
        .with_stream(source_mime, &mut stream)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Post-sign verify failed: {}", error)))?;

    let validation_state_enum = reader.validation_state();
    let validation_state = format!("{:?}", validation_state_enum);

    let parsed = serde_json::from_str::<Value>(&reader.json()).unwrap_or_else(|_| json!({}));
    let validation_status = parsed
        .get("validation_status")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let first_failure = validation_status
        .iter()
        .find(|entry| entry.get("code").and_then(Value::as_str).is_some());

    let failure_code = first_failure
        .and_then(|entry| entry.get("code"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let failure_explanation = first_failure
        .and_then(|entry| entry.get("explanation"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let failure_url = first_failure
        .and_then(|entry| entry.get("url"))
        .and_then(Value::as_str)
        .map(str::to_string);

    if validation_state_enum == ValidationState::Invalid {
        return Ok(PostSignVerification {
            validation_state,
            validation_status,
            failure_code,
            failure_explanation,
            failure_url,
        });
    }

    Ok(PostSignVerification {
        validation_state,
        validation_status,
        failure_code,
        failure_explanation,
        failure_url,
    })
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let policy_status = state.cert_policy_status.as_ref();
    Json(HealthResponse {
        success: policy_status.pass,
        ready: policy_status.pass,
        algorithm: "es256".to_string(),
        leaf_key_congruence: HealthLeafKeyCongruence {
            congruent: policy_status.leaf_key_congruent,
            detail: format!(
                "{} ({})",
                if policy_status.pass { "Rust HTTP signer credential policy pass" } else { "Rust HTTP signer credential policy fail" },
                state.signer.credential_source,
            ),
        },
        cert_policy: Some(policy_status.clone()),
    })
}

async fn health_abi(State(state): State<AppState>) -> Json<Value> {
    let certificate_count = parse_cert_chain_der(&state.signer.cert_pem)
        .map(|certs| certs.len())
        .unwrap_or(0);

    Json(json!({
        "success": true,
        "abi": {
            "wasmInitialized": false,
            "wasmSource": "native-rust-c2pa",
            "builderAvailable": true,
            "readerAvailable": true
        },
        "signerConfig": {
            "algorithm": "es256",
            "coseLayout": "native-rust",
            "cosePayloadMode": "detached",
            "protectedHeaderMode": "native-default",
            "coseX5chainMode": "leaf",
            "reserveSize": null,
            "certificateCount": certificate_count,
            "credentialFormat": "c2pa",
            "signerSetAssertionRequired": true,
            "credentialSource": state.signer.credential_source,
            "certPolicy": state.cert_policy_status.as_ref()
        }
    }))
}

async fn debug_cert_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, HttpError> {
    require_auth(&headers, &state.config)?;

    Ok(Json(json!({
        "success": true,
        "certPolicy": state.cert_policy_status.as_ref()
    })))
}

async fn debug_cert_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, HttpError> {
    require_auth(&headers, &state.config)?;

    let cert_der_chain = parse_cert_chain_der(&state.signer.cert_pem)
        .map_err(|error| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Cert chain parse failed: {}", error)))?;

    let certs = cert_der_chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            let parsed = X509Certificate::from_der(der)
                .map_err(|_| HttpError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("DER parse failed for cert index {}", index)))?;
            let (_rem, cert) = parsed;

            let subject = cert
                .subject()
                .iter_attributes()
                .filter_map(|attr| attr.as_str().ok().map(str::to_string))
                .collect::<Vec<String>>();
            let issuer = cert
                .issuer()
                .iter_attributes()
                .filter_map(|attr| attr.as_str().ok().map(str::to_string))
                .collect::<Vec<String>>();

            let mut extension_oids = Vec::<String>::new();
            let mut key_usage = json!(null);
            let mut extended_key_usage = json!(null);
            let mut basic_constraints = json!(null);

            for ext in cert.extensions() {
                extension_oids.push(ext.oid.to_id_string());
                match ext.parsed_extension() {
                    ParsedExtension::KeyUsage(ku) => {
                        key_usage = json!({
                            "digital_signature": ku.digital_signature(),
                            "content_commitment": ku.non_repudiation(),
                            "key_encipherment": ku.key_encipherment(),
                            "data_encipherment": ku.data_encipherment(),
                            "key_agreement": ku.key_agreement(),
                            "key_cert_sign": ku.key_cert_sign(),
                            "crl_sign": ku.crl_sign(),
                            "encipher_only": ku.encipher_only(),
                            "decipher_only": ku.decipher_only()
                        });
                    }
                    ParsedExtension::ExtendedKeyUsage(eku) => {
                        let mut other_oids = Vec::<String>::new();
                        for oid in &eku.other {
                            other_oids.push(oid.to_id_string());
                        }
                        extended_key_usage = json!({
                            "any": eku.any,
                            "server_auth": eku.server_auth,
                            "client_auth": eku.client_auth,
                            "code_signing": eku.code_signing,
                            "email_protection": eku.email_protection,
                            "time_stamping": eku.time_stamping,
                            "ocsp_signing": eku.ocsp_signing,
                            "other_oids": other_oids
                        });
                    }
                    ParsedExtension::BasicConstraints(bc) => {
                        basic_constraints = json!({
                            "ca": bc.ca,
                            "path_len_constraint": bc.path_len_constraint
                        });
                    }
                    _ => {}
                }
            }

            Ok::<Value, HttpError>(json!({
                "index": index,
                "is_leaf": index == 0,
                "subject": subject,
                "issuer": issuer,
                "serial": cert.serial.to_string(),
                "signature_algorithm_oid": cert.signature_algorithm.algorithm.to_id_string(),
                "spki_algorithm_oid": cert.public_key().algorithm.algorithm.to_id_string(),
                "not_before": cert.validity().not_before.to_rfc2822(),
                "not_after": cert.validity().not_after.to_rfc2822(),
                "is_ca": cert.tbs_certificate.is_ca(),
                "basic_constraints": basic_constraints,
                "key_usage": key_usage,
                "extended_key_usage": extended_key_usage,
                "extension_oids": extension_oids,
                "sha256": sha256_hex(der)
            }))
        })
        .collect::<Result<Vec<Value>, HttpError>>()?;

    Ok(Json(json!({
        "success": true,
        "certificateCount": certs.len(),
        "certificates": certs
    })))
}

async fn debug_signature_forensics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, HttpError> {
    require_auth(&headers, &state.config)?;

    let snapshot = LAST_SIGNATURE_FORENSICS
        .lock()
        .map(|value| value.clone())
        .unwrap_or_default();

    Ok(Json(json!({
        "success": true,
        "forensics": snapshot
    })))
}

fn parse_cert_chain_der(cert_chain_pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut certs = Vec::<Vec<u8>>::new();
    for pem_result in Pem::iter_from_buffer(cert_chain_pem.as_bytes()) {
        let pem = pem_result.map_err(|e| format!("PEM parse error: {}", e))?;
        certs.push(pem.contents);
    }
    if certs.is_empty() {
        return Err("no certificates found in PEM bundle".to_string());
    }
    Ok(certs)
}

async fn self_test(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SelfTestResponse>, HttpError> {
    require_auth(&headers, &state.config)?;

    let start = std::time::Instant::now();
    let (source_bytes, source_mime_raw) = fetch_source_image_bytes(&state, &state.config.self_test_image_url).await?;
    let source_mime = require_supported_image_mime(&source_mime_raw)?;

    let manifest_definition = json!({
        "claim_generator": "artwork.shop/1.0",
        "claim_generator_info": [{ "name": "artwork.shop", "version": "1.0" }],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        { "action": "c2pa.created" }
                    ]
                }
            }
        ]
    });

    let self_test_manifest_guid = format!("selftest-{}", Uuid::new_v4());
    let manifest_definition = build_manifest_definition(
        Some(manifest_definition),
        &self_test_manifest_guid,
        &state.signer,
    );

    let signed = sign_image(&source_bytes, source_mime, &manifest_definition, &state.signer)?;
    let _digest = sha256_hex(&signed);
    let verify = verify_signed_bytes(&signed, source_mime)?;

    Ok(Json(SelfTestResponse {
        success: verify.validation_state != "Invalid",
        message: "Self-test signed output generated with local reader verification.".to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
        leaf_key_congruence: HealthLeafKeyCongruence {
            congruent: state.cert_policy_status.leaf_key_congruent,
            detail: state.cert_policy_status.summary.clone(),
        },
        verification_result: SelfTestVerificationResult {
            validation_state: verify.validation_state,
            validation_status: verify.validation_status,
        },
    }))
}

async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SignRequest>,
) -> Result<Response, HttpError> {
    require_auth(&headers, &state.config)?;

    let source_image_url = payload
        .source_image_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HttpError::new(StatusCode::BAD_REQUEST, "sourceImageUrl is required."))?;

    let manifest_guid = payload
        .manifest_guid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let (source_bytes, source_mime_raw) = fetch_source_image_bytes(&state, source_image_url).await?;
    let source_mime = require_supported_image_mime(&source_mime_raw)?;
    let manifest_definition = build_manifest_definition(payload.manifest, &manifest_guid, &state.signer);
    let signed_bytes = sign_image(&source_bytes, source_mime, &manifest_definition, &state.signer)?;
    let verify = verify_signed_bytes(&signed_bytes, source_mime)?;
    let signed_sha = sha256_hex(&signed_bytes);

    let gate_mode = if state.config.fail_open_post_sign_verify {
        "report_only"
    } else {
        "enforced"
    };

    if !state.config.fail_open_post_sign_verify && verify.validation_state == "Invalid" {
        let body = Json(ErrorResponse {
            success: false,
            message: format!(
                "Post-sign verification failed{}.",
                verify
                    .failure_code
                    .as_ref()
                    .map(|code| format!(": {}", code))
                    .unwrap_or_default()
            ),
            code: Some("signer.post_sign_verification_failed".to_string()),
            validation_state: Some(verify.validation_state),
            gate_mode: Some(gate_mode.to_string()),
            failure_code: verify.failure_code,
            failure_explanation: verify.failure_explanation,
            failure_url: verify.failure_url,
        });
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, body).into_response());
    }

    let mut response = (StatusCode::OK, signed_bytes).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(source_mime),
    );
    headers.insert(
        HeaderNameExt::manifest_guid(),
        HeaderValue::from_str(&manifest_guid)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-guid")),
    );
    headers.insert(
        HeaderNameExt::signer_version(),
        HeaderValue::from_static(VERSION),
    );
    headers.insert(
        HeaderNameExt::signer_git_sha(),
        HeaderValue::from_str(&signer_git_sha()).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    headers.insert(
        HeaderNameExt::c2pa_validation_state(),
        HeaderValue::from_str(&verify.validation_state).unwrap_or_else(|_| HeaderValue::from_static("Unknown")),
    );
    headers.insert(
        HeaderNameExt::c2pa_post_sign_gate(),
        HeaderValue::from_static(gate_mode),
    );
    headers.insert(
        HeaderNameExt::signed_sha256(),
        HeaderValue::from_str(&signed_sha).unwrap_or_else(|_| HeaderValue::from_static("sha256-error")),
    );

    Ok(response)
}

struct HeaderNameExt;

impl HeaderNameExt {
    fn manifest_guid() -> header::HeaderName {
        header::HeaderName::from_static("x-manifest-guid")
    }

    fn signer_version() -> header::HeaderName {
        header::HeaderName::from_static("x-signer-version")
    }

    fn signer_git_sha() -> header::HeaderName {
        header::HeaderName::from_static("x-signer-git-sha")
    }

    fn c2pa_validation_state() -> header::HeaderName {
        header::HeaderName::from_static("x-c2pa-validation-state")
    }

    fn c2pa_post_sign_gate() -> header::HeaderName {
        header::HeaderName::from_static("x-c2pa-post-sign-gate")
    }

    fn signed_sha256() -> header::HeaderName {
        header::HeaderName::from_static("x-signed-image-sha256")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use c2pa::HashRange;
    use ciborium::Value as CborValue;
    use p256::ecdsa::signature::Verifier;
    use std::io::{Cursor, Seek, SeekFrom, Write};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct SniffSnapshot {
        tbs: Vec<u8>,
        protected_header_sha256: Option<String>,
        protected_header_canonical_sha256: Option<String>,
        protected_header_key_order: Vec<String>,
        payload_sha256: Option<String>,
        payload_canonical_sha256: Option<String>,
    }

    struct TbsSnifferSigner {
        inner: c2pa::BoxedSigner,
        sink: Arc<Mutex<Vec<SniffSnapshot>>>,
    }

    impl TbsSnifferSigner {
        fn new(inner: c2pa::BoxedSigner, sink: Arc<Mutex<Vec<SniffSnapshot>>>) -> Self {
            Self { inner, sink }
        }
    }

    fn extract_sig_structure_payload_bytes(data: &[u8]) -> Option<Vec<u8>> {
        let decoded = ciborium::from_reader::<CborValue, _>(Cursor::new(data)).ok()?;
        let values = match decoded {
            CborValue::Array(values) if values.len() >= 4 => values,
            _ => return None,
        };

        match &values[3] {
            CborValue::Bytes(payload) => Some(payload.clone()),
            _ => None,
        }
    }

    fn extract_sig_structure_protected_header_bytes(data: &[u8]) -> Option<Vec<u8>> {
        let decoded = ciborium::from_reader::<CborValue, _>(Cursor::new(data)).ok()?;
        let values = match decoded {
            CborValue::Array(values) if values.len() >= 2 => values,
            _ => return None,
        };

        match &values[1] {
            CborValue::Bytes(protected) => Some(protected.clone()),
            _ => None,
        }
    }

    fn cbor_map_key_order(bytes: &[u8]) -> Vec<String> {
        let Ok(value) = ciborium::from_reader::<CborValue, _>(Cursor::new(bytes)) else {
            return Vec::new();
        };

        let CborValue::Map(entries) = value else {
            return Vec::new();
        };

        entries
            .iter()
            .map(|(k, _)| match k {
                CborValue::Integer(i) => format!("{:?}", i),
                CborValue::Text(s) => s.clone(),
                _ => format!("{:?}", k),
            })
            .collect()
    }

    fn canonicalize_cbor(bytes: &[u8]) -> Option<Vec<u8>> {
        let value = ciborium::from_reader::<CborValue, _>(Cursor::new(bytes)).ok()?;
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).ok()?;
        Some(out)
    }

    fn manual_verify_es256_with_leaf_cert(
        tbs: &[u8],
        signature_bytes: &[u8],
        cert_chain_pem: &str,
    ) -> Result<bool, String> {
        let cert_der_chain = parse_cert_chain_der(cert_chain_pem)?;
        let leaf_der = cert_der_chain
            .first()
            .ok_or_else(|| "missing leaf certificate in chain".to_string())?;

        let (_rem, leaf_cert) = X509Certificate::from_der(leaf_der)
            .map_err(|_| "failed to parse leaf certificate DER".to_string())?;

        let leaf_pubkey_sec1 = leaf_cert.public_key().subject_public_key.data.as_ref();
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(leaf_pubkey_sec1)
            .map_err(|error| format!("failed to build verifying key from cert SPKI: {}", error))?;

        let signature = if signature_bytes.len() == 64 {
            P256Signature::try_from(signature_bytes)
                .map_err(|error| format!("failed to parse raw ES256 signature: {}", error))?
        } else {
            P256Signature::from_der(signature_bytes)
                .map_err(|error| format!("failed to parse DER ES256 signature: {}", error))?
        };

        Ok(verifying_key.verify(tbs, &signature).is_ok())
    }

    impl c2pa::Signer for TbsSnifferSigner {
        fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
            println!("DEBUG_TBS_HEX: {}", hex::encode(data));
            println!("DEBUG_TBS_LEN: {}", data.len());

            let protected = extract_sig_structure_protected_header_bytes(data);
            let protected_header_sha256 = protected.as_ref().map(|p| sha256_hex(p));
            let protected_header_canonical_sha256 = protected
                .as_ref()
                .and_then(|p| canonicalize_cbor(p))
                .map(|p| sha256_hex(&p));
            let protected_header_key_order = protected
                .as_ref()
                .map(|p| cbor_map_key_order(p))
                .unwrap_or_default();

            if let Some(hash) = &protected_header_sha256 {
                println!("SIGNER_PROTECTED_HEADER_SHA: {}", hash);
            } else {
                println!("SIGNER_PROTECTED_HEADER_SHA: unavailable");
            }

            if let Some(hash) = &protected_header_canonical_sha256 {
                println!("SIGNER_PROTECTED_HEADER_CANONICAL_SHA: {}", hash);
            } else {
                println!("SIGNER_PROTECTED_HEADER_CANONICAL_SHA: unavailable");
            }
            println!(
                "SIGNER_PROTECTED_HEADER_KEY_ORDER: {}",
                protected_header_key_order.join(",")
            );

            let payload = extract_sig_structure_payload_bytes(data);
            let payload_sha256 = payload.as_ref().map(|p| sha256_hex(p));
            let payload_canonical_sha256 = payload
                .as_ref()
                .and_then(|p| canonicalize_cbor(p))
                .map(|p| sha256_hex(&p));

            if let Some(hash) = &payload_sha256 {
                println!("SIGNER_PAYLOAD_SHA: {}", hash);
            } else {
                println!("SIGNER_PAYLOAD_SHA: unavailable");
            }

            if let Some(hash) = &payload_canonical_sha256 {
                println!("SIGNER_PAYLOAD_CANONICAL_SHA: {}", hash);
            } else {
                println!("SIGNER_PAYLOAD_CANONICAL_SHA: unavailable");
            }

            if let Ok(mut guard) = self.sink.lock() {
                guard.push(SniffSnapshot {
                    tbs: data.to_vec(),
                    protected_header_sha256,
                    protected_header_canonical_sha256,
                    protected_header_key_order,
                    payload_sha256,
                    payload_canonical_sha256,
                });
            }

            self.inner.sign(data)
        }

        fn alg(&self) -> c2pa::SigningAlg {
            self.inner.alg()
        }

        fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
            self.inner.certs()
        }

        fn reserve_size(&self) -> usize {
            self.inner.reserve_size()
        }
    }

    fn fixture_json(path: &str) -> Value {
        let text = std::fs::read_to_string(path).expect("fixture should load");
        serde_json::from_str::<Value>(&text).expect("fixture must be valid json")
    }

    fn generated_signer_material() -> SignerMaterial {
        let chain = generate_c2pa_cert_chain(
            "artwork.shop test signer",
            "artwork.shop",
            "US",
            (2026, 5, 4),
            (2028, 5, 4),
        )
        .expect("generated signer chain should build");

        SignerMaterial {
            cert_pem: chain.chain_pem,
            key_pem: chain.leaf_key_pem,
            credential_source: "test-generated".to_string(),
        }
    }

    fn minimal_manifest_definition() -> Value {
        json!({
            "claim_generator": "rust-validity-proof/1.0",
            "claim_generator_info": [{ "name": "artwork.shop", "version": "1.0" }],
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": [
                            { "action": "c2pa.created" }
                        ]
                    }
                }
            ]
        })
    }

    fn minimal_valid_webp_bytes() -> Vec<u8> {
        STANDARD
            .decode("UklGRiIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA=")
            .expect("embedded webp fixture must decode")
    }

    fn minimal_valid_mp4_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&24u32.to_be_bytes());
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(b"isom");
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"isomiso2");
        bytes.extend_from_slice(&12u32.to_be_bytes());
        bytes.extend_from_slice(b"mdat");
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }

    fn minimal_valid_mp3_bytes() -> Vec<u8> {
        vec![
            0xff, 0xfb, 0x90, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn verify_context() -> c2pa::Context {
        c2pa::Context::new()
            .with_settings(
                r#"{
                    "version": 1,
                    "verify": {
                        "verify_after_reading": true,
                        "verify_after_sign": false,
                        "verify_trust": false,
                        "verify_timestamp_trust": false
                    }
                }"#,
            )
            .expect("verification context must build")
    }

    fn assert_reader_validation_valid(signed_bytes: &[u8], mime: &str, message: &str) {
        let mut reader_src = Cursor::new(signed_bytes);
        let reader = c2pa::Reader::from_context(verify_context())
            .with_stream(mime, &mut reader_src)
            .expect("reader must open signed bytes");

        let raw = reader.json();
        let store: serde_json::Value =
            serde_json::from_str(&raw).expect("reader json must parse");

        assert_eq!(
            reader.validation_state(),
            ValidationState::Valid,
            "{message}; validation_state={:?}; store: {}",
            reader.validation_state(),
            store
        );
    }

    fn first_bytes_hex(data: &[u8], count: usize) -> String {
        hex::encode(&data[..data.len().min(count)])
    }

    #[test]
    fn supported_image_mime_gate_accepts_jpeg_and_webp() {
        assert_eq!(normalize_supported_image_mime("image/jpeg"), Some("image/jpeg"));
        assert_eq!(normalize_supported_image_mime("image/jpg"), Some("image/jpeg"));
        assert_eq!(normalize_supported_image_mime("image/webp"), Some("image/webp"));
        assert_eq!(normalize_supported_image_mime("video/mp4"), Some("video/mp4"));
        assert_eq!(normalize_supported_image_mime("application/mp4"), Some("video/mp4"));
        assert_eq!(normalize_supported_image_mime("audio/mpeg"), Some("audio/mpeg"));
        assert_eq!(normalize_supported_image_mime("audio/mp3"), Some("audio/mpeg"));
        assert_eq!(normalize_supported_image_mime("image/png"), None);
        assert!(require_supported_image_mime("image/webp").is_ok());
        assert!(require_supported_image_mime("image/png").is_err());
    }

    #[test]
    fn builder_sign_video_mp4_validates() {
        let signer_material = generated_signer_material();
        let manifest_def = minimal_manifest_definition();
        let mp4_bytes = minimal_valid_mp4_bytes();

        let signer_impl = c2pa::create_signer::from_keys(
            signer_material.cert_pem.as_bytes(),
            signer_material.key_pem.as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .expect("from_keys must succeed with generated conformant certificate chain");

        let mut builder = c2pa::Builder::from_json(&manifest_def.to_string())
            .expect("builder from manifest must succeed");

        let mut src = Cursor::new(mp4_bytes.as_slice());
        let mut dst = Cursor::new(Vec::<u8>::new());
        builder
            .sign(&*signer_impl, "video/mp4", &mut src, &mut dst)
            .expect("signing mp4 with direct from_keys signer must succeed");

        let signed_bytes = dst.into_inner();
        assert!(!signed_bytes.is_empty(), "signed mp4 output must not be empty");

        assert_reader_validation_valid(
            &signed_bytes,
            "video/mp4",
            "Builder::sign must produce a locally verifiable mp4 asset",
        );
    }

    #[test]
    fn builder_sign_audio_mp3_validates() {
        let signer_material = generated_signer_material();
        let manifest_def = minimal_manifest_definition();
        let mp3_bytes = minimal_valid_mp3_bytes();

        let signer_impl = c2pa::create_signer::from_keys(
            signer_material.cert_pem.as_bytes(),
            signer_material.key_pem.as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .expect("from_keys must succeed with generated conformant certificate chain");

        let mut builder = c2pa::Builder::from_json(&manifest_def.to_string())
            .expect("builder from manifest must succeed");

        let mut src = Cursor::new(mp3_bytes.as_slice());
        let mut dst = Cursor::new(Vec::<u8>::new());
        builder
            .sign(&*signer_impl, "audio/mpeg", &mut src, &mut dst)
            .expect("signing mp3 with direct from_keys signer must succeed");

        let signed_bytes = dst.into_inner();
        assert!(!signed_bytes.is_empty(), "signed mp3 output must not be empty");

        assert_reader_validation_valid(
            &signed_bytes,
            "audio/mpeg",
            "Builder::sign must produce a locally verifiable mp3 asset",
        );
    }

    #[test]
    fn epub_support_is_still_blocked_by_the_pinned_c2pa_crate() {
        assert_eq!(normalize_supported_image_mime("application/epub+zip"), None);
        assert!(require_supported_image_mime("application/epub+zip").is_err());
    }

    #[test]
    fn golden_manifest_requires_platform_signer_set_assertion() {
        let input = fixture_json("fixtures/golden-manifest-input.v1.json");
        let expected = fixture_json("fixtures/golden-manifest-expected.v1.json");

        let signer = SignerMaterial {
            cert_pem: "-----BEGIN CERTIFICATE-----\nZ29sZGVuLWNlcnQ=\n-----END CERTIFICATE-----\n".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nZ29sZGVuLWtleQ==\n-----END PRIVATE KEY-----\n".to_string(),
            credential_source: "test-golden".to_string(),
        };

        let manifest_guid = "golden-manifest-guid";
        let output = build_manifest_definition(Some(input), manifest_guid, &signer);

        let assertions = output
            .get("assertions")
            .and_then(Value::as_array)
            .expect("assertions must be an array");

        let labels: Vec<String> = assertions
            .iter()
            .map(|a| a.get("label").and_then(Value::as_str).unwrap_or_default().to_string())
            .collect();

        for required in expected
            .get("required_assertion_labels")
            .and_then(Value::as_array)
            .expect("required_assertion_labels missing")
        {
            let label = required.as_str().expect("label must be string");
            assert!(labels.iter().any(|actual| actual == label), "missing required assertion label {label}");
        }

        let signer_set_assertions: Vec<&Value> = assertions
            .iter()
            .filter(|a| a.get("label").and_then(Value::as_str) == Some("org.artworkshop.signer_set.v1"))
            .collect();
        assert_eq!(signer_set_assertions.len(), 1, "platform signer-set assertion must be unique and required");

        let signer_set_data = signer_set_assertions[0]
            .get("data")
            .and_then(Value::as_object)
            .expect("signer-set data must be object");

        for field in expected
            .get("required_signer_set_fields")
            .and_then(Value::as_array)
            .expect("required_signer_set_fields missing")
        {
            let key = field.as_str().expect("field name must be string");
            assert!(signer_set_data.contains_key(key), "missing signer-set field {key}");
        }

        assert_eq!(
            signer_set_data.get("schema_version").and_then(Value::as_str),
            expected.get("expected_schema_version").and_then(Value::as_str)
        );
        assert_eq!(
            signer_set_data.get("source").and_then(Value::as_str),
            expected.get("expected_source").and_then(Value::as_str)
        );
        assert_eq!(
            signer_set_data.get("hash_scope").and_then(Value::as_str),
            expected.get("expected_hash_scope").and_then(Value::as_str)
        );
        assert_eq!(
            signer_set_data.get("signing_alg").and_then(Value::as_str),
            expected.get("expected_signing_alg").and_then(Value::as_str)
        );
        assert_eq!(
            signer_set_data.get("manifest_guid").and_then(Value::as_str),
            Some(manifest_guid)
        );

        let signer_set_hash = signer_set_data
            .get("signer_set_hash")
            .and_then(Value::as_str)
            .expect("signer_set_hash missing");
        assert!(signer_set_hash.starts_with("sha256:"), "signer_set_hash must use sha256 prefix");

        let actions_assertion = assertions
            .iter()
            .find(|a| a.get("label").and_then(Value::as_str) == Some("c2pa.actions.v2"))
            .expect("actions assertion missing");
        let first_action = actions_assertion
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get("actions"))
            .and_then(Value::as_array)
            .and_then(|actions| actions.first())
            .and_then(|a| a.get("action"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(first_action, "c2pa.created");
    }

    #[test]
    fn builder_sign_no_wrapper_validates() {
        // Uses from_keys() directly with NO wrapper to isolate whether wrappers cause mismatch.
        let signer_material = generated_signer_material();
        let manifest_def = minimal_manifest_definition();
        let webp_bytes = minimal_valid_webp_bytes();

        let signer_impl = c2pa::create_signer::from_keys(
            signer_material.cert_pem.as_bytes(),
            signer_material.key_pem.as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .expect("from_keys must succeed with generated conformant certificate chain");

        let mut builder = c2pa::Builder::from_json(&manifest_def.to_string())
            .expect("builder from manifest must succeed");

        let mut src = Cursor::new(webp_bytes.as_slice());
        let mut dst = Cursor::new(Vec::<u8>::new());
        builder
            .sign(&*signer_impl, "image/webp", &mut src, &mut dst)
            .expect("signing with direct from_keys signer must succeed");

        let signed_bytes = dst.into_inner();
        assert!(!signed_bytes.is_empty(), "signed output must not be empty");

        assert_reader_validation_valid(
            &signed_bytes,
            "image/webp",
            "Builder::sign with direct from_keys (no wrapper) must produce a locally verifiable asset",
        );
    }

    #[test]
    fn builder_sign_control_with_generated_chain_validates() {
        let signer_material = generated_signer_material();
        let manifest_def = minimal_manifest_definition();
        let webp_bytes = minimal_valid_webp_bytes();
        let captured_tbs = Arc::new(Mutex::new(Vec::<SniffSnapshot>::new()));

        let signer_impl = c2pa::create_signer::from_keys(
            signer_material.cert_pem.as_bytes(),
            signer_material.key_pem.as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .expect("from_keys must succeed with generated conformant certificate chain");

        let signer_impl = TbsSnifferSigner::new(signer_impl, captured_tbs.clone());

        let mut builder = c2pa::Builder::from_json(&manifest_def.to_string())
            .expect("builder from manifest must succeed");

        let mut src = Cursor::new(webp_bytes.as_slice());
        let mut dst = Cursor::new(Vec::<u8>::new());
        builder
            .sign(&signer_impl, "image/webp", &mut src, &mut dst)
            .expect("signing must succeed");

        let signed_bytes = dst.into_inner();
        assert!(!signed_bytes.is_empty(), "signed output must not be empty");

        let signer_tbs = captured_tbs
            .lock()
            .expect("tbs capture mutex should be usable");
        assert!(!signer_tbs.is_empty(), "TBS sniffer should capture at least one sign input");
        println!("DEBUG_TBS_FIRST_20_HEX: {}", first_bytes_hex(&signer_tbs[0].tbs, 20));
        println!(
            "DEBUG_SIGNER_CAPTURED_PROTECTED_HEADER_SHA: {}",
            signer_tbs[0]
                .protected_header_sha256
                .clone()
                .unwrap_or_else(|| "unavailable".to_string())
        );
        println!(
            "DEBUG_SIGNER_CAPTURED_PROTECTED_HEADER_CANONICAL_SHA: {}",
            signer_tbs[0]
                .protected_header_canonical_sha256
                .clone()
                .unwrap_or_else(|| "unavailable".to_string())
        );
        println!(
            "DEBUG_SIGNER_CAPTURED_PROTECTED_HEADER_KEY_ORDER: {}",
            signer_tbs[0].protected_header_key_order.join(",")
        );
        println!(
            "DEBUG_SIGNER_CAPTURED_PAYLOAD_SHA: {}",
            signer_tbs[0]
                .payload_sha256
                .clone()
                .unwrap_or_else(|| "unavailable".to_string())
        );
        println!(
            "DEBUG_SIGNER_CAPTURED_PAYLOAD_CANONICAL_SHA: {}",
            signer_tbs[0]
                .payload_canonical_sha256
                .clone()
                .unwrap_or_else(|| "unavailable".to_string())
        );

        let mut reader_src = Cursor::new(signed_bytes.as_slice());
        let reader = c2pa::Reader::from_context(verify_context())
            .with_stream("image/webp", &mut reader_src)
            .expect("reader must open signed bytes for signature extraction");
        let manifest = reader
            .active_manifest()
            .expect("active manifest should be present for signature extraction");
        let signature = manifest
            .signature()
            .expect("manifest signature bytes should be present")
            .to_vec();

        println!("DEBUG_SIG_LEN: {}", signature.len());
        println!("DEBUG_SIG_HEX: {}", hex::encode(&signature));

        let manual_math_valid = manual_verify_es256_with_leaf_cert(
            &signer_tbs[0].tbs,
            &signature,
            &signer_material.cert_pem,
        )
        .expect("manual ES256 verification step should run");
        println!("MANUAL_MATH_VERIFY_SUCCESS: {}", manual_math_valid);

        assert_reader_validation_valid(
            &signed_bytes,
            "image/webp",
            "Builder::sign control path must produce a locally verifiable asset",
        );
    }

    #[test]
    fn builder_sign_embeddable_with_generated_chain_validates() {
        let signer_material = generated_signer_material();
        let manifest_def = minimal_manifest_definition();
        let webp_bytes = minimal_valid_webp_bytes();
        let captured_tbs = Arc::new(Mutex::new(Vec::<SniffSnapshot>::new()));
        let signer_impl = c2pa::create_signer::from_keys(
            signer_material.cert_pem.as_bytes(),
            signer_material.key_pem.as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .expect("from_keys must succeed with generated conformant certificate chain");
        let signer_impl = TbsSnifferSigner::new(signer_impl, captured_tbs.clone());

        let context = c2pa::Context::new().with_signer(signer_impl).into_shared();
        let mut builder = c2pa::Builder::from_shared_context(&context)
            .with_definition(manifest_def)
            .expect("builder from shared context must succeed");

        let composed_placeholder = builder
            .placeholder("image/webp")
            .expect("placeholder generation must succeed");
        assert!(!composed_placeholder.is_empty(), "placeholder bytes must not be empty");

        let manifest_pos = 2usize;
        let mut output = Vec::with_capacity(webp_bytes.len() + composed_placeholder.len());
        output.extend_from_slice(&webp_bytes[..manifest_pos]);
        output.extend_from_slice(&composed_placeholder);
        output.extend_from_slice(&webp_bytes[manifest_pos..]);

        let mut output_stream = Cursor::new(output);
        builder
            .set_data_hash_exclusions(vec![HashRange::new(
                manifest_pos as u64,
                composed_placeholder.len() as u64,
            )])
            .expect("placeholder exclusion registration must succeed");
        output_stream
            .seek(SeekFrom::Start(0))
            .expect("placeholder asset rewind must succeed");
        builder
            .update_hash_from_stream("image/webp", &mut output_stream)
            .expect("data hash update must succeed");

        let signed_manifest = builder
            .sign_embeddable("image/webp")
            .expect("embeddable signing must succeed");
        assert!(
            signed_manifest.len() <= composed_placeholder.len(),
            "signed manifest must fit inside the placeholder region"
        );

        output_stream
            .seek(SeekFrom::Start(manifest_pos as u64))
            .expect("placeholder patch seek must succeed");
        output_stream
            .write_all(&signed_manifest)
            .expect("placeholder patch write must succeed");

        let final_asset = output_stream.into_inner();

        let signer_tbs = captured_tbs
            .lock()
            .expect("tbs capture mutex should be usable for embeddable path");
        assert!(
            !signer_tbs.is_empty(),
            "TBS sniffer should capture at least one sign input for embeddable path"
        );

        let mut reader_src = Cursor::new(final_asset.as_slice());
        let reader = c2pa::Reader::from_context(verify_context())
            .with_stream("image/webp", &mut reader_src)
            .expect("reader must open embeddable signed bytes for signature extraction");
        let manifest = reader
            .active_manifest()
            .expect("active manifest should be present for embeddable signature extraction");
        let signature = manifest
            .signature()
            .expect("manifest signature bytes should be present for embeddable path")
            .to_vec();

        println!("EMBED_DEBUG_TBS_FIRST_20_HEX: {}", first_bytes_hex(&signer_tbs[0].tbs, 20));
        println!("EMBED_DEBUG_SIG_LEN: {}", signature.len());
        println!("EMBED_DEBUG_SIG_HEX: {}", hex::encode(&signature));

        let manual_math_valid = manual_verify_es256_with_leaf_cert(
            &signer_tbs[0].tbs,
            &signature,
            &signer_material.cert_pem,
        )
        .expect("manual ES256 verification step should run for embeddable path");
        println!("EMBED_MANUAL_MATH_VERIFY_SUCCESS: {}", manual_math_valid);

        assert_reader_validation_valid(
            &final_asset,
            "image/webp",
            "Builder::sign_embeddable placeholder path must produce a locally verifiable asset",
        );
    }
}
