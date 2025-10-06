use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use time::OffsetDateTime;
use tracing::{error, info};
use tracing_subscriber::prelude::*; // registry().with(...)
type HmacSha256 = Hmac<Sha256>;

/* ---------------- app state ---------------- */

#[derive(Clone)]
struct AppState {
    http: Client,
    // config
    ms_key: String,
    ms_region: String,
    ms_endpoint: String,
    tos_version: String,
    // auth
    clients: Arc<DashMap<String, String>>, // client_id -> secret
    // limits
    rate_per_min: u32,
    daily_chars: u32,
    max_text_len: usize,
    // counters (in-memory MVP; swap to Redis later)
    rate: Arc<DashMap<(String, u64), u32>>,     // (client_id, minute_epoch) -> count
    quota: Arc<DashMap<(String, String), u32>>, // (client_id, yyyy-mm-dd) -> chars
}

#[derive(Deserialize, Serialize)]
struct InReq {
    text: String,
    #[serde(default = "auto_str")]
    source: String, // "AUTO" or code
    target: String,
    #[serde(default = "engine_auto")]
    engine: String, // "auto" | "ms"
    #[serde(default)]
    client: Option<ClientMeta>,
}
fn auto_str() -> String { "AUTO".into() }
fn engine_auto() -> String { "auto".into() }

#[derive(Deserialize, Serialize)]
struct ClientMeta {
    app_version: Option<String>,
    os: Option<String>,
}

#[derive(Serialize)]
struct OutResp {
    translation: String,
    engine_used: String,
    detected_source: Option<String>,
    usage: UsageOut,
}
#[derive(Serialize)]
struct UsageOut { chars: usize, remaining_today: i32 }

#[derive(Serialize)]
struct ErrResp { error: ErrBody }
#[derive(Serialize)]
struct ErrBody { code: &'static str, message: String }

/* ---------------- legal text ---------------- */

static LEGAL_TEXT: Lazy<String> = Lazy::new(|| {
    r#"BabelScribe Relay — Terms & Privacy (v1-2025-10-02)

- This service forwards text you send to third-party translation vendors to return translations.
- We do not store your original text, except transiently in memory to process your request.
- We store minimal metadata (timestamp, length, language codes, engine, hashed text) for rate limiting and abuse prevention.
- The service is not for protected health information or other highly sensitive data.
- European users: the controller is the operator of this relay. Processing is necessary to provide the service you request. Vendors may process data outside the EU; details available on request.
- By using the service you grant us a limited license to process your text for translation and to generate usage metrics. You retain all IP in your input and output.
- Abuse, reverse engineering, and key extraction are prohibited.

Type 'I ACCEPT v1-2025-10-02' (or include header X-Accept-Legal: v1-2025-10-02) to proceed.
"#.to_string()
});

/* ---------------- startup ---------------- */

#[tokio::main]
async fn main() {
    // Load .env (Option B)
    let _ = dotenvy::dotenv();

    init_tracing();

    // Auto-provision one HMAC client if missing; print + write credentials json
    if let Some(prov) = ensure_default_hmac_client_and_dump() {
        eprintln!("\n=== First-run credentials (save this for the Windows client) ===\n{}\n", prov.pretty_json);
        if let Err(e) = write_credentials_file(&prov) {
            eprintln!("WARN: could not write credentials file: {}", e);
        } else {
            eprintln!("Wrote credentials file: {}", prov.file_path.display());
        }
    }

    let ms_key = must("AZURE_TRANSLATOR_KEY");
    let ms_region = must("AZURE_TRANSLATOR_REGION");
    let ms_endpoint = env::var("AZURE_TRANSLATOR_ENDPOINT")
        .unwrap_or_else(|_| "https://api.cognitive.microsofttranslator.com".into());

    let clients_raw = must("HMAC_CLIENTS_JSON");
    let tos_version = env::var("LEGAL_TOS_VERSION").unwrap_or_else(|_| "v1-2025-10-02".into());

    let rate_per_min: u32 = env::var("RATE_LIMIT_PER_MINUTE").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let daily_chars: u32 = env::var("DAILY_CHAR_QUOTA").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    let max_text_len: usize = env::var("MAX_TEXT_LEN").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);

    let http = Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .expect("http client");

    let clients = Arc::new(parse_clients_relaxed(&clients_raw));
    info!("Auth: loaded {} HMAC client id(s)", clients.len());

    let state = AppState {
        http,
        ms_key,
        ms_region,
        ms_endpoint,
        tos_version,
        clients,
        rate_per_min,
        daily_chars,
        max_text_len,
        rate: Arc::new(DashMap::new()),
        quota: Arc::new(DashMap::new()),
    };

    info!(
        "Relay starting (ms-first). Limits: {}/min, {}/day, max_len={}",
        rate_per_min, daily_chars, max_text_len
    );

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/tos", get(tos))
        .route("/v1/translate", post(translate))
        .with_state(state);

    let addr: SocketAddr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8787".into()).parse().expect("bind");
    info!("Listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}

fn must(k: &str) -> String {
    env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

/* ---------------- handlers ---------------- */

async fn tos(State(st): State<AppState>) -> impl IntoResponse {
    let body = LEGAL_TEXT.replace("v1-2025-10-02", &st.tos_version);
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}

async fn translate(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InReq>,
) -> Result<Json<OutResp>, (StatusCode, Json<ErrResp>)> {

    // 1) Legal acceptance
    let accept = headers.get("x-accept-legal").and_then(|v| v.to_str().ok());
    if accept != Some(st.tos_version.as_str()) {
        return Err(err(StatusCode::PRECONDITION_REQUIRED, "LEGAL_NOT_ACCEPTED",
                       format!("Include header X-Accept-Legal: {}", st.tos_version)));
    }

    // 2) HMAC auth
    let client_id = hdr(&headers, "x-client-id")?;
    let ts = hdr(&headers, "x-timestamp")?;
    let nonce = hdr(&headers, "x-nonce")?;
    let sig = hdr(&headers, "x-signature")?;
    let secret = st.clients.get(client_id)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "UNKNOWN_CLIENT", "Client id not recognized".into()))?
        .clone();

    // Reject old timestamps (> 5 min)
    let now = now_sec();
    let ts_i: i64 = ts.parse().unwrap_or(0);
    if (now - ts_i).abs() > 300 {
        return Err(err(StatusCode::UNAUTHORIZED, "STALE_REQUEST", "Timestamp too far from server time".into()));
    }

    // Compute expected signature (hash of JSON body string)
    let body_str = serde_json::to_string(&input).unwrap_or_default();
    let body_hash = sha256_hex(body_str.as_bytes());
    let signing_str = format!("POST|/v1/translate|{ts}|{nonce}|{body_hash}");
    let expected = hmac_b64(&secret, signing_str.as_bytes());
    if expected != sig {
        return Err(err(StatusCode::UNAUTHORIZED, "BAD_SIGNATURE", "Signature mismatch".into()));
    }

    // 3) Validation
    if input.text.is_empty() || input.text.len() > st.max_text_len {
        return Err(err(StatusCode::BAD_REQUEST, "BAD_LENGTH",
                       format!("Text must be 1..={} chars", st.max_text_len)));
    }
    if input.target.trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "BAD_TARGET", "Missing target".into()));
    }

    // 4) Limits
    enforce_rate(&st, client_id)?;
    let used_today = add_quota_probe(&st, client_id, input.text.chars().count() as u32)?;
    if used_today > st.daily_chars {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "DAILY_QUOTA_EXCEEDED", "Daily character quota exceeded".into()));
    }

    // 5) MS first
    let (translation, detected) = match ms_translate(&st, &input.text, &input.source, &input.target).await {
        Ok(ok) => ok,
        Err((code, msg)) => {
            error!("MS error {code}: {msg}");
            return Err(err(StatusCode::BAD_GATEWAY, "VENDOR_ERROR", "Translation vendor failed".into()));
        }
    };

    // 6) Log without PII
    let text_hash = sha256_hex(input.text.as_bytes());
    info!("ok client={} engine=ms chars={} hash={} detected={:?}",
          client_id, input.text.chars().count(), &text_hash[..16], detected);

    let remaining = st.daily_chars as i32 - used_today as i32;
    Ok(Json(OutResp {
        translation,
        engine_used: "ms".into(),
        detected_source: detected,
        usage: UsageOut { chars: input.text.chars().count(), remaining_today: remaining },
    }))
}

/* ---------------- vendor: MS ---------------- */

#[derive(Deserialize)]
struct MsItem { translations: Vec<MsTrans> }
#[derive(Deserialize)]
struct MsTrans { text: String /*, to: String (unused)*/ }

async fn ms_translate(
    st: &AppState,
    text: &str,
    source: &str,
    target: &str
) -> Result<(String, Option<String>), (u16, String)> {

    let url = format!("{}/translate", st.ms_endpoint.trim_end_matches('/'));
    let mut params = vec![("api-version","3.0"), ("to", target)];
    if !source.eq_ignore_ascii_case("AUTO") {
        params.push(("from", source));
    }

    let body = serde_json::json!([{ "Text": text }]);

    let resp = st.http.post(&url)
        .query(&params)
        .header("Ocp-Apim-Subscription-Key", &st.ms_key)
        .header("Ocp-Apim-Subscription-Region", &st.ms_region)
        .header("Content-Type", "application/json; charset=utf-8")
        .json(&body)
        .send().await.map_err(|e| (599, e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err((status, body));
    }

    let data: Vec<MsItem> = resp.json().await.map_err(|_| (598, "parse".into()))?;
    let translated = data.get(0)
        .and_then(|i| i.translations.get(0))
        .map(|t| t.text.clone())
        .ok_or_else(|| (598, "empty".into()))?;

    Ok((translated, None))
}

/* ---------------- util ---------------- */

fn err(code: StatusCode, short: &'static str, msg: String) -> (StatusCode, Json<ErrResp>) {
    (code, Json(ErrResp { error: ErrBody { code: short, message: msg } }))
}

fn hdr<'a>(h: &'a HeaderMap, key: &str) -> Result<&'a str, (StatusCode, Json<ErrResp>)> {
    h.get(key).and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "MISSING_HEADER", format!("Missing header: {key}")))
}

fn now_sec() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn day_key() -> String {
    let now = OffsetDateTime::now_utc();
    format!("{:04}-{:02}-{:02}", now.year(), now.month() as u8, now.day())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    tiny_hex::encode(out)
}

fn hmac_b64(secret: &str, data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac");
    mac.update(data);
    STANDARD.encode(mac.finalize().into_bytes())
}

// naive in-memory rate limiter: minute bucket
fn enforce_rate(st: &AppState, client_id: &str) -> Result<(), (StatusCode, Json<ErrResp>)> {
    let minute = now_sec() as u64 / 60;
    let key = (client_id.to_string(), minute);
    let cnt = st.rate.entry(key).and_modify(|c| *c += 1).or_insert(1);
    if *cnt > st.rate_per_min {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT", "Too many requests; slow down".into()));
    }
    Ok(())
}

fn add_quota_probe(st: &AppState, client_id: &str, chars: u32) -> Result<u32, (StatusCode, Json<ErrResp>)> {
    let key = (client_id.to_string(), day_key());
    let total = st.quota.entry(key).and_modify(|c| *c += chars).or_insert(chars);
    Ok(*total)
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().compact().without_time())
        .init();
}

// tiny hex (no extra dep beyond this module)
mod tiny_hex {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let b = bytes.as_ref();
        let mut out = String::with_capacity(b.len() * 2);
        for &x in b {
            out.push(CHARS[(x >> 4) as usize] as char);
            out.push(CHARS[(x & 0x0f) as usize] as char);
        }
        out
    }
}

/* ---------------- relaxed clients parser ---------------- */

fn parse_clients_relaxed(raw: &str) -> DashMap<String, String> {
    use serde_json::Value;

    // Trim + strip possible UTF-8 BOM
    let mut s = raw.trim().to_string();
    if let Some(stripped) = s.strip_prefix('\u{feff}') {
        s = stripped.to_string();
    }

    let dm = DashMap::new();

    // Preferred: strict JSON object {"id":"secret", ...}
    if s.starts_with('{') && s.ends_with('}') {
        match serde_json::from_str::<Value>(&s) {
            Ok(Value::Object(map)) => {
                for (k, v) in map {
                    if let Value::String(secret) = v {
                        dm.insert(k, secret);
                    }
                }
                if !dm.is_empty() {
                    return dm;
                }
            }
            _ => { /* fall through */ }
        }
    }

    // Relaxed: comma-separated pairs "id:secret" or "id=secret"
    for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
        let (id, secret) = if let Some(i) = part.find(':') {
            (&part[..i], &part[i + 1..])
        } else if let Some(i) = part.find('=') {
            (&part[..i], &part[i + 1..])
        } else {
            continue;
        };
        let id = id.trim();
        let secret = secret.trim();
        if !id.is_empty() && !secret.is_empty() {
            dm.insert(id.to_string(), secret.to_string());
        }
    }

    if dm.is_empty() {
        panic!("HMAC_CLIENTS_JSON invalid. Use JSON like {{\"u-...\":\"base64secret\"}} or 'id:secret,id2=secret2'.");
    }
    dm
}

/* ---------------- auto-provision (with console dump + file) ---------------- */

struct Provisioned {
    id: String,
    secret: String,
    relay_url: String,
    tos: String,
    pretty_json: String,
    file_path: PathBuf,
}

/// If HMAC map is missing/empty: generate one user, update `.env`, set process var,
/// print the JSON to console, and write `credentials/<id>.json`.
fn ensure_default_hmac_client_and_dump() -> Option<Provisioned> {
    // If HMAC_CLIENTS_JSON is present and parses to a non-empty map, do nothing.
    if let Ok(raw) = env::var("HMAC_CLIENTS_JSON") {
        if !raw.trim().is_empty() && !parse_clients_relaxed(&raw).is_empty() {
            return None;
        }
    }

    // Generate one user id + secret
    let new_id = format!("u-{}", uuid::Uuid::new_v4().simple());
    let new_secret = random_b64_32();

    let new_line = format!(r#"HMAC_CLIENTS_JSON={{"{id}":"{sec}"}}"#, id=new_id, sec=new_secret);

    // Merge into .env in CWD
    let env_path = locate_env_path();
    if let Err(e) = upsert_hmac_line(&env_path, &new_line) {
        // Fallback: set in-process so this run works.
        env::set_var("HMAC_CLIENTS_JSON", format!(r#"{{"{id}":"{sec}"}}"#, id=new_id, sec=new_secret));
        info!("Auto-provisioned HMAC client (in-process only). Could not write .env: {}", e);
    } else {
        env::set_var("HMAC_CLIENTS_JSON", format!(r#"{{"{id}":"{sec}"}}"#, id=new_id, sec=new_secret));
        info!("Auto-provisioned HMAC client and updated .env with id {}", new_id);
    }

    // Build relay URL for the credentials file
    let relay_url = env::var("RELAY_PUBLIC_URL")
        .or_else(|_| env::var("BIND_ADDR").map(|b| format!("http://{}", b)))
        .unwrap_or_else(|_| "http://127.0.0.1:8787".into());
    let relay_url = if relay_url.starts_with("http://") || relay_url.starts_with("https://") {
        relay_url
    } else {
        format!("http://{}", relay_url)
    };

    let tos = env::var("LEGAL_TOS_VERSION").unwrap_or_else(|_| "v1-2025-10-02".into());
    let pretty_json = serde_json::to_string_pretty(&serde_json::json!({
        "relay_url": relay_url,
        "tos_version": tos,
        "client_id": new_id,
        "client_secret": new_secret,
    })).unwrap();

    // compute file path BEFORE moving new_id
    let file_path = credentials_path_for(&env_path, "credentials", &new_id);

    Some(Provisioned {
        id: new_id,
        secret: new_secret,
        relay_url,
        tos,
        pretty_json,
        file_path,
    })
}

fn write_credentials_file(p: &Provisioned) -> std::io::Result<()> {
    let dir = p.file_path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let obj = serde_json::json!({
        "relay_url": p.relay_url,
        "tos_version": p.tos,
        "client_id": p.id,
        "client_secret": p.secret,
    });
    let s = serde_json::to_string(&obj).unwrap();
    fs::write(&p.file_path, s)
}

fn random_b64_32() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

fn locate_env_path() -> PathBuf {
    // Prefer working dir .env; if not exists, create there.
    let cwd = std::env::current_dir().unwrap_or_else(|_| ".".into());
    cwd.join(".env")
}

fn credentials_path_for(env_path: &Path, dirname: &str, id: &str) -> PathBuf {
    let base = env_path.parent().unwrap_or_else(|| Path::new("."));
    base.join(dirname).join(format!("{id}.json"))
}

fn upsert_hmac_line(env_path: &PathBuf, hmac_line: &str) -> std::io::Result<()> {
    // Read existing (if any)
    let mut content = String::new();
    if let Ok(s) = fs::read_to_string(env_path) {
        content = s;
    }

    let mut lines: Vec<String> = if content.is_empty() {
        Vec::new()
    } else {
        content.replace("\r\n", "\n").split('\n').map(|s| s.to_string()).collect()
    };

    // remove any existing HMAC_CLIENTS_JSON=... lines
    lines.retain(|l| !l.trim_start().starts_with("HMAC_CLIENTS_JSON="));
    // append our new line
    lines.push(hmac_line.to_string());

    let new_content = if lines.is_empty() {
        format!("{hmac_line}\n")
    } else {
        let mut s = lines.join("\n");
        if !s.ends_with('\n') { s.push('\n'); }
        s
    };

    fs::write(env_path, new_content)
}
