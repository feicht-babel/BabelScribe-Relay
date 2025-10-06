# BabelScribe Relay

BabelScribe Relay is a secure Rust/Axum-based microservice that hides Azure/DeepL translation API keys behind an authenticated relay.  
It enforces per-user HMAC authentication, rate limits, and daily quotas, so testers never see or misuse your vendor credentials.

---

## Features

- **Key protection** – Azure & DeepL keys stay server-side.
- **Per-user credentials** – each tester has a unique client ID + secret.
- **Rate limiting** – requests capped per minute/day.
- **Legal acceptance** – requests must include a `X-Accept-Legal` header.
- **Lightweight** – runs on a small VM or Docker container (e.g. Render Starter plan).

---

## Local Development

### Prerequisites
- Rust (1.72+ recommended)
- Cargo
- PowerShell (for user credential script)

### Run
```sh
cargo run
