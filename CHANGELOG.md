# Changelog

All notable changes to the **Helucryptic** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.0.14] - 2026-06-08

### Highlights

* **Microphone Noise Reduction**: Real-time microphone background noise reduction with adaptive noise profiling and configurable UI settings.
* **Cloudflare Workers Signaling**: Complete serverless signaling server using Cloudflare Workers Durable Objects with WebSocket Hibernation support as a 1:1 drop-in replacement for `server.py`.
* **Session Token Authentication**: Cryptographic session-token authentication preventing unauthorized username impersonation and channel spoofing.
* **Engine Resilience & Task Tracking**: Dedicated asyncio task tracking preventing garbage collection drops during active WebRTC negotiations, paired with an outbox queue for network drops.

---

### Added

* **Audio & Voice Processing**:
  * Adaptive noise profiling and real-time noise suppression in [tracks/audio.py](tracks/audio.py).
  * Microphone noise reduction toggle and sensitivity controls in Settings and Client UI.
  * Dedicated sound and audio pipeline tests in [tests/test_sounds.py](tests/test_sounds.py).
* **Serverless Signaling Backend**:
  * Cloudflare Worker implementation using Durable Objects in [cloudflare/src/index.js](cloudflare/src/index.js) supporting room isolation, heartbeat pings, and session tokens.
  * Public IP reflection during signaling handshake for enhanced Hub election in group rooms.
* **Security & Authentication**:
  * Session token validation preventing username impersonation in both FastAPI and Cloudflare Worker signaling layers.
  * Pre-Shared Key (PSK) authentication challenge-response validation against live pending nonces.
  * Verified-only access gate mode and corresponding security tests.
  * Rate limiting per IP (20 connections/min) and per client (100 messages/10s).
* **NAT Traversal & Network Discovery**:
  * Cross-platform network and NAT discovery module in [nat_discovery.py](nat_discovery.py).
  * Multi-candidate gateway probing (`.1`, `.254`, `.2`) and VPN gateway fallback support.
  * Consecutive failure threshold logic in [natpmp.py](natpmp.py) (deactivates automatically after 3 failed attempts to avoid log and resource bloat).
* **Reliability & Recovery**:
  * Asynchronous message outbox queue in [outbox.py](outbox.py) to buffer signals during transient network disconnects.
  * In-app "Restart Application" button and unhandled exception auto-recovery mechanism.
* **Code Quality & Tooling**:
  * Centralized design system tokens in [theme/flet_theme.py](theme/flet_theme.py).
  * Modular constants system in [constants/](constants/) (`client_constants.py`, `crypto_constants.py`, `invite_constants.py`, `natpmp_constants.py`, `secure_store_constants.py`, `server_constants.py`).
  * SonarQube static analysis configuration ([sonar-project.properties](sonar-project.properties)) and Ruff rules ([ruff.toml](ruff.toml)).
  * New automated test suites for contrast/accessibility, config, contacts, crypto, paths, secure store, settings, server, and WebRTC engine.

---

### Changed & Improved

* **WebRTC Engine**:
  * Explicit background task tracking in [webrtc_engine.py](webrtc_engine.py) to prevent asyncio GC collection of active connection coroutines.
  * Optimized loop iterations and data-channel buffer management.
  * Modernized clipboard integration across desktop platforms.
* **Cryptography & Storage**:
  * Refactored DPAPI secure store blob handler and timestamp typing.
  * Hardened file size checks and build-time asset verification in [build.py](build.py).
  * Enhanced structured diagnostic logging across crypto and transport modules.

---

### Fixed

* Fixed issue where unreferenced asyncio tasks in WebRTC engine could be prematurely garbage collected during signaling negotiations.
* Resolved potential username collision / hijacking vulnerability on signaling reconnects via session token enforcement.
* Fixed contrast issues on select UI components to meet accessibility standards.
* Fixed potential NAT-PMP infinite retry loops on non-compliant home routers by enforcing failure limits.

---

## [v1.0.13] - 2026-06-07

* Ignore local development tool and editor cache directories in version control.
* Packaging and release build pipeline updates.

---

## [v1.0.6] - 2026-05-20

* Added `flet-desktop` dependency for cross-platform desktop compatibility.
* Fixed packaging build script dependencies.

---

## [v1.0.5] - 2026-05-15

* Initial automated release workflow and desktop standalone binary builds.
