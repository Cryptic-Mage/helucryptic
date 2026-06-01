# Helucryptic Feature Specification

This spec prioritizes features that improve privacy, reliability, and smooth performance on old PCs. Features should prefer low CPU, low memory, bounded queues, and simple UI over visual polish that costs runtime resources.

## Performance Profiles

Goal: let users choose how hard media features can push their machine.

Profiles:
- Old PC: screen share max 854x480, 5 FPS, JPEG quality 45, video tile render max 5 FPS.
- Balanced: screen share max 1280x720, 10 FPS, JPEG quality 55, video tile render max 10 FPS.
- Quality: screen share max 1280x720 or 1920x1080, 15 FPS, JPEG quality 70, video tile render max 15 FPS.

Acceptance criteria:
- Profile can be changed in Settings without editing `.env`.
- New calls and screen shares use the selected profile.
- Invalid environment values are clamped to safe ranges.
- Existing low-perf env variables remain supported for packaged builds.

## Connection Diagnostics

Goal: make failed calls understandable without requiring logs.

UI should show:
- Signaling status: idle, connecting, connected, disconnected.
- Peer connection state and ICE state.
- Whether TURN is configured.
- Last connection error.
- Active peers in room.

Acceptance criteria:
- Diagnostics panel is read-only and cheap to update.
- No passwords, tokens, private keys, SDP blobs, or ICE candidates are displayed by default.
- A "Copy safe diagnostics" action redacts sensitive values.

## TURN Configuration

Goal: make connections work behind strict NATs.

Settings fields:
- TURN URL
- TURN username
- TURN password
- Test TURN configuration button

Acceptance criteria:
- Empty TURN config keeps current STUN-only behavior.
- TURN credentials are not printed in logs.
- Invalid TURN URLs show a clear validation error.
- Config can be saved locally and loaded on next startup.

## Contact Verification QR

Goal: make fingerprint verification easier and safer.

Behavior:
- Each user can show a QR code containing username, X25519 public key, Ed25519 public key, and fingerprint.
- Users can scan/import a contact verification payload.
- If a verified contact key changes, verification is removed and a warning is shown.

Acceptance criteria:
- QR payload contains only public identity data.
- Scanning a QR code never auto-verifies a contact without user confirmation.
- Existing manual fingerprint view remains available.

## File Transfer Controls

Goal: keep large file transfers stable on weak hardware and poor networks.

Features:
- Cancel outgoing transfer.
- Reject or accept incoming file before receiving if size is above a user-configurable threshold.
- Show sent/received bytes and percentage.
- Retry failed transfer from start.

Acceptance criteria:
- Sender streams from disk and never loads the whole file into memory.
- DataChannel backpressure is respected.
- Cancel closes the current transfer state on both sender and receiver.
- File integrity remains SHA-256 checked.

## Local History Search

Goal: quickly find messages without loading huge conversations.

Behavior:
- Search current contact or room.
- Results load in pages.
- Search runs against encrypted-at-rest history by decrypting only bounded result windows, or via an optional local FTS index if plaintext indexing is explicitly enabled.

Acceptance criteria:
- Default mode does not store plaintext search indexes.
- UI remains responsive during search.
- Search has a clear empty state and cancel path.

## Encrypted Profile Backup

Goal: protect identity keys during export.

Backup includes:
- Keys
- Contacts
- Settings
- Optional encrypted history database

Security:
- Backup is encrypted with a passphrase-derived key.
- Use a memory-hard KDF where practical, otherwise PBKDF2 with high iteration count.
- Never export plaintext keys unless user explicitly chooses an advanced unsafe option.

Acceptance criteria:
- Import validates backup format before replacing local files.
- Existing keys are backed up before overwrite.
- Failed import leaves current profile intact.

## Verified-Only Mode

Goal: reduce impersonation risk.

Behavior:
- When enabled, chat/file/call actions are blocked for unverified contacts.
- Room participants show verified or unverified state.
- User can temporarily allow an unverified contact for the current session.

Acceptance criteria:
- Default remains permissive for first-run usability.
- Blocking message explains how to verify.
- Key-change warnings always override temporary allowance.

## Portable Mode

Goal: support USB/offline use and easy migration.

Behavior:
- If a `portable.flag` file exists beside the executable/source, data is stored in a local `data/` folder instead of `~/.helucryptic`.

Acceptance criteria:
- No absolute user path is required.
- Existing non-portable data is not moved automatically.
- UI clearly shows where data is stored.

## Emergency Wipe

Goal: let users quickly remove local sensitive data.

Behavior:
- Wipes local history, contacts, settings, and identity keys after confirmation.
- Requires typing a confirmation phrase.
- Closes active connections before wiping.

Acceptance criteria:
- Wipe does not touch unrelated files.
- App restarts or returns to first-run state after wipe.
- Confirmation text clearly states that contacts will need to re-verify.

