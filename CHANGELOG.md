# V1.0.1 - 11 November 2026

- I updated the application and package version to V1.0.1.
- I aligned the package metadata with the version reported by the application.
- I retained the encrypted print queue, held remote intake and encrypted cloud metadata.
- Security fixes and updates. Not yet independently security-audited or production-certified.

# v0.13.0 - 11 November 2026

- I encrypt cloud and synchronised-folder manifests and receipts with per-job AES-256-GCM keys. The remote storage provider no longer sees printer names, targeted receiver IDs, state or status messages in these objects.
- I reject the old readable metadata formats instead of silently accepting them. Devices have to upgrade together, and outstanding jobs need a deliberate handover.
- I require private Unix gateway state directories and restrict the local replay ledger to mode 0600.
- I tighten document reads to regular files and refuse symlinks; opening a named pipe must not block the worker.
- I add tests for metadata tampering, wrong keys, cross-type substitution, legacy-format rejection and the cloud/folder round trips.
- I haven't claimed that the application or the host spooler is fully secure. PDF sandboxing and real printer/transport validation still need work.

# v0.12.0 - 10 November 2026

- I route incoming Tor, Drive, OneDrive and synchronised-folder documents into an encrypted local queue on hold. Collection cannot submit to a printer by default.
- I keep cloud reception separate from local release and spool submission. The desktop reads the same queue, including remote jobs.
- I add source-bound, keyed remote job references to prevent duplicate queued documents after a lost receipt or partial crash. Changed content under the same reference is rejected.
- I serialise first-run local vault-key creation across threads and processes, rather than risking mismatched encryption keys.
- I refuse readable metadata inserted into a database that has already been sealed. First upgrade from an older database remains a controlled one-time migration.
- I preserve the existing encrypted transport, device targeting and signed receipts, and acknowledge accepted remote jobs as `held`, not `printed`.
- I keep old direct-print paths behind an explicit internal compatibility option; the desktop and supported CLI receivers do not enable it.
- Physical printing, a real Tor daemon, Windows in-memory printing, PDF sandboxing and independent security review remain outstanding.

# v0.11.0 - 10 November 2026

- Encrypt local queue printer names, spool references, messages and event descriptions with AES-256-GCM.
- Migrate historical queue metadata into authenticated ciphertext and vacuum the live SQLite database.
- Import Google desktop OAuth client registration into the OS vault; reject legacy registration-file settings.
- Add user-owned Unix Tor ControlSocket integration for ephemeral onion services with required v3 client authorisation.
- Generate and store Tor X25519 client private keys in the OS vault, exposing public keys only.
- Cap concurrent Tor receiver sessions, enforce short frames and preserve replay protection.
- Keep Windows in-memory printing, real Tor interoperability, physical printer verification and PDF sandboxing as open blockers.

# Changelog

## v0.10.0

- I added optional, onion-only Tor printing with receiver targeting, encrypted receipts and replay checks.
- I moved pairing secrets and OAuth token caches to the OS credential vault. An unavailable vault now blocks sensitive operations.
- I encrypt local queued PDFs and original filenames using AES-256-GCM.
- I pass decrypted PDFs directly to CUPS through standard input on Linux, without writing another temporary PDF.
- I reject plaintext cloud jobs and disabled the old HTTP coordinator and agent launchers.
- I kept local printing independent of Chrome and cloud accounts.
- Real Tor daemon, keychain, Windows printing and physical-printer validation remain open.

## v0.9.0

- Added explicit encrypted cloud send and receive controls in the desktop interface.
- Added private per-provider pairing profiles and remote printer mappings.
- Added manual collection and signed job-status checks without background polling.
- Added regression coverage for pairing, permission checks, incorrect keys and encrypted transfers.
- Retained all local printing, account setup and existing CLI interfaces.

## 0.8.0

- Added desktop configuration and sign-in for user-owned Google Drive and OneDrive accounts.
- Kept OAuth tokens in private provider caches, separate from public app configuration.
- Added explicit local token removal and honest unverified-session status.
- Added desktop selection and storage of a trusted Windows PDF renderer.
- Added Windows user-mode build, installer and optional logon-worker scripts.
- Added account, path-validation and settings regression tests.
- Preserved the local PDF queue, existing cloud gateways and opt-in worker behaviour.
- Windows binaries, Windows printout and live provider sign-in remain unverified.

## 0.7.0

- Added a Tk desktop control panel for local printers, held jobs, cancellation, job histories and explicit print submission.
- Added status-aware actions with no unattended printing unless the user configures a background worker.
- Added a guarded, per-user Linux systemd unit generator and installer, never started automatically.
- Added desktop-controller and service tests plus a graphical smoke check.
- Kept the existing queues and encrypted optional cloud gateways unchanged.

## v0.6.0

- I added a hold/release workflow for local documents and kept held jobs out of the worker queue.
- I record job transitions in a private SQLite event history.
- I store CUPS spooler request references separately from physical print completion.
- I check the queued document's SHA-256 before printing and reject symlinked documents.
- I added a forward-only migration for existing v0.5.0 local databases.
- I added command-line actions for holding, releasing and inspecting individual jobs.
- I added source-backed engineering notes in `docs/RECONSTRUCTION.md`.

# Changes

## v0.5.0

- I add a standalone user-owned PDF queue that works without Chrome, a cloud account or a network service.
- I provide local printer discovery and commands for queueing, submission, status, cancellation and interrupted claims.
- I distinguish dry-run simulations from actual operating-system submissions.
- I declare the supported printer and cloud transports through a fixed plug-in registry, rather than loading unapproved external code.
- I keep the existing Google Drive, OneDrive and synchronised-folder gateways, including encrypted job payloads and persistent delivery records.
- I add local queue and plug-in tests alongside the previous test suite.

## v0.4.0

- Added separate user and connector bearer credentials with SHA256 digests in a private access file.
- Added per-printer access and user-specific job history to the local coordinator.
- Prevented agent credential reuse for another connector or printer registration.
- Changed expired leases from automatic requeue to uncertain status.
- Added owner-only cancellation of queued/uncertain jobs and browser controls.
- Tightened local coordinator data and database permissions; migrated the old SQLite schema.
- Added installable command-line entry points and separate coordinator access tests.

## v0.3.0

- Added authenticated document encryption for direct and synchronised cloud gateways.
- Added opt-in compatibility for older unencrypted print requests.
- Added Windows PDF printing through a configured SumatraPDF executable.
- Added a durable connector ledger with an `uncertain` outcome for interrupted submissions.
- Added encrypted job, transport tampering, Windows command and lease-retry tests.

## v0.2.0

- Added direct Google Drive and Microsoft OneDrive transports with delegated authentication.

## v0.1.0

- Added a local coordinator, Linux/CUPS connector and signed synchronised-folder gateway.

## 0.10.0 — security work and experimental Tor transport

- Added a Tor v3 onion-only transport with encrypted targeted jobs and encrypted receipts.
- The receiver listens on loopback, with persistent duplicate-claim records and fixed size limits.
- The Tor sender uses SOCKS5 domain addressing and refuses clearnet destinations.
- Pairing profiles and cloud token caches now require the operating-system credential vault.
- Legacy plaintext caches and pairing profiles are rejected rather than silently reused.
- Removed raw pairing-key clipboard export and direct-cloud CLI plaintext fallback switches.
- The Tor receiver now defaults to simulated submission until explicitly enabled.
- Physical printing, Tor client-authorisation provisioning and remaining plaintext spool paths still need work.
