# Security status — V1.0.1

**Development / security preview. Do not treat as production-certified.**

The goal is 256-bit authenticated encryption for print content, never storing
passwords, OAuth access/refresh tokens or pairing secrets in ordinary plaintext
configuration or environment files, and refusing unsafe fallbacks.

## Implemented controls

* Tor v3 `.onion` only; SOCKS5 remote hostname routing; no direct fallback.
* 256-bit AES-GCM encrypted print content and receipts in the Tor transport.
* Authenticated encrypted manifest and receipt envelopes for cloud and synchronised-folder gateways, per-device targeting, 20 MB job limits, limited
  response sizes, replay ledger and fail-closed destination checks.
* New local queue documents, filenames and identifying printer/job metadata encrypted with AES-256-GCM. The key is
  stored in the OS credential vault. New queue data fails closed if the vault is
  missing. Unencrypted legacy PDFs in a queue block startup.
* Linux CUPS accepts bytes over stdin. No additional plaintext PDF is created
  on disk by the local or cloud-folder receiver.
* Pairing keys and OAuth token caches are in the OS vault; older plaintext
  credential files are rejected until handled explicitly.
* Legacy unencrypted cloud jobs are rejected, and legacy HTTP coordinator CLI
  launchers are disabled.
* All supported remote receivers add authenticated documents to an encrypted **held** queue.
  No remote collection operation submits the document to an operating-system spooler.

## Production blockers

* Private same-user Unix ControlSocket can create ephemeral client-authorised Tor v3 services, but no real Tor daemon interoperability test or secure cross-device pairing yet.
* Tor's standard on-disk onion identity and client-auth files conflict with the
  no-plaintext-key rule; use ephemeral Tor control-port credentials instead.
* No PDF parser sandbox / anti-malware controls; the header check is not enough. Release remote jobs only after inspecting their provenance.
* Windows secure in-memory PDF spool submission is not implemented.
* A local OS spooler or printer can persist readable print jobs; external print
  spool configuration, memory access, swap and backups remain outside the agent's
  guarantees.
* No independent security audit, fuzzing of the socket protocol, or live
  multi-machine test has been completed.
* The legacy coordinator classes remain importable for regression tests, and
  should never be embedded by other applications for sensitive documents.
* Google desktop OAuth client JSON is imported to the OS vault; the original file and backups remain outside application control. Provider consent and scopes need real-account validation.

No claim that encryption prevents endpoint compromise, rogue printers or traffic
analysis. The security tests establish specific behaviour, not total security.

## Storage boundaries

The local SQLite database retains job identifiers, timestamps, state names and keyed, pseudonymous deduplication digests in readable form; document contents, printer names and free-form messages are encrypted. A migration rewrites older queue metadata and vacuums the live database. This does not securely erase historical files, WAL or journal remnants, snapshots, backups, SSD blocks or external spool copies. Do not equate at-rest encryption with a fully encrypted operating system.

## Remote intake (v0.13.0)

The normal Tor, cloud API, and synchronised-folder receiver paths now decrypt a document only in memory, authenticate its signed manifest and intended receiving device where specified, and re-encrypt the PDF into the user-owned local queue with state `held`. They do not invoke the printer backend. Each external job receives a keyed reference in SQLite; a repeat is recognised without saving a raw remote identifier or duplicating the held document. Manual release is required before spool submission.

A signed `held` acknowledgement does not assert printing. A sender must distinguish delivery into the queue from submission to the spooler and physical output. Inherited direct-submission routines remain available only through a Python-level explicit compatibility parameter; the supported commands never select them.

**Confidentiality boundary:** Google Drive, OneDrive and synchronised-folder manifests and receipts use independent HKDF-SHA256-derived AES-256-GCM keys for each job and data category. Printer IDs, receiver targeting and status messages are encrypted. The storage provider can still observe opaque random job IDs, object sizes and upload/download timing. An observer with the pairing secret can decrypt the envelopes and impersonate a trusted sender, so independent per-device sender identities remain outstanding. Old readable `.job.json` and receipt `.json` formats are refused on the supported paths, not silently migrated. Tor acknowledgements are also encrypted. Operating-system spoolers and physical printers are outside this at-rest boundary.
