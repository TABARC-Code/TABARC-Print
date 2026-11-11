# Held remote print intake

The Tor, cloud and folder connectors no longer invoke printer drivers when receiving documents.

## Data flow

1. The sender encrypts a PDF with AES-256-GCM and authenticates a manifest.
2. The receiving connector checks its permitted printer mapping, authentication, expiration, size limit and target receiver where supplied.
3. The PDF is decrypted in process memory, then encrypted into the local SQLite-backed queue's `documents/<job>.bin` file.
4. The local queue records `held` and a keyed deduplication reference. Only non-secret job states and identifiers are kept readable in SQLite.
5. The receiver sends a signed `held` receipt, which is **not** confirmation of spooler submission.
6. The desktop interface shows the held job. Release is a separate local operation; a worker only claims `queued` jobs.

## Recovery and limits

The queue's HMAC-based external reference prevents the same remote job from creating a second local job even when a receiver loses its own processed ledger between queue persistence and receipt publication. Reusing a remote reference with different PDF bytes or printer choice is rejected.

Tor connection authentication and mailbox encryption are not substitutes for PDF inspection. The header check only establishes a `%PDF-` prefix. Printer firmware, driver rendering, OS spoolers, memory, swap and backups are not under the queue's end-to-end encryption control. Cross-device collisions can still occur if two separate receiving computers are deliberately configured with the same receiver identity and pairing key. The cloud mailbox manifest and folder receipts expose limited metadata: they are signed, not fully encrypted.

The OS credential vault must be configured and unlocked. No fallback to plaintext key files is offered. Historical plaintext queues cannot be considered erased merely because SQLite migration completed.
