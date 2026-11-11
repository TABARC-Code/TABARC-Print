# Encrypted mailbox metadata, v0.13.0

The sender writes two objects to its user-owned cloud/folder inbox. `<jobid>.bin` is the original AES-256-GCM document payload; `<jobid>.job.bin` is an independently encrypted metadata envelope. The receiver checks the metadata authentication and target before downloading the larger PDF ciphertext. After acceptance into the local held queue it publishes `<jobid>.receipt.bin` with an authenticated encrypted receipt. Older `.job.json` and `.json` messages are refused on the supported paths.

## Format

- The opaque job ID is a 128-bit random hexadecimal value; its filename remains visible and is not a credential.
- Manifest prefix `TPM4`, receipt prefix `TPR4`, followed by a 12-byte random nonce and AES-256-GCM ciphertext/tag.
- Each envelope uses HKDF-SHA256 with salt = job ID, length = 32 bytes, and a distinct, versioned info string for `manifest` or `receipt`.
- Authenticated associated data includes the envelope version, category and job ID, binding the content to its filename and purpose.
- Manifest plaintext contains only fields needed for validation and delivery: protocol version, job ID, destination printer ID, timestamp, ciphertext digest, document encryption metadata and optional authorised receiver ID.
- Receipts include the job ID, queue outcome, bounded status message and timestamp. Their content is encrypted at rest and in the cloud transport.
- The encrypted envelope is limited to 8192 bytes; the document is limited to 20 MiB before encryption.

Cloud providers still observe timing, random object identifiers and ciphertext lengths. A compromised shared secret exposes all data encrypted under it and permits forged print jobs. There is not yet independent sender authentication, forward secrecy for these static-key cloud envelopes, a PDF interpreter sandbox, trusted Windows in-memory printing or physical spooler secrecy. Preventing duplicate output when multiple receivers share a cloned identity also requires further work.

No automatic migration of queued readable manifests is offered. Stop workers, finish or deliberately re-submit old work, then update every device. The old cloud provider revision history may still contain readable metadata; account owners must handle that independently.
