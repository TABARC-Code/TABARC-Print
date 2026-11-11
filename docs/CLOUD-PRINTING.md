# Optional encrypted cloud printing

Google Drive, OneDrive and synchronised folders are optional user-owned
transports. No service operated by TABARC-Code is involved. The sender uploads
AES-256-GCM encrypted PDF ciphertext and an authenticated job manifest; the
receiver decrypts in memory, checks printer and device identity, and submits to
CUPS through stdin on supported Linux installations. A signed status receipt
records spooler submission, not physical output.

The cloud desktop panel provides explicit send, status and manual collection.
A receiving account is never polled automatically merely by opening the GUI.
Tokens and pairing keys are stored only in an approved OS credential vault.
Missing vaults, legacy plaintext profiles and token caches fail closed.

The independent `tabarc-print-cloud` and `tabarc-print-gateway` CLIs require a
`--key-ref` returned by an OS vault, not a raw key or environment secret.
Plaintext legacy job compatibility is disabled. Secure cross-device pairing
is not yet automated; exchange keys only over an independently protected
channel, never through chat, shell history or text files.

**Limits:** live provider accounts are untested; platform credential APIs still
need verification; printer firmware/OS spoolers can store readable documents.
Windows secure in-memory submission is disabled, and PDF rendering is not
sandboxed. See [security limits](SECURITY.md) and [Tor](TOR-SECURITY.md).
