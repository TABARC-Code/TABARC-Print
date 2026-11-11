# TABARC Print V1.0.1

Local-first printing with optional user-owned, encrypted Google Drive, OneDrive,
synchronised-folder and experimental Tor v3 onion transports. There is **no
TABARC-hosted print server** and no Chrome extension is required.

**Security update; not yet independently security-audited or production-certified.** The new Tor path
requires an OS credential vault and encrypts both job contents and receipts.
Locally queued PDFs, filenames, printer names, spooler references and
job-history descriptions are AES-256-GCM encrypted at rest. Linux/CUPS print submission uses stdin rather than a temporary
plaintext PDF. Other printing systems may still persist readable copies.

## What is available

| Component | State |
| --- | --- |
| Local PDF queue, hold/release, history and per-printer selection | Implemented and tested locally |
| Local at-rest AES-256-GCM for new queued PDFs and filenames | Implemented and unit-tested |
| Google Drive and OneDrive direct encrypted transports | Implemented; live OAuth untested |
| OS credential-vault storage for pairing keys and OAuth tokens | Implemented; mocked vault tests |
| Encrypted Tor v3 onion-only sender and loopback receiver | Implemented; Tor daemon tests pending |
| Tor client authorisation and ephemeral onion setup | Unix-domain controller added; real Tor test pending |
| Windows PDF output through a fully in-memory trusted renderer | Not available; refuses secure-byte submission |
| Sandboxed PDF rendering and production security audit | Not completed |
| Native Windows / macOS installer verification | Not completed |

## Installation

Python 3.11 or newer is required. Install dependencies in a trusted Python
virtual environment with `pip install .[security,cloud]`. Install and unlock an
OS-supported credential vault: Windows Credential Manager, macOS Keychain or a
supported desktop Secret Service wallet. When the vault is unavailable the
application **refuses** to save pairing keys, OAuth tokens or new local queued
PDFs rather than writing those secrets to ordinary files.

On Linux, install CUPS and make sure the target printer works with the `lp`
command. Start the desktop interface with `tabarc-print-desktop`, or use
`tabarc-print-local printers` and `tabarc-print-local submit --pdf document.pdf
--printer Office --hold`.

Queued documents are encrypted at rest. `tabarc-print-local release --job JOB_ID`
releases a held document and `tabarc-print-local work --once` submits the oldest
queued document to CUPS. Submission to CUPS is **not proof of physical printing**.

## Tor transport

The Tor sender uses SOCKS5 domain-name routing, accepts only checksummed Tor v3
onion addresses and has no DNS or direct TCP fallback. The receiver binds solely
to `127.0.0.1`, requires a signed receiver-targeted encrypted job, and never
automatically repeats a job already claimed. It defaults to simulation until
`--enable-printing` is explicitly selected.

Set up Tor as a separate local service. A private, same-user Unix ControlSocket
can provision an ephemeral onion identity and authorise clients in memory. See
[the Tor security guide](docs/TOR-SECURITY.md). In particular, standard Tor
hidden-service configuration stores private keys in ordinary local files and
is not acceptable for a strict zero-plaintext-key-at-rest policy. Use ephemeral
control-port identities with `DiscardPK`, or a future OS-vault-managed identity.

The Tor executable, client authorisation and secure cross-device pairing have
**not** been exercised end-to-end in this environment. The included tests use a
synthetic local SOCKS5 listener and a local receiver harness.

## Cloud accounts and local credentials

The cloud desktop panel can configure the user's Google Drive and OneDrive
connections and manage encrypted print jobs. New OAuth tokens and pairing keys
are stored only through the operating-system credential vault. Legacy token JSON
and plaintext pairing profiles are **refused**. Revoke their credentials and
remove exposed copies from all backups before setting up a new pair. File
permissions alone are not equivalent to encryption.

The former environment-variable-based gateway secret and plaintext fallback
flags are no longer accepted by the cloud and synchronised-folder commands.
Use a vault reference in `--key-ref`, never a password or raw key in shell
history. No secret-bearing `.env` file is required.

## Important limits

* The legacy HTTP coordinator and connector CLI launchers are disabled. Their
  historical source remains for compatibility tests only. They weren't designed
  to meet the new security requirements.
* A printer's firmware, operating-system spool, drivers, swap and backups may
  still keep readable print material. The Python application cannot guarantee
  deletion from external systems.
* The PDF header check is not a malware or content sanitiser. Do not feed
  untrusted documents to a production printer until sandboxing and further
  security review are completed.
* Tor onion transport, OS vault handling and live printer drivers have not
  undergone an independent security audit or physical-device testing.
* The use of a 256-bit AES key does not imply that the entire Tor protocol
  provides 256-bit security strength. We do not make that claim.

Further details: [security audit](docs/SECURITY.md), [Tor](docs/TOR-SECURITY.md),
[plug-ins](docs/PLUGINS.md), [upgrade notes](UPGRADE.md), and
[reconstruction research](docs/RECONSTRUCTION.md).

## Receiving remote documents in V1.0.1

Incoming Tor, Google Drive, OneDrive and synchronised-folder PDFs are **held locally** rather than printed on arrival. A receiving computer needs a functioning OS credential vault to encrypt this queue. Open the desktop application (`python -m tabarc_print.desktop`) and look for `incoming-*.pdf`. Inspect the sender and destination before using **Release** and the local print controls. Chrome is not required; cloud services are optional.

For Tor, the receiver is required to run behind its user's authenticated private Unix Tor control socket with an authorised client. The onion address is not a password. Tor has not yet been tested against a live daemon. The `--enable-printing` option is now rejected.

Cloud and folder manifests and receipts now use authenticated AES-256-GCM envelopes. This hides printer identifiers, target receiver IDs, message text and job status from cloud storage providers. Random job identifiers and object timing/size remain visible to the storage provider. v0.12.0 readable manifests and receipts are not accepted by the upgraded receivers; stop workers and re-send or inspect old jobs before switching both ends to v0.13.0. Do not silently upgrade an in-flight print job. Windows secure in-memory printing is still not implemented, and operating-system spoolers may keep readable documents. See [docs/SECURITY.md](docs/SECURITY.md) before using confidential material.
