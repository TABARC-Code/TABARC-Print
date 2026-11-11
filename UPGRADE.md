# Upgrade to V1.0.1

Version V1.0.1 retains the v0.13.0 encrypted mailbox format and existing local queue format. Both ends of a cloud print pairing must use the compatible encrypted metadata format.

Stop workers before upgrading. Complete or review in-flight jobs before replacing the software. Follow the v0.13.0 instructions below if upgrading from v0.12.0 or earlier.

**Security status:** This is a security update, not yet independently security-audited or production-certified. Windows in-memory secure print submission, PDF isolation and live transport verification remain outstanding.

---

# Upgrade to v0.13.0

Stop all senders and receivers before upgrading. This release replaces the readable cloud and folder metadata files with encrypted AES-256-GCM envelopes. Both sending and receiving devices must run v0.13.0 before new cloud or folder jobs are sent.

- New manifest suffix: `.job.bin` (previously `.job.json`). New receipt suffix: `.receipt.bin` (previously `.json`). Both contain authenticated ciphertext. PDF payloads still use the existing encrypted `.bin` format.
- **Do not discard in-flight v0.12.0 jobs.** Finish them using the trusted old installation, or review the pending encrypted payload and re-send from the original PDF with the new version. The new receiver refuses the readable metadata format and reports a legacy-format error; it will not silently print these jobs.
- Old receipt files can reveal job status and messages. Back them up securely if necessary, then clear them from the user-owned cloud folder, its version history and synchronised copies according to the storage provider's retention controls. Ordinary deletion does not guarantee secure erasure.
- The existing 256-bit pairing key remains usable with both updated devices. Use the system credential vault; never place keys or OAuth tokens in environment files, scripts or command lines.
- Gateway state directories now require private ownership and mode `0700` on Unix, and the SQLite ledger is restricted to `0600`. Repair pre-existing permissions yourself before restarting.
- Remote collection continues to place documents in a held, encrypted local queue; `held` means accepted by the agent, not printed.

**Security exclusions:** Legacy HTTP coordinator code, direct-print internal compatibility hooks, PDF interpreter sandboxing, Windows in-memory printing, physical spooler retention, live Tor daemon tests and real Google/Microsoft account tests remain outside the verified security boundary. See `docs/SECURITY.md`.

---

# Upgrade to v0.12.0

Stop print workers and take an encrypted, access-controlled backup before upgrading. The cloud and Tor receiving behaviour has changed deliberately: **collecting a remote job no longer sends it to the printer**.

- Remote jobs arrive in the local encrypted queue as **held**. Open the TABARC Print desktop window, inspect the job, then explicitly release it. A released job can be submitted by the local worker or by selecting **Print selected**.
- On a user-operated cloud receiver, use the normal local queue state directory. The desktop cloud panel automatically targets the current desktop queue. The direct cloud and Tor CLI receivers use the user's default local queue unless a documented explicit override is supplied.
- A signed `held` receipt means the receiving agent has accepted a document into its encrypted local queue. It does **not** indicate spooler submission or printed paper.
- Remote receivers require an unlocked operating-system credential vault. They will fail closed without one, rather than create a plaintext key file.
- A sealed queue now refuses newly inserted readable metadata. Databases from earlier versions without a seal marker can undergo a **single** legacy metadata migration, which does not securely erase backups or historical disk blocks.
- The Tor `--enable-printing` receiver switch is retired and rejected. There is no equivalent auto-print option in the supported CLI.
- Previous cloud and Tor job identities can be retained, but a remote sender must use the same paired encryption key. Re-pair deliberately if the old key was exposed.

Windows native in-memory printing and actual Tor daemon interoperability have not been verified. Do not use this build for sensitive unattended printing or expose any legacy HTTP coordinator to the internet.

---

# Upgrade to v0.11.0

This release intentionally breaks several older, insecure interfaces.

1. Stop all background print workers before updating.
2. Existing **plaintext** queued PDFs from earlier versions are not automatically
   migrated. The new queue refuses to start if it finds `.pdf` files in its
   document queue. Re-submit from trusted originals after securely disposing of
   older copies, including backups and spool history. Ordinary deletion cannot
   guarantee recovery resistance on SSDs.
3. Pairing keys now require an OS credential vault. Plaintext profiles are
   refused, not automatically rewritten. Re-pair devices through a protected
   channel. Delete or revoke compromised old keys and tokens.
4. Cloud OAuth token caches named `google-token.json` and
   `microsoft-msal-cache.json` are no longer used. Revoke provider grants and
   remove old token files and backups before signing in again.
5. Gateway and cloud CLI commands now use `--key-ref`, not
   `TABARC_GATEWAY_SECRET`. Legacy plaintext job switches are removed.
6. Legacy HTTP coordinator and connector CLI launchers are disabled. Use the
   standalone local queue or encrypted transports.
7. Windows secure-byte submission is not implemented. Do not attempt to
   bypass it by saving decrypted temporary PDFs.
8. Tor direct printing is experimental. Read `docs/TOR-SECURITY.md` before using
   `tabarc-print-tor`; default reception is simulation, not spool submission.

Make an encrypted backup of any old installation before upgrading, but do not
retain plaintext credentials beyond the time needed for a controlled migration.

## v0.11.0 changes

- Local queue metadata from older versions is encrypted on first opening of the queue, then SQLite VACUUM runs. An OS vault must be available. Legacy disk images and backups cannot be made confidential by this migration.
- The Google desktop OAuth registration is imported into the vault when account settings are saved. Older saved file-path configurations are refused until explicitly re-imported. Handle the original registration JSON and backup copies separately.
- Tor printing now requires a private same-user Unix ControlSocket and at least one explicit v3 client public key. Windows automated Tor control is not yet available.
- Existing private keys stored on disk by a separately managed Tor service are not automatically removed by this upgrade. Use an independent key-rotation and disposal procedure.
