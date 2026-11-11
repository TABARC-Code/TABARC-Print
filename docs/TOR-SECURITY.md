# Tor print transport: experimental security profile

This module carries encrypted print jobs through **user-operated Tor v3 onion services**.
It does not host a central server and does not use Tor exit nodes. The print receiver
accepts traffic only on `127.0.0.1`, for Tor to forward to it. Sending devices make
outbound SOCKS5 connections to `127.0.0.1` and pass the full `.onion` hostname to Tor.
Direct TCP, DNS resolution, HTTP fallback and clearnet destinations are not supported.

## Cryptography and authorisation

* PDF contents use AES-256-GCM, with a fresh nonce and an HKDF-derived 256-bit key.
* Manifests are authenticated and bound to the exact receiving device, print queue,
  job ID and document digest. Signed manifests cannot be switched to plaintext.
* Responses are AES-256-GCM encrypted and signed. Status means submission to a
  spooler, **not proof of a physical printout**.
* Receiver maintains a durable job ledger and never automatically repeats a claimed
  job, even when the submission acknowledgement is lost.
* The random 256-bit shared pairing secret must live in an operating-system vault.
  The command interface accepts **only a vault reference**, not secret values in
  command arguments, environment variables, configuration or text files.
* Tor service **MUST** have version 3 client authorisation enabled, in addition to
  the application's own authentication. An onion address alone does not enforce
  access control. A publicly accessible onion service invites unwanted traffic.
* Only pre-approved printer IDs may be targeted. The receiver always queues
  documents on hold; there is no automatic remote print option.

## Operational outline

1. Install Tor as a local user service and connect it to a local SOCKS5 listener.
2. Install and unlock an OS-backed credential vault on **both** devices.
3. Create a random key with `tabarc-print-tor create-key`. Only its local vault
   reference is displayed. Secure pairing/transfer to another vault is **not yet
   automated**. Do not paste a pairing key in shell history, chat or plain files.
4. Configure an ephemeral Tor v3 onion service with `ADD_ONION NEW:ED25519-V3
   Flags=DiscardPK`, mapped to `127.0.0.1:8787`, and Tor v3 client authorisation
   (`ClientAuthV3`). Manage the control connection through local authenticated IPC.
   Standard `HiddenServiceDir` configuration writes unencrypted onion identity keys
   on disk and does **not** satisfy a zero-plaintext-key-at-rest policy.
5. On the sending device, provision Tor client authorisation with
   `ONION_CLIENT_AUTH_ADD` without `Flags=Permanent` to keep that credential
   ephemeral. The receiving and sending commands can now use the restricted Unix ControlSocket integration; live Tor verification remains outstanding. A Tor restart requires provisioning again.
6. Start `tabarc-print-tor receive --key-ref <VAULT_REF> --printer home=Office`.
   Received jobs are stored in the encrypted local queue on hold; the
   `--enable-printing` option is deliberately refused. A separate hardened PDF rendering sandbox
   must be added before accepting untrusted documents in production.
7. On the sender, use `tabarc-print-tor send --key-ref <LOCAL_REF>
   --onion <V3_ONION> --receiver-id <DEVICE_ID> --printer home --pdf document.pdf`.

The placeholder names here are not passwords or usable credentials.

## Limits that block a production security claim

* Live Tor integration, onion creation, client authorisation and device-pairing UX
  have **not** been tested with a real Tor daemon. The current tests use mock SOCKS5
  and local sockets.
* OS printing subsystems, print drivers and printers may persist **plaintext print
  jobs** in their own spool or device memory. Tor's transport encryption cannot
  prevent that. CUPS is handed PDF bytes by stdin; TABARC Print's Tor receiver
  does not create a temporary plaintext PDF file.
* The legacy HTTP coordinator and agent command-line launchers are disabled.
  Their historical classes remain for regression tests only and are unsupported
  for confidential documents; they do not meet this release's storage policy.
* Tor's standard onion and client-auth key files are plaintext at rest even with
  restrictive permissions. Only ephemeral control-port identities and a properly
  configured OS vault are compatible with the stated key-storage policy. A system
  compromise can still expose secrets while in active memory.
* Sending a signed encrypted job does not prevent traffic-analysis correlation,
  endpoint compromise, or someone with physical access reading printed paper.
* Windows in-memory Tor spool submission is deliberately disabled; secure Windows
  rendering and spooling require additional native work.
* The original application uses 256-bit AES keys for documents. This does not
  imply **256-bit security strength** for Tor's complete protocol or its public-key
  authentication. That stronger assertion would be technically false.

This is security development material, not a reviewed production release.

## User-owned ephemeral controller (v0.11.0)

On Linux or another supported Unix system, run Tor under the **same user** as
TABARC Print. Configure an authenticated-by-filesystem Unix `ControlSocket`,
owned by that user with mode 0600 inside a user-owned directory of mode 0700.
Do **not** enable an unauthenticated TCP `ControlPort`. TABARC Print intentionally
requires Tor to advertise the `NULL` authentication method **only over this
private Unix-domain socket**. It rejects the TCP control interface and
separate-user system daemon controls. Tor configuration still needs manual
system-level validation.

Create a Tor client authorisation identity on the sending computer:

```shell
 tabarc-print-tor new-client-auth
```

The command returns an OS-vault reference and a **public** 52-character X25519
key. Exchange the public key with the receiving owner through an independently
authenticated channel. Keep the private reference local. The actual key remains
in the OS vault.

Start the receiving agent with `--control-socket` and one or more
`--client-public` keys. It requests `ADD_ONION NEW:ED25519-V3
Flags=DiscardPK,V3Auth`, tied to the current controller connection. Tor does
not export the onion private key. The service expires when that connection
closes, and its address changes on restart. There is no permanent key file.

On the sending device, add `--control-socket` and `--client-auth-ref` to the
existing `send` command. The client authorisation is loaded from the vault
and registered as a **non-permanent** Tor credential before sending the
AES-256-GCM encrypted document. This requires a Tor version supporting v3
client authorisation through the control protocol.

If the controller cannot authenticate to the OS-owned socket or a registered
client public key is missing, physical printing cannot be enabled. No
passwords, pairing secrets or onion private keys are accepted in the Tor CLI
arguments. The app still cannot guarantee what the separately installed
Tor daemon or OS print spooler writes to disk.

## v0.12.0 receiving workflow

The receiver accepts a signed, device-targeted and encrypted PDF and puts it into the user's normal local encrypted queue. It returns a separately encrypted receipt with the state `held`. The user must approve the document locally before release. `--enable-printing` is no longer supported. An authenticated delivery is not evidence that the PDF is harmless: the PDF interpreter and physical printer are outside the Tor transport's cryptographic boundary.
