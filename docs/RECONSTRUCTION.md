# Engineering notes: studying existing print systems

This project is built from an independent specification of how printing systems behave. I have not copied code from the reference projects into TABARC Print. Printer APIs and subprocess contracts remain their own standard interfaces.

## What I inspected

| Reference | Evidence | Observation | What I used | Confidence |
| --- | --- | --- | --- | --- |
| OpenPrinting CUPS | [Design description](https://openprinting.github.io/cups/doc/spec-design.html) and [backend specification](https://openprinting.github.io/cups/doc/api-filter.html) | A scheduler accepts jobs, filters convert documents, and a backend delivers printer data | Keep local queue and printer-specific backend separate | Observed documentation |
| QZ Tray | [`PrintSocketServer.java`](https://github.com/qzind/tray/blob/master/src/qz/ws/PrintSocketServer.java), [`PrintSocketClient.java`](https://github.com/qzind/tray/blob/master/src/qz/ws/PrintSocketClient.java), [`PrintServiceMatcher.java`](https://github.com/qzind/tray/blob/master/src/qz/printer/PrintServiceMatcher.java) | A local WebSocket service receives requests, checks signatures/permissions and delegates operations; printer lookup has its own component | Keep browser integration optional and limit access at the local boundary | Observed source |
| SavaPage | [Workflow documentation](https://docs.savapage.org/docs/01-intro/01-03.html) and [spool path](https://wiki.savapage.org/technote/ppd/performance) | Work can be held in a virtual queue before a person releases it to a physical printer | Add explicit held and released local job states | Observed documentation |
| Barrier-X | [`WinLocalPipe.cpp`](https://github.com/TABARC-Code/barrier-x/blob/master/src/lib/ipc/WinLocalPipe.cpp) and [`IpcMessageReader.cpp`](https://github.com/TABARC-Code/barrier-x/blob/master/src/lib/ipc/IpcMessageReader.cpp) | Local application and service communication checks caller identity and bounds incoming frames | Use the same security goals for a future desktop UI, without importing its keyboard-sharing engine | Observed source |
| PrintRelay | [`client.go`](https://github.com/schappim/print-relay/blob/main/client/client.go), [`server.go`](https://github.com/schappim/print-relay/blob/main/cloudserver/server.go), [`LICENSE`](https://github.com/schappim/print-relay/blob/main/LICENSE) | An agent receives jobs from a WebSocket coordinator; the licence restricts competing hosted products | No imported code or dependency. The architecture is unsuitable for our no-hosted-server default | Observed source and licence |

Repo tree identities at inspection: QZ Tray `e2b49db530d940b1cf586dec4e19bcc1f78d9198`; OpenPrinting CUPS `e545a961ef637dc4cb946ede17dc42516a4f8c3d`. These identify trees, not published release binaries or runtime observations. SavaPage's current documentation was used for the workflow rather than inferring behaviour from an older repository snapshot.

## Reconstructed behaviour, version 0.6.0

The independent local sequence is:

1. A user submits a PDF through the local command line, optionally holding it for later.
2. The input is opened as a regular file without following the final symlink on platforms supporting `O_NOFOLLOW`, bounded to 20 MiB and checked for its PDF header.
3. A private copy is written into local storage. Its SHA-256 is recorded in SQLite together with the job, and a queue event is committed.
4. A release operation changes a held job into a queued job. Neither a held job nor a previously claimed job may be printed by a worker.
5. A worker commits its `claimed` event before calling CUPS or the Windows PDF backend. It checks the stored document digest before submitting it.
6. If CUPS returns a recognisable request reference, that reference is stored with the durable `submitted` event. This means the spooler accepted the job, **not** that paper emerged.
7. A crash or unknown submission outcome is not automatically retried. An operator must inspect the spooler before deciding what to do with an uncertain job.

Existing cloud gateways remain separate and optional. Local printing has no Google, Microsoft or browser requirement. A remote cloud receiver still needs a running local agent with the relevant cloud credentials.

## Security findings and boundaries

- The reference QZ Tray socket server contains a maximum message constant set to `Integer.MAX_VALUE` in the inspected source. We will use bounded local messages rather than copying that limit. QZ Tray has other protections; this finding alone does not establish a practical exploit.
- The inspected PrintRelay server accepts arbitrary WebSocket origins through `CheckOrigin`, and its client has an unrestricted `io.ReadAll` when fetching remote job content. Arbitrary remote URLs also need SSRF controls. None of this code is imported.
- PDF header checks are only coarse input checks. They are **not** PDF sanitisation, parsing validation or a sandbox. The installed OS print renderer can still have vulnerabilities.
- Local credentials, printers and job history remain on the user's machine. The central coordinator is optional legacy functionality, and should not be exposed directly to the internet.
- Third-party executable plug-ins remain disabled. A manifest alone does not sandbox a plug-in. Separate processes, explicit permissions, capability checking and revocation need to be implemented before community plug-ins are enabled.
- File-descriptor checks are stronger on platforms with `O_NOFOLLOW`. Windows file-system reparse-point and hardlink safety still need native checks before claiming full parity.
- Print job status cannot guarantee a physical printout. A future IPP monitor may report spooler completion, but even that needs careful interpretation for each printer.

## Verification

The version 0.5.0 source package was inspected first. SHA-256: `e4299b0349c7ee31d50b637dab65e006f09a45d41d0ce1b382fb41879c0db3e8`.

For v0.6.0, the `tests/test_v06.py` suite covers hold/release, cancelled held jobs, digest mismatches, stored document symlinks, CUPS request references, lost acknowledgements, history guardrails, SQLite migration, concurrent workers and command-line held submission.

These tests simulate print devices and remote cloud providers. No printer has physically printed, no real Google or Microsoft account has been authenticated, and no Windows installation has been exercised during this investigation.

## Licensing

CUPS uses Apache-2.0 in the inspected current repository, QZ Tray documents LGPL-2.1 for its main application source, Barrier-X GPLv2 with an OpenSSL exception, and SavaPage AGPLv3. PrintRelay's licence includes a non-competition restriction. Independent work here uses system interfaces and behavioural observations. Copying protected source or packaging original binaries would require a separate dependency and licensing review.
