# Plug-ins

I keep the installed agent local and start with a fixed list of trusted built-ins.

The `tabarc_print.plugins.REGISTRY` is the single declaration point. Each plug-in records its type, capabilities and permissions. Printer backends implement `submit(document, printer, *, dry_run, windows_renderer)`. Google Drive and OneDrive are selected through the same registry and use the previous `CloudGateway` job format.

| Built-in | Role | Permission |
| --- | --- | --- |
| `cups` | Local CUPS queue | Local printer access |
| `windows-sumatra` | Windows local PDF printer | Local printer and executable |
| `folder` | Synchronised folder or local share | Configured folder read/write |
| `google` | Direct Google Drive transport | Account OAuth and app-file access |
| `onedrive` | Direct Microsoft Graph transport | Account OAuth and file access |

A plug-in isn't granted the right to print merely because it can see a queue. The local user chooses a named printer, and cloud receivers use an explicit remote-to-local printer mapping.

## What is not yet available

This is a **built-in plug-in API**, not a third-party plug-in installer. The agent does not scan directories, import external Python entry points or execute arbitrary downloaded extensions. Support for community plug-ins requires isolated worker processes, a reviewed manifest, explicit per-plug-in approval, read/write scopes, time and memory quotas, audited commands and revocation. Plugin updates must never silently expand permissions.

No browser extension, mobile native print service or network-discovery daemon is shipped in this package. Those are separate prospective interface plug-ins.

To add a built-in printer adapter in the source, extend the explicit registry and provide the platform-specific printing implementation. Record the executable and local permissions it needs, and test that unknown plug-in names fail closed. Cloud provider APIs must use provider-specific OAuth with restricted scopes; the transport must never receive the user's local spooler credentials.
