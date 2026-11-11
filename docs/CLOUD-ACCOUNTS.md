# Cloud account configuration

The cloud desktop panel accepts Google desktop OAuth registration details or a
Microsoft application/client ID. Actual OAuth access and refresh tokens are
saved in the **operating-system credential vault**, not token JSON files.

Google uses the limited `drive.file` permission where supported. OneDrive uses
Microsoft Graph delegated `Files.ReadWrite`. These permissions give the app
control over a user-owned print mailbox, not an unrestricted printing server.
Account permissions, consent and compatibility need live verification.

Existing `google-token.json` and `microsoft-msal-cache.json` credentials are
**not** imported or read. Their presence blocks sign-in. Revoke any old grants
before securely handling old files and backing up/rotating credentials.

The Google desktop OAuth registration JSON selected by the user is read once
and imported into the OS credential vault. Application settings store only an
opaque vault reference; OAuth login reads the registration from that vault.
Some desktop registrations include a `client_secret`, which is not a secret
strong enough to authenticate a public installed app. The original user-supplied
JSON and any backups still exist outside the application; remove or rotate those
separately as appropriate. Old file-path settings now fail closed.

An unavailable vault means cloud sign-in is disabled, not a fallback to local
JSON. Existing local-only printing remains independent of cloud sign-in.
