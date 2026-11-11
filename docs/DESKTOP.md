# Desktop control panel

I keep local printers at the centre of the application. No account or hosted server is required for the desktop panel.

## Starting the panel

Install the wheel using Python 3.11 or newer. Tkinter must be available through the operating system's Python/Tk package. On desktop systems, launch:

```bash
python -m tabarc_print.desktop
```

Or use `tabarc-print-desktop` after installing the wheel. Optional arguments are `--state-dir`, `--backend auto|cups|windows-sumatra` and `--windows-renderer` (a trusted absolute path to SumatraPDF.exe for the Windows backend).

Find printers, choose a queue and click **Add PDF**. New jobs are held by default. Click **Release** and then **Print selected** to submit a job to the operating system. The action prompts for confirmation. **Submitted** means accepted by the spooler, not physically printed. **Uncertain** means the submission outcome couldn't be verified; the application does not retry automatically.

Hold, release and cancel only work before a job has been claimed. If a job is left in **claimed** after a crash, stop every worker and choose **Mark uncertain**. Do not do this while a worker is still printing. Inspect the local spooler or printer before manually resubmitting any document.

The panel refreshes the queue periodically. Direct cloud transport is optional. The **Cloud printing** panel now supports encrypted send, receipt checks, pairing and manually confirmed receiving. See [Cloud printing](CLOUD-PRINTING.md). The plug-in viewer lists approved built-in components and required permissions; it does not install or execute community code.

## Background printing

Manual **Print selected** works without a background worker. For unattended printing on Linux, a systemd **user** worker can be installed explicitly:

```bash
python -m tabarc_print.service show
python -m tabarc_print.service install
systemctl --user daemon-reload
systemctl --user enable --now tabarc-print.service
```

`install` writes a user-owned service unit but never enables or starts it automatically. The service processes **queued** jobs, not **held** jobs. Releasing a held job when a worker is active allows it to print without another confirmation. Only enable the worker if that's the behaviour you want.

To stop and remove:

```bash
systemctl --user disable --now tabarc-print.service
python -m tabarc_print.service remove
systemctl --user daemon-reload
```

The worker uses the same default local database as the desktop panel. If you use a custom state directory for the GUI, provide the same absolute `--state-dir` when generating the unit. User services normally run while the user's systemd manager is active; always-on operation after logout can require a separate administrator-approved linger configuration.

Windows Task Scheduler and macOS launchd installers are **not** included. The desktop panel currently uses Python Tk, not a bundled Windows/macOS application installer. There is no native Android print service or Chrome extension in this build.

## Graphical smoke test

On a machine with Tk and a display:

```bash
python scripts/gui_smoke.py
```

On a Linux headless build runner with Xvfb:

```bash
xvfb-run -a python scripts/gui_smoke.py
```

No real print jobs are submitted by this smoke test.

## New in v0.8.0

Choose **Cloud accounts** to set a local Google desktop OAuth JSON path or Microsoft application ID, then sign in. Tokens are not written to desktop settings. Cloud sign-in does not enable document synchronisation or unattended printing. See [Cloud accounts](CLOUD-ACCOUNTS.md).

On Windows, **Settings** lets users select their own trusted SumatraPDF.exe so printing no longer requires a command-line renderer argument. An optional scheduled worker and Windows application build recipe are described in [Windows packaging](WINDOWS.md). These Windows-specific operations are untested on Windows.

## New in v0.9.0

Choose **Cloud printing** for explicit send and collect operations through Google Drive or OneDrive. It is separate from local queue printing and does not automatically enable a receiver. See [Cloud printing](CLOUD-PRINTING.md).
