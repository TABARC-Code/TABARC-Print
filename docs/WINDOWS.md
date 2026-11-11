# Windows packaging and worker (development tooling)

TABARC Print has Windows **build instructions and an Inno Setup installer recipe**. The Windows executable and installer have **not been compiled or verified on Windows** in this release. The source package contains no prebuilt Windows executable.

## Build on a Windows machine

Use a trusted Python 3.11+ environment, PyInstaller and Inno Setup 6 if you want an installer. Audit and install dependencies first:

```powershell
py -m pip install ".[cloud]" pyinstaller
powershell -NoProfile -File .\packaging\windows\build-windows.ps1
```

The script builds two separate directories under `dist\windows`: `TABARCPrint` (graphical interface) and `TABARCPrintWorker` (queue processor). It doesn't download an installer compiler or a PDF renderer. After independently installing a trusted Inno Setup compiler, pass its executable path using `-Iscc "C:\...\ISCC.exe"` to compile the per-user installer. The installer defaults to `%LOCALAPPDATA%\Programs\TABARC Print` and does not require system-wide installation.

Before distributing installers, verify Windows Defender, SmartScreen, clean-machine installation/uninstallation, process permissions, dependency licences, application signing and loaded DLLs. No installer signature or Windows CI result exists in the archive.

## Print locally

Open the desktop application and choose **Settings** to locate your trusted, already-installed `SumatraPDF.exe`. This path is saved in the local user's print state and can be changed without editing a configuration file. The renderer isn't bundled or downloaded by TABARC Print.

Select a Windows printer, add a PDF, release a held job and explicitly submit it. This records submission to the Windows print subsystem, **not proof of paper output**.

## Optional logon worker

The installer **does not activate** background printing. To add a worker to your own Windows account, run the bundled script after installing and choosing a trusted renderer:

```powershell
powershell -NoProfile -File "<install-dir>\configure-windows-worker.ps1" -Action Install -Renderer "C:\Program Files\SumatraPDF\SumatraPDF.exe"
```

This creates a **user-owned Task Scheduler entry** which starts at the next logon. The task uses limited privileges and can only access the user's existing local queue. Held jobs remain held. Once released, queued jobs may be printed unattended while the worker is running. If you want no unattended printing, leave this unconfigured.

To remove it:

```powershell
powershell -NoProfile -File "<install-dir>\configure-windows-worker.ps1" -Action Remove
```

The helper checks that it owns the existing task before replacing or removing it. The uninstall recipe also requests removal of its worker task. Task creation, removal and uninstall still need testing on a real non-administrator Windows profile, as do console visibility and post-login startup behaviour.

## Known gaps

Native printer discovery and SumatraPDF integration need real Windows testing, including sleep/resume, failed print jobs and PDF handling. This build only checks the Windows packaging scripts structurally on Linux. A Windows installer is not equivalent to a working Windows printing service until that validation is complete.
