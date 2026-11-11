#define AppVer "0.8.0"
[Setup]
AppId={{D8587337-0F30-4DE1-A006-2CFF1CA13639}
AppName=TABARC Print
AppVersion={#AppVer}
AppPublisher=TABARC-Code
DefaultDirName={localappdata}\Programs\TABARC Print
DefaultGroupName=TABARC Print
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
OutputDir=..\..\dist\windows-installer
OutputBaseFilename=TABARCPrint-Setup-{#AppVer}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\TABARCPrint\TABARCPrint.exe
[Files]
Source: "..\..\dist\windows\TABARCPrint\*"; DestDir: "{app}\TABARCPrint"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\dist\windows\TABARCPrintWorker\*"; DestDir: "{app}\TABARCPrintWorker"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "configure-windows-worker.ps1"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{autoprograms}\TABARC Print"; Filename: "{app}\TABARCPrint\TABARCPrint.exe"
[Run]
Filename: "{app}\TABARCPrint\TABARCPrint.exe"; Description: "Open TABARC Print"; Flags: nowait postinstall skipifsilent
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -File ""{app}\configure-windows-worker.ps1"" -Action Remove"; Flags: runhidden
