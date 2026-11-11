# Build the local desktop and background-worker executables on Windows.
[CmdletBinding()]
param([string]$Python = 'py', [string]$Iscc = '')
$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$output = Join-Path $project 'dist\windows'
New-Item -ItemType Directory -Path $output -Force | Out-Null
Push-Location $project
try {
    & $Python -m PyInstaller --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller is missing from this Python environment.' }
    & $Python -c 'import tabarc_print, tkinter, cryptography, google_auth_oauthlib, msal, keyring'
    if ($LASTEXITCODE -ne 0) { throw 'Install TABARC Print with the optional cloud dependencies before building.' }
    & $Python -m PyInstaller --noconfirm --clean --onedir --windowed --name TABARCPrint `
        --distpath $output --workpath (Join-Path $project 'build\pyinstaller-desktop') `
        --specpath (Join-Path $project 'build') `
        --collect-submodules google_auth_oauthlib --collect-submodules google.oauth2 `
        --collect-submodules google.auth.transport --collect-submodules msal `
        --collect-submodules keyring.backends `
        (Join-Path $project 'scripts\windows_desktop_entry.py')
    if ($LASTEXITCODE -ne 0) { throw 'Desktop executable build failed.' }
    & $Python -m PyInstaller --noconfirm --clean --onedir --console --name TABARCPrintWorker `
        --distpath $output --workpath (Join-Path $project 'build\pyinstaller-worker') `
        --specpath (Join-Path $project 'build') `
        (Join-Path $project 'scripts\windows_worker_entry.py')
    if ($LASTEXITCODE -ne 0) { throw 'Worker executable build failed.' }
    $desktop = Join-Path $output 'TABARCPrint\TABARCPrint.exe'
    $worker = Join-Path $output 'TABARCPrintWorker\TABARCPrintWorker.exe'
    if (!(Test-Path $desktop) -or !(Test-Path $worker)) { throw 'Executable output is incomplete.' }
    Write-Host "Built: $desktop"
    Write-Host "Built: $worker"
    if ($Iscc) {
        if (!(Test-Path $Iscc -PathType Leaf)) { throw 'Inno Setup compiler not found.' }
        & $Iscc (Join-Path $project 'packaging\windows\TABARCPrint.iss')
        if ($LASTEXITCODE -ne 0) { throw 'Windows installer compilation failed.' }
    } else {
        Write-Host 'Installer not built. Supply -Iscc with the trusted Inno Setup compiler path.'
    }
} finally { Pop-Location }
