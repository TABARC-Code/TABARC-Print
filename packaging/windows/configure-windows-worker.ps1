# Windows user-owned scheduled task. Installing it never starts the worker immediately.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Show','Install','Remove')][string]$Action,
    [string]$Renderer = '',
    [string]$WorkerExecutable = '',
    [string]$StateDir = ''
)
$ErrorActionPreference = 'Stop'
$task = 'TABARC Print Local Worker'
if ($Action -eq 'Show') {
    Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Format-List TaskName, State, Author
    return
}
if ($Action -eq 'Remove') {
    $current = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    if ($current) {
        $expected = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'TABARCPrintWorker\TABARCPrintWorker.exe'))
        if ($current.Actions.Count -ne 1 -or ![string]::Equals(
            [System.IO.Path]::GetFullPath($current.Actions[0].Execute), $expected,
            [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a task that does not belong to TABARC Print.'
        }
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
    Write-Host 'Background worker task removed if present.'
    return
}
if (-not $WorkerExecutable) {
    $WorkerExecutable = Join-Path $PSScriptRoot 'TABARCPrintWorker\TABARCPrintWorker.exe'
}
$worker = [System.IO.Path]::GetFullPath($WorkerExecutable)
if (!(Test-Path $worker -PathType Leaf) -or [System.IO.Path]::GetExtension($worker) -ne '.exe') {
    throw 'Choose the installed TABARCPrintWorker.exe.'
}
if (-not $Renderer) { throw 'Supply an absolute path to your trusted SumatraPDF.exe renderer.' }
$rendererPath = [System.IO.Path]::GetFullPath($Renderer)
if (![System.IO.Path]::IsPathRooted($Renderer) -or !(Test-Path $rendererPath -PathType Leaf)) {
    throw 'The PDF renderer must exist at an absolute path.'
}
if ($rendererPath.Contains('"') -or $worker.Contains('"')) { throw 'Invalid executable path.' }
$arguments = '--backend windows-sumatra --windows-renderer "' + $rendererPath + '"'
if ($StateDir) {
    if (![System.IO.Path]::IsPathRooted($StateDir) -or $StateDir.Contains('"') -or $StateDir.EndsWith('\')) { throw 'State path must be absolute.' }
    $arguments = '--state-dir "' + [System.IO.Path]::GetFullPath($StateDir) + '" ' + $arguments
}
$arguments += ' work --interval 3'
# Never overwrite another application's task even if it uses this name.
$current = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
if ($current -and ($current.Actions.Count -ne 1 -or ![string]::Equals(
    [System.IO.Path]::GetFullPath($current.Actions[0].Execute), $worker,
    [System.StringComparison]::OrdinalIgnoreCase))) {
    throw 'An unrelated task already uses this name.'
}
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$taskAction = New-ScheduledTaskAction -Execute $worker -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $task -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host 'Installed a user-only task. It starts on the next logon, not now.'
Write-Host 'Releasing a queued job may print automatically while this worker is active.'
