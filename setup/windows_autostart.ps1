#requires -Version 5.1

<#
Configure HUSTAutologin to run at Windows startup.

Usage:
  powershell -ExecutionPolicy Bypass -File .\setup\windows_autostart.ps1
  powershell -ExecutionPolicy Bypass -File .\setup\windows_autostart.ps1 -RunNow

By default this creates an AtStartup scheduled task that can run before the
current user signs in. Task Scheduler requires the current Windows account
password for that mode. Use the Windows account password, not a PIN.

The setup stores the campus password as a DPAPI-protected SecureString under
the current Windows user. The scheduled task runs a small generated wrapper
script from %APPDATA%\HUSTAutologin.
#>

[CmdletBinding()]
param(
    [string]$TaskName = "HUSTAutologin",
    [string]$UserId = "",
    [securestring]$Password,
    [string]$PlainPassword = "",
    [string]$PythonPath = "",
    [int]$Interval = 30,
    [int]$StartupDelay = 20,
    [switch]$VerboseLog,
    [switch]$RunNow,
    [switch]$UseHighestPrivileges,
    [switch]$AtLogOn
)

$ErrorActionPreference = "Stop"

function ConvertTo-PsSingleQuoted {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Resolve-PythonPath {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        $command = Get-Command $RequestedPath -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
        if (Test-Path -LiteralPath $RequestedPath) {
            return (Resolve-Path -LiteralPath $RequestedPath).Path
        }
        throw "Python not found: $RequestedPath"
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return $python.Source
    }

    throw "Python not found in PATH. Pass -PythonPath C:\Path\To\python.exe"
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][securestring]$SecureValue)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $scriptDir
$loginScript = Join-Path $toolDir "HUSTAutologin.py"
if (-not (Test-Path -LiteralPath $loginScript)) {
    throw "Cannot find HUSTAutologin.py beside this setup script."
}

if (-not $UserId) {
    $UserId = Read-Host "Campus user id"
}
if (-not $UserId) {
    throw "Campus user id is required."
}

if (-not $Password) {
    if ($PlainPassword) {
        $Password = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
    } else {
        $Password = Read-Host "Campus password" -AsSecureString
    }
}
if (-not $Password) {
    throw "Campus password is required."
}

$principalUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$windowsPasswordPlain = $null
if (-not $AtLogOn) {
    if (-not (Test-IsAdministrator)) {
        Write-Warning "AtStartup tasks may require an elevated PowerShell. If registration fails, rerun as Administrator."
    }

    Write-Host "This will create an AtStartup task for $principalUser."
    Write-Host "Enter the Windows account password for this user. PIN / Hello credentials cannot register this task."
    $windowsPassword = Read-Host "Windows password for $principalUser" -AsSecureString
    if (-not $windowsPassword) {
        throw "Windows account password is required for startup tasks."
    }
    $windowsPasswordPlain = ConvertFrom-SecureStringToPlainText $windowsPassword
}

$pythonPath = Resolve-PythonPath $PythonPath
$loginScript = (Resolve-Path -LiteralPath $loginScript).Path

& $pythonPath -c "import requests" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Python dependency 'requests' is missing. Install it with: `"$pythonPath`" -m pip install requests"
}

$configDir = Join-Path $env:APPDATA "HUSTAutologin"
$logDir = Join-Path $configDir "logs"
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$secretFile = Join-Path $configDir "hust_autologin.secrets.xml"
$runnerScript = Join-Path $configDir "run_autologin_windows.ps1"

$secret = [pscustomobject]@{
    UserId = $UserId
    Password = $Password
    PythonPath = $pythonPath
    ScriptPath = $loginScript
    Interval = $Interval
    StartupDelay = $StartupDelay
    LogDir = $logDir
    VerboseLog = [bool]$VerboseLog
}
$secret | Export-Clixml -LiteralPath $secretFile

$secretLiteral = ConvertTo-PsSingleQuoted $secretFile
$runnerContent = @"
`$ErrorActionPreference = "Stop"
`$secret = Import-Clixml -LiteralPath $secretLiteral

`$env:CAMPUS_USER_ID = `$secret.UserId
`$env:CAMPUS_LOG_DIR = `$secret.LogDir

`$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$secret.Password)
try {
    `$env:CAMPUS_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(`$bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$bstr)
}

`$argsList = @(
    `$secret.ScriptPath,
    "--loop",
    "--interval",
    [string]`$secret.Interval,
    "--startup-delay",
    [string]`$secret.StartupDelay,
    "--no-prompt"
)
if (`$secret.VerboseLog) {
    `$argsList += "--verbose"
}

& (`$secret.PythonPath) @argsList
exit `$LASTEXITCODE
"@
Set-Content -LiteralPath $runnerScript -Value $runnerContent -Encoding UTF8

$runLevel = "Limited"
if ($UseHighestPrivileges) {
    $runLevel = "Highest"
}

$powershellExe = Join-Path $PSHOME "powershell.exe"
$taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $runnerScript
$action = New-ScheduledTaskAction -Execute $powershellExe -Argument $taskArgument
if ($AtLogOn) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $principalUser
    $description = "Run HUST campus autologin when the user logs on."
} else {
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $description = "Run HUST campus autologin at Windows startup before user logon."
}
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1)

if ($AtLogOn) {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -User $principalUser `
        -RunLevel $runLevel `
        -Description $description `
        -Force | Out-Null
} else {
    try {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -User $principalUser `
            -Password $windowsPasswordPlain `
            -RunLevel $runLevel `
            -Description $description `
            -Force | Out-Null
    } finally {
        $windowsPasswordPlain = $null
    }
}

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
}

if ($AtLogOn) {
    Write-Host "Configured scheduled task at user logon: $TaskName"
} else {
    Write-Host "Configured scheduled task at Windows startup: $TaskName"
}
Write-Host "Runner: $runnerScript"
Write-Host "Logs: $logDir"
Write-Host "Check task status with: Get-ScheduledTask -TaskName $TaskName"
