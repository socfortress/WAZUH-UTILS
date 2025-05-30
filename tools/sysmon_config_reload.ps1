# Start timing
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# Define the log file path
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# Function to log steps
function Log-Step {
    param (
        [string]$stepName,
        [string]$status,
        [string]$details = ""
    )
    try {
        $logPayload = @{
            group = 'SysmonConfigReload'
            step = $stepName
            status = $status
            details = $details
            executionTime = $stopwatch.Elapsed.ToString()
        } | ConvertTo-Json -Compress

        $logPayload | Out-File -Append -Encoding ascii $logFile
    } catch {
        Write-Host "Failed to log $stepName. Error: $_"
    }
}

# Function to reload Sysmon configuration
function Reload-SysmonConfig {
    param (
        [string]$sysmonPath,
        [string]$configPath
    )

    try {
        Log-Step -stepName 'Check Sysmon Path' -status 'started'
        if (-Not (Test-Path $sysmonPath)) {
            throw "Sysmon executable not found at $sysmonPath"
        }
        Log-Step -stepName 'Check Sysmon Path' -status 'completed'
    } catch {
        Log-Step -stepName 'Check Sysmon Path' -status 'error' -details $_
        return
    }

    try {
        Log-Step -stepName 'Check Config Path' -status 'started'
        if (-Not (Test-Path $configPath)) {
            throw "Sysmon config file not found at $configPath"
        }
        Log-Step -stepName 'Check Config Path' -status 'completed'
    } catch {
        Log-Step -stepName 'Check Config Path' -status 'error' -details $_
        return
    }

    try {
        Log-Step -stepName 'Reload Sysmon Config' -status 'started'
        & $sysmonPath -c $configPath
        Log-Step -stepName 'Reload Sysmon Config' -status 'completed'
    } catch {
        Log-Step -stepName 'Reload Sysmon Config' -status 'error' -details "An error occurred while reloading Sysmon configuration: $_"
    }
}

# Paths
$sysmonPath = "C:\Program Files\SOCFortress\sysinternals\Sysmon64.exe"
$configPath = "C:\Program Files (x86)\ossec-agent\shared\sysmon_config.xml"

# Log the start time
Log-Step -stepName 'Start Timing' -status 'started'

# Reload Sysmon Configuration
Reload-SysmonConfig -sysmonPath $sysmonPath -configPath $configPath

# Log the stop time
Log-Step -stepName 'Stop Timing' -status 'completed'

# Stop timing
$stopwatch.Stop()
