<#
.SYNOPSIS
    Queries Xen Orchestra REST API to retrieve backup job definitions and logs, generating comprehensive HTML reports with optional email integration.

.DESCRIPTION
    This script connects to a Xen Orchestra server using REST API authentication to retrieve both backup job definitions and execution logs from the last 24 hours.
    It provides a comprehensive view of all configured backup jobs (VM, metadata, and mirror types) along with their recent execution status.

.PARAMETER Help
    Display the help section

.PARAMETER XenOrchestraUrl
    The base URL of your Xen Orchestra server (e.g., "https://xo.company.com")

.PARAMETER ApiToken
    The API authentication token for Xen Orchestra access.

.PARAMETER LogFile
    Path to the log file for script execution logging.

.PARAMETER OutputPath
    Path where the HTML report file should be saved.

.PARAMETER TimeSpanHours
    Number of hours back to query for backup jobs. Defaults to 24 hours.

.PARAMETER IncludeSuccess
    Include successful backup jobs in the detailed report. Default: $true

.PARAMETER IncludeFailures
    Include failed backup jobs in the detailed report. Default: $true

.PARAMETER IncludeSkipped
    Include skipped backup jobs in the detailed report. Default: $false

.PARAMETER SkipCertificateCheck
    Skip SSL certificate validation.

.PARAMETER EnableDebugLogging
    Enable detailed debug logging.

.PARAMETER SendEmail
    Send the report via email.

.PARAMETER SmtpServer
    SMTP server hostname for sending emails.

.PARAMETER SmtpPort
    SMTP server port. Defaults to 25.

.PARAMETER SmtpUseSsl
    Use SSL/TLS encryption for SMTP connection. Default: $false

.PARAMETER EmailFrom
    Email address to send from.

.PARAMETER EmailTo
    Email address(es) to send to.

.PARAMETER EmailSubject
    Email subject line.

.PARAMETER SmtpCredential
    PSCredential object containing SMTP authentication credentials.

#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidatePattern('^https?://.*')]
    [string]$XenOrchestraUrl,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [string]$ApiToken,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { 
            $true 
        } else { 
            throw "The specified token file '$_' does not exist or is not a file." 
        }
    })]
    [string]$ApiTokenFile,

    [Parameter(ParameterSetName = 'Default')]
    [string]$LogFile,

    [Parameter(ParameterSetName = 'Default')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Default')]
    [ValidateRange(1, 168)]
    [int]$TimeSpanHours = 24,

    [Parameter(ParameterSetName = 'Default')]
    [bool]$IncludeSuccess = $true,

    [Parameter(ParameterSetName = 'Default')]
    [bool]$IncludeFailures = $true,

    [Parameter(ParameterSetName = 'Default')]
    [bool]$IncludeSkipped = $false,

    [Parameter(ParameterSetName = 'Default')]
    [int]$MaxRetries = 3,

    [Parameter(ParameterSetName = 'Default')]
    [int]$TimeoutSeconds = 30,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SkipCertificateCheck,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$EnableDebugLogging,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SendEmail,

    [Parameter(ParameterSetName = 'Default')]
    [string]$SmtpServer,

    [Parameter(ParameterSetName = 'Default')]
    [int]$SmtpPort = 25,

    [Parameter(ParameterSetName = 'Default')]
    [bool]$SmtpUseSsl = $false,

    [Parameter(ParameterSetName = 'Default')]
    [string]$EmailFrom,

    [Parameter(ParameterSetName = 'Default')]
    [string[]]$EmailTo,

    [Parameter(ParameterSetName = 'Default')]
    [string]$EmailSubject,

    [Parameter(ParameterSetName = 'Default')]
    [PSCredential]$SmtpCredential,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest

$script:LogPath = $null

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [ValidateSet('Information', 'Warning', 'Error', 'Debug', 'Verbose')]
        [string]$Level = 'Information',
        
        [string]$LogFilePath = $script:LogPath,
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (-not $NoConsole) {
        switch ($Level) {
            'Information' { Write-Host $logEntry -ForegroundColor Green }
            'Warning' { Write-Warning $logEntry }
            'Error' { Write-Error $logEntry -ErrorAction Continue }
            'Debug' { Write-Debug $logEntry }
            'Verbose' { Write-Verbose $logEntry }
        }
    }
    
    if ($LogFilePath) {
        try {
            $logDir = Split-Path $LogFilePath -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $LogFilePath -Value $logEntry -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to log file: $_"
        }
    }
}

function Get-ApiTokenFromSource {
    [CmdletBinding()]
    param(
        [string]$Token,
        [string]$TokenFile
    )
    
    # Validate that exactly one token source is provided
    if ($Token -and $TokenFile) {
        throw "Cannot specify both -ApiToken and -ApiTokenFile parameters. Please use only one method."
    }
    
    if (-not $Token -and -not $TokenFile) {
        throw "Must specify either -ApiToken or -ApiTokenFile parameter."
    }
    
    if ($TokenFile) {
        try {
            Write-Log "Reading encrypted API token from file: $TokenFile" -Level Information
            
            # Read the encrypted string from file
            $encryptedString = Get-Content -Path $TokenFile -Raw -ErrorAction Stop
            
            if (-not $encryptedString -or $encryptedString.Trim() -eq '') {
                throw "Token file appears to be empty or contains only whitespace."
            }
            
            # Convert back to SecureString
            $secureToken = $encryptedString.Trim() | ConvertTo-SecureString -ErrorAction Stop
            
            # Convert SecureString to plain text for API usage
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
            try {
                $plainTextToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                
                # Clean the token - remove any whitespace, newlines, or control characters
                $cleanToken = $plainTextToken.Trim() -replace '\s+', ''
                
                if (-not $cleanToken -or $cleanToken.Length -eq 0) {
                    throw "Decrypted token is empty after cleaning whitespace."
                }
                
                Write-Log "Successfully decrypted and cleaned API token from file (length: $($cleanToken.Length) chars)" -Level Information
                
                # Optional debug logging (only enable if needed for troubleshooting)
                if ($EnableDebugLogging) {
                    $tokenPreview = if ($cleanToken.Length -gt 8) { 
                        $cleanToken.Substring(0, 4) + "***" + $cleanToken.Substring($cleanToken.Length - 4) 
                    } else { 
                        "***" 
                    }
                    Write-Log "DEBUG: Token preview: $tokenPreview" -Level Debug
                }
                
                return $cleanToken
            }
            finally {
                # Always clean up the BSTR for security
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        catch {
            Write-Log "Failed to read or decrypt token file: $($_.Exception.Message)" -Level Error
            throw "Unable to process encrypted token file. Ensure the file was created on this machine with the same user account. Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "Using API token provided via command line parameter" -Level Information
        return $Token
    }
}

function Invoke-XenOrchestraApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [string]$Method = 'GET',
        [object]$Body,
        [int]$TimeoutSec = 30,
        [int]$MaxRetries = 3,
        [switch]$SkipCertificateCheck
    )
    
    $attempt = 1
    $delay = 2
    
    do {
        try {
            Write-Log "API Call Attempt ${attempt}: $Method $Uri" -Level Debug
            
            $params = @{
                Uri = $Uri
                Method = $Method
                Headers = $Headers
                TimeoutSec = $TimeoutSec
                ErrorAction = 'Stop'
            }
            
            if ($Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 10)
                $params.ContentType = 'application/json'
            }
            
            if ($SkipCertificateCheck) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $params.SkipCertificateCheck = $true
                    Write-Log "Skipping SSL certificate validation (PS 6.0+)" -Level Debug
                } 
                else {
                    Write-Log "Configuring custom SSL certificate validation (PS 5.1)" -Level Debug
                    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
                        param($sslSender, $certificate, $chain, $sslPolicyErrors)
                        return $true
                    }
                    
                    try {
                        $response = Invoke-RestMethod @params
                        Write-Log "API call successful with custom SSL validation" -Level Debug
                        return $response
                    }
                    finally {
                        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
                    }
                }
            }
            
            $response = Invoke-RestMethod @params
            Write-Log "API call successful" -Level Debug
            return $response
            
        } 
        catch [System.Net.WebException], [Microsoft.PowerShell.Commands.HttpResponseException] {
            $statusCode = $null
            $errorMessage = $_.Exception.Message
            
            if ($errorMessage -like "*SSL connection could not be established*" -or 
                $errorMessage -like "*certificate*" -or 
                $errorMessage -like "*TLS*") {
                
                Write-Log "SSL/TLS Error detected. Consider using -SkipCertificateCheck parameter." -Level Warning
                
                if (-not $SkipCertificateCheck) {
                    throw "SSL Certificate validation failed. Use -SkipCertificateCheck parameter. Error: $errorMessage"
                }
            }
            
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            
            Write-Log "HTTP Error - Status: $statusCode, Message: $errorMessage" -Level Warning
            
            switch ($statusCode) {
                401 { 
                    throw "Authentication failed. Please check your API token."
                }
                404 { 
                    throw "API endpoint not found: $Uri"
                }
                429 { 
                    Write-Log "Rate limited. Retrying after $delay seconds..." -Level Warning
                }
                { $_ -in @(500, 502, 503, 504) } {
                    Write-Log "Server error $statusCode. Retrying..." -Level Warning
                }
                default { 
                    throw "HTTP ${statusCode}: $errorMessage"
                }
            }
            
            if ($attempt -ge $MaxRetries) {
                throw "API call failed after $MaxRetries attempts. Last error: $errorMessage"
            }
            
            Start-Sleep -Seconds $delay
            $delay = [math]::Min($delay * 2, 60)
            $attempt++
        }
        catch {
            Write-Log "Unexpected error in API call: $($_.Exception.Message)" -Level Error
            throw
        }
    } while ($attempt -le $MaxRetries)
}

function Get-BackupJobDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseServerUrl,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        
        [int]$TimeoutSec = 30,
        [int]$MaxRetries = 3,
        [switch]$SkipCertificateCheck,
        [switch]$EnableDebugLogging
    )
    
    $allJobs = @()
    
    $jobTypes = @{
        'metadata' = @{ 
            Endpoint = '/backup/jobs/metadata'
            Type = 'Metadata Backup'
        }
        'mirror' = @{ 
            Endpoint = '/backup/jobs/mirror'
            Type = 'Mirror/Replication'
        }
        'vm' = @{ 
            Endpoint = '/backup/jobs/vm'
            Type = 'VM Backup'
        }
    }
    
    foreach ($jobTypeKey in $jobTypes.Keys) {
        try {
            Write-Log "Retrieving $($jobTypes[$jobTypeKey].Type) job definitions..." -Level Information
            
            $endpoint = $jobTypes[$jobTypeKey].Endpoint
            $jobListUrl = "$BaseApiUrl$endpoint"
            
            if ($EnableDebugLogging) {
                Write-Log "DEBUG: Querying job list from $jobListUrl" -Level Debug
            }
            
            $jobUrlList = Invoke-XenOrchestraApi -Uri $jobListUrl -Headers $Headers -TimeoutSec $TimeoutSec -MaxRetries $MaxRetries -SkipCertificateCheck:$SkipCertificateCheck
            
            if ($EnableDebugLogging -and $jobUrlList) {
                Write-Log "DEBUG: Job URL list response type: $($jobUrlList.GetType().FullName)" -Level Debug
                Write-Log "DEBUG: Job URL list content: $($jobUrlList | ConvertTo-Json -Depth 2)" -Level Debug
            }
            
            $urlArray = @()
            if ($jobUrlList) {
                if ($jobUrlList -is [array]) {
                    $urlArray = $jobUrlList
                } 
                else {
                    $urlArray = @($jobUrlList)
                }
            }
            
            if ($urlArray.Count -gt 0) {
                Write-Log "Found $($urlArray.Count) $($jobTypes[$jobTypeKey].Type) jobs" -Level Information
                
                foreach ($jobUrl in $urlArray) {
                    try {
                        $fullJobUrl = if ($jobUrl.StartsWith('/rest/v0')) {
                            "$BaseServerUrl$jobUrl"
                        } 
                        else {
                            "$BaseApiUrl$jobUrl"
                        }
                        
                        if ($EnableDebugLogging) {
                            Write-Log "DEBUG: Fetching job details from $fullJobUrl" -Level Debug
                        }
                        
                        $jobDetails = Invoke-XenOrchestraApi -Uri $fullJobUrl -Headers $Headers -TimeoutSec $TimeoutSec -MaxRetries $MaxRetries -SkipCertificateCheck:$SkipCertificateCheck
                        
                        # Ensure the response is parsed as a PowerShell object, not a string
                        if ($jobDetails -is [string]) {
                            try {
                                # Use -AsHashtable to handle empty string property names
                                $jobDetailsHashtable = $jobDetails | ConvertFrom-Json -AsHashtable
                                # Convert hashtable to PSCustomObject for easier property access
                                $jobDetails = [PSCustomObject]$jobDetailsHashtable
                                if ($EnableDebugLogging) {
                                    Write-Log "DEBUG: Converted JSON string to PowerShell object using -AsHashtable" -Level Debug
                                }
                            }
                            catch {
                                Write-Log "ERROR: Failed to parse JSON response: $_" -Level Error
                                continue
                            }
                        }
                        
                        if ($jobDetails) {
                            if ($EnableDebugLogging) {
                                $props = $jobDetails | Get-Member -MemberType Properties | ForEach-Object { $_.Name }
                                Write-Log "DEBUG: Job properties: $($props -join ', ')" -Level Debug
                                # Increase depth to avoid truncation warning, or comment out if not needed
                                # Write-Log "DEBUG: Raw job details structure: $($jobDetails | ConvertTo-Json -Depth 5)" -Level Debug
                            }
                            
                            $jobId = if ($jobDetails.PSObject.Properties['id'] -and $jobDetails.id) { 
                                $jobDetails.id 
                            } 
                            else {
                                if ($jobUrl -match '([a-f0-9\-]{36})$') {
                                    $Matches[1]
                                } 
                                else {
                                    'Unknown'
                                }
                            }
                            
                            $jobName = 'Unknown Job'
                            if ($jobDetails.PSObject.Properties['name']) {
                                $nameValue = $jobDetails.name
                                if ($nameValue -and $nameValue.ToString().Trim() -ne '') {
                                    $jobName = $nameValue.ToString().Trim()
                                }
                            }
                            
                            $jobMode = if ($jobDetails.PSObject.Properties['mode'] -and $jobDetails.mode) { 
                                $jobDetails.mode.ToString()
                            } 
                            else { 
                                'N/A' 
                            }
                            
                            $jobSettings = if ($jobDetails.PSObject.Properties['settings'] -and $jobDetails.settings) { 
                                $jobDetails.settings 
                            } 
                            else { 
                                $null 
                            }
                            
                            if ($EnableDebugLogging) {
                                Write-Log "DEBUG: Extracted values - ID: $jobId, Name: '$jobName', Mode: $jobMode" -Level Debug
                            }
                            
                            $jobDef = [PSCustomObject]@{
                                Id = $jobId
                                Name = $jobName
                                Type = $jobTypeKey
                                TypeDisplay = $jobTypes[$jobTypeKey].Type
                                Mode = $jobMode
                                Settings = $jobSettings
                                LastExecution = $null
                                LastExecutionStatus = 'Not Run'
                                LastExecutionTime = $null
                                RawDefinition = $jobDetails
                            }
                            
                            $allJobs += $jobDef
                            
                            if ($EnableDebugLogging) {
                                Write-Log "DEBUG: Added job: ID=$jobId, Name=$jobName, Type=$jobTypeKey" -Level Debug
                            }
                        }
                    }
                    catch {
                        Write-Log "Failed to retrieve job details from $jobUrl : $($_.Exception.Message)" -Level Warning
                    }
                }
            } 
            else {
                Write-Log "No $($jobTypes[$jobTypeKey].Type) jobs found" -Level Information
            }
        }
        catch {
            Write-Log "Failed to retrieve $($jobTypes[$jobTypeKey].Type) job list: $($_.Exception.Message)" -Level Warning
        }
    }
    
    Write-Log "Retrieved total of $($allJobs.Count) backup job definitions" -Level Information
    return $allJobs
}

function Merge-JobDefinitionsWithLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$JobDefinitions = @(),
        
        [Parameter(Mandatory = $true)]
        [object[]]$BackupLogs,
        
        [switch]$EnableDebugLogging
    )
    
    if (-not $JobDefinitions) {
        $JobDefinitions = @()
    }
    
    Write-Log "Correlating $($JobDefinitions.Count) job definitions with $($BackupLogs.Count) backup logs" -Level Information
    
    # Debug: Show all available backup log statuses
    if ($EnableDebugLogging) {
        $logStatusCounts = $BackupLogs | Group-Object Status | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-Log "DEBUG: Available backup log statuses: $($logStatusCounts -join ', ')" -Level Debug
        
        $skippedLogs = @($BackupLogs | Where-Object { $_.Status -eq 'Skipped' })
        $skippedLogsCount = if ($skippedLogs) { $skippedLogs.Count } else { 0 }
        if ($skippedLogsCount -gt 0) {
            Write-Log "DEBUG: Found $skippedLogsCount skipped backup logs:" -Level Debug
            foreach ($skippedLog in $skippedLogs) {
                Write-Log "DEBUG: - Skipped log: JobName='$($skippedLog.JobName)', RunId='$($skippedLog.RunId)', JobId='$($skippedLog.JobId)'" -Level Debug
            }
        } else {
            Write-Log "DEBUG: No skipped backup logs found" -Level Debug
        }
        
        # Additional debug: Show what we're correlating
        Write-Log "DEBUG: Total BackupLogs received for correlation: $($BackupLogs.Count)" -Level Debug
        Write-Log "DEBUG: JobDefinitions to correlate: $($JobDefinitions.Count)" -Level Debug
    }
    
    foreach ($jobDef in $JobDefinitions) {
        $matchingLogs = @()
        
        $matchingLogs += $BackupLogs | Where-Object { 
            $_.RunId -eq $jobDef.Id -or 
            ($_.PSObject.Properties['JobId'] -and $_.JobId -eq $jobDef.Id)
        }
        
        if ($matchingLogs.Count -eq 0) {
            $matchingLogs += $BackupLogs | Where-Object { 
                $_.JobName -eq $jobDef.Name 
            }
        }
        
        if ($matchingLogs.Count -gt 0) {
            $mostRecentLog = $matchingLogs | Sort-Object StartTime -Descending | Select-Object -First 1
            
            $jobDef.LastExecution = $mostRecentLog
            $jobDef.LastExecutionStatus = $mostRecentLog.Status
            $jobDef.LastExecutionTime = $mostRecentLog.StartTime
            
            if ($EnableDebugLogging) {
                Write-Log "DEBUG: Matched job '$($jobDef.Name)' with log entry - Status: $($mostRecentLog.Status), Time: $($mostRecentLog.StartTime)" -Level Debug
            }
        } 
        else {
            if ($EnableDebugLogging) {
                Write-Log "DEBUG: No matching log entry found for job '$($jobDef.Name)' (ID: $($jobDef.Id))" -Level Debug
            }
        }
    }
    
    return $JobDefinitions
}

function ConvertTo-BackupJobObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$ApiResponse,
        
        [switch]$EnableDebugLogging
    )
    
    process {
        try {
            if ($EnableDebugLogging) {
                $propertyNames = $ApiResponse | Get-Member -MemberType Properties | ForEach-Object { $_.Name }
                $propertyString = $propertyNames -join ', '
                Write-Log "DEBUG: Processing backup job data with properties: $propertyString" -Level Debug
            }
            
            $startTime = $null
            $endTime = $null
            
            if ($ApiResponse.PSObject.Properties['start'] -and $ApiResponse.start) {
                try {
                    $startTime = [DateTime]::new(1970, 1, 1).AddMilliseconds([long]$ApiResponse.start).ToLocalTime()
                    if ($EnableDebugLogging) {
                        Write-Log "DEBUG: Converted start time: $($ApiResponse.start) -> $startTime" -Level Debug
                    }
                } 
                catch {
                    Write-Log "ERROR: Failed to convert start time $($ApiResponse.start): $_" -Level Warning
                }
            }
            
            if ($ApiResponse.PSObject.Properties['end'] -and $ApiResponse.end) {
                try {
                    $endTime = [DateTime]::new(1970, 1, 1).AddMilliseconds([long]$ApiResponse.end).ToLocalTime()
                    if ($EnableDebugLogging) {
                        Write-Log "DEBUG: Converted end time: $($ApiResponse.end) -> $endTime" -Level Debug
                    }
                } 
                catch {
                    Write-Log "ERROR: Failed to convert end time $($ApiResponse.end): $_" -Level Warning
                }
            }
            
            $duration = if ($startTime -and $endTime) {
                $endTime - $startTime
            } 
            else { 
                $null 
            }
            
            $jobName = if ($ApiResponse.PSObject.Properties['jobName'] -and $ApiResponse.jobName) { 
                $ApiResponse.jobName.ToString()
            } 
            else { 
                'Unknown Job' 
            }
            
            $statusValue = if ($ApiResponse.PSObject.Properties['status'] -and $ApiResponse.status) { 
                $ApiResponse.status.ToString().ToLower()
            } 
            else { 
                'unknown' 
            }
            
            $runId = if ($ApiResponse.PSObject.Properties['id'] -and $ApiResponse.id) { 
                $ApiResponse.id.ToString()
            } 
            else { 
                'N/A' 
            }
            
            $jobId = if ($ApiResponse.PSObject.Properties['jobId'] -and $ApiResponse.jobId) { 
                $ApiResponse.jobId.ToString()
            } 
            else { 
                $null 
            }
            
            $methodValue = 'backup'
            if ($ApiResponse.PSObject.Properties['data'] -and $ApiResponse.data -and 
                $ApiResponse.data.PSObject.Properties['mode'] -and $ApiResponse.data.mode) {
                $methodValue = "backup ($($ApiResponse.data.mode))"
            } 
            elseif ($ApiResponse.PSObject.Properties['message'] -and $ApiResponse.message) {
                $methodValue = $ApiResponse.message.ToString()
            }
            
            $errorMessage = $null
            if ($ApiResponse.PSObject.Properties['result'] -and $ApiResponse.result) {
                if ($ApiResponse.result.PSObject.Properties['message'] -and $ApiResponse.result.message) {
                    $errorMessage = $ApiResponse.result.message.ToString()
                } 
                elseif ($ApiResponse.result -is [string]) {
                    $errorMessage = $ApiResponse.result
                }
            }
            
            $mappedStatus = 'Unknown'
            try {
                switch -Exact ($statusValue) {
                    'success' { $mappedStatus = 'Success' }
                    'completed' { $mappedStatus = 'Success' }
                    'ok' { $mappedStatus = 'Success' }
                    'failure' { $mappedStatus = 'Failed' }
                    'failed' { $mappedStatus = 'Failed' }
                    'error' { $mappedStatus = 'Failed' }
                    'interrupted' { $mappedStatus = 'Interrupted' }
                    'skipped' { $mappedStatus = 'Skipped' }
                    'skip' { $mappedStatus = 'Skipped' }
                    'pending' { $mappedStatus = 'Running' }
                    'running' { $mappedStatus = 'Running' }
                    default { $mappedStatus = $statusValue }
                }
            }
            catch {
                $mappedStatus = $statusValue
            }
            
            if ($EnableDebugLogging) {
                Write-Log "DEBUG: Mapped status '$statusValue' -> '$mappedStatus'" -Level Debug
                Write-Log "DEBUG: Final job: Name='$jobName', Status='$mappedStatus', Start='$startTime', End='$endTime'" -Level Debug
            }
            
            [PSCustomObject]@{
                JobName = $jobName
                JobId = $jobId
                Status = $mappedStatus
                StartTime = $startTime
                EndTime = $endTime
                Duration = if ($duration) {
                    "{0:hh\:mm\:ss}" -f $duration
                } 
                else { 
                    'N/A' 
                }
                RunId = $runId
                Method = $methodValue
                ErrorMessage = $errorMessage
            }
        }
        catch {
            Write-Log "Error converting backup job data: $_" -Level Warning
            if ($EnableDebugLogging) {
                Write-Log "DEBUG: Raw object type: $($ApiResponse.GetType().FullName)" -Level Debug
            }
            
            $fallbackJobName = if ($ApiResponse.PSObject.Properties['jobName']) { 
                $ApiResponse.jobName 
            } 
            else { 
                'Parse Error' 
            }
            
            $fallbackStatus = if ($ApiResponse.PSObject.Properties['status']) { 
                $ApiResponse.status 
            } 
            else { 
                'Error' 
            }
            
            [PSCustomObject]@{
                JobName = $fallbackJobName
                JobId = $null
                Status = $fallbackStatus
                StartTime = $null
                EndTime = $null
                Duration = 'N/A'
                RunId = 'N/A'
                Method = 'N/A'
                ErrorMessage = $_.Exception.Message
            }
        }
    }
}

function ConvertTo-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$JobDefinitions = @(),
        
        [Parameter(Mandatory = $false)]
        [object[]]$BackupJobs = @(),
        
        [string]$Title = "Xen Orchestra Backup Report",
        [int]$TimeSpanHours = 24
    )
    
    if (-not $JobDefinitions) { 
        $JobDefinitions = @() 
    }
    if (-not $BackupJobs) { 
        $BackupJobs = @() 
    }
    if (-not ($JobDefinitions -is [array])) { 
        $JobDefinitions = @($JobDefinitions) 
    }
    if (-not ($BackupJobs -is [array])) { 
        $BackupJobs = @($BackupJobs) 
    }
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fromDate = (Get-Date).AddHours(-$TimeSpanHours).ToString("yyyy-MM-dd HH:mm:ss")
    
    $emailStyles = @'
<style>
    body { 
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
        font-size: 12px; 
        color: #333333; 
        background-color: #f8f9fa; 
        margin: 0; 
        padding: 20px;
    }
    .container { 
        max-width: 1200px; 
        margin: 0 auto; 
        background-color: white; 
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .header { 
        background-color: #2c3e50; 
        color: white; 
        padding: 25px; 
        text-align: center; 
        border-radius: 8px 8px 0 0;
        /* Fallback for email clients that don't support gradients */
        background: #2c3e50;
    }
    .header h1 { 
        margin: 0; 
        font-size: 24px; 
        font-weight: 300; 
        color: white !important; 
    }
    .header p { 
        margin: 10px 0 0 0; 
        color: #ffffff !important; 
        opacity: 0.9; 
    }
    .header-fallback {
        background-color: #f8f9fa;
        border: 2px solid #2c3e50;
        border-radius: 5px;
        padding: 15px;
        margin-bottom: 20px;
        text-align: center;
    }
    .header-fallback h2 {
        color: #2c3e50;
        margin: 0 0 10px 0;
        font-size: 20px;
    }
    .header-fallback p {
        color: #666;
        margin: 0;
        font-size: 12px;
    }
    .content { padding: 25px; }
    .section { 
        margin-bottom: 30px; 
        padding: 20px;
        border: 1px solid #e0e0e0;
        border-radius: 5px;
        background: #fdfdfd;
    }
    .section h2 { 
        color: #2c3e50; 
        margin: 0 0 15px 0; 
        font-size: 18px;
        border-bottom: 2px solid #3498db;
        padding-bottom: 8px;
    }
    .summary { 
        background: #ecf0f1; 
        padding: 15px; 
        border-radius: 5px; 
        margin-bottom: 20px; 
        display: flex;
        justify-content: space-around;
        text-align: center;
    }
    .summary div { flex: 1; }
    .summary .number { font-size: 24px; font-weight: bold; color: #2c3e50; }
    .summary .label { font-size: 12px; color: #7f8c8d; margin-top: 5px; }
    
    .job-definition-grid {
        /* Fallback for email clients that don't support grid */
        width: 100%;
        margin-top: 15px;
        /* Use table display for better email client support */
        display: table;
        table-layout: fixed;
        border-spacing: 20px 0;
    }
    
    /* Modern browsers will use grid, email clients will ignore this */
    @supports (display: grid) {
        .job-definition-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            border-spacing: 0;
        }
    }
    
    .job-type-group {
        background: white;
        border: 1px solid #ddd;
        border-radius: 5px;
        overflow: hidden;
        /* For email clients using table display */
        display: table-cell;
        vertical-align: top;
        width: 33.33%;
        /* Minimum width to prevent too much squishing */
        min-width: 300px;
    }
    
    /* Modern browsers using grid will override the table-cell display */
    @supports (display: grid) {
        .job-type-group {
            display: block;
            width: auto;
        }
    }
    
    /* Responsive behavior for narrow screens */
    @media screen and (max-width: 1000px) {
        .job-definition-grid {
            display: block !important;
            border-spacing: 0;
        }
        .job-type-group {
            display: block !important;
            width: 100% !important;
            margin-bottom: 20px;
        }
    }
    
    .job-type-header {
        background: #34495e;
        color: white;
        padding: 12px 15px;
        font-weight: bold;
        font-size: 14px;
    }
    
    .job-list {
        padding: 0;
        margin: 0;
    }
    
    .job-item {
        padding: 10px 15px;
        border-bottom: 1px solid #f0f0f0;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .job-item:last-child {
        border-bottom: none;
    }
    
    .job-name {
        flex: 1;
        font-weight: 500;
        color: #2c3e50;
        margin-right: 10px;
        word-break: break-word;
    }
    
    .job-status {
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 10px;
        font-weight: bold;
        min-width: 60px;
        text-align: center;
    }
    
    table { 
        width: 100%; 
        border-collapse: collapse; 
        margin: 15px 0;
        background: white;
    }
    th { 
        background: #34495e; 
        color: white; 
        padding: 12px 8px; 
        text-align: left; 
        font-weight: 600; 
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    td { 
        padding: 10px 8px; 
        border-bottom: 1px solid #e0e0e0; 
        font-size: 11px;
    }
    tr:hover { background-color: #f8f9fa; }
    tr:nth-child(even) { background-color: #fdfdfd; }
    
    .status-success { 
        color: #27ae60; 
        background: #d5f4e6; 
    }
    .status-failed { 
        color: #e74c3c; 
        background: #fdeaea; 
    }
    .status-skipped { 
        color: #f39c12; 
        background: #fef9e7; 
    }
    .status-running { 
        color: #2980b9; 
        background: #e3f2fd; 
    }
    .status-interrupted { 
        color: #8e44ad; 
        background: #f4ecf7; 
    }
    .status-not-run {
        color: #7f8c8d;
        background: #f8f9fa;
    }
    
    .footer { 
        background: #ecf0f1; 
        padding: 15px 25px; 
        font-size: 11px; 
        color: #7f8c8d; 
        border-radius: 0 0 8px 8px;
        text-align: center;
    }
    .no-data { 
        text-align: center; 
        padding: 40px; 
        color: #7f8c8d; 
        font-style: italic; 
    }
    
    @media screen and (max-width: 600px) {
        .container { margin: 10px; }
        .summary { flex-direction: column; }
        .summary div { margin-bottom: 15px; }
        .job-definition-grid { grid-template-columns: 1fr; }
        table { font-size: 10px; }
        th, td { padding: 6px 4px; }
    }
</style>
'@
    
    $jobDefinitionsHtml = ""
    $jobDefinitionsCount = if ($JobDefinitions) { 
        $JobDefinitions.Count 
    } 
    else { 
        0 
    }
    
    if ($jobDefinitionsCount -gt 0) {
        $jobsByType = $JobDefinitions | Group-Object TypeDisplay
        
        $jobGridHtml = ""
        foreach ($jobTypeGroup in $jobsByType) {
            $typeName = $jobTypeGroup.Name
            $typeJobs = $jobTypeGroup.Group | Sort-Object Name
            $typeJobsCount = if ($typeJobs) { 
                $typeJobs.Count 
            } 
            else { 
                0 
            }
            
            $jobItemsHtml = ""
            foreach ($job in $typeJobs) {
                $statusClass = switch ($job.LastExecutionStatus) {
                    'Success' { 'status-success' }
                    'Failed' { 'status-failed' }
                    'Skipped' { 'status-skipped' }
                    'Running' { 'status-running' }
                    'Interrupted' { 'status-interrupted' }
                    default { 'status-not-run' }
                }
                
                $statusText = if ($job.LastExecutionStatus -eq 'Not Run') { 
                    'Not Run' 
                } 
                else { 
                    $job.LastExecutionStatus 
                }
                
                $jobNameEncoded = [System.Net.WebUtility]::HtmlEncode($job.Name)
                
                $jobItemsHtml += @"
                <div class="job-item">
                    <div class="job-name" title="$jobNameEncoded">$jobNameEncoded</div>
                    <div class="job-status $statusClass">$statusText</div>
                </div>
"@
            }
            
            $jobGridHtml += @"
            <div class="job-type-group">
                <div class="job-type-header">$typeName ($typeJobsCount jobs)</div>
                <div class="job-list">
                    $jobItemsHtml
                </div>
            </div>
"@
        }
        
        $totalDefinedJobs = $jobDefinitionsCount
        $jobsRunArray = @($JobDefinitions | Where-Object { $_.LastExecutionStatus -ne 'Not Run' })
        $jobsRun = $jobsRunArray.Count
        $jobsNotRun = $totalDefinedJobs - $jobsRun
        $successfulJobsArray = @($JobDefinitions | Where-Object { $_.LastExecutionStatus -eq 'Success' })
        $successfulJobs = $successfulJobsArray.Count
        $failedJobsArray = @($JobDefinitions | Where-Object { $_.LastExecutionStatus -eq 'Failed' })
        $failedJobs = $failedJobsArray.Count
        $runningJobsArray = @($JobDefinitions | Where-Object { $_.LastExecutionStatus -eq 'Running' })
        $runningJobs = $runningJobsArray.Count
        $skippedJobsArray = @($JobDefinitions | Where-Object { $_.LastExecutionStatus -eq 'Skipped' })
        $skippedJobs = $skippedJobsArray.Count
        
        $jobsSummaryHtml = @"
<div class="summary">
    <div>
        <div class="number">$totalDefinedJobs</div>
        <div class="label">Defined Jobs</div>
    </div>
    <div>
        <div class="number" style="color: #2980b9;">$jobsRun</div>
        <div class="label">Executed (24h)</div>
    </div>
    <div>
        <div class="number" style="color: #27ae60;">$successfulJobs</div>
        <div class="label">Successful</div>
    </div>
    <div>
        <div class="number" style="color: #e74c3c;">$failedJobs</div>
        <div class="label">Failed</div>
    </div>
    <div>
        <div class="number" style="color: #2980b9;">$runningJobs</div>
        <div class="label">Running</div>
    </div>
    <div>
        <div class="number" style="color: #f39c12;">$skippedJobs</div>
        <div class="label">Skipped</div>
    </div>
    <div>
        <div class="number" style="color: #7f8c8d;">$jobsNotRun</div>
        <div class="label">Not Executed</div>
    </div>
</div>
"@
        
        $jobDefinitionsHtml = @"
<div class="section">
    <h2>Backup Job Definitions Overview</h2>
    <p>This section shows all configured backup jobs and their execution status within the last $TimeSpanHours hours.</p>
    $jobsSummaryHtml
    <div class="job-definition-grid">
        $jobGridHtml
    </div>
</div>
"@
    }
    
    $detailedLogsHtml = ""
    $backupJobsCount = if ($BackupJobs) { 
        $BackupJobs.Count 
    } 
    else { 
        0 
    }
    
    if ($backupJobsCount -gt 0) {
        $totalJobs = $backupJobsCount
        $successCount = 0
        $failedCount = 0
        $skippedCount = 0
        $runningCount = 0
        $interruptedCount = 0
        
        foreach ($job in $BackupJobs) {
            switch ($job.Status) {
                'Success' { $successCount++ }
                'Failed' { $failedCount++ }
                'Skipped' { $skippedCount++ }
                'Running' { $runningCount++ }
                'Interrupted' { $interruptedCount++ }
            }
        }
        
    # Build summary HTML with only non-zero counters
    $summaryItems = @()
    
    # Always show total
    $summaryItems += @"
    <div>
        <div class="number">$totalJobs</div>
        <div class="label">Execution Records</div>
    </div>
"@
    
    # Always show successful
    $summaryItems += @"
    <div>
        <div class="number" style="color: #27ae60;">$successCount</div>
        <div class="label">Successful</div>
    </div>
"@
    
    # Always show failed
    $summaryItems += @"
    <div>
        <div class="number" style="color: #e74c3c;">$failedCount</div>
        <div class="label">Failed</div>
    </div>
"@
    
    # Show running if > 0
    if ($runningCount -gt 0) {
        $summaryItems += @"
    <div>
        <div class="number" style="color: #2980b9;">$runningCount</div>
        <div class="label">Running</div>
    </div>
"@
    }
    
    # Show skipped only if > 0
    if ($skippedCount -gt 0) {
        $summaryItems += @"
    <div>
        <div class="number" style="color: #f39c12;">$skippedCount</div>
        <div class="label">Skipped</div>
    </div>
"@
    }
    
    # Show interrupted if > 0
    if ($interruptedCount -gt 0) {
        $summaryItems += @"
    <div>
        <div class="number" style="color: #8e44ad;">$interruptedCount</div>
        <div class="label">Interrupted</div>
    </div>
"@
    }
    
    $detailedSummaryHtml = @"
<div class="summary">
    $($summaryItems -join "`n    ")
</div>
"@
        
        $tableRows = ""
        foreach ($job in $BackupJobs) {
            $statusClass = switch ($job.Status) {
                'Success' { 'status-success' }
                'Failed' { 'status-failed' }
                'Skipped' { 'status-skipped' }
                'Running' { 'status-running' }
                'Interrupted' { 'status-interrupted' }
                default { '' }
            }
            
            $jobNameEncoded = [System.Net.WebUtility]::HtmlEncode($job.JobName)
            $startTimeFormatted = if ($job.StartTime) { 
                $job.StartTime.ToString("yyyy-MM-dd HH:mm:ss") 
            } 
            else { 
                'N/A' 
            }
            $endTimeFormatted = if ($job.EndTime) { 
                $job.EndTime.ToString("yyyy-MM-dd HH:mm:ss") 
            } 
            else { 
                'N/A' 
            }
            $errorMessageEncoded = if ($job.ErrorMessage) { 
                [System.Net.WebUtility]::HtmlEncode($job.ErrorMessage.Substring(0, [Math]::Min(100, $job.ErrorMessage.Length)))
            } 
            else { 
                '' 
            }
            
            $tableRows += @"
        <tr>
            <td>$jobNameEncoded</td>
            <td><span class="job-status $statusClass">$($job.Status)</span></td>
            <td>$startTimeFormatted</td>
            <td>$endTimeFormatted</td>
            <td>$($job.Duration)</td>
            <td>$errorMessageEncoded</td>
        </tr>
"@
        }
        
        $tableHtml = @"
<table>
    <thead>
        <tr>
            <th>Job Name</th>
            <th>Status</th>
            <th>Start Time</th>
            <th>End Time</th>
            <th>Duration</th>
            <th>Error Message</th>
        </tr>
    </thead>
    <tbody>
$tableRows
    </tbody>
</table>
"@
        
        $detailedLogsHtml = @"
<div class="section">
    <h2>Detailed Backup Execution Logs</h2>
    <p>This section shows detailed information about backup job executions within the last $TimeSpanHours hours.</p>
    $detailedSummaryHtml
    $tableHtml
</div>
"@
    } 
    else {
        $detailedLogsHtml = @"
<div class="section">
    <h2>Detailed Backup Execution Logs</h2>
    <div class="no-data">No backup execution records found in the specified time period.</div>
</div>
"@
    }
    
    $htmlReport = @"
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>$Title</title>
    $emailStyles
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$Title</h1>
            <p>Generated on $reportDate | Showing data from $fromDate to $reportDate</p>
        </div>
        <div class="content">
            $jobDefinitionsHtml
            $detailedLogsHtml
        </div>
        <div class="footer">
            <p>This is an automated report from Xen Orchestra backup monitoring system.</p>
            <p>For technical support, contact your IT administrator.</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $htmlReport
}

function Send-EmailReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlContent,
        
        [Parameter(Mandatory = $true)]
        [string]$SmtpServer,
        
        [Parameter(Mandatory = $true)]
        [int]$SmtpPort,
        
        [Parameter(Mandatory = $true)]
        [bool]$SmtpUseSsl,
        
        [Parameter(Mandatory = $true)]
        [string]$EmailFrom,
        
        [Parameter(Mandatory = $true)]
        [string[]]$EmailTo,
        
        [Parameter(Mandatory = $true)]
        [string]$EmailSubject,
        
        [PSCredential]$SmtpCredential
    )
    
    try {
        Write-Log "Preparing email report..." -Level Information
        
        $mailParams = @{
            SmtpServer = $SmtpServer
            Port = $SmtpPort
            UseSsl = $SmtpUseSsl
            From = $EmailFrom
            To = $EmailTo
            Subject = $EmailSubject
            Body = $HtmlContent
            BodyAsHtml = $true
            Encoding = [System.Text.Encoding]::UTF8
        }
        
        if ($SmtpCredential) {
            $mailParams.Credential = $SmtpCredential
        }
        
        Write-Log "Sending email report to: $($EmailTo -join ', ')" -Level Information
        Send-MailMessage @mailParams
        
        Write-Log "Email report sent successfully!" -Level Information
        return $true
    }
    catch {
        Write-Log "Failed to send email report: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Show-ScriptHelp {
    [CmdletBinding()]
    param()
    
    $helpText = @"

=============================================================================
                 XEN ORCHESTRA BACKUP REPORT GENERATOR
=============================================================================

DESCRIPTION:
    This script connects to a Xen Orchestra server to retrieve comprehensive 
    backup job information, including both job definitions and execution logs.
    It generates detailed HTML reports and can optionally send them via email.

BASIC USAGE:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "your-api-token"

AUTHENTICATION (Choose one method):
    -ApiToken <string>      : Provide API token directly as parameter
    -ApiTokenFile <path>    : Path to file containing encrypted API token

REQUIRED PARAMETERS:
    -XenOrchestraUrl <url>  : Base URL of your Xen Orchestra server
                             Example: "https://xo.company.com"

OPTIONAL PARAMETERS:

  LOGGING & OUTPUT:
    -LogFile <path>         : Path for script execution log file
                             Default: .\logs\XOBackupReport_YYYYMMDD.log
    -OutputPath <path>      : Path to save HTML report file
                             If not specified, returns HTML content

  REPORT FILTERING:
    -TimeSpanHours <int>    : Hours back to query for backup jobs (1-168)
                             Default: 24
    -IncludeSuccess <bool>  : Include successful backups in report
                             Default: $true
    -IncludeFailures <bool> : Include failed backups in report  
                             Default: $true
    -IncludeSkipped <bool>  : Include skipped backups in report
                             Default: $false

  CONNECTION SETTINGS:
    -MaxRetries <int>       : Number of API call retry attempts
                             Default: 3
    -TimeoutSeconds <int>   : API call timeout in seconds
                             Default: 30
    -SkipCertificateCheck   : Skip SSL certificate validation
                             Use for self-signed certificates

  DEBUGGING:
    -EnableDebugLogging     : Enable detailed debug output
                             Useful for troubleshooting API issues

  EMAIL SETTINGS:
    -SendEmail              : Send report via email
    -SmtpServer <string>    : SMTP server hostname
    -SmtpPort <int>         : SMTP port number (Default: 25)
    -SmtpUseSsl <bool>      : Use SSL/TLS for SMTP (Default: $false)
    -EmailFrom <string>     : Sender email address
    -EmailTo <string[]>     : Recipient email address(es)
    -EmailSubject <string>  : Email subject line
    -SmtpCredential <cred>  : SMTP authentication credentials

EXAMPLES:

  Basic report generation:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "abc123"

  Save report to file:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiTokenFile "C:\secure\token.txt" -OutputPath "C:\Reports\backup-report.html"

  Include skipped jobs and extend time range:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "abc123" -TimeSpanHours 48 -IncludeSkipped $true

  Send email report:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "abc123" -SendEmail -SmtpServer "mail.company.com" -EmailFrom "noreply@company.com" -EmailTo "admin@company.com"

  Debug mode with certificate bypass:
    .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiToken "abc123" -SkipCertificateCheck -EnableDebugLogging

WHAT THE SCRIPT DOES:

  1. AUTHENTICATION
     - Connects to Xen Orchestra using REST API
     - Supports both direct token and encrypted token file methods
     - Tests authentication before proceeding

  2. JOB DEFINITIONS
     - Retrieves all configured backup jobs (VM, Metadata, Mirror types)
     - Shows job status, settings, and configuration details
     - Provides overview of all backup job definitions

  3. EXECUTION LOGS  
     - Queries backup execution logs for specified time period
     - Filters results based on success/failure/skip preferences
     - Correlates job definitions with recent execution history

  4. REPORT GENERATION
     - Creates comprehensive HTML report with:
       * Executive summary with statistics
       * Job definitions overview by type
       * Detailed execution logs table
       * Professional styling for email/web viewing

  5. OUTPUT OPTIONS
     - Save to HTML file for local viewing
     - Send via email with full HTML formatting
     - Return content for pipeline processing

API TOKEN SECURITY:

  For enhanced security, use -ApiTokenFile instead of -ApiToken:
  
  1. Create encrypted token file:
     PS> Read-Host "Enter API Token" -AsSecureString | ConvertFrom-SecureString | Out-File "C:\secure\xo-token.txt"
  
  2. Use in script:
     PS> .\Get-XenOrchestraBackupReport.ps1 -XenOrchestraUrl "https://xo.company.com" -ApiTokenFile "C:\secure\xo-token.txt"

TROUBLESHOOTING:

  SSL Certificate Issues:
    Add -SkipCertificateCheck parameter
  
  Authentication Failures:
    - Verify API token is valid
    - Check Xen Orchestra URL is correct
    - Try -EnableDebugLogging for detailed error info
  
  No Data Returned:
    - Increase -TimeSpanHours value
    - Set -IncludeSkipped $true to see all job types
    - Verify backup jobs exist and have run recently

  Connection Timeouts:
    - Increase -TimeoutSeconds value
    - Check network connectivity to Xen Orchestra server

NOTES:
    - Script requires PowerShell 5.1 or higher
    - API token requires sufficient permissions in Xen Orchestra
    - Email functionality requires access to SMTP server
    - HTML reports are optimized for modern email clients and browsers


=============================================================================

"@
    
    Write-Host $helpText -ForegroundColor Cyan
    exit 0
}


# Main script logic
if ($Help) {
    Show-ScriptHelp
    return
}

try {
    Write-Host "=== Enhanced Xen Orchestra Backup Report Generator ===" -ForegroundColor Cyan
    Write-Host "Starting backup job definitions and execution status retrieval..." -ForegroundColor Green
    
    if ($SendEmail) {
        if (-not $SmtpServer) {
            throw "SmtpServer parameter is required when SendEmail is specified"
        }
        if (-not $EmailFrom) {
            throw "EmailFrom parameter is required when SendEmail is specified"
        }
        if (-not $EmailTo) {
            throw "EmailTo parameter is required when SendEmail is specified"
        }
        if (-not $EmailSubject) {
            $EmailSubject = "Xen Orchestra Backup Report - $(Get-Date -Format 'yyyy-MM-dd')"
        }
    }
    
    if (-not $LogFile) {
        $logDir = Join-Path $PSScriptRoot "logs"
        $LogFile = Join-Path $logDir "XOBackupReport_$(Get-Date -Format 'yyyyMMdd').log"
    }
    $script:LogPath = $LogFile
    
    Write-Log "Script execution started" -Level Information
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
    
    # Get the API token from the specified source
    $resolvedApiToken = Get-ApiTokenFromSource -Token $ApiToken -TokenFile $ApiTokenFile
    
    if (-not $XenOrchestraUrl -or -not $resolvedApiToken) {
        throw "XenOrchestraUrl and either ApiToken or ApiTokenFile are required parameters"
    }
    
    $XenOrchestraUrl = $XenOrchestraUrl.TrimEnd('/')
    $baseApiUrl = "$XenOrchestraUrl/rest/v0"
    
    Write-Log "Connecting to Xen Orchestra at: $XenOrchestraUrl" -Level Information
    
    $headers = @{
        'Accept' = 'application/json'
        'User-Agent' = 'PowerShell-XenOrchestra-BackupMonitor/2.0'
        'Cookie' = "authenticationToken=$resolvedApiToken"
    }
    
    Write-Log "Testing authentication..." -Level Information
    
    try {
        $null = Invoke-XenOrchestraApi -Uri "$baseApiUrl/vms" -Headers $headers -TimeoutSec $TimeoutSeconds -MaxRetries 1 -SkipCertificateCheck:$SkipCertificateCheck
        Write-Log "Authentication successful using cookie method" -Level Information
    }
    catch {
        Write-Log "Cookie authentication failed, trying Bearer token..." -Level Debug
        $headers['Authorization'] = "Bearer $resolvedApiToken"
        $headers.Remove('Cookie')
        
        try {
            $null = Invoke-XenOrchestraApi -Uri "$baseApiUrl/vms" -Headers $headers -TimeoutSec $TimeoutSeconds -MaxRetries 1 -SkipCertificateCheck:$SkipCertificateCheck
            Write-Log "Authentication successful using Bearer token" -Level Information
        }
        catch {
            throw "Failed to authenticate with Xen Orchestra using provided API token"
        }
    }
    
    # Clear the resolved token variable for security
    $resolvedApiToken = $null
    [System.GC]::Collect()
    
    Write-Log "=== Retrieving Backup Job Definitions ===" -Level Information
    $jobDefinitions = Get-BackupJobDefinitions -BaseApiUrl $baseApiUrl -BaseServerUrl $XenOrchestraUrl -Headers $headers -TimeoutSec $TimeoutSeconds -MaxRetries $MaxRetries -SkipCertificateCheck:$SkipCertificateCheck -EnableDebugLogging:$EnableDebugLogging
    
    if (-not $jobDefinitions) {
        $jobDefinitions = @()
        Write-Log "No backup job definitions were successfully retrieved" -Level Warning
    }
    
    $endTime = Get-Date
    $startTime = $endTime.AddHours(-$TimeSpanHours)
    $startTimestamp = [long]([DateTimeOffset]$startTime).ToUnixTimeMilliseconds()
    
    Write-Log "=== Retrieving Backup Execution Logs ===" -Level Information
    Write-Log "Querying backup jobs from $($startTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level Information
    
    $apiUrl = "$baseApiUrl/backup/logs/"
    $queryParams = @(
        "filter=start:>=$startTimestamp",
        "fields=id,jobId,jobName,start,status,end,result",
        "limit=500"
    )
    $fullUrl = $apiUrl + "?" + ($queryParams -join '&')
    
    Write-Log "API Request: GET $fullUrl" -Level Debug
    Write-Log "Using server-side filtering for timestamp >= $startTimestamp ($($startTime.ToString('yyyy-MM-dd HH:mm:ss')))" -Level Information
    
    $backupLogs = Invoke-XenOrchestraApi -Uri $fullUrl -Headers $headers -TimeoutSec $TimeoutSeconds -MaxRetries $MaxRetries -SkipCertificateCheck:$SkipCertificateCheck
    
    if ($EnableDebugLogging) {
        Write-Log "DEBUG: Response type: $($backupLogs.GetType().FullName)" -Level Debug
        Write-Log "DEBUG: Response is array: $($backupLogs -is [array])" -Level Debug
        if ($backupLogs -is [array]) {
            Write-Log "DEBUG: Array count: $($backupLogs.Count)" -Level Debug
        }
    }
    
    if (-not ($backupLogs -is [array])) {
        if ($backupLogs) {
            $backupLogs = @($backupLogs)
        } 
        else {
            $backupLogs = @()
        }
    }
    
    Write-Log "Retrieved $(@($backupLogs).Count) backup log entries from server-side filtering" -Level Information
    
    $backupJobs = @()
    $allConvertedJobs = @()

    if ($backupLogs -and $backupLogs.Count -gt 0) {
        # Convert all jobs first (including skipped ones)
        $allConvertedJobs = @($backupLogs) | ConvertTo-BackupJobObject -EnableDebugLogging:$EnableDebugLogging
        
        Write-Log "Converted $($allConvertedJobs.Count) backup job logs" -Level Information
        
        # Filter jobs for detailed report based on user preferences
        $filteredJobs = @()
        foreach ($job in $allConvertedJobs) {
            $shouldInclude = $false
            
            if ($job.Status -eq 'Success' -and $IncludeSuccess) {
                $shouldInclude = $true
            }
            elseif ($job.Status -eq 'Failed' -and $IncludeFailures) {
                $shouldInclude = $true
            }
            elseif ($job.Status -eq 'Skipped' -and $IncludeSkipped) {
                $shouldInclude = $true
            }
            elseif ($job.Status -in @('Interrupted', 'Unknown', 'Error', 'Pending', 'Running')) {
                $shouldInclude = $true
            }
            
            if ($shouldInclude) {
                $filteredJobs += $job
            }
        }
        
        $backupJobs = $filteredJobs
        Write-Log "Filtered to $($backupJobs.Count) jobs matching criteria for detailed report" -Level Information
    } 
    else {
        Write-Log "No backup log entries found within the specified time range" -Level Warning
    }

    Write-Log "=== Correlating Job Definitions with Execution Logs ===" -Level Information
    # Use ALL converted jobs (including skipped) for correlation to get accurate statuses
    $enrichedJobDefinitions = Merge-JobDefinitionsWithLogs -JobDefinitions $jobDefinitions -BackupLogs $allConvertedJobs -EnableDebugLogging:$EnableDebugLogging
    
    if (-not $enrichedJobDefinitions) {
        $enrichedJobDefinitions = @()
    } 
    elseif (-not ($enrichedJobDefinitions -is [array])) {
        $enrichedJobDefinitions = @($enrichedJobDefinitions)
    }
    
    $successCount = 0
    $failedCount = 0
    $skippedCount = 0
    $runningCount = 0
    $interruptedCount = 0
    
    foreach ($job in $backupJobs) {
        switch ($job.Status) {
            'Success' { $successCount++ }
            'Failed' { $failedCount++ }
            'Skipped' { $skippedCount++ }
            'Running' { $runningCount++ }
            'Interrupted' { $interruptedCount++ }
        }
    }
    
    $summary = @{
        Total = $backupJobs.Count
        Success = $successCount
        Failed = $failedCount
        Skipped = $skippedCount
        Running = $runningCount
        Interrupted = $interruptedCount
    }
    
    Write-Log "=== Summary Statistics ===" -Level Information
    Write-Log "Job Definitions: $(if ($enrichedJobDefinitions) { $enrichedJobDefinitions.Count } else { 0 })" -Level Information
    Write-Log "Execution Records - Total: $($summary.Total), Success: $($summary.Success), Failed: $($summary.Failed), Running: $($summary.Running), Skipped: $($summary.Skipped), Interrupted: $($summary.Interrupted)" -Level Information
    
    Write-Log "=== Generating Enhanced HTML Report ===" -Level Information
    $htmlReport = ConvertTo-HtmlReport -JobDefinitions $enrichedJobDefinitions -BackupJobs $backupJobs -Title "Xen Orchestra Backup Report" -TimeSpanHours $TimeSpanHours
    
    if ($SendEmail) {
        Send-EmailReport -HtmlContent $htmlReport -SmtpServer $SmtpServer -SmtpPort $SmtpPort -SmtpUseSsl $SmtpUseSsl -EmailFrom $EmailFrom -EmailTo $EmailTo -EmailSubject $EmailSubject -SmtpCredential $SmtpCredential
    }
    
    if ($OutputPath) {
        try {
            $outputDir = Split-Path $OutputPath -Parent
            if ($outputDir -and -not (Test-Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            }
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
            Write-Log "HTML report saved to: $OutputPath" -Level Information
            Write-Host "Enhanced report saved successfully to: $OutputPath" -ForegroundColor Green
        }
        catch {
            Write-Log "Failed to save report to file: $_" -Level Error
            throw "Unable to save report: $_"
        }
    }
    elseif (-not $SendEmail) {
        Write-Log "Returning HTML report content" -Level Information
        return $htmlReport
    }
    
    Write-Log "Script execution completed successfully" -Level Information
    Write-Host "Enhanced backup report generation completed successfully!" -ForegroundColor Green
}
catch {
    $errorMessage = "Script execution failed: $($_.Exception.Message)"
    Write-Log $errorMessage -Level Error
    Write-Host $errorMessage -ForegroundColor Red
    
    if ($_.ScriptStackTrace) {
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    }
    
    throw
}
finally {
    Write-Log "Script cleanup completed" -Level Debug
}