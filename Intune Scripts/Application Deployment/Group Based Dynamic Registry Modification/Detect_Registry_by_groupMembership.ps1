<#
.SYNOPSIS
    Detects if registry settings match the expected configuration based on the group memberships of the currently logged-in user, fetched from Microsoft Graph API.

.DESCRIPTION
    This script retrieves the group memberships of the currently logged-in user from Microsoft Entra ID using Microsoft Graph API. 
    It checks if the registry settings match the expected values for these groups, verifying the `FilePath` registry value for the user profile based on membership. 
    The script dynamically retrieves the user's SID, loading their registry hive if needed, and logs output for successful verification or mismatches. 
    A static set of registry values is also checked and compared for all users.

.NOTES
    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Email: Sebastian.Markdanner@chanceofsecurity.com
    Version: 1.3
    Date: 12-11-2024
#>

function Log {
    # Logs a message with a timestamp
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] [String] $message
    )

    $ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
    Write-Output "$ts $message"
}

# Configurable Variables
$tenantId       = "YOUR_TENANT_ID"                                          # Microsoft tenant ID
$clientId       = "YOUR_CLIENT_ID"                                          # Microsoft client ID for API access
$clientSecret   = "YOUR_CLIENT_SECRET"                                      # Secret for API authentication
$resource       = "https://graph.microsoft.com"                             # Microsoft Graph API resource URL
$graphApiUrl    = "https://graph.microsoft.com/v1.0"                        # Microsoft Graph API base URL
$SIDFilePath    = "C:\ProgramData\Microsoft\<company>\SID.txt"              # Path to save the user's SID
$domain         = "@yourdomain.com"                                         # Domain suffix to complete UPN
$regPath        = "Software\ExampleApp"                                     # Registry path for checking values
$logPath        = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs" # Directory for log file
$logFile        = "PS-<LOGFILEPATH>-v1.0.log"                               # Log filename

# Start logging
Start-Transcript -Path "$($logPath)\$logFile" -Append

# Group-to-FilePath mappings based on user group membership
$GroupToFilePath = @{
    'Group01' = "D:\Example\Path"
    'Group02' = "H:\Example\Path"
    'Group03' = "D:\Example\Path\SubPath"
    'Group04' = "D:\Example"
    'Group05' = "P:\Example\Path"
}

# Function to read the user's SID from a specified file
function Get-SIDFromFile {
    param ([string]$SIDFilePath)

    if (Test-Path $SIDFilePath) {
        $SID = Get-Content -Path $SIDFilePath -ErrorAction Stop
        if (-not [string]::IsNullOrEmpty($SID)) {
            return $SID.Trim()
        } else {
            Log "SID file is empty."
            exit 1
        }
    } else {
        Log "SID file not found at: $SIDFilePath"
        exit 1
    }
}

# Function to obtain an access token for Microsoft Graph API
function Get-GraphToken {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret,
        [string]$resource
    )

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = "$resource/.default"
    }

    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
    return $response.access_token
}

# Function to retrieve the UPN (User Principal Name) of the currently logged-in user
function Get-LoggedInUserUPN {
    $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName)
    if ($loggedInUser -and $loggedInUser -like "*\*") {
        $loggedInUser = $loggedInUser.Split('\')[1] + $domain
    }
    return $loggedInUser
}

# Function to load the user's registry hive if necessary
function Load-UserRegistryHive {
    param ([string]$UserSID)

    if (-not (Test-Path "HKU\$UserSID")) {
        $userProfilePath = (Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.SID -eq $UserSID }).LocalPath
        $regHivePath = "$userProfilePath\NTUSER.DAT"

        if (Test-Path $regHivePath) {
            reg.exe load "HKU\$UserSID" $regHivePath
            Log "User registry hive loaded for SID: $UserSID"
        } else {
            Log "Could not find NTUSER.DAT for user: $UserSID"
            exit 1
        }
    } else {
        Log "User registry hive already loaded for SID: $UserSID"
    }
}

# Retrieve Microsoft Graph API token
$token = Get-GraphToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret -resource $resource

# Retrieve the current logged-in user's UPN
$userPrincipalName = Get-LoggedInUserUPN

if (-not $userPrincipalName) {
    Log "No logged-in user found, exiting."
    exit 1
}

Log "Retrieved UPN: $userPrincipalName"

# URL Encode the UPN for use in API requests
$encodedUpn = [System.Web.HttpUtility]::UrlEncode($userPrincipalName)

# Query Microsoft Graph for group memberships of the user
$headers = @{
    Authorization = "Bearer $token"
}
$graphApiUrlWithUpn = "$graphApiUrl/users/$encodedUpn/memberOf"

try {
    $graphResponse = Invoke-RestMethod -Uri $graphApiUrlWithUpn -Headers $headers -Method Get
    $userGroups = $graphResponse.value | ForEach-Object { $_.displayName }
    Log "User is a member of $userGroups"
} catch {
    Log "Failed to retrieve group memberships from Microsoft Graph. Error: $_"
    exit 1
}

# Retrieve user's SID from the SID file
$userSID = Get-SIDFromFile -SIDFilePath $SIDFilePath

if (-not $userSID) {
    Log "No SID was found in the file, exiting."
    exit 1
}

Log "Retrieved User SID from file: $userSID"

# Load the user's registry hive if required
Load-UserRegistryHive -UserSID $userSID

# Check if the registry key for the application exists and matches expected values
try {
    $regKeyExists = Get-ItemProperty -Path "Registry::HKU\$userSID\$regPath" -ErrorAction Stop
    Log "Registry key exists: HKU\$userSID\$regPath"

    # Retrieve and verify the FilePath value from the registry
    $regFilePath = $regKeyExists.FilePath
    $expectedFilePath = $null
    $groupMatched = $false

    # Determine the expected file path based on the user's group memberships
    foreach ($group in $userGroups) {
        if ($GroupToFilePath.ContainsKey($group)) {
            $expectedFilePath = $GroupToFilePath[$group]
            $groupMatched = $true
        }
    }

    # Verify if the registry FilePath matches the expected file path
    if ($regFilePath -and $groupMatched -and $regFilePath -eq $expectedFilePath) {
        Log "Registry key and FilePath are correctly set."
        Write-Output "Success!"
    } else {
        Log "Mismatch in FilePath. Expected: $expectedFilePath, Found: $regFilePath."
        exit 1
    }

} catch {
    Log "Registry key does not exist: HKU\$userSID\$regPath. Error: $_"
    exit 1
}

# Successful validation
Log "Validation successful."
Write-Output "Success!"
Stop-Transcript
exit 0
