<#
.SYNOPSIS
    Fetches group membership information for the currently logged-in user from Microsoft Graph API and configures registry settings based on group memberships.

.DESCRIPTION
    This script leverages the Microsoft Graph API to retrieve the group memberships of the logged-in user within Microsoft Entra ID. 
    Based on these group memberships, the script applies specific registry values associated with each group. Additionally, the 
    user's SID is dynamically retrieved and saved to a specified file location, allowing for reuse for detection. 
    Static registry values are also applied regardless of group membership.

.NOTES
    Author: Sebastian Flæng Markdanner
    Website: https://chanceofsecurity.com
    Email: Sebastian.Markdanner@chanceofsecurity.com
    Version: 1.1
    Date: 12-11-2024
#>

# Configurable Variables. Modify as needed

$tenantId           = "YOUR_TENANT_ID"                              # Microsoft tenant ID
$clientId           = "YOUR_CLIENT_ID"                              # Microsoft client ID for API access
$clientSecret       = "YOUR_CLIENT_SECRET"                          # Secret for API authentication
$resource           = "https://graph.microsoft.com"                 # Microsoft Graph API resource URL
$graphApiUrl        = "https://graph.microsoft.com/v1.0"            # Microsoft Graph API base URL
$SIDFilePath        = "C:\ProgramData\Microsoft\<company>\SID.txt"  # Path to save the user's SID
$domain             = "@yourdomain.com"                             # Domain suffix to complete UPN
$regPath            = "Software\ExampleApp"                         # Registry path for setting values

# Group-to-FilePath Mappings based on user group membership. Modify as needed.
$GroupToFilePath = @{
    'Group01' = "D:\Example\Path"
    'Group02' = "H:\Example\Path"
    'Group03' = "D:\Example\Path\SubPath"
    'Group04' = "D:\Example"
    'Group05' = "P:\Example\Path"
}

# Static Registry Values to be Set
$StaticRegValues = @{
    "StaticKey01" = "true"
    "StaticKey02" = "true"
    "StaticKey03" = "false"
    "StaticKey04" = "false"
    "StaticKey05" = "false"
}

# Function to load the user's registry hive, set values, and unload it using reg.exe
function Set-UserRegistryValues {
    param (
        [string]$UserSID,
        [string]$FilePath
    )

    # Retrieve the user profile path dynamically based on SID
    $userProfilePath = Get-UserProfilePath -UserSID $UserSID
    if (-not $userProfilePath) {
        Write-Log "Unable to retrieve user profile path for SID: $UserSID"
        return
    }

    # Define path to the user's NTUSER.DAT file, used to load their registry hive
    $regHivePath = "$userProfilePath\NTUSER.DAT"

    # Load the user registry hive into HKEY_USERS if not already loaded
    if (-not (Test-Path "HKU\$UserSID")) {
        reg.exe load "HKU\$UserSID" $regHivePath
    }

    # Registry key path for user settings under HKEY_USERS
    $RegKey = "HKU\$UserSID\$regPath"

    # Initialize a new hashtable for registry values and add static values from $StaticRegValues
    $RegValues = @{}
    $StaticRegValues.GetEnumerator() | ForEach-Object { $RegValues[$_.Key] = $_.Value }
    
    # Add the dynamic file path based on group membership to the registry values
    $RegValues["DynamicFilePath"] = $FilePath

    # Ensure the registry key exists
    reg.exe add "$RegKey" /f

    # Create or modify each registry property using reg.exe, based on the values in $RegValues
    foreach ($item in $RegValues.GetEnumerator()) {
        $name = $item.Key
        $value = $item.Value

        # Check if the registry value exists before adding or modifying
        Write-Host "Checking if registry key: $name exists"
        $regQuery = reg.exe query "$RegKey" /v $name 2>&1

        if ($regQuery -like "*ERROR*") {
            # If the registry value does not exist, add it
            Write-Host "Adding registry key: $name with value: $value"
            reg.exe add "$RegKey" /v $name /t REG_SZ /d $value /f
        } else {
            # If the registry value exists, modify it
            Write-Host "Modifying existing registry key: $name with new value: $value"
            reg.exe add "$RegKey" /v $name /t REG_SZ /d $value /f
        }
    }

    Write-Log "Registry values applied successfully for FilePath: $FilePath"
}

# Function to retrieve the UPN (User Principal Name) of the currently logged-in user
function Get-LoggedInUserUPN {
    # Use WMI to get the currently logged-in user's information
    $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName)
    
    if ($loggedInUser -and $loggedInUser -like "*\*") {
        # If username is in domain\username format, convert to UPN format
        $loggedInUser = $loggedInUser.Split('\')[1] + $domain
    }
    
    return $loggedInUser
}

# Function to retrieve the SID of the logged-on user
function Get-LoggedOnUserSID {
    # Retrieve all logged-on users
    $loggedOnUsers = Get-LoggedOnUser
    
    # Filter to get the active or console session user
    $activeUser = $loggedOnUsers | Where-Object { $_.IsActiveUserSession -eq $true }
    
    if ($activeUser) {
        return $activeUser.SID
    } else {
        Write-Log "No active user session found."
        return $null
    }
}

# Function to save the user's SID to a specified file path
function Save-SIDToFile {
    param (
        [string]$UserSID,
        [string]$filePath
    )

    try {
        # Extract the directory path from the file path
        $directoryPath = Split-Path -Path $filePath -Parent

        # Check if the directory exists, and create it if necessary
        if (-not (Test-Path -Path $directoryPath)) {
            Write-Log "Directory does not exist, creating: $directoryPath"
            New-Item -Path $directoryPath -ItemType Directory -Force
        }

        # Save the SID to the specified file
        Write-Log "Saving SID to file: $filePath"
        $UserSID | Out-File -FilePath $filePath -Force
        Write-Log "Successfully saved SID: $UserSID to $filePath"
    } catch {
        Write-Log "Failed to save SID to file: $($_.Exception.Message)"
    }
}

# Retrieve Microsoft Graph API token using service principal credentials
$token = Get-GraphToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret -resource $resource

# Retrieve the UPN of the currently logged-in user
$userPrincipalName = Get-LoggedInUserUPN

if (-not $userPrincipalName) {
    Write-Log "No logged-in user found, exiting."
    exit 1
}

Write-Log "Retrieved UPN: $userPrincipalName"

# URL Encode the UPN to include in API requests
$encodedUpn = [System.Web.HttpUtility]::UrlEncode($userPrincipalName)

# Query Microsoft Graph for the user's group memberships
$headers = @{
    Authorization = "Bearer $token"
}

$graphApiUrlWithUpn = "$graphApiUrl/users/$encodedUpn/memberOf"
Write-Log "Graph API URL: $graphApiUrlWithUpn"

try {
    $graphResponse = Invoke-RestMethod -Uri $graphApiUrlWithUpn -Headers $headers -Method Get
    $userGroups = $graphResponse.value | ForEach-Object { $_.displayName }
    Write-Log "User is a member of the following groups: $($userGroups -join ', ')"
} catch {
    Write-Log "Failed to retrieve group memberships from Microsoft Graph. Error: $($_.Exception.Message)"
}

# Retrieve the SID of the logged-in user and save it to a file
$userSID = Get-LoggedOnUserSID
Write-Log "Retrieved user SID: $userSID"

# Save SID to the specified file if it was successfully retrieved
if ($userSID) {
    Save-SIDToFile -UserSID $userSID -FilePath $SIDFilePath
    Write-Log "SID saved to $SIDFilePath"
} else {
    Write-Log "No SID was found to save."
}

# Loop through the user's groups and apply the appropriate registry values
foreach ($group in $userGroups) {
    if ($GroupToFilePath.ContainsKey($group)) {
        $filePath = $GroupToFilePath[$group]
        Write-Log "Applying registry changes for group: $group, FilePath: $filePath"

        # Set the registry values for the application based on the user's SID
        Set-UserRegistryValues -UserSID $userSID -FilePath $filePath
    }
}