# Collect Azure RBAC roles and Administrator roles
# Authored by: Jonatan Borg & Sebastian Markdanner / extri:co

########################################################################################################

# Prerequisites:
# Service Principal needs Reader role for the subscriptions to read RBAC roles.
#
# Graph API Application permissions:
# Application.Read.All
# AuditLog.Read.All
# Directory.Read.All
# PrivilegedAccess.Read.AzureAD
# RoleManagement.Read.All
# User.Read.All
# Mail.Send *Make sure to set the permission scope*
#
# Powershell modules:
# AzureAD
# Az.Accounts
# Az.Resources
# Microsoft.Graph.Identity.DirectoryManagement
# Microsoft.Graph.Authentication
# Microsoft.Graph.User.Actions
# ImportExcel

########################################################################################################

# Service Principal RBAC role for reading assignments
# $Subscriptions = Get-AzSubscription
# $servicePrincipal = Get-AzADServicePrincipal -ApplicationId $ClientId
# foreach ($sub in $Subscriptions) {
#     $roleAssignment = Get-AzRoleAssignment -ObjectId $servicePrincipal.Id -RoleDefinitionName "Reader" -scope "/subscriptions/$Sub"
#     if (!($roleAssignment)){
#        New-AzRoleAssignment -ObjectId $servicePrincipal.Id -RoleDefinitionName "Reader" -scope "/subscriptions/$Sub"
#     }
# }

########################################################################################################

# * Setting permission scope for Mail.Send:
# Create a Mail-Enabled Security Group, and add the identity that the Mail.Send permission should allow access to.
# Connect-ExchangeOnline
# New-DistributionGroup -name "SMTP Graph" -alias "smtp-graph" -Type security
# Set-DistributionGroup "SMTP Graph" -EmailAddresses SMTP:smtp-graph@sport24.dk -HiddenFromAddressListsEnabled $true
# Add-DistributionGroupMember -Identity "SMTP Graph" -Member username@email.com
# New-ApplicationAccessPolicy -AppId <serviceprincipalClientID> -PolicyScopeGroupId <mail-enabled-security-group@tenant.com> -AccessRight RestrictAccess -Description "Restrict this app to members of the group <group name>"

########################################################################################################

# Parameters
param (
    [Parameter(Mandatory=$true)][string]$TenantId, # root domain of tenant
    [Parameter(Mandatory=$true)][string]$ClientId, #the GUID of your app. For best result, use app with Directory.Read.All scope granted. For PIM use RoleManagement.Read.Directory
    [Parameter(Mandatory=$true)][string]$Client_secret, #client secret for the app
    [bool]$SaveFiles = $true,
    [bool]$PimRoles = $true,
    [string]$outDir = ("C:\Temp"),
    [Parameter(Mandatory=$true)][bool]$localRun = $true,
    [string]$mailFrom = $null,
    [string]$mailTo,
    [string]$mailSubject = ("Admin Roles overview"),
    [string]$mailAttachment = ("Admin-RBAC-roles-overview"),
    [string]$mailAttachment2 = ("Admin-M365-roles-overview")
)

function Get-GraphData {
    param($uri, $authHeader)
    $data = @()
    do {
        $result = Invoke-WebRequest -Uri $uri -Verbose:$VerbosePreference -ErrorAction Stop -Headers $authHeader

        if ($null -eq $result.Content) {
            Write-Host "Result content is null."
            return $null
        }

        $contentAsJson = $result.Content | ConvertFrom-Json

        if ($null -eq $contentAsJson.Value) {
            Write-Host "No data found at this URI."
            return $null
        }

        $uri = $contentAsJson.'@odata.nextLink'
        Start-Sleep -Milliseconds 500
        $data += $contentAsJson.Value
    } while ($uri)
    return $data
}

# Define the required module names
$requiredModules = @("AzureAD", "Az.Accounts", "Az.Resources", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Authentication", "Microsoft.Graph.Users.Actions", "ImportExcel")

# Check if any required module is not installed
$modulesToInstall = $requiredModules | Where-Object { -not (Get-Module -ListAvailable | Where-Object { $_.Name -eq $_ }) }

if ($modulesToInstall) {
    # Check for administrator rights
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script requires administrator rights to install the required modules. Please run the script as an administrator."
        exit
    }
}

Write-Progress -Activity "Installing and importing required modules" -Status "Starting" -PercentComplete 0
foreach ($module in $requiredModules) {
    Write-Progress -Activity "Installing and importing required modules" -Status "Checking for module '$module'" -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
    if ($module -eq "AzureAD") {
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq "AzureADPreview" }) {
            Write-Progress -Activity "Installing and importing required modules" -Status "Module 'AzureADPreview' is already installed. Skipping installation of 'AzureAD'" -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
            if (-not (Get-Module | Where-Object { $_.Name -eq "AzureADPreview" })) {
                Write-Progress -Activity "Installing and importing required modules" -Status "Importing module 'AzureADPreview'" -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
                Import-Module -Name AzureADPreview
            }
            continue
        }
    } elseif (-not (Get-Module -ListAvailable | Where-Object { $_.Name -eq $module })) {
        Write-Progress -Activity "Installing and importing required modules" -Status "Module '$module' is not installed. Installing..." -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Progress -Activity "Installing and importing required modules" -Status "Module '$module' is already installed." -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
    }
    if (-not (Get-Module | Where-Object { $_.Name -eq $module })) {
        Write-Progress -Activity "Installing and importing required modules" -Status "Importing module '$module'" -PercentComplete (($requiredModules.IndexOf($module) / $requiredModules.Count) * 100)
        Import-Module -Name $module
    }
}
Write-Progress -Activity "Installing and importing required modules" -Status "Completed" -Completed

# Define export Directory
if ($localRun -ne $true) {
    $outDir = $env:TEMP
}

# Check if the output directory exists
if (-not (Test-Path -Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir
}

# Define the file paths for the CSV files
$filePath1 = Join-Path $outDir $mailAttachment
$filePath2 = Join-Path $outDir $mailAttachment2

# Define output file name
$exportFilePath1 = "$($filePath1)_$((Get-Date).ToString('HH-mm_dd-MM-yyyy')).csv"
$exportFilePath2 = "$($filePath2)_$((Get-Date).ToString('HH-mm_dd-MM-yyyy')).csv"

# Convert the application secret to a secure string
$secureApplicationSecret = ConvertTo-SecureString -String $Client_secret -AsPlainText -Force

# Create a PSCredential object with the application ID and secure application secret
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $secureApplicationSecret

# Prepare token request.
$url = 'https://login.microsoftonline.com/' + $TenantId + '/oauth2/v2.0/token'

$body = @{
    grant_type = "client_credentials"
    client_id = $ClientId
    client_secret = $Client_secret
    scope = "https://graph.microsoft.com/.default"
}

# Obtain the token.
Write-Verbose "Authenticating..."
try {
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $url -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "Unable to obtain access token, aborting..."
    return
}

$token = ($tokenRequest.Content | ConvertFrom-Json).access_token

$authHeader = @{
   'Content-Type'='application/json'
   'Authorization'="Bearer $token"
}
#endregion Authentication

# Authenticate with Azure using a service principal
Write-Verbose "Connecting to Azure"
$null = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -WarningAction SilentlyContinue
Write-Verbose "Connected to Azure"
# Get role assignments pr. subscription
Write-Verbose "Collecting Azure Subscriptions"
$subscriptions = Get-AzSubscription
$RBACRoles = @{}
$csvData = @()

# Total subscriptions counter for progress bar
$totalSubscriptions = $subscriptions.Count
Write-Verbose "$totalSubscriptions found"
# Reset subscriptions counter for progress bar
$subCount = 0

foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    $null = Set-AzContext -SubscriptionId $subscription.SubscriptionId
    
    # Increment the counter variable for subscriptions
    $subCount++

    # Update the progress bar
    Write-Progress -id 0 -Activity "Processing subscriptions" -Status "$subCount of $totalSubscriptions processed. Currently processing subscription: $($subscription.Name)." -PercentComplete ($subCount / $totalSubscriptions * 100)
    
    # Get all Azure RBAC roles
    $roleAssignmentOutput = Get-AzRoleAssignment
    
    # Total Azure RBAC counter for progress bar
    $totalRoleAssignments = $roleAssignmentOutput.Count

    # Reset Azure RBAC counter for progress bar
    $counterRBAC = 0

    # Define an array to store the RBAC roles for the current subscription
    $RBACRolesForCurrentSubscription = @()

    # Loop through each Azure RBAC role assignment
    foreach ($roleAssignment in $roleAssignmentOutput) {
        # Increment the counter variable for Azure RBAC
        $counterRBAC++
        
        # Update the progress bar
        Write-Progress -id 1 -ParentId 0 -Activity "Processing Role Assignments" -Status "$counterRBAC of $totalRoleAssignments processed" -PercentComplete ($counterRBAC / $totalRoleAssignments * 100)

        # Create a custom object to store the user information
        if ($roleAssignment.ObjectType -in @("Group", "ServicePrincipal", "Unknown")) {
            # Use the DisplayName property for groups, service principals, and unknown object types
            $accountName = $roleAssignment.DisplayName
        } else {
            # Use the SignInName property for other object types
            $accountName = $roleAssignment.SignInName
        }

        # Determine the new ObjectType and DisplayName based on the conditions
        $newObjectType = $roleAssignment.ObjectType
        $newDisplayName = $roleAssignment.DisplayName
        if ($roleAssignment.ObjectType -eq "User" -and $roleAssignment.SignInName -like "*#EXT#@*") {
            $newObjectType = "External User"
            $newDisplayName = "External User: " + $roleAssignment.DisplayName
        } elseif ($roleAssignment.ObjectType -eq "User") {
            $newDisplayName = "User: " + $roleAssignment.DisplayName
        } elseif ($newObjectType -ne "User") {
            $newDisplayName = $newObjectType + ": " + $roleAssignment.DisplayName
        }

        # Set the URI for the /auditLogs/signIns endpoint with a $filter query parameter.
        if ($roleAssignment.ObjectType -eq "User") {
            if ($newObjectType -eq "External User") {
                # Use a variable that dynamically changes based on the UPN of the external user
                $externalUser = Get-AzADUser -UserPrincipalName $roleAssignment.SignInName
                $externalMail = $externalUser.Mail
                $uri = 'https://graph.microsoft.com/beta/users?$filter=mail eq ''{0}''&$select=userPrincipalName,signInActivity' -f $externalMail
            } else {
                # Use the normal UPN
                $uri = 'https://graph.microsoft.com/beta/users?$filter=userPrincipalName eq ''{0}''&$select=userPrincipalName,signInActivity' -f $accountName
            }

            # Initialize an array to store the sign-in logs.
            $lastSignin = @()

            # Send a GET request to the /auditLogs/signIns endpoint.
            $result = Invoke-WebRequest -Uri $uri -Method Get -Verbose:$VerbosePreference -ErrorAction Stop -Headers $authHeader

            # Convert the response to a JSON object.
            $json = $result.Content | ConvertFrom-Json

            # The $json.value array now contains the most recent sign-in log for the specified identity.
            $lastSignin = $json.value[0]
            } else {
                # Initialize lastSignin as an object with a signInActivity property
                $lastSignin = New-Object PSObject -Property @{
                    signInActivity = New-Object PSObject -Property @{
                        lastSignInDateTime = ""
                    }
                }
            }

        # Create a custom object to store the role information, including the last sign-in date if available
        $customObject = [PSCustomObject]@{
            DisplayName = $newDisplayName
            RoleDefinitionName = $roleAssignment.RoleDefinitionName
            LastSignInDateTime = $lastSignin.signInActivity.lastSignInDateTime  # Add this line
            ObjectType = $newObjectType
            Scope = $roleAssignment.Scope
            RoleAssignmentId = $roleAssignment.RoleAssignmentId
            ObjectId = $roleAssignment.ObjectId
            AccountName = $accountName
            SubscriptionName = $subscription.Name
        }

        # Add the custom object to the array of RBAC roles for the current subscription
        $RBACRolesForCurrentSubscription += $customObject

        # Process the RBAC roles for the current subscription and add them to the hashtable
        foreach ($role in $RBACRolesForCurrentSubscription) {
            if ($null -ne $accountName) {
                if (-not $RBACRoles.ContainsKey($accountName)) {
                $RBACRoles[$accountName] = @()
                }
            $RBACRoles[$accountName] += $role
            }
        }
    }
}

# Clear the progress bars when processing is complete.
Write-Progress -Id 1 -Activity "Processing Role Assignments" -Completed.
Write-Progress -Id 0 -Activity "Processing subscriptions" -Completed.

# Populate CSV data array
foreach ($accountName in $RBACRoles.Keys) {
    $csvData += $RBACRoles[$accountName] | Select-Object AccountName, DisplayName, SubscriptionName, RoleDefinitionName, LastSignInDateTime, ObjectType, Scope, RoleAssignmentId
}

# Export Azure RBAC information to CSV file.
$csvData | Export-Csv -Path $exportFilePath1 -Delimiter ";" -Force

# Disconnect from Azure AD.
$null = Disconnect-AzAccount

# Define the service plan ID to check for
$servicePlanId = "eec0eb4f-6444-4f95-aba0-50c24d67f998"

# Get all subscriptions for the tenant
$subscriptionsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Headers $authHeader
$servicePlanEnabled = $subscriptionsResponse.value.ServicePlans.ServicePlanId -contains $servicePlanId

# Output service plan status
$foreground = if ($servicePlanEnabled) { "Green" } else { "DarkMagenta" }
Write-Host "The service plan Azure AD Premium P2 is $(if ($servicePlanEnabled) { "enabled" } else { "not enabled" }) for the tenant." -ForegroundColor $foreground

# region Roles
Write-Verbose "Collecting role assignments..."
# Collect role assignments
$roles = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -authHeader $authHeader
$roles1 = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition' -authHeader $authHeader

$combinedRoles = @()
foreach ($role in $roles) {
    $roleDef = ($roles1 | Where-Object {$_.id -eq $role.id}).roleDefinition
    $combinedRole = $role | Select-Object *, @{Name='roleDefinition'; Expression={ $roleDef }}
    $combinedRoles += $combinedRole
}

# Collect SignIn Activity
$signIn = Get-GraphData -uri 'https://graph.microsoft.com/beta/users?$select=userPrincipalName,signInActivity' -authHeader $authHeader

#process PIM eligible role assignments
if ($servicePlanEnabled -and $PimRoles) {
    Write-Verbose "Collecting PIM eligible role assignments..."
    $uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,directoryScopeId,roleDefinitionId,status&$expand=*'

    do {
        $result = Invoke-WebRequest -Uri $uri -Verbose:$VerbosePreference -ErrorAction Stop -Headers $authHeader
        $uri = $($result | ConvertFrom-Json).'@odata.nextLink'
        #If we are getting multiple pages, best add some delay to avoid throttling
        Start-Sleep -Milliseconds 500
        $combinedRoles += ($result | ConvertFrom-Json).Value
    } while ($uri)
}

if (!$combinedRoles) { Write-Verbose "No valid role assignments found, verify the required permissions have been granted?"}

Write-Verbose "A total of $($combinedRoles.count) role assignments were found, of which $(($combinedRoles | Where-Object {$_.directoryScopeId -eq "/"}).Count) are tenant-wide and $(($combinedRoles | Where-Object {$_.directoryScopeId -ne "/"}).Count) are AU-scoped. $(($combinedRoles | Where-Object {!$_.status}).Count) roles are permanently assigned, you might want to address that!"
#endregion Roles

# Prepare the output
Write-Verbose "Preparing the output..."
$report = @()
foreach ($role in $combinedRoles) {
    $assignmentType = if ($role.status -eq "Provisioned") { "Eligible" } else { "Permanent" }
    $reportLine=[ordered]@{
        "Principal" = switch ($role.principal.'@odata.type') {
            '#microsoft.graph.user' {$role.principal.userPrincipalName}
            '#microsoft.graph.servicePrincipal' {$role.principalId}
            '#microsoft.graph.group' {$role.principal.id}
        }
        "PrincipalDisplayName" = $role.principal.displayName
        "PrincipalType" = $role.principal.'@odata.type'.Split(".")[-1]
        "AssignedRoleScope" = if ($role.directoryScopeId -ne '/') { $role.directoryScopeId }
        "IsBuiltIn" = $role.roleDefinition.isBuiltIn
        "RoleTemplate" = $role.roleDefinition.templateId
    }
    foreach ($sign in $signIn) {
        if ($sign.userPrincipalName -eq $reportLine.Principal) {
            $reportLine["LastSignIn"] = $sign.signInActivity.lastSignInDateTime
            break
        }
    }
    if ($assignmentType -eq "Permanent") {
        $reportLine["PermanentRole"] = $role.roleDefinition.displayName
    } else {
        $reportLine["EligibleRole"] = $role.roleDefinition.displayName
    }
    $report += @([pscustomobject]$reportLine)
}

# Group the data by Principal
$groupedReport = $report | Group-Object -Property Principal | ForEach-Object {
    [PSCustomObject]@{
        Principal = $_.Name
        PrincipalDisplayName = $_.Group[0].PrincipalDisplayName
        PrincipalType = $_.Group[0].PrincipalType
        LastSignin = $_.Group[0].LastSignIn
        PermanentRoles = ($_.Group | Where-Object { $_.PSObject.Properties.Name -contains 'PermanentRole' } | Select-Object -ExpandProperty PermanentRole) -join ', '
        EligibleRoles = ($_.Group | Where-Object { $_.PSObject.Properties.Name -contains 'EligibleRole' } | Select-Object -ExpandProperty EligibleRole) -join ', '
        AssignedRoleScopes = ($_.Group | Where-Object { $_.AssignedRoleScope } | Select-Object -ExpandProperty AssignedRoleScope) -join ', '
        IsBuiltIn = $_.Group[0].IsBuiltIn
        RoleTemplate = $_.Group[0].RoleTemplate
    }
}

# Convert array properties to strings and update PrincipalType for external users
$report = $groupedReport | ForEach-Object {
    $principalType = if ($_.PrincipalType -eq 'user' -and $_.Principal -like '*#EXT#@*') {
        'External User'
    } else {
        $_.PrincipalType
    }
    [PSCustomObject]@{
        Principal = $_.Principal
        PrincipalDisplayName = $_.PrincipalDisplayName
        PrincipalType = $principalType
        LastSignin = $_.LastSignIn
        PermanentRoles = $_.PermanentRoles
        EligibleRoles = $_.EligibleRoles
        AssignedRoleScopes = $_.AssignedRoleScopes
        IsBuiltIn = $_.IsBuiltIn
        RoleTemplate = $_.RoleTemplate
    }
}

# Export the Administrator roles data to a CSV file.
$report | Export-CSV -Path $exportFilePath2 -Delimiter ";" -Encoding UTF8 -Force

# Create a new Excel file and export data from CSV to Excel sheets.
$excelFilePath = Join-Path $outDir "M365 And RBAC Admin Roles_$((Get-Date).ToString('HH.mm_dd-MM-yyyy')).xlsx"
$csvPaths = @($exportFilePath1, $exportFilePath2)
$sheetNames = @("RBAC Roles", "M365 Roles")

for ($i = 0; $i -lt $csvPaths.Length; $i++) {
    $csvData = Import-Csv -Path $csvPaths[$i] -Delimiter ";"
    $params = @{
        Path = $excelFilePath
        WorksheetName = $sheetNames[$i]
        AutoSize = $true
        Append = ($i -eq 1)
    }
    $csvData | Export-Excel @params
}

# Cleanup CSV files if not a local run
if ($localRun) {
    Remove-Item -Path $csvPaths -Force
}

# Mail results or display file path
if ($mailFrom) {
    # Prepare and send the email
    $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($excelFilePath))
    $URLsend = "https://graph.microsoft.com/v1.0/users/" + $mailFrom + "/sendMail"
    $FileName=(Get-Item -Path $excelFilePath).name

    $mailParams = @{
        message = @{
            subject = $mailSubject + " " + (Get-Date -Format "dddd dd/MM/yyyy")
            body = @{
                contentType = "Text"
                content = "Automatic mail with user roles attached"
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $mailTo
                    }
                }
            )
            attachments = @(
                @{
                    "@odata.type" = "#microsoft.graph.fileAttachment"
                    name = $FileName
                    contentBytes = $base64string
                }
            )

        }
        saveToSentItems = "false"
    }
    Invoke-RestMethod -Method POST -uri $URLsend -Headers $authHeader -Body ($mailParams | ConvertTo-Json -Depth 10)

    Write-Host "Email sent to $mailTo with results attached." -ForegroundColor DarkYellow

    # Cleanup
    if (-not $SaveFiles -and -not $localRun) {
        Remove-Item -Path $excelFilePath -Force
    }
} else {
    Write-Host "Results exported to $excelFilePath" -ForegroundColor Green
}