<#
Collect Azure RBAC roles and Administrator roles
Authored by: Jonatan Borg & Sebastian Markdanner / extri:co

########################################################################################################

Prerequisites:
Service Principal needs Reader role for the subscriptions to read RBAC roles.

Graph API Application permissions:
Application.Read.All
AuditLog.Read.All
Directory.Read.All
PrivilegedAccess.Read.AzureAD
RoleManagement.Read.All
User.Read.All
Mail.Send *Make sure to set the permission scope*

Entra Roles:
Report Reader
Directory Reader

Powershell modules:

AzureAD
Az.Accounts
Az.Resources
Microsoft.Graph.Identity.DirectoryManagement
Microsoft.Graph.Authentication
Microsoft.Graph.User.Actions
ImportExcel

########################################################################################################

Service Principal RBAC role for reading assignments:

$Subscriptions = Get-AzSubscription
$servicePrincipal = Get-AzADServicePrincipal -ApplicationId $ClientId
New-AzRoleAssignment -ObjectId $servicePrincipal.Id -RoleDefinitionName "Reader" -scope "/"

########################################################################################################

* Setting permission scope for Mail.Send:

Create a Mail-Enabled Security Group, and add the identity that the Mail.Send permission should allow access to.
Connect-ExchangeOnline
New-DistributionGroup -name "SMTP Graph" -alias "smtp-graph" -Type security
Set-DistributionGroup "SMTP Graph" -EmailAddresses SMTP:smtp-graph@yourdomain.com -HiddenFromAddressListsEnabled $true
Add-DistributionGroupMember -Identity "SMTP Graph" -Member username@email.com
New-ApplicationAccessPolicy -AppId <serviceprincipalClientID> -PolicyScopeGroupId <mail-enabled-security-group@tenant.com> -AccessRight RestrictAccess -Description "Restrict this app to members of the group <group name>"

########################################################################################################
#>

# Parameters
param (
    [Parameter(Mandatory=$true)][string]$TenantId,
    [Parameter(Mandatory=$true)][string]$ClientId,
    [Parameter(Mandatory=$true)][string]$Client_secret,
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

$WarningPreference = "SilentlyContinue"

# Helper Functions
function Get-GraphData {
    param($uri, $authHeader)
    $data = @()
    do {
        $result = Invoke-WebRequest -Uri $uri -Verbose:$VerbosePreference -ErrorAction Stop -Headers $authHeader
        if ($null -eq $result.Content) { return $null }
        $contentAsJson = $result.Content | ConvertFrom-Json
        if ($null -eq $contentAsJson.Value) { return $null }
        $uri = $contentAsJson.'@odata.nextLink'
        Start-Sleep -Milliseconds 500
        $data += $contentAsJson.Value
    } while ($uri)
    return $data
}

function SafeRemoveModule { param([string]$moduleName) if (Get-Module $moduleName -ErrorAction SilentlyContinue) { Remove-Module $moduleName -Force -ErrorAction SilentlyContinue } }

function Test-Admin { $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

function Sanitize-TableName { param([string]$name) return $name -replace '[^a-zA-Z0-9_]', '_' }

function Get-AzAccessToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    $body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret; resource = "https://management.azure.com/" }
    $url = "https://login.microsoftonline.com/$TenantId/oauth2/token"
    $response = Invoke-RestMethod -Method Post -Uri $url -ContentType "application/x-www-form-urlencoded" -Body $body
    return $response.access_token
}

function Check-Module {
    param([string]$moduleName)
    $installedModule = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
    $onlineModule = Find-Module -Name $moduleName -ErrorAction SilentlyContinue
    if ($installedModule -and $onlineModule) {
        if ($installedModule.Version -lt $onlineModule.Version) { return $true }
    } elseif (-not $installedModule) { return $true }
    return $false
}

function Install-OrUpdateModule {
    param([string]$moduleName)
    if (Check-Module -moduleName $moduleName) {
        if (Test-Admin) { Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers }
        else { Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser }
    }
    if (-not (Get-Module -Name $moduleName -ListAvailable)) { Import-Module -Name $moduleName -Force }
}

$requiredModules = @(
    "Az.Accounts",
    "Az.Resources",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Reports",
    "Microsoft.Graph.Identity.Governance",
    "ImportExcel"
)

if ($localRun){
    $totalSteps = $requiredModules.Count
    $currentStep = 0
    Write-Progress -Id 0 -Activity "Managing required modules" -Status "Starting" -PercentComplete 0

    foreach ($module in $requiredModules) {
        $currentStep++
        $overallProgress = ($currentStep / $totalSteps) * 100
        Write-Progress -Id 0 -Activity "Managing required modules" -Status "Processing $module" -PercentComplete $overallProgress
        Install-OrUpdateModule -moduleName $module
        Write-Progress -Id 1 -Activity "Imported $module" -Status "Complete" -Completed
    }

    Write-Progress -Id 0 -Activity "Managing required modules" -Status "Complete" -Completed
    Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser -WarningAction Ignore
    Write-verbose "Modules have been updated. Proceeding with the script."
}


# Define export Directory
if ($localRun -ne $true) { $tempDir = [System.IO.Path]::GetTempPath(); $outDir = Join-Path -Path $tempDir -ChildPath "AzureReports" }
if (-not (Test-Path -Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

$filePath1 = Join-Path $outDir $mailAttachment
$filePath2 = Join-Path $outDir $mailAttachment2
$exportFilePath1 = "$($filePath1)_$((Get-Date).ToString('HH-mm_dd-MM-yyyy')).csv"
$exportFilePath2 = "$($filePath2)_$((Get-Date).ToString('HH-mm_dd-MM-yyyy')).csv"

$secureApplicationSecret = ConvertTo-SecureString -String $Client_secret -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $secureApplicationSecret

$url = 'https://login.microsoftonline.com/' + $TenantId + '/oauth2/v2.0/token'
$body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $Client_secret; scope = "https://graph.microsoft.com/.default" }

Write-Verbose "Authenticating..."
try {
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $url -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing -ErrorAction Stop
    $token = ($tokenRequest.Content | ConvertFrom-Json).access_token
    $authHeader = @{ 'Content-Type' = 'application/json'; 'Authorization' = "Bearer $token" }
} catch {
    Write-Host "Unable to obtain access token, aborting..."
    return
}

Write-Verbose "Connecting to Azure"
$null = Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId -WarningAction SilentlyContinue
Write-Verbose "Connected to Azure"

Write-Verbose "Collecting all users, groups, and service principals from EntraID"
try {
    $allUsers = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allUsers.Count) users"
    $allGroups = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allGroups.Count) groups"
    $allServicePrincipals = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName' -authHeader $authHeader
    Write-Verbose "Collected $($allServicePrincipals.Count) service principals"
    if ($allUsers.Count -eq 0 -and $allGroups.Count -eq 0 -and $allServicePrincipals.Count -eq 0) { throw "No data collected from EntraID" }
} catch {
    Write-Error "Error collecting data from EntraID: $_"
    return
}

$allPrincipals = @()
$allPrincipals += $allUsers | ForEach-Object { [PSCustomObject]@{ id = $_.id; type = 'User'; identifier = $_.userPrincipalName } }
$allPrincipals += $allGroups | ForEach-Object { [PSCustomObject]@{ id = $_.id; type = 'Group'; identifier = $_.displayName } }
$allPrincipals += $allServicePrincipals | ForEach-Object { [PSCustomObject]@{ id = $_.id; type = 'ServicePrincipal'; identifier = $_.appId } }

Write-Verbose "Collecting Azure Subscriptions"
$subscriptions = Get-AzSubscription
$RBACRoles = @{}
$csvData = @()
$totalSubscriptions = $subscriptions.Count
Write-Verbose "$totalSubscriptions found"
$subCount = 0
$uniqueRoleAssignments = @{}
$eligibleRoleAssignments = @{}

foreach ($subscription in $subscriptions) {
    $null = Set-AzContext -SubscriptionId $subscription.SubscriptionId
    $subCount++
    Write-Progress -id 0 -Activity "Processing subscriptions" -Status "$subCount of $totalSubscriptions processed. Currently processing subscription: $($subscription.Name)." -PercentComplete ($subCount / $totalSubscriptions * 100)
    
    $roleAssignmentOutput = Get-AzRoleAssignment
    foreach ($roleAssignment in $roleAssignmentOutput) {
        if ($roleAssignment.ObjectType -in @("Group", "ServicePrincipal", "Unknown")) {
            $accountName = $roleAssignment.DisplayName
            $displayName = "$($roleAssignment.ObjectType): $($roleAssignment.DisplayName)"
        } else {
            $accountName = $roleAssignment.SignInName
            $displayName = if ($accountName -like "*#EXT#@*") { "External User: $($roleAssignment.DisplayName)" } else { "User: $($roleAssignment.DisplayName)" }
        }

        if ($accountName -like "*#EXT#@*") {
            $externalUser = $allUsers | Where-Object { $_.id -eq $roleAssignment.ObjectId }
            if ($externalUser -and $externalUser.mail) { $accountName = $externalUser.mail }
        }

        $key = "$($accountName)|$($roleAssignment.RoleDefinitionName)|$($roleAssignment.Scope)"
        if (-not $uniqueRoleAssignments.ContainsKey($key)) {
            $uniqueRoleAssignments[$key] = [PSCustomObject]@{
                AccountName = $accountName
                DisplayName = $displayName
                SubscriptionName = $subscription.Name
                RoleDefinitionName = $roleAssignment.RoleDefinitionName
                AssignmentType = "Active"
                LastSignIn = $null
                Scope = $roleAssignment.Scope
                ObjectType = $roleAssignment.ObjectType
            }
        }
    }

    Write-Verbose "Collecting eligible Azure RBAC roles using ARM API for subscription $($subscription.SubscriptionId)"
    $armToken = Get-AzAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $Client_secret
    $armUri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&$expand=principal,roleDefinition"

    try {
        $response = Invoke-RestMethod -Uri $armUri -Method Get -Headers @{ Authorization = "Bearer $armToken" }
        if ($response.PSObject.Properties.Name -contains 'value' -and $response.value -is [array]) {
            $roleEligibilitySchedules = $response.value
            Write-Verbose "Found $($roleEligibilitySchedules.Count) eligible role assignments for subscription $($subscription.SubscriptionId)"
            foreach ($schedule in $roleEligibilitySchedules) {
                Write-Verbose "Processing eligible role: $($schedule.properties.expandedProperties.roleDefinition.displayName) for principal: $($schedule.properties.expandedProperties.principal.displayName)"
                $entraUser = $allUsers | Where-Object { $_.displayName -eq $schedule.properties.expandedProperties.principal.displayName } | Select-Object -First 1

                if ($entraUser) {
                    $accountName = if ($entraUser.userPrincipalName -like "*#EXT#*") { $entraUser.mail } else { $entraUser.userPrincipalName }
                    $displayName = if ($entraUser.userPrincipalName -like "*#EXT#*") { "External User: $($entraUser.displayName)" } else { "User: $($entraUser.displayName)" }
                } else {
                    $entraGroup = $allGroups | Where-Object { $_.displayName -eq $schedule.properties.expandedProperties.principal.displayName } | Select-Object -First 1
                    $entraServicePrincipal = $allServicePrincipals | Where-Object { $_.displayName -eq $schedule.properties.expandedProperties.principal.displayName } | Select-Object -First 1

                    if ($entraGroup) {
                        $accountName = $entraGroup.id
                        $displayName = "Group: $($entraGroup.displayName)"
                    } elseif ($entraServicePrincipal) {
                        $accountName = $entraServicePrincipal.appId
                        $displayName = "ServicePrincipal: $($entraServicePrincipal.displayName)"
                    } else {
                        $accountName = $schedule.properties.expandedProperties.principal.displayName
                        $displayName = $schedule.properties.expandedProperties.principal.displayName
                    }
                }

                $roleDefinitionName = $schedule.properties.expandedProperties.roleDefinition.displayName
                $scopeId = $schedule.properties.expandedProperties.scope.id
                $key = "$accountName|$roleDefinitionName|$scopeId"
                if (-not $eligibleRoleAssignments.ContainsKey($key)) {
                    $eligibleRoleAssignments[$key] = [PSCustomObject]@{
                        AccountName = $accountName
                        DisplayName = $displayName
                        SubscriptionName = $subscription.Name
                        RoleDefinitionName = $roleDefinitionName
                        AssignmentType = "Eligible"
                        LastSignIn = $null
                        Scope = $scopeId
                        ObjectType = $schedule.properties.expandedProperties.principal.type
                    }
                    Write-Verbose "Added eligible role assignment with key: $key"
                } else {
                    Write-Verbose "Duplicate eligible role assignment found with key: $key"
                }
            }
        } else {
            Write-Verbose "Unexpected response structure from API for subscription $($subscription.SubscriptionId)"
            Write-Verbose "Response: $($response | ConvertTo-Json -Depth 3)"
        }
    } catch {
        Write-Verbose "Error processing eligible roles for subscription $($subscription.SubscriptionId)"
        Write-Verbose "Error Type: $($_.Exception.GetType().FullName)"
        Write-Verbose "Error Message: $($_.Exception.Message)"
        Write-Verbose "Error Details: $($_ | ConvertTo-Json -Depth 3)"
    }
    Write-Verbose "Total eligible roles for subscription $($subscription.SubscriptionId): $($eligibleRoleAssignments.Count)"
}

$combinedRoles = @() + $uniqueRoleAssignments.Values + $eligibleRoleAssignments.Values
if ($combinedRoles -eq $null -or $combinedRoles.Count -eq 0) {
    Write-Host "No combined roles found, aborting export."
    return
}

Write-Verbose "Total active roles: $($uniqueRoleAssignments.Count)"
Write-Verbose "Total eligible roles: $($eligibleRoleAssignments.Count)"
Write-Verbose "Total combined roles: $($combinedRoles.Count)"

$userSignIns = Get-GraphData -uri 'https://graph.microsoft.com/beta/users?$select=id,userPrincipalName,signInActivity' -authHeader $authHeader
$desiredOrder = @("AccountName", "DisplayName", "SubscriptionName", "RoleDefinitionName", "AssignmentType", "LastSignIn", "Scope", "ObjectType")

foreach ($role in $combinedRoles) {
    if ($role.ObjectType -eq "User") {
        $userSignIn = $userSignIns | Where-Object { $_.userPrincipalName -eq $role.AccountName }
        $lastSignInValue = if ($userSignIn) { $userSignIn.signInActivity.lastSignInDateTime } else { $null }
        $updatedRole = [PSCustomObject]@{}
        foreach ($property in $desiredOrder) {
            $value = $role.PSObject.Properties[$property].Value
            $updatedRole | Add-Member -MemberType NoteProperty -Name $property -Value $value -Force
        }
        $updatedRole.LastSignIn = $lastSignInValue
        $index = $combinedRoles.IndexOf($role)
        $combinedRoles[$index] = $updatedRole
    }
}

foreach ($role in $combinedRoles) {
    if ($role.ObjectType -ne "User") {
        $updatedRole = [PSCustomObject]@{}
        foreach ($property in $desiredOrder) {
            $value = $role.PSObject.Properties[$property].Value
            $updatedRole | Add-Member -MemberType NoteProperty -Name $property -Value $value -Force
        }
        $index = $combinedRoles.IndexOf($role)
        $combinedRoles[$index] = $updatedRole
    }
}

Write-Progress -Id 0 -Activity "Processing subscriptions" -Completed
$combinedRoles | Export-Csv -Path $exportFilePath1 -Delimiter ";" -NoTypeInformation -Encoding UTF8 -Force
$null = Disconnect-AzAccount

$servicePlanId = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
$subscriptionsResponse = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Headers $authHeader
$servicePlanEnabled = $subscriptionsResponse.value.ServicePlans.ServicePlanId -contains $servicePlanId
$foreground = if ($servicePlanEnabled) { "Green" } else { "DarkMagenta" }
Write-Host "The service plan Azure AD Premium P2 is $(if ($servicePlanEnabled) { "enabled" } else { "not enabled" }) for the tenant." -ForegroundColor $foreground

Write-Verbose "Collecting role assignments..."
$roles = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal' -authHeader $authHeader
$roles1 = Get-GraphData -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition' -authHeader $authHeader
$eligibleRoles = Get-GraphData -uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition' -authHeader $authHeader

$combinedRoles = @()
foreach ($role in $roles) {
    $roleDef = ($roles1 | Where-Object {$_.id -eq $role.id}).roleDefinition
    $combinedRole = $role | Select-Object *, @{Name='roleDefinitionNew'; Expression={ $roleDef }}
    $combinedRole | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Active"
    $combinedRoles += $combinedRole
}

foreach ($role in $eligibleRoles) {
    $combinedRole = $role | Select-Object *, @{Name='roleDefinitionNew'; Expression={ $role.roleDefinition }}
    $combinedRole | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Eligible"
    $combinedRoles += $combinedRole
}

$signIn = Get-GraphData -uri 'https://graph.microsoft.com/beta/users?$select=userPrincipalName,signInActivity' -authHeader $authHeader
if (!$combinedRoles) { Write-Verbose "No valid role assignments found, verify the required permissions have been granted?"}
Write-Verbose "A total of $($combinedRoles.count) role assignments were found, of which $(($combinedRoles | Where-Object {$_.directoryScopeId -eq "/"}).Count) are tenant-wide and $(($combinedRoles | Where-Object {$_.directoryScopeId -ne "/"}).Count) are AU-scoped. $(($combinedRoles | Where-Object {!$_.status}).Count) roles are permanently assigned, you might want to address that!"

Write-Verbose "Preparing the output..."
$report = @()
foreach ($role in $combinedRoles) {
    $assignmentType = $role.AssignmentType
    $reportLine = [ordered]@{
        "Principal" = switch ($role.principal.'@odata.type') {
            '#microsoft.graph.user' {
                if ($role.principal.userPrincipalName -like "*#EXT#*") {
                    $role.principal.mail
                } else {
                    $role.principal.userPrincipalName
                }
            }
            '#microsoft.graph.servicePrincipal' {$role.principal.appId}
            '#microsoft.graph.group' {$role.principal.id}
            Default { $null }
        }
        "PrincipalDisplayName" = switch ($role.principal.'@odata.type') {
            '#microsoft.graph.user' { 
                if ($role.principal.userPrincipalName -like "*#EXT#*") {
                    "External User: $($role.principal.displayName)"
                } else {
                    "User: $($role.principal.displayName)"
                }
            }
            '#microsoft.graph.servicePrincipal' { "ServicePrincipal: $($role.principal.displayName)" }
            '#microsoft.graph.group' { "Group: $($role.principal.displayName)" }
            Default { $role.principal.displayName }
        }
        "LastSignIn" = ""
        "ActiveRole" = if ($assignmentType -eq "Active") { $role.roleDefinitionNew.displayName } else { $null }
        "EligibleRole" = if ($assignmentType -eq "Eligible") { $role.roleDefinitionNew.displayName } else { $null }
        "IsBuiltIn" = $role.roleDefinitionNew.isBuiltIn
        "PrincipalType" = if ($role.ObjectType -eq "Eligible") { "Eligible" } else { $role.principal.'@odata.type'.Split(".")[-1] }
    }

    foreach ($sign in $signIn) {
        if ($sign.userPrincipalName -eq $reportLine.Principal) {
            $reportLine["LastSignIn"] = $sign.signInActivity.lastSignInDateTime
            break
        }
    }

    $report += @([pscustomobject]$reportLine)
}

$groupedReport = $report | Group-Object -Property Principal, AssignedRoleScope | ForEach-Object {
    [PSCustomObject]@{
        Principal = $_.Name
        PrincipalDisplayName = $_.Group[0].PrincipalDisplayName
        PrincipalType = $_.Group[0].PrincipalType
        LastSignin = $_.Group[0].LastSignIn
        ActiveRoles = ($_.Group | Where-Object { $_.PSObject.Properties.Name -contains 'ActiveRole' } | Select-Object -ExpandProperty ActiveRole) -join ', '
        EligibleRoles = ($_.Group | Where-Object { $_.PSObject.Properties.Name -contains 'EligibleRole' } | Select-Object -ExpandProperty EligibleRole) -join ', '
        IsBuiltIn = $_.Group[0].IsBuiltIn
    }
}

$report = $groupedReport | ForEach-Object {
    $principalType = if ($_.PrincipalType -eq 'user' -and $_.Principal -like '*#EXT#@*') { 'External User' } else { $_.PrincipalType }
    [PSCustomObject]@{
        Principal = $_.Principal
        PrincipalDisplayName = $_.PrincipalDisplayName
        PrincipalType = $principalType
        LastSignin = $_.LastSignin
        ActiveRoles = $_.ActiveRoles
        EligibleRoles = $_.EligibleRoles
        IsBuiltIn = $_.IsBuiltIn
    }
}

$report = $report | Sort-Object -Property Principal, RoleTemplate, AssignedRoleScopes, ActiveRoles, EligibleRoles -Unique
$report | Export-Csv -Path $exportFilePath2 -Delimiter ";" -Encoding UTF8 -Force

$excelFilePath = Join-Path $outDir "M365 And RBAC Admin Roles_$((Get-Date).ToString('HH.mm_dd-MM-yyyy')).xlsx"
$csvPaths = @($exportFilePath1, $exportFilePath2)
$sheetNames = @("RBAC Roles", "M365 Roles")
$tableStyle = "Medium2"

for ($i = 0; $i -lt $csvPaths.Length; $i++) {
    $csvData = Import-Csv -Path $csvPaths[$i] -Delimiter ";"
    $params = @{
        Path = $excelFilePath
        WorksheetName = $sheetNames[$i]
        AutoSize = $true
        Append = ($i -eq 1)
        TableName = Sanitize-TableName($sheetNames[$i])
        TableStyle = $tableStyle
    }
    $csvData | Export-Excel @params
}

if (-not $localRun -or -not $SaveFiles) { Remove-Item -Path $csvPaths -Force }

if ($mailFrom) {
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
    if (-not $SaveFiles -or -not $localRun) { Remove-Item -Path $excelFilePath -Force }
} else {
    Write-Host "Results exported to $excelFilePath" -ForegroundColor Green
}
