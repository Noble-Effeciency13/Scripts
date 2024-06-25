#################################################################
#                                                               #
# Script written by Sebastian Flæng Markdanner                  #
# Used for enrolling existing Entra ID joined devices to Intune #
#                                                               #
#################################################################

function Log-Error {
    param([string]$message)
    $message | Out-File -FilePath $logPath -Append
    Write-Host $message -ForegroundColor Red
}

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to close this window."
    exit
}

$tempFolder = "C:\temp\PsExecTemp"
$psexecPath = "$tempFolder\PsExec.exe"
$logPath = "$tempFolder\MDMEnrollmentLog.txt"

if (-not (Test-Path $tempFolder)) {
    New-Item -Path $tempFolder -ItemType Directory -Force
}

if (-not (Test-Path $psexecPath)) {
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "$tempFolder\PSTools.zip"
        Expand-Archive -LiteralPath "$tempFolder\PSTools.zip" -DestinationPath $tempFolder -ErrorAction Stop
    } catch {
        Log-Error "Error downloading or extracting PsExec: $($_.Exception.Message)"
        exit 1
    }
}

$scriptContent = @"
function Log-Error {
    param([string]`$message)
    "`$message" | Out-File -FilePath "$logPath" -Append
    Write-Host "`$message" -ForegroundColor Red
}

try {
    `$keyinfo = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*"
    `$url = `$keyinfo.Name.Split("\")[-1]
    `$path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\`$url"
    if (-not (Test-Path `$path)) { throw "KEY `$path not found!" }
    
    `$props = Get-ItemProperty -Path `$path -Name MdmEnrollmentUrl
    if (-not `$props) {
        throw "MDM Enrollment URL not set"
    }

    New-ItemProperty -LiteralPath `$path -Name 'MdmEnrollmentUrl' -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -PropertyType String -Force
    New-ItemProperty -LiteralPath `$path -Name 'MdmTermsOfUseUrl' -Value 'https://portal.manage.microsoft.com/TermsofUse.aspx' -PropertyType String -Force
    New-ItemProperty -LiteralPath `$path -Name 'MdmComplianceUrl' -Value 'https://portal.manage.microsoft.com/?portalAction=Compliance' -PropertyType String -Force

    & C:\Windows\system32\deviceenroller.exe /c /AutoEnrollMDM
    Write-Host "Device is performing the MDM enrollment!" -ForegroundColor Green
    exit 0
} catch {
    Log-Error "Error: `$($_.Exception.Message)"
    exit 1001
}
"@
$scriptContent | Out-File -FilePath "$tempFolder\MDMEnrollmentScript.ps1" -Encoding ASCII

try {
    & $psexecPath -accepteula -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$tempFolder\MDMEnrollmentScript.ps1" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "The script ran successfully. Please check Intune for enrollment status. Status update can take up to 30 minutes" -ForegroundColor Green
    } else {
        throw "The script did not run successfully. Please check the error messages and try again."
    }
} catch {
    Log-Error "PsExec Execution Error: $($_.Exception.Message)"
}

Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue