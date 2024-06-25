$registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$valueName = "RestrictDriverInstallationToAdministrators"
$expectedValue = "0"

try {
    $actualValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop).$valueName
    if ($actualValue -eq $expectedValue) {
        Write-Output "Correct value"
        exit 0
    } else {
        Write-Output "Incorrect value"
        exit 1
    }
} catch {
    Write-Output "Key or value does not exist"
    exit 1
}