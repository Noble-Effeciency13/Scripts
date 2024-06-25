# Path to the registry key
$keyPath = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

# Check if the registry key exists and has the correct value
$keyExists = Test-Path $keyPath
$value = Get-ItemProperty -Path $keyPath -Name "(default)" -ErrorAction SilentlyContinue

if ($keyExists -and $value."(default)" -eq "") {
    Write-Output "Registry key is correctly set."
    exit 0
} else {
    Write-Output "Registry key is not set correctly."
    exit 1
}