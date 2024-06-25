# Add the registry key
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve reg:64

# Restart File Explorer
Stop-Process -Name explorer -Force
Start-Process explorer.exe