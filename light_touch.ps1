#requires -RunAsAdministrator
Write-Host "`n=== Remedy A: Registry-only IPv6 suppression (DisabledComponents=0xFF) ===" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }

New-ItemProperty -Path $regPath -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force | Out-Null
Write-Host "Set DisabledComponents to 0xFF (255)." -ForegroundColor Green

ipconfig /flushdns | Out-Null
Write-Host "Flushed DNS cache." -ForegroundColor Green

Write-Host "`nNEXT: Reboot (disable Fast Startup for cleanest results). Then test with nslookup." -ForegroundColor Yellow
Write-Host ""
