#requires -RunAsAdministrator
Write-Host "`n=== Remedy B: HARDENED (Unbind IPv6 + 0xFF + SMHNR) ===" -ForegroundColor Cyan

# 1) Unbind IPv6 from physical adapters
Write-Host "Unbinding IPv6 from PHYSICAL adapters..." -ForegroundColor Cyan
$phys = Get-NetAdapter | Where-Object { $_.HardwareInterface -eq $true -and $_.Status -ne "Disabled" }

foreach ($a in $phys) {
  try {
    Disable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction Stop | Out-Null
    Write-Host ("  - IPv6 unbound: {0}" -f $a.Name) -ForegroundColor Green
  } catch {
    Write-Host ("  - Failed on {0}: {1}" -f $a.Name, $_.Exception.Message) -ForegroundColor Yellow
  }
}

# 2) Registry backstop (0xFF)
Write-Host "Applying DisabledComponents=0xFF..." -ForegroundColor Cyan
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force | Out-Null
Write-Host "  - Set DisabledComponents to 0xFF." -ForegroundColor Green

# 3) Disable Smart Multi-Homed Name Resolution (helps when multiple interfaces exist)
Write-Host "Disabling Smart Multi-Homed Name Resolution (policy)..." -ForegroundColor Cyan
$dnsPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $dnsPolicyPath)) { New-Item -Path $dnsPolicyPath -Force | Out-Null }
New-ItemProperty -Path $dnsPolicyPath -Name "DisableSmartNameResolution" -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  - Disabled SMHNR (DisableSmartNameResolution=1)." -ForegroundColor Green

# 4) Flush DNS
ipconfig /flushdns | Out-Null
Write-Host "Flushed DNS cache." -ForegroundColor Green

Write-Host "`nNEXT: Disable Fast Startup and REBOOT. Then test with nslookup." -ForegroundColor Yellow
Write-Host ""
