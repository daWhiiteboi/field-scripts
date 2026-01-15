#requires -RunAsAdministrator
Write-Host "`n=== Rollback: Re-enable IPv6 + Remove Overrides ===" -ForegroundColor Cyan

# Rebind IPv6 on physical adapters
Write-Host "Rebinding IPv6 on PHYSICAL adapters..." -ForegroundColor Cyan
$phys = Get-NetAdapter | Where-Object { $_.HardwareInterface -eq $true -and $_.Status -ne "Disabled" }

foreach ($a in $phys) {
  try {
    Enable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction Stop | Out-Null
    Write-Host ("  - IPv6 bound: {0}" -f $a.Name) -ForegroundColor Green
  } catch {
    Write-Host ("  - Failed on {0}: {1}" -f $a.Name, $_.Exception.Message) -ForegroundColor Yellow
  }
}

# Remove DisabledComponents override
$tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
try {
  Remove-ItemProperty -Path $tcpip6Path -Name "DisabledComponents" -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Removed DisabledComponents override." -ForegroundColor Green
} catch {}

# Remove SMHNR policy override
$dnsPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
try {
  Remove-ItemProperty -Path $dnsPolicyPath -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Removed DisableSmartNameResolution policy override." -ForegroundColor Green
} catch {}

ipconfig /flushdns | Out-Null
Write-Host "Flushed DNS cache." -ForegroundColor Green

Write-Host "`nNEXT: Reboot recommended (disable Fast Startup for cleanest results)." -ForegroundColor Yellow
Write-Host ""
