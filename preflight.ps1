$activeIfs = (Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }).InterfaceAlias
$dnsV6 = Get-DnsClientServerAddress -AddressFamily IPv6 |
  Where-Object { $_.InterfaceAlias -notlike "Loopback*" -and $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }

Write-Host "`nActive interfaces: $($activeIfs -join ', ')" -ForegroundColor Gray

if ($dnsV6) {
  Write-Host "`nIPv6 DNS FOUND on real interfaces (bypass risk):" -ForegroundColor Yellow
  $dnsV6 | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
  Write-Host "`nVERDICT: High chance of IPv6/router DNS bypass. Use adapter-level IPv6 unbind if Pi-hole doesn't stick." -ForegroundColor Red
} else {
  Write-Host "`nNo IPv6 DNS configured on Ethernet/Wi-Fi." -ForegroundColor Green
  if ($activeIfs.Count -ge 2) {
    Write-Host "VERDICT: Likely OK. Disable Wi-Fi (or Ethernet) during setup/testing to avoid split-DNS behavior." -ForegroundColor Yellow
  } else {
    Write-Host "VERDICT: Likely OK. Registry-only approach usually sufficient." -ForegroundColor Green
  }
}
