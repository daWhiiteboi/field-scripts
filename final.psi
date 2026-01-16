# Identify the active physical adapter
$Adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.HardwareInterface -eq $true }

# Set the DNS to your Pi-hole IP (replace 192.168.1.10 with your actual Pi-hole IP)
$PiholeIP = "192.168.1.10"

foreach ($a in $Adapter) {
    Set-DnsClientServerAddress -InterfaceAlias $a.Name -ServerAddresses ($PiholeIP)
    Write-Host "DNS set to $PiholeIP on $($a.Name)" -ForegroundColor Green
}
