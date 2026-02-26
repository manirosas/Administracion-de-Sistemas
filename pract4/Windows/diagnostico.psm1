Write-Host "DIAGNÓSTICO DEL SISTEMA"
Write-Host ""
Write-Host "Nombre del equipo:"
Write-Host $env:COMPUTERNAME
Write-Host ""

Write-Host "Direcciones IP:"
Get-NetIPAddress -AddressFamily IPv4 |
Where-Object { $_.IPAddress -notlike "127.*" } |
Select-Object InterfaceAlias, IPAddress
Write-Host ""
Write-Host "Espacio en disco (Unidad C:):"
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$Total = [math]::Round($disk.Size / 1GB, 2)
$Libre = [math]::Round($disk.FreeSpace / 1GB, 2)
Write-Host "Total: $Total GB"
Write-Host "Libre: $Libre GB"
Write-Host ""