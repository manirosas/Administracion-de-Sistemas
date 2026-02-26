# Main.ps1
# Administrador unificado de red (DHCP y DNS) para Windows Server

# Verificar privilegios de Administrador
Import-Module "$PSScriptRoot\Common.psm1" -Force
Test-Administrator

# Cargar módulos específicos
Import-Module "$PSScriptRoot\diagnostico.psm1" -Force
Import-Module "$PSScriptRoot\DHCP.psm1" -Force
Import-Module "$PSScriptRoot\DNS.psm1" -Force

# Variables globales (pueden personalizarse)
$Global:DHCPInterface = "Ethernet 2"

# Función para mostrar el menú principal
function Show-Menu {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "   ADMINISTRADOR DE RED - DHCP y DNS    " -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "1)  DHCP - Verificar/instalar servidor"
    Write-Host "2)  DHCP - Configurar ámbito (scope)"
    Write-Host "3)  DHCP - Ver concesiones activas"
    Write-Host "4)  DHCP - Borrar configuración"
    Write-Host "-----------------------------------------"
    Write-Host "5)  DNS  - Instalar rol DNS"
    Write-Host "6)  DNS  - Alta de zona y registros"
    Write-Host "7)  DNS  - Baja de zona"
    Write-Host "8)  DNS  - Consultar zonas y registros"
    Write-Host "-----------------------------------------"
    Write-Host "0)  Salir"
    Write-Host "========================================="
    $opcion = Read-Host "Selecciona una opción"
    return $opcion
}

# Bucle principal
do {
    $op = Show-Menu
    switch ($op) {
        '1' { Install-DHCPServer; Pausa }
        '2' { Configure-DHCPScope; Pausa }
        '3' { Show-DHCPLeases; Pausa }
        '4' { Remove-DHCPConfiguration; Pausa }
        '5' { Install-DNSServer; Pausa }
        '6' { New-DNSZoneAndRecords; Pausa }
        '7' { Remove-DNSZone; Pausa }
        '8' { Show-DNSZonesAndRecords; Pausa }
        '0' { Write-Host "Saliendo..." -ForegroundColor Green }
        default { Write-Host "Opción no válida." -ForegroundColor Red; Pausa }
    }
} until ($op -eq '0')
