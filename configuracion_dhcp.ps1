# SCRIPT DHCP - Windows Server 2022

function Pausa {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

# Validar IP
function Validar-IP {
    param ([string]$ip)

    try {
        [System.Net.IPAddress]::Parse($ip) | Out-Null
        return $true
    } catch {
        return $false
    }
}

# Convertir IP a entero
function IP-a-Int {
    param ([string]$ip)
    $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

# Obtener máscara automática
function Mascara-Automatica {
    param ([string]$ip)

    $primerOcteto = [int]($ip.Split(".")[0])

    if ($primerOcteto -le 126) { return "255.0.0.0" }
    elseif ($primerOcteto -le 191) { return "255.255.0.0" }
    else { return "255.255.255.0" }
}

# Obtener Gateway automático
function Gateway-Automatico {
    param ([string]$ip)
    $partes = $ip.Split(".")
    return "$($partes[0]).$($partes[1]).$($partes[2]).1"
}

# INSTALAR DHCP
function Instalar-DHCP {
    $rol = Get-WindowsFeature -Name DHCP
    if ($rol.Installed) {
        Write-Host "El rol DHCP ya está instalado."
        return
    }

    $resp = Read-Host "¿Deseas instalar el rol DHCP? (S/N)"
    if ($resp -match "^[sS]") {
        Install-WindowsFeature DHCP -IncludeManagementTools
        Write-Host "Rol DHCP instalado correctamente."
    } else {
        Write-Host "Instalación cancelada."
    }
}

# CONFIGURAR DHCP
function Configurar-DHCP {

    do {
        $ipInicio = Read-Host "IP inicial del rango"
    } until (Validar-IP $ipInicio -and ($ipInicio.Split(".")[3] -ne "255"))

    do {
        $ipFinal = Read-Host "IP final del rango"
    } until (Validar-IP $ipFinal -and ($ipFinal.Split(".")[3] -ne "255"))

    if ((IP-a-Int $ipFinal) -le (IP-a-Int $ipInicio)) {
        Write-Host "ERROR: La IP final debe ser mayor a la inicial."
        return
    }

    $mascara = Read-Host "Máscara de red (ENTER para automática)"
    if ([string]::IsNullOrWhiteSpace($mascara)) {
        $mascara = Mascara-Automatica $ipInicio
        Write-Host "Máscara automática asignada: $mascara"
    }

    $leaseHoras = Read-Host "Tiempo de concesión en horas"
    $lease = New-TimeSpan -Hours $leaseHoras

    $gateway = Read-Host "Gateway (ENTER para automático)"
    if ([string]::IsNullOrWhiteSpace($gateway)) {
        $gateway = Gateway-Automatico $ipInicio
        Write-Host "Gateway automático: $gateway"
    }

    $scopeName = "Scope_$($ipInicio)_$($ipFinal)"

    Add-DhcpServerv4Scope `
        -Name $scopeName `
        -StartRange $ipInicio `
        -EndRange $ipFinal `
        -SubnetMask $mascara `
        -LeaseDuration $lease

    Set-DhcpServerv4OptionValue `
        -ScopeId $ipInicio `
        -Router $gateway

    Write-Host "Scope DHCP configurado correctamente."
}

# VER LEASES
function Ver-Leases {
    Get-DhcpServerv4Lease | Format-Table IPAddress, HostName, ClientId, LeaseExpiryTime
}

# BORRAR CONFIGURACIÓN DHCP
function Borrar-DHCP {
    $resp = Read-Host "¿Seguro que deseas borrar la configuración DHCP? (S/N)"
    if ($resp -notmatch "^[sS]") { return }

    Get-DhcpServerv4Scope | Remove-DhcpServerv4Scope -Force
    Write-Host "Configuración DHCP eliminada correctamente."
}

# MENÚ PRINCIPAL
do {
    Clear-Host
    Write-Host "   ADMINISTRACIÓN DHCP"
    Write-Host "1. Instalar rol DHCP"
    Write-Host "2. Configurar DHCP"
    Write-Host "3. Ver leases activos"
    Write-Host "4. Borrar configuración DHCP"
    Write-Host "5. Salir"
    Write-Host "==============================="

    $opcion = Read-Host "Selecciona una opción"

    switch ($opcion) {
        "1" { Instalar-DHCP; Pausa }
        "2" { Configurar-DHCP; Pausa }
        "3" { Ver-Leases; Pausa }
        "4" { Borrar-DHCP; Pausa }
        "5" { Write-Host "Saliendo..." }
        default { Write-Host "Opción inválida"; Pausa }
    }

} until ($opcion -eq "5")
