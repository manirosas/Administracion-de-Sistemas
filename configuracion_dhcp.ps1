# ===============================
# DHCP - Windows Server 2022
# ===============================

$Interfaz = "Ethernet 2"

# -------------------------------
function Pausa {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar"
}

# -------------------------------
function Validar-IP {
    param([string]$ip)
    try {
        [System.Net.IPAddress]::Parse($ip) | Out-Null
        return $true
    } catch {
        return $false
    }
}

# -------------------------------
function IP-a-Int {
    param([string]$ip)
    $bytes = ([System.Net.IPAddress]::Parse($ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes,0)
}

function Int-a-IP {
    param([uint32]$int)
    $bytes = [BitConverter]::GetBytes($int)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

# -------------------------------
function Mascara-Automatica {
    param([string]$ip)
    $octeto = [int]($ip.Split(".")[0])
    if ($octeto -le 126) { "255.0.0.0" }
    elseif ($octeto -le 191) { "255.255.0.0" }
    else { "255.255.255.0" }
}

# -------------------------------
function Gateway-Automatico {
    param([string]$ip)
    $p = $ip.Split(".")
    "$($p[0]).$($p[1]).$($p[2]).1"
}

# -------------------------------
function Instalar-DHCP {
    $rol = Get-WindowsFeature DHCP
    if ($rol.Installed) {
        Write-Host "El rol DHCP ya está instalado."
        return
    }

    $r = Read-Host "¿Deseas instalar el rol DHCP? (S/N)"
    if ($r -match "^[sS]") {
        Install-WindowsFeature DHCP -IncludeManagementTools
        Write-Host "Rol DHCP instalado correctamente."
    }
}

# -------------------------------
function Configurar-DHCP {

    # IP del servidor
    do {
        $ipServidor = Read-Host "IP inicial (se asignará al servidor)"
    } until (
        Validar-IP $ipServidor -and
        ($ipServidor.Split(".")[3] -ne "255")
    )

    # IP final
    do {
        $ipFinal = Read-Host "IP final del rango DHCP"
    } until (
        Validar-IP $ipFinal -and
        ($ipFinal.Split(".")[3] -ne "255")
    )

    if ((IP-a-Int $ipFinal) -le (IP-a-Int $ipServidor)) {
        Write-Host "ERROR: la IP final debe ser mayor que la inicial"
        return
    }

    # DHCP inicia desde IP + 1
    $ipInicioDHCP = Int-a-IP ((IP-a-Int $ipServidor) + 1)

    # Máscara
    $mascara = Read-Host "Máscara (ENTER para automática)"
    if ([string]::IsNullOrWhiteSpace($mascara)) {
        $mascara = Mascara-Automatica $ipServidor
        Write-Host "Máscara asignada automáticamente: $mascara"
    }

    # Gateway
    $gateway = Read-Host "Gateway (ENTER para automático)"
    if ([string]::IsNullOrWhiteSpace($gateway)) {
        $gateway = Gateway-Automatico $ipServidor
        Write-Host "Gateway automático: $gateway"
    }

    # DNS
    do {
        $dns1 = Read-Host "DNS primario (OBLIGATORIO)"
    } until (Validar-IP $dns1)

    $dns2 = Read-Host "DNS secundario (ENTER para omitir)"
    if (-not (Validar-IP $dns2)) {
        $dns2 = $null
    }

    # -----------------------------
    # LIMPIAR IPs EXISTENTES
    Get-NetIPAddress -InterfaceAlias $Interfaz -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1"
    } |
    ForEach-Object {
        Remove-NetIPAddress `
            -InterfaceAlias $Interfaz `
            -IPAddress $_.IPAddress `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }

    # Asignar IP al servidor
    New-NetIPAddress `
        -InterfaceAlias $Interfaz `
        -IPAddress $ipServidor `
        -PrefixLength 24 `
        -DefaultGateway $gateway `
        -ErrorAction SilentlyContinue

    # Forzar DNS en el servidor
    Set-DnsClientServerAddress `
        -InterfaceAlias $Interfaz `
        -ServerAddresses $dns1 `
        -ErrorAction SilentlyContinue

    # Lease
    $leaseHoras = Read-Host "Tiempo de concesión (horas)"
    $lease = New-TimeSpan -Hours $leaseHoras

    # Scope
    $scopeId = "$($ipServidor.Split('.')[0]).$($ipServidor.Split('.')[1]).$($ipServidor.Split('.')[2]).0"
    $scopeName = "Scope_$scopeId"

    Add-DhcpServerv4Scope `
        -Name $scopeName `
        -StartRange $ipInicioDHCP `
        -EndRange $ipFinal `
        -SubnetMask $mascara `
        -LeaseDuration $lease

    # Opciones DHCP
    Set-DhcpServerv4OptionValue `
        -ScopeId $scopeId `
        -Router $gateway `
        -DnsServer $dns1, $dns2 `
        -ErrorAction SilentlyContinue

    Restart-Service DHCPServer

    Write-Host ""
    Write-Host "DHCP CONFIGURADO CORRECTAMENTE"
    Write-Host "IP Servidor : $ipServidor"
    Write-Host "Rango DHCP  : $ipInicioDHCP - $ipFinal"
    Write-Host "Gateway     : $gateway"
    Write-Host "DNS         : $dns1 $dns2"
}

# -------------------------------
function Ver-Leases {
    Get-DhcpServerv4Lease | Format-Table IPAddress, HostName, ClientId, LeaseExpiryTime
}

# -------------------------------
function Borrar-DHCP {
    $r = Read-Host "¿Eliminar todos los scopes DHCP? (S/N)"
    if ($r -match "^[sS]") {
        Get-DhcpServerv4Scope | Remove-DhcpServerv4Scope -Force
        Write-Host "Scopes eliminados."
    }
}

# ===============================
# MENÚ PRINCIPAL
# ===============================
do {
    Clear-Host
    Write-Host "ADMINISTRACIÓN DHCP"
    Write-Host "1. Instalar rol DHCP"
    Write-Host "2. Configurar DHCP"
    Write-Host "3. Ver leases activos"
    Write-Host "4. Borrar configuración DHCP"
    Write-Host "5. Salir"
    Write-Host "============================="

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
