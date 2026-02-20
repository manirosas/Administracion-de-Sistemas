# ==============================
# CONFIGURACIÓN GENERAL
# ==============================
$InterfaceName = "enp0s8"
$DefaultDomain = "reprobados.com"

# ==============================
# FUNCIONES
# ==============================

function Pausa {
    Read-Host "Presiona ENTER para continuar"
}

function Validar-IP($ip) {
    return $ip -match '^(\d{1,3}\.){3}\d{1,3}$'
}

function Obtener-IP-Servidor {
    return (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
}

function Configurar-IP-Fija {
    Write-Host "No se detectó IP fija en $InterfaceName" -ForegroundColor Yellow

    do {
        $ip = Read-Host "Ingresa IP fija"
    } until (Validar-IP $ip)

    do {
        $mask = Read-Host "Ingresa longitud de prefijo (ej. 24)"
    } until ($mask -match '^\d+$')

    do {
        $gateway = Read-Host "Ingresa gateway"
    } until (Validar-IP $gateway)

    New-NetIPAddress `
        -InterfaceAlias $InterfaceName `
        -IPAddress $ip `
        -PrefixLength $mask `
        -DefaultGateway $gateway

    Set-DnsClientServerAddress `
        -InterfaceAlias $InterfaceName `
        -ServerAddresses $ip

    Write-Host "IP fija configurada correctamente" -ForegroundColor Green
}

function Verificar-IP {
    $ip = Obtener-IP-Servidor
    if (-not $ip) {
        Configurar-IP-Fija
    }
}

function Instalar-DNS {
    $dns = Get-WindowsFeature DNS
    if ($dns.Installed) {
        Write-Host "DNS Server ya está instalado" -ForegroundColor Green
    } else {
        Install-WindowsFeature DNS -IncludeManagementTools
        Write-Host "DNS Server instalado correctamente" -ForegroundColor Green
    }
}

function Crear-Zona {
    $domain = Read-Host "Dominio (ENTER = $DefaultDomain)"
    if (-not $domain) { $domain = $DefaultDomain }

    if (Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue) {
        Write-Host "La zona ya existe" -ForegroundColor Yellow
        return
    }

    Add-DnsServerPrimaryZone `
        -Name $domain `
        -ZoneFile "$domain.dns" `
        -DynamicUpdate None

    Write-Host "Zona $domain creada correctamente" -ForegroundColor Green
}

function Alta-DNS {
    $domain = Read-Host "Dominio (ej. ejemplo.com)"
    if (-not $domain) { $domain = $DefaultDomain }

    $serverIP = Obtener-IP-Servidor

    $ip = Read-Host "IP destino (ENTER = $serverIP)"
    if (-not $ip) { $ip = $serverIP }

    # Registro raíz
    Add-DnsServerResourceRecordA `
        -ZoneName $domain `
        -Name "@" `
        -IPv4Address $ip `
        -AllowUpdateAny `
        -TimeToLive 01:00:00 `
        -ErrorAction SilentlyContinue

    # Registro www
    Add-DnsServerResourceRecordA `
        -ZoneName $domain `
        -Name "www" `
        -IPv4Address $ip `
        -AllowUpdateAny `
        -TimeToLive 01:00:00 `
        -ErrorAction SilentlyContinue

    Write-Host "Registros creados correctamente" -ForegroundColor Green
}

function Consultar-DNS {
    Get-DnsServerZone | Format-Table ZoneName, ZoneType
}

function Baja-DNS {
    $domain = Read-Host "Dominio"
    $name = Read-Host "Registro (ej. www o @)"

    Remove-DnsServerResourceRecord `
        -ZoneName $domain `
        -Name $name `
        -RRType A `
        -Force

    Write-Host "Registro eliminado correctamente" -ForegroundColor Green
}

function Pruebas {
    $domain = Read-Host "Dominio a probar (ENTER = $DefaultDomain)"
    if (-not $domain) { $domain = $DefaultDomain }

    Write-Host "NSLOOKUP:" -ForegroundColor Cyan
    nslookup $domain

    Write-Host "PING WWW:" -ForegroundColor Cyan
    ping "www.$domain"
}

# ==============================
# MENÚ PRINCIPAL
# ==============================

do {
    Clear-Host
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  DNS WINDOWS SERVER - MENÚ   " -ForegroundColor Cyan
    Write-Host "=============================="
    Write-Host "1) Verificar / Asignar IP fija"
    Write-Host "2) Instalar DNS Server"
    Write-Host "3) Crear zona DNS"
    Write-Host "4) Alta de registros DNS"
    Write-Host "5) Consultar zonas DNS"
    Write-Host "6) Baja de registro DNS"
    Write-Host "7) Pruebas de resolución"
    Write-Host "0) Salir"
    Write-Host "=============================="

    $op = Read-Host "Selecciona opción"

    switch ($op) {
        "1" { Verificar-IP; Pausa }
        "2" { Instalar-DNS; Pausa }
        "3" { Crear-Zona; Pausa }
        "4" { Alta-DNS; Pausa }
        "5" { Consultar-DNS; Pausa }
        "6" { Baja-DNS; Pausa }
        "7" { Pruebas; Pausa }
    }

} while ($op -ne "0")
