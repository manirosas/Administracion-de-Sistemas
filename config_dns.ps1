# SCRIPT DNS - Windows Server 2022

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

# INSTALAR DNS (IDEMPOTENTE)
function Instalar-DNS {
    $rol = Get-WindowsFeature -Name DNS
    if ($rol.Installed) {
        Write-Host "El rol DNS ya está instalado."
        return
    }

    $resp = Read-Host "¿Deseas instalar el rol DNS? (S/N)"
    if ($resp -match "^[sS]") {
        Install-WindowsFeature DNS -IncludeManagementTools
        Write-Host "Rol DNS instalado correctamente."
    } else {
        Write-Host "Instalación cancelada."
    }
}

# ALTA DE ZONA DNS
function Alta-ZonaDNS {

    $zona = Read-Host "Nombre de la zona (ej. ejemplo.local)"

    if (Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue) {
        Write-Host "La zona ya existe."
        return
    }

    Add-DnsServerPrimaryZone `
        -Name $zona `
        -ZoneFile "$zona.dns"

    Write-Host "Zona DNS creada correctamente."
}

# ALTA DE REGISTRO DNS
function Alta-RegistroDNS {

    $zona = Read-Host "Zona DNS"
    if (-not (Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue)) {
        Write-Host "La zona no existe."
        return
    }

    Write-Host "1. Registro A"
    Write-Host "2. Registro CNAME"
    $tipo = Read-Host "Selecciona el tipo de registro"

    switch ($tipo) {

        "1" {
            $nombre = Read-Host "Nombre del host (ej. www)"
            do {
                $ip = Read-Host "IP del host"
            } until (Validar-IP $ip)

            Add-DnsServerResourceRecordA `
                -ZoneName $zona `
                -Name $nombre `
                -IPv4Address $ip

            Write-Host "Registro A creado correctamente."
        }

        "2" {
            $alias = Read-Host "Nombre del alias"
            $destino = Read-Host "Nombre destino (FQDN)"

            Add-DnsServerResourceRecordCName `
                -ZoneName $zona `
                -Name $alias `
                -HostNameAlias $destino

            Write-Host "Registro CNAME creado correctamente."
        }

        default {
            Write-Host "Opción inválida."
        }
    }
}
# BAJA DE REGISTRO DNS
function Baja-RegistroDNS {

    $zona = Read-Host "Zona DNS"
    if (-not (Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue)) {
        Write-Host "La zona no existe."
        return
    }

    $nombre = Read-Host "Nombre del registro a eliminar"

    $registros = Get-DnsServerResourceRecord -ZoneName $zona -Name $nombre -ErrorAction SilentlyContinue
    if (-not $registros) {
        Write-Host "El registro no existe."
        return
    }

    foreach ($r in $registros) {
        Remove-DnsServerResourceRecord `
            -ZoneName $zona `
            -InputObject $r `
            -Force
    }

    Write-Host "Registro eliminado correctamente."
}

# CONSULTAR ZONAS DNS
function Consultar-ZonasDNS {
    Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsAutoCreated
}

# MENÚ PRINCIPAL
do {
    Clear-Host
    Write-Host "==============================="
    Write-Host "   ADMINISTRACIÓN DNS"
    Write-Host "==============================="
    Write-Host "1. Instalar rol DNS"
    Write-Host "2. Dar de alta zona DNS"
    Write-Host "3. Dar de alta registro DNS"
    Write-Host "4. Dar de baja registro DNS"
    Write-Host "5. Consultar zonas DNS"
    Write-Host "6. Salir"
    Write-Host "==============================="

    $opcion = Read-Host "Selecciona una opción"

    switch ($opcion) {
        "1" { Instalar-DNS; Pausa }
        "2" { Alta-ZonaDNS; Pausa }
        "3" { Alta-RegistroDNS; Pausa }
        "4" { Baja-RegistroDNS; Pausa }
        "5" { Consultar-ZonasDNS; Pausa }
        "6" { Write-Host "Saliendo..." }
        default { Write-Host "Opción inválida"; Pausa }
    }

} until ($opcion -eq "6")
