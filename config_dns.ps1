# SCRIPT DNS - Windows Server 2022
# Administración de Zonas y Registros (A, CNAME)

function Pausa {
    Write-Host ""
    Read-Host "Presiona ENTER para continuar..."
}

# 1. INSTALACIÓN IDEMPOTENTE
function Instalar-DNS {
    $rol = Get-WindowsFeature -Name DNS
    if ($rol.Installed) {
        Write-Host "El rol DNS ya está instalado."
    } else {
        $resp = Read-Host "¿Deseas instalar el rol DNS? (S/N)"
        if ($resp -match "^[sS]") {
            Write-Host "Instalando DNS y herramientas de gestión..."
            Install-WindowsFeature DNS -IncludeManagementTools
            Write-Host "Instalación completada."
        } else {
            Write-Host "Operación cancelada."
        }
    }
}

# 2. ALTA DE REGISTROS (ZONA -> DOMINIO -> REGISTROS)
function Alta-RegistrosDNS {
    $zona = Read-Host "Ingresa el nombre de la zona (ej. reprobados.com)"
    
    # Crear zona si no existe
    if (!(Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue)) {
        Write-Host "La zona no existe. Creándola..."
        # Intento de creación para entornos con o sin Active Directory
        try {
            Add-DnsServerPrimaryZone -Name $zona -ReplicationScope "Forest" -ErrorAction Stop
        } catch {
            Add-DnsServerPrimaryZone -Name $zona -ZoneFile "$zona.dns" -ErrorAction SilentlyContinue
        }
    }

    # Registro Tipo A
    $ipA = Read-Host "Ingresa la IP para el registro Tipo A de $zona"
    Add-DnsServerResourceRecordA -ZoneName $zona -Name "@" -IPv4Address $ipA -AllowUpdateAny
    Write-Host "Registro A (@ -> $ipA) creado."

    # Registro WWW (A o CNAME)
    $tipoWWW = Read-Host "¿Deseas crear 'www' como (A) o (CNAME)?"
    if ($tipoWWW.ToUpper() -eq "A") {
        $ipWWW = Read-Host "Ingresa la IP para www.$zona"
        Add-DnsServerResourceRecordA -ZoneName $zona -Name "www" -IPv4Address $ipWWW
    } else {
        Add-DnsServerResourceRecordCName -ZoneName $zona -Name "www" -HostNameAlias "$zona."
    }
    Write-Host "Registro www creado correctamente."
}

# 3. DAR DE BAJA ZONAS
function Baja-ZonaDNS {
    $zona = Read-Host "Ingresa el nombre de la zona a ELIMINAR"
    if (Get-DnsServerZone -Name $zona -ErrorAction SilentlyContinue) {
        $confirm = Read-Host "¿Estás seguro de eliminar la zona $zona y TODOS sus registros? (S/N)"
        if ($confirm -match "^[sS]") {
            Remove-DnsServerZone -Name $zona -Force
            Write-Host "Zona $zona eliminada."
        }
    } else {
        Write-Host "La zona no existe."
    }
}

# 4. CONSULTAR ZONAS Y DOMINIOS
function Consultar-DNS {
    Write-Host "--- ZONAS ACTUALES ---"
    Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsReadOnly | Format-Table -AutoSize
    
    $zona = Read-Host "Ingresa nombre de zona para ver sus registros (ENTER para saltar)"
    if (![string]::IsNullOrWhiteSpace($zona)) {
        Get-DnsServerResourceRecord -ZoneName $zona | Select-Object HostName, RecordType, RecordData | Format-Table -AutoSize
    }
}

# MENÚ PRINCIPAL
do {
    Clear-Host
    Write-Host "======================================"
    Write-Host "      ADMINISTRACIÓN DNS SERVER"
    Write-Host "======================================"
    Write-Host "1. Instalar rol DNS (Idempotente)"
    Write-Host "2. Alta de Zona y Registros (A/CNAME)"
    Write-Host "3. Dar de baja una Zona"
    Write-Host "4. Consultar Zonas y Registros"
    Write-Host "5. Salir"
    Write-Host "======================================"
    
    $opcion = Read-Host "Selecciona una opción"

    switch ($opcion) {
        "1" { Instalar-DNS; Pausa }
        "2" { Alta-RegistrosDNS; Pausa }
        "3" { Baja-ZonaDNS; Pausa }
        "4" { Consultar-DNS; Pausa }
        "5" { Write-Host "Saliendo..." }
        default { Write-Host "Opción inválida"; Pausa }
    }
} until ($opcion -eq "5")
