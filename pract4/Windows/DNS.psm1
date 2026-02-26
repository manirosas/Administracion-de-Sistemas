# DNS.psm1
# Funciones para administrar el servidor DNS en Windows Server

# Dependencia del módulo Common (se importa en el script principal)

function Install-DNSServer {
    <#
    .SYNOPSIS
        Verifica/instala el rol DNS y herramientas de gestión.
    #>
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

function New-DNSZoneAndRecords {
    <#
    .SYNOPSIS
        Crea una zona primaria y registros A/CNAME.
    #>
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

    # Registro Tipo A (dominio principal)
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

function Remove-DNSZone {
    <#
    .SYNOPSIS
        Elimina una zona DNS completa.
    #>
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

function Show-DNSZonesAndRecords {
    <#
    .SYNOPSIS
        Muestra las zonas existentes y opcionalmente los registros de una zona.
    #>
    Write-Host "--- ZONAS ACTUALES ---"
    Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsReadOnly | Format-Table -AutoSize

    $zona = Read-Host "Ingresa nombre de zona para ver sus registros (ENTER para saltar)"
    if (![string]::IsNullOrWhiteSpace($zona)) {
        Get-DnsServerResourceRecord -ZoneName $zona | Select-Object HostName, RecordType, RecordData | Format-Table -AutoSize
    }
}

Export-ModuleMember -Function Install-DNSServer, New-DNSZoneAndRecords, Remove-DNSZone, Show-DNSZonesAndRecords