# DHCP.psm1
# Funciones para administrar el servidor DHCP en Windows Server

# Dependencia del módulo Common (se importa en el script principal)

function Install-DHCPServer {
    <#
    .SYNOPSIS
        Verifica/instala el rol DHCP y asegura que el servicio esté funcionando.
    #>
    $feature = Get-WindowsFeature -Name DHCP
    if ($feature.Installed) {
        Write-Host "DHCP ya está instalado."
    } else {
        Write-Host "Instalando rol DHCP..."
        Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
        Write-Host "Instalación completada."
    }

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Start-Service DHCPServer
        Set-Service DHCPServer -StartupType Automatic
    }

    # Autorizar servidor en el dominio si es necesario (entornos con AD)
    $authCheck = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.DnsName -eq $env:COMPUTERNAME }
    if (-not $authCheck) {
        try {
            Add-DhcpServerInDC -ErrorAction SilentlyContinue
        } catch {}
    }

    Write-Host "Listo."
}

function Configure-DHCPScope {
    <#
    .SYNOPSIS
        Configura un nuevo ámbito DHCP y asigna IP estática al servidor.
    #>
    # Verificar que la interfaz "Ethernet 2" existe
    $adapter = Get-NetAdapter -Name "Ethernet 2" -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Write-Host "Error: No se encontró la interfaz 'Ethernet 2'."
        return
    }

    # Solicitar parámetros
    do {
        $ipStart = Read-Host "IP inicial del rango"
        if (-not (Validate-IP $ipStart)) { Write-Host "IP inválida." }
    } while (-not (Validate-IP $ipStart))

    do {
        $ipEnd = Read-Host "IP final del rango"
        if (-not (Validate-IP $ipEnd)) {
            Write-Host "IP inválida."
            $ipEnd = $null
            continue
        }
        if ((IP-ToInt $ipEnd) -le (IP-ToInt $ipStart)) {
            Write-Host "La IP final debe ser mayor a la IP inicial."
            $ipEnd = $null
        }
    } while (-not $ipEnd)

    do {
        $lease = Read-Host "Duración del lease en horas"
        if ($lease -notmatch '^\d+$' -or [int]$lease -lt 1) {
            Write-Host "Ingrese un número válido mayor a 0."
            $lease = $null
        }
    } while (-not $lease)

    do {
        $dns1 = Read-Host "DNS primario"
        if (-not (Validate-IP $dns1)) { Write-Host "IP inválida." }
    } while (-not (Validate-IP $dns1))

    do {
        $dns2 = Read-Host "DNS secundario"
        if (-not (Validate-IP $dns2)) { Write-Host "IP inválida." }
    } while (-not (Validate-IP $dns2))

    # Calcular parámetros derivados
    $mask    = Get-AutoMask -ip $ipStart
    $prefix  = Get-MaskPrefix -mask $mask
    $gateway = Get-AutoGateway -ip $ipStart
    $poolStart = Int-ToIP -n ((IP-ToInt $ipStart) + 1)

    Write-Host ""
    Write-Host "Máscara detectada : $mask"
    Write-Host "Gateway detectado : $gateway"
    Write-Host "Rango DHCP        : $poolStart - $ipEnd"
    Write-Host ""

    # Configurar IP estática en Ethernet 2
    Write-Host "Configurando IP $ipStart en 'Ethernet 2'..."

    # Eliminar configuraciones IP previas en la interfaz
    $existingIPs = Get-NetIPAddress -InterfaceAlias "Ethernet 2" -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($eip in $existingIPs) {
        Remove-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress $eip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }

    $existingGW = Get-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    if ($existingGW) {
        Remove-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
    }

    New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress $ipStart -PrefixLength $prefix -DefaultGateway $gateway -ErrorAction SilentlyContinue | Out-Null

    # Configurar DNS en la interfaz
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses $dns1,$dns2

    # Crear ámbito DHCP
    $scopeId = $ipStart

    $existing = Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "El scope $scopeId ya existe. Eliminando para reconfigurar..."
        Remove-DhcpServerv4Scope -ScopeId $scopeId -Force
    }

    Add-DhcpServerv4Scope -Name "Scope_$ipStart" -StartRange $poolStart -EndRange $ipEnd `
        -SubnetMask $mask -LeaseDuration ([TimeSpan]::FromHours([int]$lease)) -State Active

    Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router $gateway -DnsServer $dns1,$dns2

    Write-Host ""
    Write-Host "DHCP configurado correctamente."
    Write-Host "  Interfaz  : Ethernet 2"
    Write-Host "  Servidor  : $ipStart"
    Write-Host "  Rango     : $poolStart - $ipEnd"
    Write-Host "  Máscara   : $mask"
    Write-Host "  Gateway   : $gateway"
    Write-Host "  DNS       : $dns1 / $dns2"
    Write-Host "  Lease     : $lease horas"
}

function Show-DHCPLeases {
    <#
    .SYNOPSIS
        Muestra las concesiones activas de todos los ámbitos DHCP.
    #>
    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if (-not $scopes) {
        Write-Host "No hay scopes configurados."
        return
    }
    foreach ($scope in $scopes) {
        Write-Host ""
        Write-Host "Scope: $($scope.ScopeId) - $($scope.Name)"
        Write-Host "----------------------------------------"
        $leases = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
        if ($leases) {
            foreach ($l in $leases) {
                Write-Host "  IP: $($l.IPAddress)  MAC: $($l.ClientId)  Host: $($l.HostName)  Estado: $($l.AddressState)"
            }
        } else {
            Write-Host "  Sin leases activos."
        }
    }
}

function Remove-DHCPConfiguration {
    <#
    .SYNOPSIS
        Elimina todos los ámbitos DHCP configurados.
    #>
    $confirm = Read-Host "Esto eliminará todos los scopes DHCP. Confirmar? (s/n)"
    if ($confirm -ne 's') {
        Write-Host "Cancelado."
        return
    }
    $scopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    if ($scopes) {
        foreach ($scope in $scopes) {
            Remove-DhcpServerv4Scope -ScopeId $scope.ScopeId -Force
            Write-Host "Scope $($scope.ScopeId) eliminado."
        }
    } else {
        Write-Host "No había scopes configurados."
    }
    Write-Host "Configuración DHCP borrada."
}

Export-ModuleMember -Function Install-DHCPServer, Configure-DHCPScope, Show-DHCPLeases, Remove-DHCPConfiguration