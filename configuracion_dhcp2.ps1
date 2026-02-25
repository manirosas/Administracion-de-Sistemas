# DHCP Manager - Windows Server
# Requiere ejecucion como Administrador

function Validate-IP {
    param([string]$ip)
    if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $octets = $ip.Split('.')
        foreach ($o in $octets) {
            if ([int]$o -gt 255) { return $false }
        }
        if ($ip -eq '0.0.0.0' -or $ip -eq '255.255.255.255') { return $false }
        return $true
    }
    return $false
}

function Get-AutoMask {
    param([string]$ip)
    $first = [int]$ip.Split('.')[0]
    if ($first -le 127) { return '255.0.0.0' }
    elseif ($first -le 191) { return '255.255.0.0' }
    else { return '255.255.255.0' }
}

function Get-MaskPrefix {
    param([string]$mask)
    $bits = 0
    foreach ($o in $mask.Split('.')) {
        $b = [Convert]::ToString([int]$o, 2)
        $bits += ($b.ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }
    return $bits
}

function Get-AutoGateway {
    param([string]$ip)
    $parts = $ip.Split('.')
    return "$($parts[0]).$($parts[1]).$($parts[2]).1"
}

function IP-ToInt {
    param([string]$ip)
    $o = $ip.Split('.')
    return ([int]$o[0] * 16777216) + ([int]$o[1] * 65536) + ([int]$o[2] * 256) + [int]$o[3]
}

function Int-ToIP {
    param([int64]$n)
    $a = [math]::Floor($n / 16777216)
    $rem = $n % 16777216
    $b = [math]::Floor($rem / 65536)
    $rem = $rem % 65536
    $c = [math]::Floor($rem / 256)
    $d = $rem % 256
    return "$a.$b.$c.$d"
}

function Install-DHCP {
    $feature = Get-WindowsFeature -Name DHCP
    if ($feature.Installed) {
        Write-Host "DHCP ya esta instalado."
    } else {
        Write-Host "Instalando rol DHCP..."
        Install-WindowsFeature -Name DHCP -IncludeManagementTools | Out-Null
        Write-Host "Instalacion completada."
    }

    $svc = Get-Service -Name DHCPServer -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Start-Service DHCPServer
        Set-Service DHCPServer -StartupType Automatic
    }

    $authCheck = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { $_.DnsName -eq $env:COMPUTERNAME }
    if (-not $authCheck) {
        try {
            Add-DhcpServerInDC -ErrorAction SilentlyContinue
        } catch {}
    }

    Write-Host "Listo."
}

function Configure-DHCP {
    # Verificar que la interfaz existe
    $adapter = Get-NetAdapter -Name "Ethernet 2" -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Write-Host "Error: No se encontro la interfaz 'Ethernet 2'."
        return
    }

    # IP inicial
    do {
        $ipStart = Read-Host "IP inicial del rango"
        if (-not (Validate-IP $ipStart)) { Write-Host "IP invalida." }
    } while (-not (Validate-IP $ipStart))

    # IP final
    do {
        $ipEnd = Read-Host "IP final del rango"
        if (-not (Validate-IP $ipEnd)) {
            Write-Host "IP invalida."
            $ipEnd = $null
            continue
        }
        if ((IP-ToInt $ipEnd) -le (IP-ToInt $ipStart)) {
            Write-Host "La IP final debe ser mayor a la IP inicial."
            $ipEnd = $null
        }
    } while (-not $ipEnd)

    # Lease
    do {
        $lease = Read-Host "Duracion del lease en horas"
        if ($lease -notmatch '^\d+$' -or [int]$lease -lt 1) {
            Write-Host "Ingrese un numero valido mayor a 0."
            $lease = $null
        }
    } while (-not $lease)

    # DNS primario
    do {
        $dns1 = Read-Host "DNS primario"
        if (-not (Validate-IP $dns1)) { Write-Host "IP invalida." }
    } while (-not (Validate-IP $dns1))

    # DNS secundario
    do {
        $dns2 = Read-Host "DNS secundario"
        if (-not (Validate-IP $dns2)) { Write-Host "IP invalida." }
    } while (-not (Validate-IP $dns2))

    $mask    = Get-AutoMask -ip $ipStart
    $prefix  = Get-MaskPrefix -mask $mask
    $gateway = Get-AutoGateway -ip $ipStart
    $poolStart = Int-ToIP -n ((IP-ToInt $ipStart) + 1)

    Write-Host ""
    Write-Host "Mascara detectada : $mask"
    Write-Host "Gateway detectado : $gateway"
    Write-Host "Rango DHCP        : $poolStart - $ipEnd"
    Write-Host ""

    # Configurar IP en Ethernet 2
    Write-Host "Configurando IP $ipStart en 'Ethernet 2'..."

    $existingIPs = Get-NetIPAddress -InterfaceAlias "Ethernet 2" -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($eip in $existingIPs) {
        Remove-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress $eip.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }

    $existingGW = Get-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    if ($existingGW) {
        Remove-NetRoute -InterfaceAlias "Ethernet 2" -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
    }

    New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress $ipStart -PrefixLength $prefix -DefaultGateway $gateway -ErrorAction SilentlyContinue | Out-Null

    # DNS en la interfaz sin validar si existe
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 2" -ServerAddresses $dns1,$dns2

    # Scope DHCP
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
    Write-Host "  Mascara   : $mask"
    Write-Host "  Gateway   : $gateway"
    Write-Host "  DNS       : $dns1 / $dns2"
    Write-Host "  Lease     : $lease horas"
}

function Show-Leases {
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

function Remove-DHCPConfig {
    $confirm = Read-Host "Esto eliminara todos los scopes DHCP. Confirmar? (s/n)"
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
        Write-Host "No habia scopes configurados."
    }
    Write-Host "Configuracion DHCP borrada."
}

# Menu principal
do {
    Write-Host ""
    Write-Host "=== DHCP Manager ==="
    Write-Host "1. Instalar DHCP"
    Write-Host "2. Configurar DHCP"
    Write-Host "3. Ver leases activos"
    Write-Host "4. Borrar configuracion DHCP"
    Write-Host "0. Salir"
    Write-Host ""
    $op = Read-Host "Opcion"

    switch ($op) {
        '1' { Install-DHCP }
        '2' { Configure-DHCP }
        '3' { Show-Leases }
        '4' { Remove-DHCPConfig }
        '0' { Write-Host "Saliendo." }
        default { Write-Host "Opcion no valida." }
    }
} while ($op -ne '0')
