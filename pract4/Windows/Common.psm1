# Common.psm1
# Funciones reutilizables para administración de red en Windows Server

function Test-Administrator {
    <#
    .SYNOPSIS
        Verifica si el script se ejecuta como Administrador.
    #>
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: Este script debe ejecutarse como Administrador." -ForegroundColor Red
        exit 1
    }
}

function Pausa {
    <#
    .SYNOPSIS
        Pausa la ejecución hasta que el usuario presione ENTER.
    #>
    Write-Host ""
    Read-Host "Presiona ENTER para continuar..."
}

function Validate-IP {
    <#
    .SYNOPSIS
        Valida que una cadena sea una dirección IPv4 válida y no reservada.
    #>
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
    <#
    .SYNOPSIS
        Determina automáticamente la máscara de red según la primera clase de la IP.
    #>
    param([string]$ip)
    $first = [int]$ip.Split('.')[0]
    if ($first -le 127) { return '255.0.0.0' }
    elseif ($first -le 191) { return '255.255.0.0' }
    else { return '255.255.255.0' }
}

function Get-MaskPrefix {
    <#
    .SYNOPSIS
        Convierte una máscara de red en formato decimal a prefijo CIDR.
    #>
    param([string]$mask)
    $bits = 0
    foreach ($o in $mask.Split('.')) {
        $b = [Convert]::ToString([int]$o, 2)
        $bits += ($b.ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }
    return $bits
}

function Get-AutoGateway {
    <#
    .SYNOPSIS
        Genera una puerta de enlace por defecto a partir de la IP (misma subred, .1).
    #>
    param([string]$ip)
    $parts = $ip.Split('.')
    return "$($parts[0]).$($parts[1]).$($parts[2]).1"
}

function IP-ToInt {
    <#
    .SYNOPSIS
        Convierte una dirección IPv4 a entero de 32 bits.
    #>
    param([string]$ip)
    $o = $ip.Split('.')
    return ([int]$o[0] * 16777216) + ([int]$o[1] * 65536) + ([int]$o[2] * 256) + [int]$o[3]
}

function Int-ToIP {
    <#
    .SYNOPSIS
        Convierte un entero de 32 bits a dirección IPv4.
    #>
    param([int64]$n)
    $a = [math]::Floor($n / 16777216)
    $rem = $n % 16777216
    $b = [math]::Floor($rem / 65536)
    $rem = $rem % 65536
    $c = [math]::Floor($rem / 256)
    $d = $rem % 256
    return "$a.$b.$c.$d"
}

Export-ModuleMember -Function Test-Administrator, Pausa, Validate-IP, Get-AutoMask, Get-MaskPrefix, Get-AutoGateway, IP-ToInt, Int-ToIP