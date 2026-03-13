#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# RUTAS DE ESTADO PERSISTENTE
# =============================================================================

$ESTADO_DIR    = "C:\ProgramData\pract6"
$ESTADO_IIS    = "$ESTADO_DIR\iis.conf"
$ESTADO_APACHE = "$ESTADO_DIR\apache.conf"
$ESTADO_NGINX  = "$ESTADO_DIR\nginx.conf"

# Rutas de instalacion
$APACHE_DIR = "$env:APPDATA\Apache24"
# Nginx: Chocolatey instala en C:\tools\nginx-VERSION, detectar dinamicamente
$NGINX_DIR  = (Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
               Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
if (-not $NGINX_DIR) { $NGINX_DIR = "C:\tools\nginx" }
$IIS_SITE   = "Default Web Site"
$APACHE_SVC = "Apache"   # Nombre real del servicio instalado por Chocolatey

# Puertos reservados (no permitidos)
$PUERTOS_RESERVADOS = @(20,21,22,23,25,53,110,143,389,443,445,3306,5432,6379,8443,27017)

# =============================================================================
# IMPORTAR FUNCIONES DE SERVIDORES HTTP
# =============================================================================

. "$PSScriptRoot\http_funciones.ps1"

# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================

function Write-Linea {
    Write-Host "------------------------------------------------------------"
}

function Write-Titulo($texto) {
    Write-Host ""
    Write-Linea
    Write-Host "  $texto"
    Write-Linea
}

function Pausar {
    Write-Host ""
    Read-Host "  Presione Enter para continuar"
}

function Mensaje-Invalido {
    Write-Host "  Opcion invalida. Intente de nuevo."
}

function Inicializar-Estado {
    if (-not (Test-Path $ESTADO_DIR)) {
        New-Item -ItemType Directory -Path $ESTADO_DIR -Force | Out-Null
    }
    if (-not (Test-Path $ESTADO_IIS))    { "PUERTO=80"   | Set-Content $ESTADO_IIS    -Encoding UTF8 }
    if (-not (Test-Path $ESTADO_APACHE)) { "PUERTO=8081" | Set-Content $ESTADO_APACHE -Encoding UTF8 }
    if (-not (Test-Path $ESTADO_NGINX))  { "PUERTO=8082" | Set-Content $ESTADO_NGINX  -Encoding UTF8 }
}

function Leer-Puerto($archivo, $defecto) {
    if (Test-Path $archivo) {
        $linea = Get-Content $archivo | Select-String "PUERTO=(\d+)"
        if ($linea -match "PUERTO=(\d+)") { return $Matches[1] }
    }
    return $defecto
}

function Guardar-Puerto($archivo, $puerto) {
    "PUERTO=$puerto" | Set-Content $archivo -Encoding UTF8
}

function Servicio-Instalado($nombre) {
    if ($nombre -eq "nginx") {
        return $null -ne (Get-Process nginx -ErrorAction SilentlyContinue)
    }
    return $null -ne (Get-Service -Name $nombre -ErrorAction SilentlyContinue)
}

function Estado-Servicio($nombre) {
    if ($nombre -eq "nginx") {
        if (Get-Process nginx -ErrorAction SilentlyContinue) { return "running" }
        return "stopped"
    }
    $svc = Get-Service -Name $nombre -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return "no instalado" }
    return $svc.Status.ToString().ToLower()
}

# =============================================================================
# CHOCOLATEY / WINGET
# =============================================================================

function Verificar-Chocolatey {
    return $null -ne (Get-Command choco -ErrorAction SilentlyContinue)
}

function Instalar-Chocolatey {
    Write-Host "  Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
    Write-Host "  Chocolatey instalado correctamente."
}

function Verificar-Winget {
    return $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
}

# =============================================================================
# VALIDACION DE PUERTOS
# =============================================================================

function Es-Puerto-Reservado($puerto) {
    return $PUERTOS_RESERVADOS -contains [int]$puerto
}

function Puerto-En-Uso($puerto) {
    $resultado = Test-NetConnection -ComputerName localhost -Port $puerto -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    return $resultado.TcpTestSucceeded
}

function Validar-Puerto($puerto, $puertoActual = "") {
    if ($puerto -notmatch '^\d+$') {
        Write-Host "  ERROR: El puerto debe ser un numero entero."
        return $false
    }
    $p = [int]$puerto
    if ($p -lt 1 -or $p -gt 65535) {
        Write-Host "  ERROR: Puerto fuera de rango. Use un valor entre 1 y 65535."
        return $false
    }
    if (Es-Puerto-Reservado $p) {
        Write-Host "  ERROR: Puerto $p reservado para otro servicio del sistema."
        Write-Host "  Puertos no permitidos: $($PUERTOS_RESERVADOS -join ', ')"
        return $false
    }
    if ($puertoActual -ne "" -and $puerto -eq $puertoActual) {
        Write-Host "  AVISO: El puerto $puerto ya esta configurado para este servicio."
        return $false
    }
    if (Puerto-En-Uso $p) {
        Write-Host "  ERROR: El puerto $p ya esta en uso por otro proceso."
        Write-Host "  Use: netstat -ano | findstr :$p  para ver que proceso lo ocupa."
        return $false
    }
    return $true
}

function Pedir-Puerto($defecto, $puertoActual = "") {
    while ($true) {
        $input = Read-Host "  Puerto [$defecto]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $defecto }
        if ($input -notmatch '^\d+$') {
            Write-Host "  ERROR: El puerto solo debe contener numeros."
            continue
        }
        if (Validar-Puerto $input $puertoActual) { return $input }
    }
}

# =============================================================================
# FIREWALL
# =============================================================================

function Firewall-Abrir-Puerto($puerto, $nombre) {
    $ruleName = "HTTP-Custom-$nombre-$puerto"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName  $ruleName `
        -Direction    Inbound `
        -Protocol     TCP `
        -LocalPort    $puerto `
        -Action       Allow `
        -Profile      Any `
        -Enabled      True | Out-Null
    Write-Host "  Firewall: regla '$ruleName' creada para puerto $puerto/TCP."
}

function Firewall-Cerrar-Puerto($puerto, $nombre) {
    $ruleName = "HTTP-Custom-$nombre-$puerto"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    Write-Host "  Firewall: regla '$ruleName' eliminada (puerto $puerto)."
}

# =============================================================================
# INDEX.HTML PERSONALIZADO
# =============================================================================

function Crear-Index-Html($directorio, $servicio, $version, $puerto) {
    if (-not (Test-Path $directorio)) {
        New-Item -ItemType Directory -Path $directorio -Force | Out-Null
    }
    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>$servicio</title>
</head>
<body>
    <h1>$servicio</h1>
    <p>Servidor: $servicio</p>
    <p>Version: $version</p>
    <p>Puerto: $puerto</p>
    <p>Sistema: Windows Server</p>
</body>
</html>
"@
    $html | Set-Content "$directorio\index.html" -Encoding UTF8
    Write-Host "  index.html creado en: $directorio"
}

# =============================================================================
# CONSULTA DE VERSIONES (CHOCOLATEY)
# =============================================================================

function Obtener-Versiones-Choco($paquete) {
    if (-not (Verificar-Chocolatey)) { return @() }
    try {
        $salida = choco search $paquete --all-versions --limit-output 2>$null
        if ($null -eq $salida) { return @() }
        $versiones = @($salida | Where-Object { $_ -match "^\S+\|\S+" } |
                     ForEach-Object { ($_ -split '\|')[1] } |
                     Select-Object -Unique)
        return $versiones
    } catch { return @() }
}

function Obtener-Versiones-Winget($paquete) {
    if (-not (Verificar-Winget)) { return @() }
    try {
        $salida = winget show --id $paquete --versions 2>$null
        if ($null -eq $salida) { return @() }
        $versiones = @($salida | Where-Object { $_ -match '^\s*[\d.]' } |
                     ForEach-Object { $_.Trim() })
        return $versiones
    } catch { return @() }
}

function Seleccionar-Version-Choco($paquete) {
    Write-Host ""
    Write-Host "  Consultando versiones disponibles en Chocolatey para '$paquete'..."
    $versiones = @(Obtener-Versiones-Choco $paquete)

    if ($versiones.Count -eq 0) {
        Write-Host "  AVISO: No se encontraron versiones. Se instalara la version por defecto."
        return "default"
    }

    Write-Linea
    Write-Host "  Versiones disponibles:"
    for ($i = 0; $i -lt $versiones.Count; $i++) {
        Write-Host ("    {0,2}) {1}" -f ($i+1), $versiones[$i])
    }
    Write-Host ("    {0,2}) Instalar version por defecto del repositorio" -f ($versiones.Count+1))
    Write-Linea

    $total = $versiones.Count + 1
    while ($true) {
        $opc = Read-Host "  Seleccione una version [1-$total]"
        if ($opc -notmatch '^\d+$' -or [int]$opc -lt 1 -or [int]$opc -gt $total) {
            Write-Host "  ERROR: Opcion fuera de rango."
            continue
        }
        if ([int]$opc -eq $total) { return "default" }
        return $versiones[[int]$opc - 1]
    }
}

# =============================================================================
# MENUS DE PANTALLA
# =============================================================================

function Menu-Principal {
    Inicializar-Estado
    Clear-Host
    Write-Linea
    Write-Host "  SISTEMA DE APROVISIONAMIENTO WEB - Windows Server"
    Write-Linea
    Write-Host ""
    Write-Host "  Estado de servicios:"
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "IIS",    (Estado-Servicio "W3SVC"),  (Leer-Puerto $ESTADO_IIS    "80"))
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "Apache", (Estado-Servicio "Apache"), (Leer-Puerto $ESTADO_APACHE "8081"))
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "Nginx",  (Estado-Servicio "nginx"),  (Leer-Puerto $ESTADO_NGINX  "8082"))
    Write-Host ""
    Write-Linea
    Write-Host "  1) Consultar versiones disponibles"
    Write-Host "  2) Instalar y configurar servidor"
    Write-Host "  3) Cambiar puerto"
    Write-Host "  4) Borrar configuracion / Desinstalar"
    Write-Host "  0) Salir"
    Write-Linea
    Write-Host ""
}

function Mostrar-Menu-Servidor($accion) {
    Write-Host ""
    Write-Linea
    Write-Host "  $accion - Seleccione servidor HTTP"
    Write-Linea
    Write-Host "  1) IIS (Internet Information Services)"
    Write-Host "  2) Apache Win64"
    Write-Host "  3) Nginx para Windows"
    Write-Host "  0) Volver"
    Write-Linea
    Write-Host ""
}

# =============================================================================
# VERIFICACION DE ADMINISTRADOR
# =============================================================================

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  ERROR: Este script debe ejecutarse como Administrador."
    Write-Host "  Use: powershell -ExecutionPolicy Bypass -File main.ps1"
    Write-Host ""
    exit 1
}

# =============================================================================
# BUCLE PRINCIPAL
# =============================================================================

while ($true) {
    Menu-Principal
    $opcion = Read-Host "  Opcion"
    switch ($opcion) {
        "1" { Menu-Versiones       }
        "2" { Menu-Instalar        }
        "3" { Menu-Cambiar-Puerto  }
        "4" { Menu-Borrar          }
        "0" {
            Write-Host ""
            Write-Host "  Saliendo del sistema de aprovisionamiento."
            Write-Host ""
            exit 0
        }
        default { Mensaje-Invalido }
    }
}
