#Requires -RunAsAdministrator

. "$PSScriptRoot\lib_util.ps1"
. "$PSScriptRoot\lib_ftp_client.ps1"
. "$PSScriptRoot\lib_http.ps1"
. "$PSScriptRoot\lib_ftp_server.ps1"
. "$PSScriptRoot\lib_ssl.ps1"
. "$PSScriptRoot\lib_hash.ps1"

# =============================================================================
# MENU PRINCIPAL
# =============================================================================

function Menu-Principal {
    Clear-Host
    Write-Linea
    Write-Host "  PRACTICA 7 - INFRAESTRUCTURA DE DESPLIEGUE CON SSL/TLS"
    Write-Linea
    Write-Host "  Estado actual de servicios:"
    Write-Host ("    {0,-10} {1}" -f "IIS",    (Get-EstadoServicio "W3SVC"))
    Write-Host ("    {0,-10} {1}" -f "Apache", (Get-EstadoServicio "Apache"))
    Write-Host ("    {0,-10} {1}" -f "Nginx",  (Get-EstadoServicio "nginx"))
    Write-Host ("    {0,-10} {1}" -f "FTP-IIS",(Get-EstadoServicio "FTPSVC"))
    Write-Linea
    Write-Host "  1) Instalar servicio HTTP  (IIS / Apache / Nginx)"
    Write-Host "  2) Instalar servicio FTP   (IIS-FTP)"
    Write-Host "  3) Configurar SSL/TLS      (HTTP o FTP)"
    Write-Host "  4) Cliente FTP dinamico    (navegar repositorio privado)"
    Write-Host "  5) Verificar integridad    (hash de instaladores)"
    Write-Host "  6) Resumen de instalaciones"
    Write-Host "  0) Salir"
    Write-Linea
    Write-Host ""
}

function Menu-Origen {
    Write-Host ""
    Write-Linea
    Write-Host "  ORIGEN DE INSTALACION"
    Write-Linea
    Write-Host "  1) WEB  - Gestor de paquetes (Chocolatey)"
    Write-Host "  2) FTP  - Repositorio privado (con verificacion de hash)"
    Write-Host "  0) Cancelar"
    Write-Linea
    return (Read-Host "  Opcion")
}

function Menu-Servidor-HTTP {
    Write-Host ""
    Write-Linea
    Write-Host "  SELECCIONE SERVIDOR HTTP"
    Write-Linea
    Write-Host "  1) IIS"
    Write-Host "  2) Apache"
    Write-Host "  3) Nginx"
    Write-Host "  0) Cancelar"
    Write-Linea
    return (Read-Host "  Opcion")
}

# =============================================================================
# FLUJO: INSTALAR HTTP
# =============================================================================

function Flujo-Instalar-HTTP {
    $srv = Menu-Servidor-HTTP
    if ($srv -eq "0") { return }

    $origen = Menu-Origen
    if ($origen -eq "0") { return }

    switch ($origen) {
        "1" { Instalar-HTTP-Web $srv }
        "2" { Instalar-HTTP-FTP $srv }
        default { Write-Host "  Opcion invalida."; Pausar }
    }
}

function Mostrar-Versiones-Choco {
    param([string]$paquete)
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) { Write-Host "  (Chocolatey no disponible, se usara la version por defecto)"; return }
    Write-Host "  Consultando versiones de '$paquete' en Chocolatey..."
    $salida = choco search $paquete --all-versions --limit-output 2>$null |
              Where-Object { $_ -match "^\S+\|\S+" } |
              ForEach-Object { ($_ -split '\|')[1] } |
              Select-Object -Unique -First 15
    if (-not $salida -or $salida.Count -eq 0) { Write-Host "  (sin resultados)"; return }
    Write-Linea
    Write-Host "  Versiones disponibles para '$paquete':"
    $i = 1; foreach ($v in $salida) { Write-Host ("    {0,2}) {1}" -f $i, $v); $i++ }
    Write-Linea
}

function Instalar-HTTP-Web {
    param([string]$srv)

    switch ($srv) {
        "1" {
            Instalar-IIS
            $puerto = Read-Host "  Puerto para IIS [80]"
            if ([string]::IsNullOrWhiteSpace($puerto)) { $puerto = "80" }
            New-IISWebsite -name "ServicioWebIIS" -port ([int]$puerto)
        }
        "2" {
            Mostrar-Versiones-Choco "apache-httpd"
            Instalar-Apache
            $puerto = Read-Host "  Puerto para Apache [8081]"
            if ([string]::IsNullOrWhiteSpace($puerto)) { $puerto = "8081" }
            Configure-ApacheService -DocumentRoot "C:\WebServers\Apache" -Port ([int]$puerto) -CreateFirewallRule
        }
        "3" {
            Mostrar-Versiones-Choco "nginx"
            $puerto = Read-Host "  Puerto para Nginx [8082]"
            if ([string]::IsNullOrWhiteSpace($puerto)) { $puerto = "8082" }
            # Puerto se pasa a Instalar-Nginx para evitar conflicto con puerto 80
            Instalar-Nginx -Puerto ([int]$puerto)
        }
    }

    $ssl = (Read-Host "  Desea activar SSL en este servicio? [S/N]").ToUpper()
    if ($ssl -eq "S") { Flujo-SSL-HTTP $srv }
}

function Instalar-HTTP-FTP {
    param([string]$srv)

    $nombreSrv = switch ($srv) { "1"{"IIS"} "2"{"Apache"} "3"{"Nginx"} }
    $rutaRemota = "/http/Windows/$nombreSrv"

    Write-Host "  Conectando al repositorio FTP privado..."
    $cred = Pedir-Credenciales-FTP
    if (-not $cred) { return }

    $archivo = Navegar-Y-Seleccionar-FTP -Servidor $cred.Servidor -Credenciales $cred.Cred -RutaInicial $rutaRemota
    if (-not $archivo) { return }

    $destino = "$env:TEMP\$($archivo.Nombre)"
    Write-Host "  Descargando $($archivo.Nombre)..."
    Descargar-Archivo-FTP -Url $archivo.Url -Credenciales $cred.Cred -Destino $destino

    # Verificar hash
    $hashRemoto = Obtener-Hash-Remoto-FTP -UrlBase $archivo.UrlBase -NombreArchivo $archivo.Nombre -Credenciales $cred.Cred
    if ($hashRemoto) {
        if (-not (Verificar-Hash -Archivo $destino -HashEsperado $hashRemoto)) {
            Write-Host "  ERROR: El archivo descargado esta corrupto. Abortando."
            Pausar; return
        }
        Write-Host "  Hash verificado correctamente."
    } else {
        Write-Host "  AVISO: No se encontro archivo .sha256. Continuando sin verificacion."
    }

    Instalar-Desde-Archivo -Archivo $destino -Tipo $nombreSrv

    $ssl = (Read-Host "  Desea activar SSL en este servicio? [S/N]").ToUpper()
    if ($ssl -eq "S") { Flujo-SSL-HTTP $srv }
}

# =============================================================================
# FLUJO: INSTALAR FTP
# =============================================================================

function Flujo-Instalar-FTP {
    $origen = Menu-Origen
    if ($origen -eq "0") { return }

    switch ($origen) {
        "1" { Instalar-FTP-Web }
        "2" { Instalar-FTP-FTP }
        default { Write-Host "  Opcion invalida."; Pausar }
    }
}

function Instalar-FTP-Web {
    Instalar-FTP-Completo
}

function Instalar-FTP-FTP {
    Instalar-FTP-Completo
}

# =============================================================================
# FLUJO: SSL/TLS
# =============================================================================

function Flujo-SSL {
    Write-Host ""
    Write-Linea
    Write-Host "  CONFIGURAR SSL/TLS"
    Write-Linea
    Write-Host "  1) SSL en IIS"
    Write-Host "  2) SSL en Apache"
    Write-Host "  3) SSL en Nginx"
    Write-Host "  4) FTPS en IIS-FTP"
    Write-Host "  0) Cancelar"
    Write-Linea
    $opc = Read-Host "  Opcion"

    switch ($opc) {
        "1" { Flujo-SSL-HTTP "1" }
        "2" { Flujo-SSL-HTTP "2" }
        "3" { Flujo-SSL-HTTP "3" }
        "4" { Configurar-FTPS }
        "0" { return }
        default { Write-Host "  Opcion invalida."; Pausar }
    }
}

function Flujo-SSL-HTTP {
    param([string]$srv)
    $puerto = Read-Host "  Puerto HTTP actual del servicio"
    if (-not (Validar-Puerto-Basico $puerto)) { return }

    switch ($srv) {
        "1" {
            New-IISWebsite -name "ServicioWebIIS" -port ([int]$puerto)
            New-IISSSLCertificate-AutoPort -selectedHttpPort ([int]$puerto) `
                -SiteName "ServicioWebIIS" -DnsName "reprobados.com" -ForceHTTPS
        }
        "2" {
            Configure-ApacheService -DocumentRoot "C:\WebServers\Apache" -Port ([int]$puerto) -CreateFirewallRule
            New-ApacheSSLCertificate-AutoPort -selectedHttpPort ([int]$puerto) `
                -DnsName "reprobados.com" -DocumentRoot "C:\WebServers\Apache" -ForceHTTPS
        }
        "3" {
            $version = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
            $nginxPath = (Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
                          Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
            if (-not $nginxPath) { Write-Host "  Nginx no encontrado."; Pausar; return }
            Setup-NginxService -Port ([int]$puerto) -DocumentRoot "C:\WebServers\Nginx" -CreateFirewallRule
            New-NginxSSLCertificate-AutoPort -selectedHttpPort ([int]$puerto) `
                -DnsName "reprobados.com" -NginxPath $nginxPath -ForceHTTPS
        }
    }
    Pausar
}

# =============================================================================
# FLUJO: RESUMEN
# =============================================================================

function Flujo-Resumen {
    Write-Linea
    Write-Host "  RESUMEN DE INSTALACIONES Y ESTADO SSL"
    Write-Linea

    $servicios = @(
        @{Nombre="IIS";      SvcName="W3SVC";  Puerto=80;   Proto="http"},
        @{Nombre="Apache";   SvcName="Apache"; Puerto=8081; Proto="http"},
        @{Nombre="Nginx";    SvcName="nginx";  Puerto=8082; Proto="http"},
        @{Nombre="IIS-FTP";  SvcName="FTPSVC"; Puerto=21;   Proto="ftp"}
    )

    foreach ($s in $servicios) {
        $estado = Get-EstadoServicio $s.SvcName
        $ssl    = Test-SSL-Activo -Servicio $s.Nombre
        Write-Host ("  {0,-10} Estado: {1,-12} SSL: {2}" -f $s.Nombre, $estado, $ssl)
    }

    Write-Linea
    Pausar
}

# =============================================================================
# BUCLE PRINCIPAL
# =============================================================================

while ($true) {
    Menu-Principal
    $opcion = Read-Host "  Opcion"
    switch ($opcion) {
        "1" { Flujo-Instalar-HTTP      }
        "2" { Flujo-Instalar-FTP       }
        "3" { Flujo-SSL                }
        "4" { Flujo-Cliente-FTP        }
        "5" { Flujo-Verificar-Hash     }
        "6" { Flujo-Resumen            }
        "0" { Write-Host "  Saliendo."; exit 0 }
        default { Write-Host "  Opcion invalida." }
    }
}