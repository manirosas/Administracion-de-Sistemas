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
$APACHE_DIR = "C:\Apache24"
$NGINX_DIR  = "C:\nginx"
$IIS_SITE   = "Default Web Site"

# Puertos reservados (no permitidos)
$PUERTOS_RESERVADOS = @(20,21,22,23,25,53,110,143,389,443,445,3306,5432,6379,8443,27017)

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
    return $null -ne (Get-Service -Name $nombre -ErrorAction SilentlyContinue)
}

function Estado-Servicio($nombre) {
    $svc = Get-Service -Name $nombre -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return "no instalado" }
    return $svc.Status.ToString().ToLower()
}

# =============================================================================
# VERIFICACION DE CHOCOLATEY / WINGET
# =============================================================================

function Verificar-Chocolatey {
    return $null -ne (Get-Command choco -ErrorAction SilentlyContinue)
}

function Instalar-Chocolatey {
    Write-Host "  Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    # Recargar PATH
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
        if (Validar-Puerto $input $puertoActual) {
            return $input
        }
    }
}

# =============================================================================
# FIREWALL - WINDOWS ADVANCED FIREWALL
# =============================================================================

function Firewall-Abrir-Puerto($puerto, $nombre) {
    $ruleName = "HTTP-Custom-$nombre-$puerto"
    # Eliminar regla previa si existe
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
# CONSULTA DE VERSIONES
# =============================================================================

function Obtener-Versiones-Choco($paquete) {
    if (-not (Verificar-Chocolatey)) { return @() }
    try {
        # choco info --all lista todas las versiones disponibles
        $salida = choco info $paquete --all --limit-output 2>$null
        $versiones = $salida | Where-Object { $_ -match "^\S+\|(\S+)" } |
                     ForEach-Object { ($_ -split '\|')[1] } |
                     Select-Object -Unique
        return $versiones
    } catch { return @() }
}

function Obtener-Versiones-Winget($paquete) {
    if (-not (Verificar-Winget)) { return @() }
    try {
        $salida = winget show --id $paquete --versions 2>$null
        $versiones = $salida | Where-Object { $_ -match '^\s*[\d.]' } |
                     ForEach-Object { $_.Trim() }
        return $versiones
    } catch { return @() }
}

function Seleccionar-Version-Choco($paquete) {
    Write-Host ""
    Write-Host "  Consultando versiones disponibles en Chocolatey para '$paquete'..."
    $versiones = Obtener-Versiones-Choco $paquete

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
# MENU DE PANTALLA PRINCIPAL
# =============================================================================

function Menu-Principal {
    Inicializar-Estado
    Clear-Host
    Write-Linea
    Write-Host "  SISTEMA DE APROVISIONAMIENTO WEB - Windows Server"
    Write-Linea
    Write-Host ""
    Write-Host "  Estado de servicios:"
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "IIS",    (Estado-Servicio "W3SVC"),        (Leer-Puerto $ESTADO_IIS    "80"))
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "Apache", (Estado-Servicio "Apache2.4"),    (Leer-Puerto $ESTADO_APACHE "8081"))
    Write-Host ("    {0,-10} estado: {1,-14} puerto: {2}" -f "Nginx",  (Estado-Servicio "nginx"),        (Leer-Puerto $ESTADO_NGINX  "8082"))
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
# CONSULTA DE VERSIONES (MENU)
# =============================================================================

function Consultar-Versiones-IIS {
    Write-Titulo "Versiones de IIS disponibles"
    Write-Host "  IIS se instala como caracteristica de Windows."
    Write-Host "  La version depende del sistema operativo."
    Write-Host ""

    # Detectar version actual
    if (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue) {
        $feat = Get-WindowsFeature -Name Web-Server
        $estado = if ($feat.Installed) { "instalada" } else { "no instalada" }
        Write-Host "  Caracteristica 'Web-Server' (IIS): $estado"
    } else {
        # Windows 10/11 - usar DISM
        $dism = dism /online /get-featureinfo /featurename:IIS-WebServerRole 2>$null
        if ($dism) {
            Write-Host "  $($dism | Select-String 'State')"
        } else {
            Write-Host "  No se pudo determinar el estado de IIS en este sistema."
        }
    }

    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if ($iisVer) {
        Write-Host "  Version instalada: $iisVer"
    }
    Write-Host "  Puerto configurado: $(Leer-Puerto $ESTADO_IIS '80')"
    Pausar
}

function Consultar-Versiones-Apache {
    Write-Titulo "Versiones disponibles de Apache Win64 (Chocolatey)"
    if (-not (Verificar-Chocolatey)) {
        Write-Host "  Chocolatey no esta instalado."
        Write-Host "  Se instalara automaticamente al elegir 'Instalar'."
    } else {
        Write-Host "  Consultando Chocolatey..."
        Write-Host ""
        choco info apache-httpd --all 2>$null | Select-Object -First 30
    }
    Write-Host ""
    Write-Host "  Puerto configurado: $(Leer-Puerto $ESTADO_APACHE '8081')"
    Pausar
}

function Consultar-Versiones-Nginx {
    Write-Titulo "Versiones disponibles de Nginx para Windows (Chocolatey / Winget)"
    if (Verificar-Chocolatey) {
        Write-Host "  --- Chocolatey ---"
        choco info nginx --all 2>$null | Select-Object -First 20
    }
    if (Verificar-Winget) {
        Write-Host ""
        Write-Host "  --- Winget ---"
        winget show --id Nginx.Nginx --versions 2>$null | Select-Object -First 20
    }
    if (-not (Verificar-Chocolatey) -and -not (Verificar-Winget)) {
        Write-Host "  Ni Chocolatey ni Winget estan disponibles."
        Write-Host "  Se instalara Chocolatey automaticamente al elegir 'Instalar'."
    }
    Write-Host ""
    Write-Host "  Puerto configurado: $(Leer-Puerto $ESTADO_NGINX '8082')"
    Pausar
}

function Menu-Versiones {
    while ($true) {
        Mostrar-Menu-Servidor "Consultar versiones"
        $opc = Read-Host "  Opcion"
        switch ($opc) {
            "1" { Consultar-Versiones-IIS    }
            "2" { Consultar-Versiones-Apache }
            "3" { Consultar-Versiones-Nginx  }
            "0" { return }
            default { Mensaje-Invalido }
        }
    }
}

# =============================================================================
# IIS - INSTALAR Y CONFIGURAR (OBLIGATORIO)
# =============================================================================

function Instalar-IIS {
    Write-Titulo "Instalar y Configurar IIS (Internet Information Services)"

    # --- Instalar caracteristica de Windows ---
    $yaInstalado = $false
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $yaInstalado = $true
        Write-Host "  IIS ya esta instalado."
        $resp = Read-Host "  Desea reconfigurar? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
    } catch {
        Write-Host "  Instalando IIS (caracteristica de Windows)..."
        try {
            # Windows Server
            Install-WindowsFeature -Name Web-Server,Web-Common-Http,Web-Static-Content,
                Web-Http-Errors,Web-Http-Logging,Web-Request-Monitor,
                Web-Security,Web-Filtering,Web-Http-Redirect,
                Web-Mgmt-Console,Web-Scripting-Tools `
                -IncludeManagementTools -ErrorAction Stop | Out-Null
        } catch {
            # Windows 10/11
            Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,
                IIS-WebServer,IIS-CommonHttpFeatures,IIS-StaticContent,
                IIS-DefaultDocument,IIS-HttpErrors,IIS-Security,
                IIS-RequestFiltering,IIS-HttpLogging,IIS-ManagementConsole `
                -All -NoRestart | Out-Null
        }
        Import-Module WebAdministration -ErrorAction Stop
        Write-Host "  IIS instalado correctamente."
    }

    # --- Puerto ---
    $puertoActual = Leer-Puerto $ESTADO_IIS "80"
    Write-Host "  Defina el puerto de escucha para IIS:"
    $puerto = Pedir-Puerto "80" ""

    # --- Web root personalizado ---
    $webRoot = "C:\inetpub\wwwroot\pract6"
    if (-not (Test-Path $webRoot)) {
        New-Item -ItemType Directory -Path $webRoot -Force | Out-Null
    }

    # --- Sitio web IIS ---
    # Eliminar binding anterior en ese puerto si existe
    $bindingAnterior = Get-WebBinding -Name $IIS_SITE -ErrorAction SilentlyContinue |
                       Where-Object { $_.bindingInformation -like "*:${puertoActual}:*" }
    if ($bindingAnterior) {
        Remove-WebBinding -Name $IIS_SITE -BindingInformation "*:${puertoActual}:" -ErrorAction SilentlyContinue
    }

    # Configurar binding con PowerShell IIS
    $existeBinding = Get-WebBinding -Name $IIS_SITE -ErrorAction SilentlyContinue |
                     Where-Object { $_.bindingInformation -eq "*:${puerto}:" }
    if (-not $existeBinding) {
        New-WebBinding -Name $IIS_SITE -IPAddress "*" -Port $puerto -Protocol "http"
        Write-Host "  Binding IIS: puerto $puerto configurado."
    }

    # Actualizar ruta fisica del sitio
    Set-ItemProperty "IIS:\Sites\$IIS_SITE" -Name physicalPath -Value $webRoot
    Write-Host "  Web root IIS: $webRoot"

    # --- SEGURIDAD: Eliminar encabezado X-Powered-By ---
    $srvH = Get-WebConfigurationProperty -Filter "//httpProtocol/customHeaders" `
                                         -PSPath "IIS:\Sites\$IIS_SITE" `
                                         -Name collection -ErrorAction SilentlyContinue
    $xpb = $srvH | Where-Object { $_.name -eq "X-Powered-By" }
    if ($xpb) {
        Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
            -Filter "system.webServer/httpProtocol/customHeaders" `
            -Name "." -AtElement @{name="X-Powered-By"} -ErrorAction SilentlyContinue
        Write-Host "  Seguridad: encabezado X-Powered-By eliminado."
    }

    # --- SEGURIDAD: Ocultar version del servidor (Request Filtering) ---
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
        -Filter "system.webServer/security/requestFiltering" `
        -Name "removeServerHeader" -Value $true
    Write-Host "  Seguridad: encabezado Server ocultado via Request Filtering."

    # --- SEGURIDAD: Encabezados de seguridad ---
    $headers = @(
        @{name="X-Frame-Options";       value="SAMEORIGIN"},
        @{name="X-Content-Type-Options";value="nosniff"},
        @{name="X-XSS-Protection";      value="1; mode=block"},
        @{name="Referrer-Policy";       value="strict-origin-when-cross-origin"}
    )
    foreach ($h in $headers) {
        try {
            Remove-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
                -Filter "system.webServer/httpProtocol/customHeaders" `
                -Name "." -AtElement @{name=$h.name} -ErrorAction SilentlyContinue
            Add-WebConfiguration -PSPath "IIS:\Sites\$IIS_SITE" `
                -Filter "system.webServer/httpProtocol/customHeaders" `
                -Value @{name=$h.name; value=$h.value}
        } catch { }
    }
    Write-Host "  Seguridad: encabezados X-Frame-Options, X-Content-Type-Options, etc. configurados."

    # --- SEGURIDAD: Bloquear metodos HTTP peligrosos (Request Filtering) ---
    $metodosBloquear = @("TRACE","TRACK","DELETE","PUT","PATCH")
    foreach ($metodo in $metodosBloquear) {
        try {
            Add-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
                -Filter "system.webServer/security/requestFiltering/verbs" `
                -Name "." -Value @{verb=$metodo; allowed=$false}
        } catch { }
    }
    Write-Host "  Seguridad: metodos TRACE, TRACK, DELETE, PUT, PATCH bloqueados."

    # --- SEGURIDAD: Deshabilitar listado de directorios ---
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
        -Filter "system.webServer/directoryBrowse" `
        -Name "enabled" -Value $false
    Write-Host "  Seguridad: listado de directorios deshabilitado."

    # --- Permisos del directorio ---
    $acl = Get-Acl $webRoot
    $iisUser = "IIS_IUSRS"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $iisUser, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $webRoot -AclObject $acl
    Write-Host "  Permisos: $iisUser con ReadAndExecute en $webRoot."

    # --- Index personalizado ---
    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if (-not $iisVer) { $iisVer = "Desconocida" }
    Crear-Index-Html $webRoot "IIS" $iisVer $puerto

    # --- Firewall ---
    Firewall-Abrir-Puerto $puerto "IIS"
    Guardar-Puerto $ESTADO_IIS $puerto

    # --- Iniciar servicio ---
    Start-Service W3SVC -ErrorAction SilentlyContinue
    Write-Host "  IIS iniciado."

    Write-Host ""
    Write-Host "  Instalacion completada."
    Write-Host "  Servicio : IIS (W3SVC)"
    Write-Host "  Version  : $iisVer"
    Write-Host "  Puerto   : $puerto"
    Write-Host "  Web root : $webRoot"
    Pausar
}

# =============================================================================
# APACHE WIN64 - INSTALAR Y CONFIGURAR (via Chocolatey)
# =============================================================================

function Instalar-Apache {
    Write-Titulo "Instalar y Configurar Apache Win64"

    # Verificar/instalar Chocolatey
    if (-not (Verificar-Chocolatey)) {
        Write-Host "  Chocolatey es necesario para instalar Apache."
        $resp = Read-Host "  Instalar Chocolatey ahora? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
        Instalar-Chocolatey
    }

    if (Servicio-Instalado "Apache2.4") {
        Write-Host "  Apache ya esta instalado."
        $resp = Read-Host "  Desea reconfigurar? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
    }

    # Seleccion de version via Chocolatey
    $version = Seleccionar-Version-Choco "apache-httpd"

    # Puerto
    Write-Host ""
    Write-Host "  Defina el puerto de escucha para Apache:"
    $puerto = Pedir-Puerto "8081" ""

    # Instalar
    if ($version -eq "default") {
        Write-Host "  Instalando Apache Win64 (version por defecto)..."
        choco install apache-httpd -y --no-progress 2>&1 | Tee-Object -Variable chocoOut
    } else {
        Write-Host "  Instalando Apache Win64 version $version..."
        choco install apache-httpd --version $version -y --no-progress 2>&1 | Tee-Object -Variable chocoOut
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  AVISO: No se pudo instalar la version $version. Instalando por defecto..."
            choco install apache-httpd -y --no-progress
        }
    }

    # Recargar PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")

    # Detectar directorio de instalacion
    if (-not (Test-Path "$APACHE_DIR\conf\httpd.conf")) {
        Write-Host "  AVISO: No se encontro httpd.conf en $APACHE_DIR."
        Write-Host "  Verifique la instalacion manualmente."
        Pausar; return
    }

    $verReal = (choco list apache-httpd --local-only --limit-output 2>$null) -replace "apache-httpd\|",""
    if ([string]::IsNullOrEmpty($verReal)) { $verReal = "Instalada" }

    # Web root
    $webRoot = "$APACHE_DIR\htdocs\pract6"
    New-Item -ItemType Directory -Path $webRoot -Force | Out-Null

    # --- Configuracion httpd.conf ---
    $httpdConf = "$APACHE_DIR\conf\httpd.conf"
    $contenido = Get-Content $httpdConf -Raw

    # Puerto
    $contenido = $contenido -replace "(?m)^Listen \d+", "Listen $puerto"

    # Ocultar version
    if ($contenido -notmatch "ServerTokens") {
        $contenido += "`nServerTokens Prod`nServerSignature Off`n"
    } else {
        $contenido = $contenido -replace "ServerTokens \w+", "ServerTokens Prod"
        $contenido = $contenido -replace "ServerSignature \w+", "ServerSignature Off"
    }

    # Habilitar mod_headers y mod_rewrite
    $contenido = $contenido -replace "#LoadModule headers_module",   "LoadModule headers_module"
    $contenido = $contenido -replace "#LoadModule rewrite_module",   "LoadModule rewrite_module"

    $contenido | Set-Content $httpdConf -Encoding UTF8
    Write-Host "  httpd.conf: puerto $puerto, ServerTokens Prod, modulos habilitados."

    # --- VirtualHost con encabezados de seguridad ---
    $vhostPath = "$APACHE_DIR\conf\extra\pract6-vhost.conf"
    @"
<VirtualHost *:$puerto>
    DocumentRoot "$webRoot"
    ServerName localhost

    <Directory "$webRoot">
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted

        <LimitExcept GET POST HEAD>
            Require all denied
        </LimitExcept>
    </Directory>

    <IfModule mod_headers.c>
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
    </IfModule>

    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK|DELETE|PUT|PATCH) [NC]
        RewriteRule .* - [F,L]
    </IfModule>
</VirtualHost>
"@ | Set-Content $vhostPath -Encoding UTF8

    # Incluir el VirtualHost en httpd.conf si no esta incluido
    $httpdContenido = Get-Content $httpdConf -Raw
    if ($httpdContenido -notmatch "pract6-vhost.conf") {
        Add-Content $httpdConf "`nInclude conf/extra/pract6-vhost.conf" -Encoding UTF8
    }
    Write-Host "  VirtualHost configurado: $vhostPath"

    # --- Index personalizado ---
    Crear-Index-Html $webRoot "Apache Win64" $verReal $puerto

    # --- Registrar como servicio de Windows ---
    if (-not (Servicio-Instalado "Apache2.4")) {
        & "$APACHE_DIR\bin\httpd.exe" -k install 2>$null
        Write-Host "  Apache registrado como servicio de Windows."
    }

    # --- Firewall ---
    Firewall-Abrir-Puerto $puerto "Apache"
    Guardar-Puerto $ESTADO_APACHE $puerto

    # --- Iniciar ---
    Start-Service "Apache2.4" -ErrorAction SilentlyContinue
    $estado = Estado-Servicio "Apache2.4"
    Write-Host "  Apache: $estado en puerto $puerto."

    Write-Host ""
    Write-Host "  Instalacion completada."
    Write-Host "  Servicio : Apache2.4"
    Write-Host "  Version  : $verReal"
    Write-Host "  Puerto   : $puerto"
    Write-Host "  Web root : $webRoot"
    Pausar
}

# =============================================================================
# NGINX PARA WINDOWS - INSTALAR Y CONFIGURAR (via Chocolatey)
# =============================================================================

function Instalar-Nginx {
    Write-Titulo "Instalar y Configurar Nginx para Windows"

    if (-not (Verificar-Chocolatey)) {
        Write-Host "  Chocolatey es necesario para instalar Nginx."
        $resp = Read-Host "  Instalar Chocolatey ahora? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
        Instalar-Chocolatey
    }

    if (Servicio-Instalado "nginx") {
        Write-Host "  Nginx ya esta instalado."
        $resp = Read-Host "  Desea reconfigurar? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
    }

    $version = Seleccionar-Version-Choco "nginx"

    Write-Host ""
    Write-Host "  Defina el puerto de escucha para Nginx:"
    $puerto = Pedir-Puerto "8082" ""

    if ($version -eq "default") {
        choco install nginx -y --no-progress
    } else {
        choco install nginx --version $version -y --no-progress
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  AVISO: Instalando version por defecto..."
            choco install nginx -y --no-progress
        }
    }

    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")

    # Detectar directorio nginx
    if (-not (Test-Path "$NGINX_DIR\conf\nginx.conf")) {
        Write-Host "  AVISO: No se encontro nginx.conf en $NGINX_DIR."
        Pausar; return
    }

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    if ([string]::IsNullOrEmpty($verReal)) { $verReal = "Instalada" }

    # Web root
    $webRoot = "$NGINX_DIR\html\pract6"
    New-Item -ItemType Directory -Path $webRoot -Force | Out-Null

    # --- nginx.conf ---
    @"
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    server_tokens off;

    include      mime.types;
    default_type application/octet-stream;
    sendfile     on;
    keepalive_timeout 65;

    add_header X-Frame-Options        "SAMEORIGIN"                      always;
    add_header X-Content-Type-Options "nosniff"                         always;
    add_header X-XSS-Protection       "1; mode=block"                   always;
    add_header Referrer-Policy        "strict-origin-when-cross-origin" always;

    server {
        listen      $puerto;
        server_name localhost;
        root        $($webRoot -replace '\\','/');
        index       index.html;

        if (`$request_method !~ ^(GET|HEAD|POST)`$) {
            return 405;
        }

        location / {
            try_files `$uri `$uri/ =404;
        }

        location ~ /\. {
            deny all;
        }
    }
}
"@ | Set-Content "$NGINX_DIR\conf\nginx.conf" -Encoding UTF8
    Write-Host "  nginx.conf configurado con seguridad aplicada, puerto $puerto."

    # --- Index personalizado ---
    Crear-Index-Html $webRoot "Nginx Windows" $verReal $puerto

    # --- Registrar como servicio (usando NSSM o sc) ---
    $nssmPath = (Get-Command nssm -ErrorAction SilentlyContinue)?.Source
    if ($nssmPath) {
        nssm install nginx "$NGINX_DIR\nginx.exe" 2>$null
        nssm set nginx AppDirectory $NGINX_DIR 2>$null
        Write-Host "  Nginx registrado como servicio via NSSM."
    } else {
        # Alternativa: sc create
        $existeSvc = Get-Service -Name "nginx" -ErrorAction SilentlyContinue
        if (-not $existeSvc) {
            sc.exe create nginx binPath= "$NGINX_DIR\nginx.exe" start= auto | Out-Null
            Write-Host "  Nginx registrado como servicio via sc.exe."
        }
    }

    # --- Firewall ---
    Firewall-Abrir-Puerto $puerto "Nginx"
    Guardar-Puerto $ESTADO_NGINX $puerto

    # --- Iniciar ---
    Start-Service "nginx" -ErrorAction SilentlyContinue
    $estado = Estado-Servicio "nginx"
    Write-Host "  Nginx: $estado en puerto $puerto."

    Write-Host ""
    Write-Host "  Instalacion completada."
    Write-Host "  Servicio : nginx"
    Write-Host "  Version  : $verReal"
    Write-Host "  Puerto   : $puerto"
    Write-Host "  Web root : $webRoot"
    Pausar
}

function Menu-Instalar {
    while ($true) {
        Mostrar-Menu-Servidor "Instalar y configurar"
        $opc = Read-Host "  Opcion"
        switch ($opc) {
            "1" { Instalar-IIS    }
            "2" { Instalar-Apache }
            "3" { Instalar-Nginx  }
            "0" { return }
            default { Mensaje-Invalido }
        }
    }
}

# =============================================================================
# CAMBIAR PUERTO
# =============================================================================

function Cambiar-Puerto-IIS {
    Write-Titulo "Cambiar Puerto - IIS"

    if (-not (Servicio-Instalado "W3SVC")) {
        Write-Host "  ERROR: IIS no esta instalado."
        Pausar; return
    }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $pa = Leer-Puerto $ESTADO_IIS "80"
    Write-Host "  Puerto actual: $pa"
    Write-Host ""
    Write-Host "  Defina el nuevo puerto:"
    $np = Pedir-Puerto $pa $pa

    # Cambiar binding IIS con Set-WebBinding
    try {
        Set-WebBinding -Name $IIS_SITE `
                       -BindingInformation "*:${pa}:" `
                       -PropertyName "bindingInformation" `
                       -Value "*:${np}:"
        Write-Host "  IIS binding actualizado a puerto $np."
    } catch {
        # Alternativa: eliminar y recrear
        Remove-WebBinding -Name $IIS_SITE -BindingInformation "*:${pa}:" -ErrorAction SilentlyContinue
        New-WebBinding    -Name $IIS_SITE -IPAddress "*" -Port $np -Protocol "http"
        Write-Host "  IIS binding recreado en puerto $np."
    }

    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    Crear-Index-Html "C:\inetpub\wwwroot\pract6" "IIS" $iisVer $np

    Firewall-Cerrar-Puerto $pa "IIS"
    Firewall-Abrir-Puerto  $np "IIS"
    Guardar-Puerto $ESTADO_IIS $np

    Restart-Service W3SVC -ErrorAction SilentlyContinue
    Write-Host "  IIS reiniciado en puerto $np."
    Pausar
}

function Cambiar-Puerto-Apache {
    Write-Titulo "Cambiar Puerto - Apache Win64"

    if (-not (Servicio-Instalado "Apache2.4")) {
        Write-Host "  ERROR: Apache no esta instalado."
        Pausar; return
    }

    $pa = Leer-Puerto $ESTADO_APACHE "8081"
    Write-Host "  Puerto actual: $pa"
    Write-Host ""
    Write-Host "  Defina el nuevo puerto:"
    $np = Pedir-Puerto $pa $pa

    $httpdConf = "$APACHE_DIR\conf\httpd.conf"
    if (Test-Path $httpdConf) {
        (Get-Content $httpdConf -Raw) -replace "(?m)^Listen \d+", "Listen $np" |
            Set-Content $httpdConf -Encoding UTF8
        Write-Host "  httpd.conf: puerto actualizado a $np."
    }

    $vhostPath = "$APACHE_DIR\conf\extra\pract6-vhost.conf"
    if (Test-Path $vhostPath) {
        (Get-Content $vhostPath -Raw) -replace "<VirtualHost \*:\d+>", "<VirtualHost *:$np>" |
            Set-Content $vhostPath -Encoding UTF8
        Write-Host "  VirtualHost: puerto actualizado."
    }

    $verReal = (choco list apache-httpd --local-only --limit-output 2>$null) -replace "apache-httpd\|",""
    Crear-Index-Html "$APACHE_DIR\htdocs\pract6" "Apache Win64" $verReal $np

    Firewall-Cerrar-Puerto $pa "Apache"
    Firewall-Abrir-Puerto  $np "Apache"
    Guardar-Puerto $ESTADO_APACHE $np

    Restart-Service "Apache2.4" -ErrorAction SilentlyContinue
    Write-Host "  Apache reiniciado en puerto $np."
    Pausar
}

function Cambiar-Puerto-Nginx {
    Write-Titulo "Cambiar Puerto - Nginx Windows"

    if (-not (Servicio-Instalado "nginx")) {
        Write-Host "  ERROR: Nginx no esta instalado."
        Pausar; return
    }

    $pa = Leer-Puerto $ESTADO_NGINX "8082"
    Write-Host "  Puerto actual: $pa"
    Write-Host ""
    Write-Host "  Defina el nuevo puerto:"
    $np = Pedir-Puerto $pa $pa

    $ngConf = "$NGINX_DIR\conf\nginx.conf"
    if (Test-Path $ngConf) {
        (Get-Content $ngConf -Raw) -replace "listen\s+$pa;", "listen $np;" |
            Set-Content $ngConf -Encoding UTF8
        Write-Host "  nginx.conf: puerto actualizado a $np."
    }

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    Crear-Index-Html "$NGINX_DIR\html\pract6" "Nginx Windows" $verReal $np

    Firewall-Cerrar-Puerto $pa "Nginx"
    Firewall-Abrir-Puerto  $np "Nginx"
    Guardar-Puerto $ESTADO_NGINX $np

    Restart-Service "nginx" -ErrorAction SilentlyContinue
    Write-Host "  Nginx reiniciado en puerto $np."
    Pausar
}

function Menu-Cambiar-Puerto {
    while ($true) {
        Mostrar-Menu-Servidor "Cambiar puerto"
        $opc = Read-Host "  Opcion"
        switch ($opc) {
            "1" { Cambiar-Puerto-IIS    }
            "2" { Cambiar-Puerto-Apache }
            "3" { Cambiar-Puerto-Nginx  }
            "0" { return }
            default { Mensaje-Invalido }
        }
    }
}

# =============================================================================
# BORRAR CONFIGURACION / DESINSTALAR
# =============================================================================

function Borrar-IIS {
    Write-Titulo "Borrar configuracion / Desinstalar IIS"

    if (-not (Servicio-Instalado "W3SVC")) {
        Write-Host "  IIS no esta instalado."
        Pausar; return
    }

    Write-Host "  Se eliminara la configuracion de IIS (la caracteristica de Windows se mantendra)."
    $conf = Read-Host "  Confirmar? [s/N]"
    if ($conf -notmatch '^[sS]$') { return }

    $p = Leer-Puerto $ESTADO_IIS "80"

    Stop-Service W3SVC -ErrorAction SilentlyContinue

    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Remove-WebBinding -Name $IIS_SITE -BindingInformation "*:${p}:" -ErrorAction SilentlyContinue
    if (Test-Path "C:\inetpub\wwwroot\pract6") {
        Remove-Item -Recurse -Force "C:\inetpub\wwwroot\pract6"
    }
    Remove-Item -Force $ESTADO_IIS -ErrorAction SilentlyContinue

    Firewall-Cerrar-Puerto $p "IIS"

    Start-Service W3SVC -ErrorAction SilentlyContinue
    Write-Host "  Configuracion de IIS eliminada. Puerto $p cerrado."
    Pausar
}

function Borrar-Apache {
    Write-Titulo "Borrar configuracion / Desinstalar Apache Win64"

    if (-not (Servicio-Instalado "Apache2.4")) {
        Write-Host "  Apache no esta instalado."
        Pausar; return
    }

    Write-Host "  Se eliminara Apache Win64 y sus archivos."
    $conf = Read-Host "  Confirmar? [s/N]"
    if ($conf -notmatch '^[sS]$') { return }

    $p = Leer-Puerto $ESTADO_APACHE "8081"

    Stop-Service    "Apache2.4" -ErrorAction SilentlyContinue
    Disable-Service "Apache2.4" -ErrorAction SilentlyContinue

    if (Verificar-Chocolatey) {
        choco uninstall apache-httpd -y --remove-dependencies 2>$null
    } else {
        & "$APACHE_DIR\bin\httpd.exe" -k uninstall 2>$null
        Remove-Item -Recurse -Force $APACHE_DIR -ErrorAction SilentlyContinue
    }

    Remove-Item -Force $ESTADO_APACHE -ErrorAction SilentlyContinue
    Firewall-Cerrar-Puerto $p "Apache"

    Write-Host "  Apache desinstalado. Puerto $p cerrado."
    Pausar
}

function Borrar-Nginx {
    Write-Titulo "Borrar configuracion / Desinstalar Nginx Windows"

    if (-not (Servicio-Instalado "nginx")) {
        Write-Host "  Nginx no esta instalado."
        Pausar; return
    }

    Write-Host "  Se eliminara Nginx y sus archivos."
    $conf = Read-Host "  Confirmar? [s/N]"
    if ($conf -notmatch '^[sS]$') { return }

    $p = Leer-Puerto $ESTADO_NGINX "8082"

    Stop-Service "nginx" -ErrorAction SilentlyContinue

    if (Verificar-Chocolatey) {
        choco uninstall nginx -y 2>$null
    } else {
        sc.exe delete nginx | Out-Null
        Remove-Item -Recurse -Force $NGINX_DIR -ErrorAction SilentlyContinue
    }

    Remove-Item -Force $ESTADO_NGINX -ErrorAction SilentlyContinue
    Firewall-Cerrar-Puerto $p "Nginx"

    Write-Host "  Nginx desinstalado. Puerto $p cerrado."
    Pausar
}

function Menu-Borrar {
    while ($true) {
        Mostrar-Menu-Servidor "Borrar configuracion / Desinstalar"
        $opc = Read-Host "  Opcion"
        switch ($opc) {
            "1" { Borrar-IIS    }
            "2" { Borrar-Apache }
            "3" { Borrar-Nginx  }
            "0" { return }
            default { Mensaje-Invalido }
        }
    }
}

# =============================================================================
# BUCLE PRINCIPAL
# =============================================================================

# Verificar que se ejecuta como Administrador
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  ERROR: Este script debe ejecutarse como Administrador."
    Write-Host "  Haga clic derecho en PowerShell y seleccione 'Ejecutar como administrador'."
    Write-Host "  O use: Start-Process powershell -Verb RunAs -ArgumentList '-File main.ps1'"
    Write-Host ""
    exit 1
}

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
