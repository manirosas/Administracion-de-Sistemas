<#
.SYNOPSIS
    http_funciones.ps1 - Funciones de instalacion y gestion de servidores HTTP
    Importado por main.ps1 via dot-sourcing: . "$PSScriptRoot\http_funciones.ps1"
#>

# =============================================================================
# CONSULTA DE VERSIONES (MENU)
# =============================================================================

function Consultar-Versiones-IIS {
    Write-Titulo "Versiones de IIS disponibles"
    Write-Host "  IIS se instala como caracteristica de Windows."
    Write-Host "  La version depende del sistema operativo."
    Write-Host ""

    if (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue) {
        $feat = Get-WindowsFeature -Name Web-Server
        $estado = if ($feat.Installed) { "instalada" } else { "no instalada" }
        Write-Host "  Caracteristica 'Web-Server' (IIS): $estado"
    } else {
        $dism = dism /online /get-featureinfo /featurename:IIS-WebServerRole 2>$null
        if ($dism) {
            Write-Host "  $($dism | Select-String 'State')"
        } else {
            Write-Host "  No se pudo determinar el estado de IIS en este sistema."
        }
    }

    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if ($iisVer) { Write-Host "  Version instalada: $iisVer" }
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
            Install-WindowsFeature -Name Web-Server,Web-Common-Http,Web-Static-Content,
                Web-Http-Errors,Web-Http-Logging,Web-Request-Monitor,
                Web-Security,Web-Filtering,Web-Http-Redirect,
                Web-Mgmt-Console,Web-Scripting-Tools `
                -IncludeManagementTools -ErrorAction Stop | Out-Null
        } catch {
            Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,
                IIS-WebServer,IIS-CommonHttpFeatures,IIS-StaticContent,
                IIS-DefaultDocument,IIS-HttpErrors,IIS-Security,
                IIS-RequestFiltering,IIS-HttpLogging,IIS-ManagementConsole `
                -All -NoRestart | Out-Null
        }
        Import-Module WebAdministration -ErrorAction Stop
        Write-Host "  IIS instalado correctamente."
    }

    $puertoActual = Leer-Puerto $ESTADO_IIS "80"
    Write-Host "  Defina el puerto de escucha para IIS:"
    $puerto = Pedir-Puerto "80" ""

    $webRoot = "C:\inetpub\wwwroot\pract6"
    if (-not (Test-Path $webRoot)) { New-Item -ItemType Directory -Path $webRoot -Force | Out-Null }

    $bindingAnterior = Get-WebBinding -Name $IIS_SITE -ErrorAction SilentlyContinue |
                       Where-Object { $_.bindingInformation -like "*:${puertoActual}:*" }
    if ($bindingAnterior) {
        Remove-WebBinding -Name $IIS_SITE -BindingInformation "*:${puertoActual}:" -ErrorAction SilentlyContinue
    }

    $existeBinding = Get-WebBinding -Name $IIS_SITE -ErrorAction SilentlyContinue |
                     Where-Object { $_.bindingInformation -eq "*:${puerto}:" }
    if (-not $existeBinding) {
        New-WebBinding -Name $IIS_SITE -IPAddress "*" -Port $puerto -Protocol "http"
        Write-Host "  Binding IIS: puerto $puerto configurado."
    }

    Set-ItemProperty "IIS:\Sites\$IIS_SITE" -Name physicalPath -Value $webRoot
    Write-Host "  Web root IIS: $webRoot"

    # Eliminar X-Powered-By
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

    # Ocultar version del servidor
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
        -Filter "system.webServer/security/requestFiltering" `
        -Name "removeServerHeader" -Value $true
    Write-Host "  Seguridad: encabezado Server ocultado via Request Filtering."

    # Encabezados de seguridad
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
    Write-Host "  Seguridad: encabezados de seguridad configurados."

    # Bloquear metodos peligrosos
    foreach ($metodo in @("TRACE","TRACK","DELETE","PUT","PATCH")) {
        try {
            Add-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
                -Filter "system.webServer/security/requestFiltering/verbs" `
                -Name "." -Value @{verb=$metodo; allowed=$false}
        } catch { }
    }
    Write-Host "  Seguridad: metodos TRACE, TRACK, DELETE, PUT, PATCH bloqueados."

    # Deshabilitar listado de directorios
    Set-WebConfigurationProperty -PSPath "IIS:\Sites\$IIS_SITE" `
        -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false
    Write-Host "  Seguridad: listado de directorios deshabilitado."

    # Permisos
    $acl = Get-Acl $webRoot
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "IIS_IUSRS", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $webRoot -AclObject $acl
    Write-Host "  Permisos: IIS_IUSRS con ReadAndExecute en $webRoot."

    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if (-not $iisVer) { $iisVer = "Desconocida" }
    Crear-Index-Html $webRoot "IIS" $iisVer $puerto

    Firewall-Abrir-Puerto $puerto "IIS"
    Guardar-Puerto $ESTADO_IIS $puerto

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

    if (-not (Verificar-Chocolatey)) {
        Write-Host "  Chocolatey es necesario para instalar Apache."
        $resp = Read-Host "  Instalar Chocolatey ahora? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
        Instalar-Chocolatey
    }

    if (Servicio-Instalado "Apache") {
        Write-Host "  Apache ya esta instalado."
        $resp = Read-Host "  Desea reconfigurar? [s/N]"
        if ($resp -notmatch '^[sS]$') { return }
    }

    $version = Seleccionar-Version-Choco "apache-httpd"

    Write-Host ""
    Write-Host "  Defina el puerto de escucha para Apache:"
    $puerto = Pedir-Puerto "8081" ""

    $chocoParams = "/Port:$puerto"
    if ($version -eq "default") {
        Write-Host "  Instalando Apache Win64 (version por defecto) en puerto $puerto..."
        choco install apache-httpd -y --no-progress --force --params $chocoParams 2>&1 | Tee-Object -Variable chocoOut
    } else {
        Write-Host "  Instalando Apache Win64 version $version en puerto $puerto..."
        choco install apache-httpd --version $version -y --no-progress --force --params $chocoParams 2>&1 | Tee-Object -Variable chocoOut
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  AVISO: No se pudo instalar la version $version. Instalando por defecto..."
            choco install apache-httpd -y --no-progress --force --params $chocoParams
        }
    }

    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")

    if (-not (Test-Path "$APACHE_DIR\conf\httpd.conf")) {
        Write-Host "  AVISO: No se encontro httpd.conf en $APACHE_DIR."
        Write-Host "  Verifique la instalacion manualmente."
        Pausar; return
    }

    $verReal = (choco list apache-httpd --local-only --limit-output 2>$null) -replace "apache-httpd\|",""
    if ([string]::IsNullOrEmpty($verReal)) { $verReal = "Instalada" }

    $webRoot = "$APACHE_DIR\htdocs"
    New-Item -ItemType Directory -Path $webRoot -Force | Out-Null

    $httpdConf = "$APACHE_DIR\conf\httpd.conf"
    $contenido = Get-Content $httpdConf -Raw
    $contenido = $contenido -replace "(?m)^Listen \d+", "Listen $puerto"
    if ($contenido -notmatch "ServerTokens") {
        $contenido += "`nServerTokens Prod`nServerSignature Off`n"
    } else {
        $contenido = $contenido -replace "ServerTokens \w+", "ServerTokens Prod"
        $contenido = $contenido -replace "ServerSignature \w+", "ServerSignature Off"
    }
    $contenido = $contenido -replace "#LoadModule headers_module", "LoadModule headers_module"
    $contenido = $contenido -replace "#LoadModule rewrite_module", "LoadModule rewrite_module"
    $contenido | Set-Content $httpdConf -Encoding UTF8
    Write-Host "  httpd.conf: puerto $puerto, ServerTokens Prod, modulos habilitados."

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

    $httpdContenido = Get-Content $httpdConf -Raw
    if ($httpdContenido -notmatch "pract6-vhost.conf") {
        Add-Content $httpdConf "`nInclude conf/extra/pract6-vhost.conf" -Encoding UTF8
    }
    Write-Host "  VirtualHost configurado: $vhostPath"

    Crear-Index-Html $webRoot "Apache Win64" $verReal $puerto

    if (-not (Servicio-Instalado "Apache")) {
        & "$APACHE_DIR\bin\httpd.exe" -k install 2>$null
        Write-Host "  Apache registrado como servicio de Windows."
    }

    Firewall-Abrir-Puerto $puerto "Apache"
    Guardar-Puerto $ESTADO_APACHE $puerto

    Start-Service "Apache" -ErrorAction SilentlyContinue
    $estado = Estado-Servicio "Apache"
    Write-Host "  Apache: $estado en puerto $puerto."

    Write-Host ""
    Write-Host "  Instalacion completada."
    Write-Host "  Servicio : Apache"
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

    # Detectar directorio nginx DESPUES de instalar (incluye version en el nombre)
    $NGINX_DIR = (Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
    if (-not $NGINX_DIR) {
        Write-Host "  AVISO: No se encontro el directorio de Nginx en C:\tools."
        Pausar; return
    }
    Write-Host "  Directorio Nginx detectado: $NGINX_DIR"

    if (-not (Test-Path "$NGINX_DIR\conf\nginx.conf")) {
        Write-Host "  AVISO: No se encontro nginx.conf en $NGINX_DIR."
        Pausar; return
    }

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    if ([string]::IsNullOrEmpty($verReal)) { $verReal = "Instalada" }

    $webRoot = "$NGINX_DIR\html"
    New-Item -ItemType Directory -Path $webRoot -Force | Out-Null

    # nginx.conf SIN BOM (Nginx no soporta UTF-8 con BOM)
    $ngContenido = @"
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
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText("$NGINX_DIR\conf\nginx.conf", $ngContenido, $utf8NoBom)
    Write-Host "  nginx.conf configurado sin BOM, puerto $puerto."

    Crear-Index-Html $webRoot "Nginx Windows" $verReal $puerto

    # Detener procesos y servicios previos
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $scQuery = sc.exe query nginx 2>$null
    if ($scQuery -match "SERVICE_NAME") {
        sc.exe stop nginx 2>$null | Out-Null
        Start-Sleep -Seconds 1
        sc.exe delete nginx 2>$null | Out-Null
        Start-Sleep -Seconds 2
        Write-Host "  Servicio nginx previo eliminado."
    }
    try {
        $nssmQuery = & nssm status nginx 2>$null
        if ($nssmQuery -and $nssmQuery -notmatch "open") {
            nssm remove nginx confirm 2>$null | Out-Null
            Start-Sleep -Seconds 2
            Write-Host "  Servicio nginx NSSM previo eliminado."
        }
    } catch { }

    Firewall-Abrir-Puerto $puerto "Nginx"
    Guardar-Puerto $ESTADO_NGINX $puerto

    Start-Process -FilePath "$NGINX_DIR\nginx.exe" -WorkingDirectory $NGINX_DIR -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $estado = if (Get-Process nginx -ErrorAction SilentlyContinue) { "running" } else { "error al iniciar" }
    Write-Host "  Nginx: $estado en puerto $puerto."

    Write-Host ""
    Write-Host "  Instalacion completada."
    Write-Host "  Servicio : nginx (proceso)"
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

    try {
        Set-WebBinding -Name $IIS_SITE `
                       -BindingInformation "*:${pa}:" `
                       -PropertyName "bindingInformation" `
                       -Value "*:${np}:"
        Write-Host "  IIS binding actualizado a puerto $np."
    } catch {
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

    if (-not (Servicio-Instalado "Apache")) {
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
    Crear-Index-Html "$APACHE_DIR\htdocs" "Apache Win64" $verReal $np

    Firewall-Cerrar-Puerto $pa "Apache"
    Firewall-Abrir-Puerto  $np "Apache"
    Guardar-Puerto $ESTADO_APACHE $np

    Restart-Service "Apache" -ErrorAction SilentlyContinue
    Write-Host "  Apache reiniciado en puerto $np."
    Pausar
}

function Cambiar-Puerto-Nginx {
    Write-Titulo "Cambiar Puerto - Nginx Windows"

    if (-not (Servicio-Instalado "nginx")) {
        Write-Host "  ERROR: Nginx no esta instalado."
        Pausar; return
    }

    $NGINX_DIR = (Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
    if (-not $NGINX_DIR) { $NGINX_DIR = "C:\tools\nginx" }

    $pa = Leer-Puerto $ESTADO_NGINX "8082"
    Write-Host "  Puerto actual: $pa"
    Write-Host ""
    Write-Host "  Defina el nuevo puerto:"
    $np = Pedir-Puerto $pa $pa

    $ngConf = "$NGINX_DIR\conf\nginx.conf"
    if (Test-Path $ngConf) {
        $contenidoNg = (Get-Content $ngConf -Raw) -replace "listen\s+$pa;", "listen $np;"
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($ngConf, $contenidoNg, $utf8NoBom)
        Write-Host "  nginx.conf: puerto actualizado a $np."
    }

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    Crear-Index-Html "$NGINX_DIR\html" "Nginx Windows" $verReal $np

    Firewall-Cerrar-Puerto $pa "Nginx"
    Firewall-Abrir-Puerto  $np "Nginx"
    Guardar-Puerto $ESTADO_NGINX $np

    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Process -FilePath "$NGINX_DIR\nginx.exe" -WorkingDirectory $NGINX_DIR -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $estado = if (Get-Process nginx -ErrorAction SilentlyContinue) { "running" } else { "error al iniciar" }
    Write-Host "  Nginx: $estado en puerto $np."
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

    if (-not (Servicio-Instalado "Apache")) {
        Write-Host "  Apache no esta instalado."
        Pausar; return
    }

    Write-Host "  Se eliminara Apache Win64 y sus archivos."
    $conf = Read-Host "  Confirmar? [s/N]"
    if ($conf -notmatch '^[sS]$') { return }

    $p = Leer-Puerto $ESTADO_APACHE "8081"
    Stop-Service    "Apache" -ErrorAction SilentlyContinue
    Disable-Service "Apache" -ErrorAction SilentlyContinue

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
    $NGINX_DIR = (Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)

    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Verificar-Chocolatey) {
        choco uninstall nginx -y 2>$null
    } else {
        sc.exe delete nginx | Out-Null
        if ($NGINX_DIR) { Remove-Item -Recurse -Force $NGINX_DIR -ErrorAction SilentlyContinue }
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
