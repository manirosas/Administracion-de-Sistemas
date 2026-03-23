# =============================================================================
# lib_ssl.ps1 - SSL/TLS para IIS, Apache, Nginx y FTPS
# =============================================================================

$DNS_NAME = "reprobados.com"

# =============================================================================
# CERTIFICADOS
# =============================================================================

function New-CertificadoAutofirmado {
    param(
        [string]$DnsName       = $DNS_NAME,
        [int]$ValidityYears    = 5,
        [string]$FriendlyName  = "Prac7 SSL"
    )
    $existente = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=$DnsName" -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1
    if ($existente) {
        Write-Host "  Reutilizando certificado: $($existente.Thumbprint)"
        return $existente
    }
    $cert = New-SelfSignedCertificate `
        -DnsName $DnsName `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddYears($ValidityYears) `
        -FriendlyName $FriendlyName `
        -KeyExportPolicy Exportable `
        -KeyLength 2048 `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
    Write-Host "  Certificado creado: $($cert.Thumbprint) / CN=$DnsName"
    return $cert
}

function New-CertificadoOpenSSL {
    param(
        [string]$CertDir,
        [string]$DnsName   = $DNS_NAME,
        [int]$ValidityDays = 365
    )
    $certFile = "$CertDir\server.crt"
    $keyFile  = "$CertDir\server.key"

    if (-not (Test-Path $CertDir)) { New-Item -ItemType Directory -Path $CertDir -Force | Out-Null }

    if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
        Write-Host "  Reutilizando certificado OpenSSL en $CertDir"
        return @{ CertFile=$certFile; KeyFile=$keyFile }
    }

    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) { Install-OpenSSLIfMissing }

    $env:OPENSSL_CONF = "C:\Program Files\OpenSSL-Win64\bin\openssl.cfg"

    $argList = "req -x509 -nodes -days $ValidityDays -newkey rsa:2048" +
               " -keyout `"$keyFile`" -out `"$certFile`"" +
               " -subj `/C=MX/ST=Sinaloa/L=Culiacan/O=Reprobados/CN=$DnsName`""

    Start-Process -FilePath "openssl" -ArgumentList $argList -NoNewWindow -Wait

    if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
        Write-Host "  Certificado OpenSSL generado en $CertDir"
        return @{ CertFile=$certFile; KeyFile=$keyFile }
    }
    Write-Host "  ERROR: No se genero el certificado SSL."
    return $null
}

# =============================================================================
# SSL IIS
# Redireccion via web.config (no depende de URL Rewrite module)
# =============================================================================
function Configurar-SSL-IIS {
    param(
        [string]$SiteName  = "ServicioWebIIS",
        [int]$HttpPort     = 80,
        [int[]]$HttpsPorts = @(443,444,8443,9443),
        [switch]$ForceHTTPS
    )
    Import-Module WebAdministration -ErrorAction Stop

    if (-not (Get-Website -Name $SiteName -ErrorAction SilentlyContinue)) {
        New-IISWebsite -name $SiteName -port $HttpPort
    }

    # Puerto fisico del sitio
    $physicalPath = (Get-ItemProperty "IIS:\Sites\$SiteName").physicalPath

    # Seleccionar puerto HTTPS libre
    $httpsPort = $null
    foreach ($p in $HttpsPorts) {
        if (-not (Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue)) {
            $httpsPort = $p; break
        }
    }
    if (-not $httpsPort) { Write-Host "  No hay puertos HTTPS disponibles."; return }

    $cert = New-CertificadoAutofirmado -DnsName $DNS_NAME

    # --- Binding HTTPS ---
    $existeHttps = Get-WebBinding -Name $SiteName -Protocol https -Port $httpsPort -ErrorAction SilentlyContinue
    if ($existeHttps) { Remove-WebBinding -Name $SiteName -Protocol https -Port $httpsPort }
    New-WebBinding -Name $SiteName -Protocol https -Port $httpsPort -IPAddress "*" -SslFlags 0
    $binding = Get-WebBinding -Name $SiteName -Protocol https -Port $httpsPort
    $binding.AddSslCertificate($cert.Thumbprint, "my")

    # --- Binding HTTP ---
    if (-not (Get-WebBinding -Name $SiteName -Protocol http -Port $HttpPort -ErrorAction SilentlyContinue)) {
        New-WebBinding -Name $SiteName -Protocol http -Port $HttpPort -IPAddress "*"
    }

    # --- Redireccion HTTP -> HTTPS ---
    # Metodo 1 (preferido): URL Rewrite con variable {SERVER_NAME} - redirige al mismo host
    # Metodo 2 (fallback):  httpRedirect con IP local fija cuando URL Rewrite no esta instalado
    if ($ForceHTTPS -and $physicalPath -and (Test-Path $physicalPath)) {

        # Habilitar modulo httpRedirect de IIS (necesario para ambos metodos)
        try { Install-WindowsFeature Web-Http-Redirect -ErrorAction SilentlyContinue | Out-Null } catch {}
        try { Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}

        # Redireccion HTTP -> HTTPS via location especifico en applicationHost.config
        # Usar -Location "SiteName" crea un bloque separado que tiene prioridad
        # sobre el <location path=""> global que tiene enabled="false"
        $ipLocal = (Get-NetIPAddress -AddressFamily IPv4 |
                    Where-Object {
                        $_.InterfaceAlias -notlike "*Loopback*" -and
                        $_.IPAddress      -notlike "169.*"
                    } | Select-Object -First 1).IPAddress
        if (-not $ipLocal) { $ipLocal = "localhost" }
        $destino = "https://$ipLocal`:$httpsPort/"

        try {
            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST" `
                -Location $SiteName `
                -Filter "system.webServer/httpRedirect" `
                -Name "enabled" -Value $true

            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST" `
                -Location $SiteName `
                -Filter "system.webServer/httpRedirect" `
                -Name "destination" -Value $destino

            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST" `
                -Location $SiteName `
                -Filter "system.webServer/httpRedirect" `
                -Name "exactDestination" -Value $false

            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST" `
                -Location $SiteName `
                -Filter "system.webServer/httpRedirect" `
                -Name "httpResponseStatus" -Value "Permanent"

            Write-Host "  Redireccion configurada: http://$ipLocal`:$HttpPort -> $destino"
        } catch {
            Write-Host "  ERROR al configurar redirect: $_"
        }
    }

    New-FirewallRule -DisplayName "IIS HTTPS $httpsPort" -Port $httpsPort -Protocol "TCP"
    New-FirewallRule -DisplayName "IIS HTTP $HttpPort"   -Port $HttpPort  -Protocol "TCP"

    try { Stop-WebItem "IIS:\Sites\$SiteName" -ErrorAction SilentlyContinue } catch {}
    Start-Sleep 2
    try { Start-WebItem "IIS:\Sites\$SiteName" -ErrorAction SilentlyContinue } catch {}

    # Actualizar index.html con SSL=Activo
    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if (-not $iisVer) { $iisVer = "10.0" }
    if ($physicalPath) {
        New-IndexHtml -Directorio $physicalPath -Servicio "IIS" -Version $iisVer -Puerto $httpsPort
    }

    Write-Host "  IIS SSL listo. HTTP:$HttpPort -> HTTPS:$httpsPort | CN=$DNS_NAME"
}

# =============================================================================
# SSL Apache
# Problema Forbidden resuelto: Directory apunta a $DocumentRoot, no a htdocs
# =============================================================================
function Configurar-SSL-Apache {
    param(
        [int]$HttpPort        = 8081,
        [int[]]$HttpsPorts    = @(443,444,8443,9443,10443),
        [string]$DocumentRoot = "C:\WebServers\Apache",
        [switch]$ForceHTTPS
    )
    $apachePath = Get-ApachePath
    if (-not $apachePath) { Write-Host "  ERROR: Apache no encontrado."; return }

    $httpdExe  = "$apachePath\bin\httpd.exe"
    $httpdConf = "$apachePath\conf\httpd.conf"
    $sslConf   = "$apachePath\conf\extra\httpd-ssl.conf"

    # Seleccionar puerto HTTPS libre
    $httpsPort = $null
    foreach ($p in $HttpsPorts) {
        if (-not (Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue)) {
            $httpsPort = $p; break
        }
    }
    if (-not $httpsPort) { Write-Host "  No hay puertos HTTPS disponibles."; return }

    $certInfo = New-CertificadoOpenSSL -CertDir "$apachePath\conf\ssl"
    if (-not $certInfo) { return }

    # Asegurarse de que el DocumentRoot existe y tiene permisos
    if (-not (Test-Path $DocumentRoot)) {
        New-Item -ItemType Directory -Path $DocumentRoot -Force | Out-Null
    }

    # Habilitar modulos
    $conf = Get-Content $httpdConf -Raw
    foreach ($mod in @('ssl_module','rewrite_module','socache_shmcb_module','headers_module')) {
        $conf = $conf -replace "#LoadModule $mod", "LoadModule $mod"
    }
    $conf = $conf -replace 'Include conf/extra/httpd-ahssl.conf', '#Include conf/extra/httpd-ahssl.conf'
    if ($conf -notmatch 'Include conf/extra/httpd-ssl\.conf') {
        $conf += "`nInclude conf/extra/httpd-ssl.conf`n"
    } else {
        $conf = $conf -replace '#Include conf/extra/httpd-ssl\.conf', 'Include conf/extra/httpd-ssl.conf'
    }
    Set-Content $httpdConf -Value $conf -Encoding UTF8

    # *** CLAVE: <Directory> apunta a $DocumentRoot, no a htdocs ***
    # Tambien usar barras normales que Apache entiende en Windows
    $docRootFwd  = $DocumentRoot  -replace '\\','/'
    $apachePathFwd = $apachePath  -replace '\\','/'
    $certFileFwd = $certInfo.CertFile -replace '\\','/'
    $keyFileFwd  = $certInfo.KeyFile  -replace '\\','/'

    $vhostHttps = @"

Listen $httpsPort

<VirtualHost *:$httpsPort>
    ServerName $DNS_NAME`:$httpsPort
    DocumentRoot "$docRootFwd"
    DirectoryIndex index.html

    SSLEngine on
    SSLCertificateFile    "$certFileFwd"
    SSLCertificateKeyFile "$keyFileFwd"

    <Directory "$docRootFwd">
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set X-Content-Type-Options "nosniff"
    </IfModule>

    ErrorLog  "$apachePathFwd/logs/ssl_error.log"
    CustomLog "$apachePathFwd/logs/ssl_access.log" common
</VirtualHost>

"@

    # Limpiar httpd-ssl.conf de VirtualHosts y Listen anteriores
    if (Test-Path $sslConf) {
        $sslContent = Get-Content $sslConf -Raw
        $sslContent = $sslContent -replace '(?ms)<VirtualHost.*?</VirtualHost>', ''
        $sslContent = $sslContent -replace '(?m)^\s*Listen\s+\d+\s*$', ''
    } else {
        $sslContent = "# SSL Configuration Apache - Prac7`n"
    }
    $sslContent += $vhostHttps
    Set-Content $sslConf -Value $sslContent -Encoding UTF8

    # VirtualHost HTTP con redireccion
    if ($ForceHTTPS) {
        $vhostHttp = @"

<VirtualHost *:$HttpPort>
    ServerName $DNS_NAME`:$HttpPort
    DocumentRoot "$docRootFwd"

    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule ^(.*)$ https://%{SERVER_NAME}:$httpsPort/$1 [R=301,L]
    </IfModule>

    <Directory "$docRootFwd">
        Options -Indexes
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

"@
        $confActual = Get-Content $httpdConf -Raw
        $confActual = $confActual -replace '(?ms)<VirtualHost \*:\d+>.*?DocumentRoot.*?</VirtualHost>\s*', ''
        $confActual += $vhostHttp
        Set-Content $httpdConf -Value $confActual -Encoding UTF8
        Write-Host "  Redireccion HTTP:$HttpPort -> HTTPS:$httpsPort."
    }

    # Verificar sintaxis
    $test = & $httpdExe -t 2>&1 | Out-String
    if ($test -notmatch "Syntax OK") {
        Write-Host "  ERROR sintaxis Apache:"; Write-Host $test
        return
    }

    New-FirewallRule -DisplayName "Apache HTTPS $httpsPort" -Port $httpsPort -Protocol "TCP"

    $svc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
    if ($svc) { Stop-Service $svc.Name -Force; Start-Sleep 2; Start-Service $svc.Name }

    $verReal = (choco list apache-httpd --local-only --limit-output 2>$null) -replace "apache-httpd\|",""
    if ($verReal) { New-IndexHtml -Directorio $DocumentRoot -Servicio "Apache" -Version $verReal -Puerto $httpsPort }

    Write-Host "  Apache SSL listo. HTTP:$HttpPort -> HTTPS:$httpsPort | CN=$DNS_NAME"
}

# =============================================================================
# SSL Nginx
# =============================================================================
function Configurar-SSL-Nginx {
    param(
        [int]$HttpPort     = 8082,
        [int[]]$HttpsPorts = @(443,444,8443,9443,10443),
        [switch]$ForceHTTPS
    )
    $nginxPath = Get-NginxPath
    if (-not $nginxPath) { Write-Host "  ERROR: Nginx no encontrado en C:\tools."; return }

    $nginxExe  = "$nginxPath\nginx.exe"
    $nginxConf = "$nginxPath\conf\nginx.conf"

    $httpsPort = $null
    foreach ($p in $HttpsPorts) {
        if (-not (Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue)) {
            $httpsPort = $p; break
        }
    }
    if (-not $httpsPort) { Write-Host "  No hay puertos HTTPS disponibles."; return }

    $certInfo = New-CertificadoOpenSSL -CertDir "$nginxPath\conf\ssl"
    if (-not $certInfo) { return }

    # Rutas con barras normales para nginx.conf
    $certFwd = ($certInfo.CertFile -replace '\\','/') -replace "^[A-Za-z]:/","/"
    $keyFwd  = ($certInfo.KeyFile  -replace '\\','/') -replace "^[A-Za-z]:/","/"
    # Nginx en Windows acepta rutas absolutas con letra de unidad si usamos barras /
    $certFwd = $certInfo.CertFile -replace '\\','/'
    $keyFwd  = $certInfo.KeyFile  -replace '\\','/'

    # Backup
    $backup = "$nginxConf.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $nginxConf $backup -Force

    $httpsRedirect = "https://`$host:$httpsPort`$request_uri"

    $httpsBlock = @"

    server {
        listen      $httpsPort ssl;
        server_name $DNS_NAME localhost;

        ssl_certificate     "$certFwd";
        ssl_certificate_key "$keyFwd";
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options        "SAMEORIGIN"  always;
        add_header X-Content-Type-Options "nosniff"     always;

        location / {
            root  html;
            index index.html index.htm;
        }
        error_page 500 502 503 504 /50x.html;
        location = /50x.html { root html; }
    }

"@

    $httpBlock = ""
    if ($ForceHTTPS) {
        $httpBlock = @"

    server {
        listen      $HttpPort;
        server_name $DNS_NAME localhost;
        return 301  $httpsRedirect;
    }

"@
    }

    $confContent = Get-Content $nginxConf -Raw

    # Reemplazar bloques server existentes dentro del http {}
    # Estrategia: cortar todo desde el primer "server {" hasta el ultimo "}" del http block
    try {
        $firstServer = $confContent.IndexOf("    server {")
        if ($firstServer -lt 0) { $firstServer = $confContent.IndexOf("server {") }

        if ($firstServer -ge 0) {
            $lastBrace   = $confContent.LastIndexOf("}")
            $antes       = $confContent.Substring(0, $firstServer)
            $despues     = $confContent.Substring($lastBrace)          # solo el ultimo "}"
            $confContent = $antes + $httpsBlock + $httpBlock + $despues
        } else {
            # No habia server block, agregar dentro de http {}
            $lastBrace   = $confContent.LastIndexOf("}")
            $confContent = $confContent.Substring(0, $lastBrace) +
                           $httpsBlock + $httpBlock + "}"
        }
    } catch {
        $confContent += $httpsBlock + $httpBlock
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($nginxConf, $confContent, $utf8NoBom)

    # Validar
    Push-Location $nginxPath
    $test = & $nginxExe -t 2>&1 | Out-String
    Pop-Location

    if ($test -notmatch "syntax is ok") {
        Write-Host "  ERROR nginx.conf. Restaurando backup."; Write-Host $test
        Copy-Item $backup $nginxConf -Force; return
    }

    New-FirewallRule -DisplayName "Nginx HTTPS $httpsPort" -Port $httpsPort -Protocol "TCP"
    if ($ForceHTTPS) { New-FirewallRule -DisplayName "Nginx HTTP $HttpPort" -Port $HttpPort -Protocol "TCP" }

    # Reiniciar
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 1
    Start-Process -FilePath $nginxExe -WorkingDirectory $nginxPath -WindowStyle Hidden
    Start-Sleep 2

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    if ($verReal) { New-IndexHtml -Directorio "$nginxPath\html" -Servicio "Nginx" -Version $verReal -Puerto $httpsPort }

    Write-Host "  Nginx SSL listo. HTTP:$HttpPort -> HTTPS:$httpsPort | CN=$DNS_NAME"
}

# =============================================================================
# FTPS en IIS-FTP
# =============================================================================
function Configurar-FTPS {
    param([string]$SiteName = "Repositorio")

    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $aux) { Write-Host "  FTPSVC no instalado."; return }

    Import-Module WebAdministration -ErrorAction SilentlyContinue

    $cert = New-CertificadoAutofirmado -DnsName $DNS_NAME -FriendlyName "FTPS Prac7"

    Set-ItemProperty "IIS:\Sites\$SiteName" `
        -Name "ftpServer.security.ssl.serverCertHash"       -Value $cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\$SiteName" `
        -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslRequire"
    Set-ItemProperty "IIS:\Sites\$SiteName" `
        -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslRequire"

    Restart-Service ftpsvc
    Write-Host "  FTPS activo en '$SiteName'. Cert: $($cert.Thumbprint) | CN=$DNS_NAME"
}