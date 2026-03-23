# =============================================================================
# lib_http.ps1 - Instalacion de servidores HTTP (IIS, Apache, Nginx)
# =============================================================================

function Get-ApachePath {
    foreach ($p in @(
        "C:\Apache24",
        "C:\Apache",
        "$env:APPDATA\Apache24",
        "C:\Users\Administrator\AppData\Roaming\Apache24"
    )) {
        if (Test-Path "$p\bin\httpd.exe") { return $p }
    }
    return $null
}

function Get-NginxPath {
    $dir = Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
           Sort-Object Name -Descending | Select-Object -First 1
    if ($dir -and (Test-Path "$($dir.FullName)\nginx.exe")) { return $dir.FullName }
    return $null
}

# =============================================================================
# HTML INDEX con CSS basico
# =============================================================================
function New-IndexHtml {
    param(
        [string]$Directorio,
        [string]$Servicio,
        [string]$Version,
        [int]$Puerto,
        [string]$SO = "Windows Server"
    )
    if (-not (Test-Path $Directorio)) {
        New-Item -ItemType Directory -Path $Directorio -Force | Out-Null
    }
    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>$Servicio - Practica 7</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 2.5rem 3rem;
      max-width: 480px;
      width: 90%;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .badge {
      display: inline-block;
      background: #3b82f6;
      color: #fff;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.2rem 0.7rem;
      border-radius: 999px;
      margin-bottom: 1rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
    h1 { font-size: 1.8rem; margin-bottom: 1.5rem; color: #f1f5f9; }
    table { width: 100%; border-collapse: collapse; }
    td {
      padding: 0.55rem 0.4rem;
      border-bottom: 1px solid #334155;
      font-size: 0.95rem;
    }
    td:first-child { color: #94a3b8; width: 45%; }
    td:last-child  { color: #38bdf8; font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    .footer {
      margin-top: 1.5rem;
      font-size: 0.78rem;
      color: #475569;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Practica 7</span>
    <h1>$Servicio</h1>
    <table>
      <tr><td>Sistema operativo</td><td>$SO</td></tr>
      <tr><td>Version</td><td>$Version</td></tr>
      <tr><td>Puerto HTTP</td><td>$Puerto</td></tr>
      <tr><td>Dominio</td><td>reprobados.com</td></tr>
      <tr><td>SSL/TLS</td><td>Activo (HTTPS)</td></tr>
    </table>
    <div class="footer">Generado el $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
  </div>
</body>
</html>
"@
    $html | Set-Content "$Directorio\index.html" -Encoding UTF8
    Write-Host "  index.html creado en: $Directorio"
}

# =============================================================================
# IIS
# =============================================================================
function Instalar-IIS {
    $yaInstalado = $false
    try { Import-Module WebAdministration -ErrorAction Stop; $yaInstalado = $true } catch {}
    if ($yaInstalado) { Write-Host "  IIS ya esta instalado."; return }

    Write-Host "  Instalando IIS..."
    try {
        Install-WindowsFeature -Name Web-Server, Web-Common-Http, Web-Static-Content,
            Web-Http-Errors, Web-Http-Logging, Web-Security, Web-Filtering,
            Web-Mgmt-Console, Web-Scripting-Tools `
            -IncludeManagementTools | Out-Null
    } catch {
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole,
            IIS-WebServer, IIS-CommonHttpFeatures, IIS-StaticContent,
            IIS-DefaultDocument, IIS-HttpErrors, IIS-Security,
            IIS-RequestFiltering, IIS-HttpLogging, IIS-ManagementConsole `
            -All -NoRestart | Out-Null
    }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Write-Host "  IIS instalado."
}

function New-IISWebsite {
    param(
        [string]$name,
        [int]$port,
        [string]$physicalPath = "C:\WebServers\IIS\$name"
    )
    Import-Module WebAdministration -ErrorAction SilentlyContinue

    if (-not (Test-Path $physicalPath)) {
        New-Item -Path $physicalPath -ItemType Directory -Force | Out-Null
    }

    # Obtener version IIS
    $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
    if (-not $iisVer) { $iisVer = "10.0" }

    New-IndexHtml -Directorio $physicalPath -Servicio "IIS" -Version $iisVer -Puerto $port

    # Permisos para IIS_IUSRS
    $acl  = Get-Acl $physicalPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "IIS_IUSRS","ReadAndExecute","ContainerInherit,ObjectInherit","None","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $physicalPath -AclObject $acl

    $existing = Get-Website -Name $name -ErrorAction SilentlyContinue
    if ($existing) { Remove-Website -Name $name -ErrorAction SilentlyContinue }

    New-Website -Name $name -Port $port -PhysicalPath $physicalPath -IPAddress "*" | Out-Null
    Start-Website -Name $name -ErrorAction SilentlyContinue

    New-FirewallRule -DisplayName "IIS HTTP $name $port" -Port $port -Protocol "TCP"
    Write-Host "  Sitio IIS '$name' en puerto $port => $physicalPath"
}

# =============================================================================
# Apache
# =============================================================================
function Instalar-Apache {
    $svc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
    if ($svc) { Write-Host "  Apache ya instalado ($($svc.Name))."; return }

    Asegurar-Chocolatey
    Write-Host "  Instalando apache-httpd via Chocolatey..."
    choco install apache-httpd -y --no-progress
    Refrescar-Path
    Write-Host "  Apache instalado."
}

function Configure-ApacheService {
    param(
        [string]$DocumentRoot = "C:\WebServers\Apache",
        [int]$Port = 8081,
        [switch]$CreateFirewallRule
    )
    $apachePath = Get-ApachePath
    if (-not $apachePath) { Write-Host "  ERROR: Apache no encontrado."; return }

    $httpdConf = "$apachePath\conf\httpd.conf"

    if (-not (Test-Path $DocumentRoot)) {
        New-Item -Path $DocumentRoot -ItemType Directory -Force | Out-Null
    }

    $verReal = (choco list apache-httpd --local-only --limit-output 2>$null) -replace "apache-httpd\|",""
    if (-not $verReal) { $verReal = "2.4.x" }

    New-IndexHtml -Directorio $DocumentRoot -Servicio "Apache" -Version $verReal -Puerto $Port

    $content = Get-Content $httpdConf -Raw
    $content = $content -replace '(?m)^Listen \d+',          "Listen $Port"
    $content = $content -replace 'DocumentRoot "[^"]+"',     "DocumentRoot `"$DocumentRoot`""
    # Actualizar tambien el Directory que Apache define justo despues de DocumentRoot
    $content = $content -replace '<Directory "[^"]+htdocs">',  "<Directory `"$DocumentRoot`">"
    Set-Content $httpdConf -Value $content -Encoding UTF8

    $svc = Get-Service -Name "Apache*" -ErrorAction SilentlyContinue
    if (-not $svc) {
        Push-Location "$apachePath\bin"; & .\httpd.exe -k install 2>$null; Pop-Location
    }
    try { Restart-Service -Name (Get-Service "Apache*").Name -Force -ErrorAction Stop }
    catch { Start-Service -Name (Get-Service "Apache*").Name -ErrorAction SilentlyContinue }

    if ($CreateFirewallRule) {
        New-FirewallRule -DisplayName "Apache HTTP $Port" -Port $Port -Protocol "TCP"
    }
    Write-Host "  Apache configurado en puerto $Port. DocumentRoot: $DocumentRoot"
}

# =============================================================================
# Nginx  -  instala con puerto personalizado para evitar conflicto con puerto 80
# =============================================================================
function Instalar-Nginx {
    param([int]$Puerto = 8082)

    $existente = Get-NginxPath
    if ($existente) { Write-Host "  Nginx ya instalado en: $existente"; return }

    Asegurar-Chocolatey

    Write-Host "  Instalando nginx via Chocolatey (puerto $Puerto)..."
    # --params evita que chocolatey intente usar el 80
    choco install nginx -y --no-progress --params "/Port:$Puerto"
    Refrescar-Path

    # Si fallo (choco no acepto el param), descargar zip manualmente
    if (-not (Get-NginxPath)) {
        Write-Host "  Instalacion via choco fallo. Descargando zip oficial..."
        $zipUrl  = "https://nginx.org/download/nginx-1.26.2.zip"
        $zipDest = "$env:TEMP\nginx.zip"
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipDest -UseBasicParsing
        New-Item -ItemType Directory "C:\tools" -Force | Out-Null
        Expand-Archive -Path $zipDest -DestinationPath "C:\tools" -Force
        Remove-Item $zipDest -Force
    }

    $nginxPath = Get-NginxPath
    if (-not $nginxPath) { Write-Host "  ERROR: No se pudo instalar Nginx."; return }

    Write-Host "  Nginx instalado en: $nginxPath"
    Setup-NginxService -Port $Puerto -DocumentRoot "C:\WebServers\Nginx" -CreateFirewallRule
}

function Setup-NginxService {
    param(
        [int]$Port = 8082,
        [string]$DocumentRoot = "C:\WebServers\Nginx",
        [switch]$CreateFirewallRule
    )
    $nginxPath = Get-NginxPath
    if (-not $nginxPath) { Write-Host "  ERROR: Nginx no encontrado en C:\tools."; return }

    $nginxConf = "$nginxPath\conf\nginx.conf"

    if (-not (Test-Path $DocumentRoot)) {
        New-Item -Path $DocumentRoot -ItemType Directory -Force | Out-Null
    }

    $verReal = (choco list nginx --local-only --limit-output 2>$null) -replace "nginx\|",""
    if (-not $verReal) { $verReal = (Split-Path $nginxPath -Leaf) -replace "nginx-","" }

    New-IndexHtml -Directorio "$nginxPath\html" -Servicio "Nginx" -Version $verReal -Puerto $Port
    New-IndexHtml -Directorio $DocumentRoot     -Servicio "Nginx" -Version $verReal -Puerto $Port

    # Reemplazar el primer listen en el server block
    $content = Get-Content $nginxConf -Raw
    $content = $content -replace '(?m)(\s*listen\s+)\d+(;)', "`${1}$Port`$2"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($nginxConf, $content, $utf8NoBom)

    # Detener proceso anterior si existe
    Get-Process nginx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-Process -FilePath "$nginxPath\nginx.exe" -WorkingDirectory $nginxPath -WindowStyle Hidden
    Start-Sleep -Seconds 2

    if ($CreateFirewallRule) {
        New-FirewallRule -DisplayName "Nginx HTTP $Port" -Port $Port -Protocol "TCP"
    }
    Write-Host "  Nginx configurado en puerto $Port. Root: $nginxPath\html"
}

# =============================================================================
# Helpers internos
# =============================================================================
function Asegurar-Chocolatey {
    if (Get-Command choco -ErrorAction SilentlyContinue) { return }
    Write-Host "  Instalando Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(
        'https://community.chocolatey.org/install.ps1'))
    Refrescar-Path
}

function Refrescar-Path {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
}

# Aliases compatibles con main.ps1
function New-IISSSLCertificate-AutoPort {
    param([int]$selectedHttpPort,[string]$SiteName="ServicioWebIIS",[string]$DnsName,[switch]$ForceHTTPS)
    Configurar-SSL-IIS -SiteName $SiteName -HttpPort $selectedHttpPort -ForceHTTPS:$ForceHTTPS
}
function New-ApacheSSLCertificate-AutoPort {
    param([int]$selectedHttpPort,[string]$DnsName,[string]$DocumentRoot="C:\WebServers\Apache",[switch]$ForceHTTPS)
    Configurar-SSL-Apache -HttpPort $selectedHttpPort -DocumentRoot $DocumentRoot -ForceHTTPS:$ForceHTTPS
}
function New-NginxSSLCertificate-AutoPort {
    param([int]$selectedHttpPort,[string]$DnsName,[string]$NginxPath,[switch]$ForceHTTPS)
    Configurar-SSL-Nginx -HttpPort $selectedHttpPort -ForceHTTPS:$ForceHTTPS
}