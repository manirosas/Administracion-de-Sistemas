# =============================================================================
# lib_ftp_server.ps1 - Servidor FTP IIS + Repositorio de instaladores HTTP
# Estructura: C:\http\Windows\{IIS,Apache,Nginx}\{instaladores + .sha256}
# =============================================================================

function Instalar-Servicio-FTP {
    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $aux) {
        Write-Host "  Instalando rol Web-Server (incluye FTP)..."
        Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools
        Write-Host "  Instalacion completada."
    } else {
        Write-Host "  El servicio FTPSVC ya esta instalado."
    }
}

# =============================================================================
# REPOSITORIO: descargar instaladores y generar .sha256
# =============================================================================
function Build-Repositorio-HTTP {
    param(
        [string]$RootPath   = "C:\http",
        [switch]$SkipDownload
    )

    Write-Host ""
    Write-Linea
    Write-Host "  CONSTRUYENDO REPOSITORIO FTP"
    Write-Host "  Ruta: $RootPath\Windows\{IIS,Apache,Nginx}"
    Write-Linea

    $dirs = @(
        "$RootPath\Windows\IIS",
        "$RootPath\Windows\Apache",
        "$RootPath\Windows\Nginx"
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        Write-Host "  Directorio: $d"
    }

    # -------------------------------------------------------------------------
    # IIS - no tiene binario descargable, generar README + info del sistema
    # -------------------------------------------------------------------------
    $iisDir  = "$RootPath\Windows\IIS"
    $iisInfo = "$iisDir\IIS_Info.txt"
    if (-not (Test-Path $iisInfo)) {
        $iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
        if (-not $iisVer) { $iisVer = "10.0 (Windows Server)" }
@"
IIS - Internet Information Services
=====================================
Version instalada : $iisVer
Sistema           : $(($env:OS))
Generado          : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

IIS se instala como rol de Windows, no tiene instalador MSI independiente.
Para instalarlo: Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature

Puertos por defecto:
  HTTP  : 80
  HTTPS : 443
"@ | Set-Content $iisInfo -Encoding UTF8
        Write-Host "  IIS: informacion generada en $iisInfo"
    }

    if ($SkipDownload) {
        Write-Host "  -SkipDownload activo, omitiendo descargas."
        return
    }

    # -------------------------------------------------------------------------
    # NGINX - descargar zip oficial desde nginx.org
    # -------------------------------------------------------------------------
    $nginxDir      = "$RootPath\Windows\Nginx"
    $nginxVersions = @(
        @{ Version="1.26.2"; URL="https://nginx.org/download/nginx-1.26.2.zip" },
        @{ Version="1.26.1"; URL="https://nginx.org/download/nginx-1.26.1.zip" },
        @{ Version="1.25.5"; URL="https://nginx.org/download/nginx-1.25.5.zip" }
    )

    foreach ($v in $nginxVersions) {
        $fileName = "nginx-$($v.Version)-win64.zip"
        $destPath = "$nginxDir\$fileName"
        $hashPath = "$destPath.sha256"

        if (Test-Path $destPath) {
            Write-Host "  Nginx $($v.Version): ya existe"
        } else {
            Write-Host "  Descargando Nginx $($v.Version)..." -NoNewline
            try {
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($v.URL, $destPath)
                $wc.Dispose()
                Write-Host " OK"
            } catch {
                Write-Host " FALLO: $_"
                continue
            }
        }

        if (-not (Test-Path $hashPath)) {
            $hash = (Get-FileHash $destPath -Algorithm SHA256).Hash
            "SHA256: $hash`nArchivo: $fileName`nVersion: $($v.Version)`nURL: $($v.URL)`nGenerado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
                Set-Content $hashPath -Encoding UTF8
            Write-Host "  Nginx $($v.Version): .sha256 generado"
        }
    }

    # -------------------------------------------------------------------------
    # APACHE - descargar zip desde ApacheLounge
    # -------------------------------------------------------------------------
    $apacheDir      = "$RootPath\Windows\Apache"
    $apacheVersions = @(
        @{ Version="2.4.62"; URL="https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.62-240718-win64-VS17.zip" },
        @{ Version="2.4.59"; URL="https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.59-240404-win64-VS17.zip" },
        @{ Version="2.4.58"; URL="https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.58-231018-win64-VS17.zip" }
    )

    foreach ($v in $apacheVersions) {
        $fileName = "apache-$($v.Version)-win64.zip"
        $destPath = "$apacheDir\$fileName"
        $hashPath = "$destPath.sha256"

        if (Test-Path $destPath) {
            Write-Host "  Apache $($v.Version): ya existe"
        } else {
            Write-Host "  Descargando Apache $($v.Version)..." -NoNewline
            try {
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($v.URL, $destPath)
                $wc.Dispose()
                Write-Host " OK"
            } catch {
                Write-Host " FALLO: $_"
                continue
            }
        }

        if (-not (Test-Path $hashPath)) {
            $hash = (Get-FileHash $destPath -Algorithm SHA256).Hash
            "SHA256: $hash`nArchivo: $fileName`nVersion: $($v.Version)`nURL: $($v.URL)`nGenerado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
                Set-Content $hashPath -Encoding UTF8
            Write-Host "  Apache $($v.Version): .sha256 generado"
        }
    }

    Write-Host ""
    Write-Host "  Repositorio listo en $RootPath\Windows"
    Write-Linea
}

# =============================================================================
# SITIO FTP: crear/configurar apuntando al repositorio
# =============================================================================
function Configurar-Sitio-FTP {
    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $aux) { Write-Host "  FTPSVC no instalado."; return }

    $Name = "Repositorio"
    $Ruta = "C:\http"

    # Estructura completa del repositorio
    $dirs = @(
        $Ruta,
        "$Ruta\Windows",
        "$Ruta\Windows\IIS",
        "$Ruta\Windows\Apache",
        "$Ruta\Windows\Nginx"
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
    }

    icacls $Ruta /reset /T /C /Q > $null 2>&1
    if (Test-Path "$Ruta\web.config") {
        Remove-Item "$Ruta\web.config" -Force -ErrorAction SilentlyContinue
    }

    Import-Module WebAdministration
    New-WebFtpSite -Name $Name -Port 21 -PhysicalPath $Ruta -Force | Out-Null

    # SSL opcional por defecto (se activa con Configurar-FTPS)
    Set-ItemProperty "IIS:\Sites\$Name" `
        -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$Name" `
        -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslAllow"

    Set-ItemProperty "IIS:\Sites\$Name" `
        -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true  > $null 2>&1
    Set-ItemProperty "IIS:\Sites\$Name" `
        -Name "ftpServer.security.authentication.basicAuthentication.enabled"    -Value $true  > $null 2>&1
    Set-ItemProperty -Path "IIS:\Sites\$Name" `
        -Name "ftpServer.userIsolation.mode" -Value "None" > $null 2>&1

    # Firewall
    if (-not (Get-NetFirewallRule -Name "Regla_FTP_In" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "Regla_FTP_In" -DisplayName "FTP Puerto 21" `
            -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow > $null 2>&1
    }
    if (-not (Get-NetFirewallRule -Name "Regla_FTP_Pasivo" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "Regla_FTP_Pasivo" `
            -DisplayName "FTP Pasivo 50000-51000" `
            -Direction Inbound -Protocol TCP -LocalPort 50000-51000 -Action Allow
    }

    Set-WebConfigurationProperty -Filter /system.ftpServer/firewallSupport `
        -Name lowDataChannelPort  -Value 50000
    Set-WebConfigurationProperty -Filter /system.ftpServer/firewallSupport `
        -Name highDataChannelPort -Value 51000

    # Autorizacion: lectura anonima + lectura/escritura autenticados
    Clear-WebConfiguration -Filter /system.ftpServer/security/authorization `
        -PSPath "IIS:\" -Location $Name -ErrorAction SilentlyContinue
    Add-WebConfiguration -Filter /system.ftpServer/security/authorization `
        -PSPath "IIS:\" -Location $Name `
        -Value @{accessType="Allow"; users="*"; permissions="Read"} > $null 2>&1

    # Permisos NTFS
    foreach ($d in $dirs) {
        $acl = Get-Acl $d
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl $d $acl
        Set-NtfsRule $d "Administrators"      "FullControl"
        Set-NtfsRule $d "SYSTEM"              "FullControl"
        Set-NtfsRule $d "IIS_IUSRS"           "ReadAndExecute"
        Set-NtfsRule $d "IUSR"                "ReadAndExecute"
        Set-NtfsRule $d "Authenticated Users" "ReadAndExecute"
    }

    Restart-Service ftpsvc
    Restart-WebItem "IIS:\Sites\$Name"

    Write-Host "  Sitio FTP '$Name' configurado."
    Write-Host "  Raiz FTP : $Ruta"
    Write-Host "  Estructura:"
    Write-Host "    $Ruta\"
    Write-Host "    +-- Windows\"
    Write-Host "    |   +-- IIS\      (IIS_Info.txt)"
    Write-Host "    |   +-- Apache\   (*.zip + *.sha256)"
    Write-Host "    |   +-- Nginx\    (*.zip + *.sha256)"
}

# =============================================================================
# FLUJO COMPLETO: instalar FTP + construir repositorio
# =============================================================================
function Instalar-FTP-Completo {
    Write-Host ""
    Write-Linea
    Write-Host "  INSTALACION FTP + REPOSITORIO HTTP"
    Write-Linea

    # 1. Instalar servicio si falta
    Instalar-Servicio-FTP

    # 2. Configurar sitio FTP
    Configurar-Sitio-FTP

    # 3. Construir repositorio con descargas
    $descargar = (Read-Host "  Desea descargar los instaladores ahora? (puede tardar) [S/N]").ToUpper()
    if ($descargar -eq "S") {
        Build-Repositorio-HTTP -RootPath "C:\http"
    } else {
        Build-Repositorio-HTTP -RootPath "C:\http" -SkipDownload
        Write-Host "  Estructura creada. Para descargar instaladores ejecute: Build-Repositorio-HTTP"
    }

    # 4. SSL opcional
    $ssl = (Read-Host "  Activar SSL/FTPS? [S/N]").ToUpper()
    if ($ssl -eq "S") { Configurar-FTPS }

    Write-Host ""
    Write-Host "  FTP listo. Conecta con:"
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.*" } |
           Select-Object -First 1).IPAddress
    Write-Host "  ftp://$ip"
    Write-Host "  Usuario: anonimo (sin password) o usuario del sistema"
    Pausar
}

function Verificar-FTP {
    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $aux) {
        Write-Host "  FTPSVC no esta instalado."
    } else {
        Write-Host "  Estado FTPSVC: $($aux.Status)"
        Get-Service -Name "FTPSVC" | Format-Table Name, Status, DisplayName -AutoSize
    }
}

function Monitoreo-FTP {
    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $aux) { Write-Host "  FTPSVC no instalado."; return }
    Write-Host "`n=== Estado FTP ==="
    Get-Service -Name "FTPSVC" | Format-Table -AutoSize
    Write-Host "`n=== Conexiones activas en puerto 21 ==="
    Get-NetTCPConnection -LocalPort 21 -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, RemoteAddress, RemotePort, State | Format-Table -AutoSize
    Write-Host "`n=== Estructura del repositorio ==="
    if (Test-Path "C:\http\Windows") {
        Get-ChildItem "C:\http\Windows" -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullName, Length |
            Format-Table -AutoSize
    }
}