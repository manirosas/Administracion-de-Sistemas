#Requires -RunAsAdministrator
Import-Module WebAdministration

Write-Host "============================================================"
Write-Host "  RESET FTP - Practica 7"
Write-Host "============================================================"

# =============================================================================
# 1. DETENER Y ELIMINAR SITIOS FTP ANTERIORES
# =============================================================================
Write-Host "`n[1] Eliminando sitios FTP anteriores..."

iisreset /stop | Out-Null
Start-Sleep -Seconds 2

foreach ($s in @("FTP Service", "FTPServerRepo", "FTP Site", "Repositorio")) {
    if (Get-Website -Name $s -ErrorAction SilentlyContinue) {
        Remove-Website -Name $s -ErrorAction SilentlyContinue
        Write-Host "  Eliminado: $s"
    }
}

# =============================================================================
# 2. CREAR ESTRUCTURA DEL REPOSITORIO
# =============================================================================
Write-Host "`n[2] Creando estructura C:\http\Windows\..."

foreach ($d in @("C:\http","C:\http\Windows","C:\http\Windows\IIS","C:\http\Windows\Apache","C:\http\Windows\Nginx")) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    Write-Host "  $d"
}

if (Test-Path "C:\http\web.config") { Remove-Item "C:\http\web.config" -Force }

$iisVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp" -ErrorAction SilentlyContinue).VersionString
if (-not $iisVer) { $iisVer = "10.0" }
"IIS $iisVer - Se instala como rol de Windows.`nInstalar: Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature`nGenerado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
    Set-Content "C:\http\Windows\IIS\README.txt" -Encoding UTF8

# =============================================================================
# 3. DESCARGAR INSTALADORES
# =============================================================================
Write-Host "`n[3] Descargando instaladores..."

$paquetes = @(
    @{ Nombre="nginx-1.26.2-win64.zip"; URL="https://nginx.org/download/nginx-1.26.2.zip";                                                              Dir="Nginx";  Version="1.26.2" },
    @{ Nombre="nginx-1.26.1-win64.zip"; URL="https://nginx.org/download/nginx-1.26.1.zip";                                                              Dir="Nginx";  Version="1.26.1" },
    @{ Nombre="nginx-1.25.5-win64.zip"; URL="https://nginx.org/download/nginx-1.25.5.zip";                                                              Dir="Nginx";  Version="1.25.5" },
    @{ Nombre="apache-2.4.62-win64.zip"; URL="https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.62-240718-win64-VS17.zip"; Dir="Apache"; Version="2.4.62" },
    @{ Nombre="apache-2.4.59-win64.zip"; URL="https://www.apachelounge.com/download/VS17/binaries/httpd-2.4.59-240404-win64-VS17.zip"; Dir="Apache"; Version="2.4.59" }
)

foreach ($p in $paquetes) {
    $dest = "C:\http\Windows\$($p.Dir)\$($p.Nombre)"
    if (Test-Path $dest) { Write-Host "  Ya existe: $($p.Nombre)"; continue }
    Write-Host "  Descargando $($p.Nombre)..." -NoNewline
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($p.URL, $dest)
        $wc.Dispose()
        $hash = (Get-FileHash $dest -Algorithm SHA256).Hash
        "SHA256: $hash`nArchivo: $($p.Nombre)`nVersion: $($p.Version)`nURL: $($p.URL)`nGenerado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
            Set-Content "$dest.sha256" -Encoding UTF8
        Write-Host " OK ($([math]::Round((Get-Item $dest).Length/1MB,1)) MB)"
    } catch { Write-Host " FALLO: $_" }
}

# =============================================================================
# 4. PERMISOS NTFS
# =============================================================================
Write-Host "`n[4] Permisos NTFS en C:\http..."
icacls "C:\http" /reset /T /C /Q > $null 2>&1
icacls "C:\http" /grant "Administrators:(OI)(CI)F"       /T /C /Q > $null 2>&1
icacls "C:\http" /grant "SYSTEM:(OI)(CI)F"               /T /C /Q > $null 2>&1
icacls "C:\http" /grant "IIS_IUSRS:(OI)(CI)RX"           /T /C /Q > $null 2>&1
icacls "C:\http" /grant "IUSR:(OI)(CI)RX"                /T /C /Q > $null 2>&1
icacls "C:\http" /grant "Authenticated Users:(OI)(CI)RX" /T /C /Q > $null 2>&1
icacls "C:\http" /grant "Everyone:(OI)(CI)RX"            /T /C /Q > $null 2>&1
Write-Host "  OK"

# =============================================================================
# 5. PREGUNTAR SSL
# =============================================================================
Write-Host ""
$usarSSL = (Read-Host "  Desea activar SSL/FTPS? [S/N]").ToUpper()

$cert = $null
if ($usarSSL -eq "S") {
    Write-Host "`n[5] Generando certificado SSL para reprobados.com..."

    # Eliminar certificados FTPS anteriores
    Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.FriendlyName -like "*FTPS*" -or ($_.Subject -eq "CN=reprobados.com" -and $_.FriendlyName -like "*FTPS*") } |
        ForEach-Object { Remove-Item $_.PSPath -ErrorAction SilentlyContinue }

    # Crear certificado nuevo
    $cert = New-SelfSignedCertificate `
        -DnsName "reprobados.com" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -NotAfter (Get-Date).AddYears(5) `
        -FriendlyName "FTPS Prac7" `
        -KeyExportPolicy Exportable `
        -KeyLength 2048 `
        -KeyUsage DigitalSignature, KeyEncipherment

    Write-Host "  Certificado creado: $($cert.Thumbprint)"

    # Dar permisos sobre la clave privada al servicio FTP
    # La clave mas reciente en MachineKeys es la del certificado que acabamos de crear
    Start-Sleep -Seconds 1
    $keyFile = (Get-ChildItem "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

    Write-Host "  Clave privada: $keyFile"
    icacls $keyFile /grant "NT SERVICE\ftpsvc:(R)"  | Out-Null
    icacls $keyFile /grant "NETWORK SERVICE:(R)"    | Out-Null
    icacls $keyFile /grant "LOCAL SERVICE:(R)"      | Out-Null
    icacls $keyFile /grant "Everyone:(R)"           | Out-Null
    Write-Host "  Permisos de clave privada aplicados."
}

# =============================================================================
# 6. CREAR SITIO FTP
# =============================================================================
Write-Host "`n[6] Iniciando IIS y creando sitio FTP 'Repositorio'..."
iisreset /start | Out-Null
Start-Sleep -Seconds 3

New-WebFtpSite -Name "Repositorio" -Port 21 -PhysicalPath "C:\http" -Force | Out-Null
Write-Host "  Sitio creado."

# Sin aislamiento de usuarios
Set-ItemProperty "IIS:\Sites\Repositorio" -Name "ftpServer.userIsolation.mode" -Value "None"

# Autenticacion
Set-ItemProperty "IIS:\Sites\Repositorio" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true
Set-ItemProperty "IIS:\Sites\Repositorio" -Name "ftpServer.security.authentication.basicAuthentication.enabled"    -Value $true

# =============================================================================
# 7. CONFIGURAR SSL EN EL SITIO
# =============================================================================
if ($usarSSL -eq "S" -and $cert) {
    Write-Host "`n[7] Configurando FTPS..."

    Set-ItemProperty "IIS:\Sites\Repositorio" `
        -Name "ftpServer.security.ssl.serverCertHash"       -Value $cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\Repositorio" `
        -Name "ftpServer.security.ssl.serverCertStoreName"  -Value "MY"
    Set-ItemProperty "IIS:\Sites\Repositorio" `
        -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\Repositorio" `
        -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslAllow"

    Write-Host "  FTPS configurado (SslAllow - acepta con y sin SSL)"
    Write-Host "  Thumbprint: $($cert.Thumbprint)"
    Write-Host ""
    Write-Host "  NOTA: Se usa SslAllow (no SslRequire) para que clientes"
    Write-Host "  sin soporte TLS tambien puedan conectarse."
    Write-Host "  Para forzar SSL exclusivo cambia a SslRequire manualmente."
} else {
    # Sin SSL
    Set-ItemProperty "IIS:\Sites\Repositorio" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\Repositorio" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslAllow"
    Write-Host "`n[7] SSL no activado."
}

# =============================================================================
# 8. AUTORIZACION FTP
# =============================================================================
Write-Host "`n[8] Autorizacion FTP..."
Clear-WebConfiguration -Filter /system.ftpServer/security/authorization `
    -PSPath "IIS:\" -Location "Repositorio" -ErrorAction SilentlyContinue
Add-WebConfiguration -Filter /system.ftpServer/security/authorization `
    -PSPath "IIS:\" -Location "Repositorio" `
    -Value @{accessType="Allow"; users="?"; permissions="Read"} > $null 2>&1
Add-WebConfiguration -Filter /system.ftpServer/security/authorization `
    -PSPath "IIS:\" -Location "Repositorio" `
    -Value @{accessType="Allow"; users="*"; permissions="Read"} > $null 2>&1
Write-Host "  Lectura permitida a anonimo y autenticados."

# =============================================================================
# 9. FIREWALL Y PUERTOS PASIVOS
# =============================================================================
Write-Host "`n[9] Firewall..."
foreach ($r in @(@{N="FTP_21";D="FTP Puerto 21";P=21}, @{N="FTP_Pasivo";D="FTP Pasivo 50000-51000";P="50000-51000"})) {
    Remove-NetFirewallRule -Name $r.N -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $r.N -DisplayName $r.D -Direction Inbound `
        -Protocol TCP -LocalPort $r.P -Action Allow | Out-Null
    Write-Host "  Regla: $($r.D)"
}
Set-WebConfigurationProperty -Filter /system.ftpServer/firewallSupport -Name lowDataChannelPort  -Value 50000
Set-WebConfigurationProperty -Filter /system.ftpServer/firewallSupport -Name highDataChannelPort -Value 51000

# =============================================================================
# 10. REINICIAR Y MOSTRAR RESULTADO
# =============================================================================
Write-Host "`n[10] Reiniciando FTP..."
Restart-Service ftpsvc
Start-Sleep -Seconds 2

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.*" } |
    Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "============================================================"
Write-Host "  LISTO"
Write-Host "============================================================"
Write-Host ""
Write-Host "  Sitio FTP : Repositorio"
Write-Host "  IP        : $ip  Puerto: 21"
Write-Host "  Raiz      : C:\http"
if ($usarSSL -eq "S") {
    Write-Host "  SSL       : SslAllow (acepta FTP y FTPS)"
    Write-Host "  Cert      : $($cert.Thumbprint)"
} else {
    Write-Host "  SSL       : No activado"
}
Write-Host ""
Write-Host "  Conectar anonimo  : ftp://$ip"
Write-Host "  Conectar con user : ftp://ftpuser@$ip"
Write-Host ""
Write-Host "  Estructura del repositorio:"
Get-ChildItem "C:\http" -Recurse -ErrorAction SilentlyContinue |
    Select-Object @{N="Ruta";E={$_.FullName -replace [regex]::Escape("C:\http\"),""}},
                  @{N="Tamano";E={if($_.PSIsContainer){"[DIR]"}else{"$([math]::Round($_.Length/1MB,1)) MB"}}} |
    Format-Table -AutoSize

Read-Host "  Presione Enter para salir"