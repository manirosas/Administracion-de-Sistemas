# =============================================================================
# lib_util.ps1 - Funciones de utilidad compartidas
# =============================================================================

function Write-Linea { Write-Host "------------------------------------------------------------" }

function Pausar { Write-Host ""; Read-Host "  Presione Enter para continuar" }

function Get-EstadoServicio {
    param([string]$nombre)
    if ($nombre -eq "nginx") {
        if (Get-Process nginx -ErrorAction SilentlyContinue) { return "running" }
        return "detenido"
    }
    $svc = Get-Service -Name $nombre -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return "no instalado" }
    return $svc.Status.ToString().ToLower()
}

function Validar-Puerto-Basico {
    param([string]$puerto)
    if ($puerto -notmatch '^\d+$') { Write-Host "  ERROR: Puerto invalido."; return $false }
    $p = [int]$puerto
    if ($p -lt 1 -or $p -gt 65535) { Write-Host "  ERROR: Puerto fuera de rango."; return $false }
    return $true
}

function Test-SSL-Activo {
    param([string]$Servicio)
    switch ($Servicio) {
        "IIS" {
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                # Buscar cualquier binding HTTPS en el sitio
                $b = Get-WebBinding -Name "ServicioWebIIS" -Protocol https -ErrorAction SilentlyContinue
                if ($b) {
                    $puerto = ($b | Select-Object -First 1).bindingInformation.Split(':')[1]
                    return "SI (HTTPS:$puerto)"
                }
                # Tambien revisar si tiene certificado asignado en applicationHost
                $cert = Get-ChildItem Cert:\LocalMachine\My |
                    Where-Object { $_.Subject -like "*reprobados*" -and $_.NotAfter -gt (Get-Date) } |
                    Select-Object -First 1
                if ($cert) { return "SI (cert: $($cert.Thumbprint.Substring(0,8))...)" }
                return "NO"
            } catch { return "NO" }
        }
        "Apache" {
            $paths = @("C:\Apache24","C:\Apache","$env:APPDATA\Apache24",
                       "C:\Users\Administrator\AppData\Roaming\Apache24")
            foreach ($p in $paths) {
                if (Test-Path "$p\conf\ssl\server.crt") { return "SI" }
            }
            return "NO"
        }
        "Nginx" {
            $dir = Get-ChildItem "C:\tools" -Filter "nginx*" -Directory -ErrorAction SilentlyContinue |
                   Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
            if ($dir -and (Test-Path "$dir\conf\ssl\server.crt")) { return "SI" }
            return "NO"
        }
        "IIS-FTP" {
            try {
                Import-Module WebAdministration -ErrorAction SilentlyContinue
                $pol = Get-WebConfigurationProperty `
                    -PSPath "MACHINE/WEBROOT/APPHOST" -Location "Repositorio" `
                    -Filter "system.ftpServer/security/ssl" `
                    -Name "controlChannelPolicy" -ErrorAction SilentlyContinue
                if ($pol -and $pol.Value -eq "SslRequire") { return "SI (SslRequire)" }
                # Verificar si tiene certificado asignado
                $hash = Get-WebConfigurationProperty `
                    -PSPath "MACHINE/WEBROOT/APPHOST/Repositorio" `
                    -Filter "system.ftpServer/security/ssl" `
                    -Name "serverCertHash" -ErrorAction SilentlyContinue
                if ($hash -and $hash.Value -ne "") { return "SI (cert asignado)" }
                return "NO"
            } catch { return "NO" }
        }
        default { return "Desconocido" }
    }
}

function Pedir-Credenciales-FTP {
    Write-Host ""
    $servidor  = Read-Host "  Servidor FTP (ej: ftp://192.168.1.1)"
    $usuario   = Read-Host "  Usuario FTP"
    $passPlain = Read-Host "  Password FTP"
    if ([string]::IsNullOrWhiteSpace($servidor)) { return $null }
    $cred = New-Object System.Net.NetworkCredential($usuario, $passPlain)
    return @{ Servidor=$servidor; Cred=$cred; Usuario=$usuario; Pass=$passPlain }
}

function Set-NtfsRule {
    param(
        [string]$Path,
        [string]$Identity,
        [string]$Rights,
        [string]$Inheritance = "ContainerInherit,ObjectInherit",
        [string]$Propagation = "None",
        [string]$Type = "Allow"
    )
    $acl  = Get-Acl -Path $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity, $Rights, $Inheritance, $Propagation, $Type)
    if ($Type -eq "Deny") { $acl.AddAccessRule($rule) } else { $acl.SetAccessRule($rule) }
    Set-Acl -Path $Path -AclObject $acl
}

function Install-OpenSSLIfMissing {
    $openSSL = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openSSL) {
        Write-Host "  OpenSSL no encontrado. Instalando con Chocolatey..."
        choco install openssl -y
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
    }
    $opensslPath = "C:\Program Files\OpenSSL-Win64\bin"
    if ((Test-Path $opensslPath) -and ($env:Path -notlike "*$opensslPath*")) {
        $env:Path += ";$opensslPath"
    }
}

function New-FirewallRule {
    param(
        [string]$DisplayName,
        [int]$Port,
        [string]$Protocol = "TCP"
    )
    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) { Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue }
    New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Protocol $Protocol `
        -LocalPort $Port -Action Allow -Enabled True | Out-Null
    Write-Host "  Firewall: regla '$DisplayName' en puerto $Port/$Protocol."
}