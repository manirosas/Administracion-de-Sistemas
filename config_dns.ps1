# dns_manager.ps1
# Gestor DNS para Windows Server
# Requiere PowerShell como Administrador

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Ejecuta PowerShell como Administrador."
    exit 1
}

$LOG_FILE = "C:\dns_manager.log"

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$ts] $Msg" | Out-File -Append -FilePath $LOG_FILE -Encoding UTF8
}

function ok   { param($m) Write-Host "OK: $m";    Write-Log "OK: $m" }
function err  { param($m) Write-Host "ERROR: $m"; Write-Log "ERROR: $m" }
function info { param($m) Write-Host "$m";         Write-Log "$m" }

function Pausar { Read-Host "ENTER para continuar" | Out-Null }

function Validar-IP {
    param([string]$IP)
    return $IP -match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
}

function Validar-Dominio {
    param([string]$Dom)
    return $Dom -match '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
}

function Normalizar-Dominio {
    param([string]$Entrada)
    $d = $Entrada.ToLower().Trim()
    if ($d -match '^www\.(.+)$') { return $matches[1] }
    return $d
}

function Get-IPServidor {
    $ip = Get-NetIPAddress -AddressFamily IPv4 |
          Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -ne '0.0.0.0' } |
          Select-Object -First 1
    return $ip.IPAddress
}

# --------------------------------------------------------------------------
# IP estatica
# --------------------------------------------------------------------------

function Configurar-IP {
    Write-Host ""

    $adaptadores = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    Write-Host "Adaptadores activos:"
    $idx = 1
    foreach ($a in $adaptadores) {
        $ipInfo = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $dhcp   = (Get-NetIPInterface -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4).Dhcp
        $tipo   = if ($dhcp -eq "Enabled") { "DHCP" } else { "Estatica" }
        Write-Host "  [$idx] $($a.Name) - IP: $($ipInfo.IPAddress) ($tipo)"
        $idx++
    }
    Write-Host ""

    $tieneEstatica = $adaptadores | Where-Object {
        (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).Dhcp -eq "Disabled"
    }

    if ($tieneEstatica) {
        ok "El servidor ya tiene IP estatica."
        return
    }

    info "El servidor usa DHCP."
    $resp = Read-Host "Configurar IP estatica? (s/n)"
    if ($resp -notmatch '^[Ss]$') { return }

    Write-Host ""
    $sel = Read-Host "Numero de adaptador a configurar"
    $adaptador = @($adaptadores)[$sel - 1]

    if (-not $adaptador) {
        err "Adaptador invalido."
        return
    }

    $ifIndex  = $adaptador.InterfaceIndex
    $ipActual = (Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
    $gwActual = (Get-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).NextHop

    do {
        $nuevaIP = Read-Host "Nueva IP [$ipActual]"
        if ([string]::IsNullOrWhiteSpace($nuevaIP)) { $nuevaIP = $ipActual }
    } until (Validar-IP $nuevaIP)

    do {
        $prefijo = Read-Host "Prefijo CIDR [24]"
        if ([string]::IsNullOrWhiteSpace($prefijo)) { $prefijo = 24 }
        $prefijo = [int]$prefijo
    } until ($prefijo -ge 8 -and $prefijo -le 30)

    do {
        $nuevoGW = Read-Host "Gateway [$gwActual]"
        if ([string]::IsNullOrWhiteSpace($nuevoGW)) { $nuevoGW = $gwActual }
    } until (Validar-IP $nuevoGW)

    do {
        $dnsExt = Read-Host "DNS externo [8.8.8.8]"
        if ([string]::IsNullOrWhiteSpace($dnsExt)) { $dnsExt = "8.8.8.8" }
    } until (Validar-IP $dnsExt)

    Write-Host ""
    Write-Host "IP      : $nuevaIP/$prefijo"
    Write-Host "Gateway : $nuevoGW"
    Write-Host "DNS ext : $dnsExt"

    $conf = Read-Host "Aplicar? (s/n)"
    if ($conf -notmatch '^[Ss]$') { info "Cancelado."; return }

    try {
        Remove-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix "0.0.0.0/0" -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $nuevaIP -PrefixLength $prefijo -DefaultGateway $nuevoGW | Out-Null
        Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses ("127.0.0.1", $dnsExt)
        ok "IP estatica aplicada: $nuevaIP/$prefijo"
        Write-Log "IP configurada: $nuevaIP/$prefijo gw=$nuevoGW"
    } catch {
        err "Error al configurar IP: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------------
# Instalacion
# --------------------------------------------------------------------------

function Instalar-DNS {
    Write-Host ""

    $feature = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue

    if ($feature -and $feature.Installed) {
        ok "El rol DNS Server ya esta instalado."
    } else {
        info "Instalando rol DNS Server..."
        try {
            $result = Install-WindowsFeature -Name DNS -IncludeManagementTools -Restart:$false
            if ($result.Success) {
                ok "Rol DNS Server instalado."
                if ($result.RestartNeeded -eq "Yes") {
                    info "Se recomienda reiniciar el servidor."
                }
            } else {
                err "No se pudo instalar el rol DNS."
                return
            }
        } catch {
            err "Error: $($_.Exception.Message)"
            return
        }
    }

    $svc = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            ok "Servicio DNS ya en ejecucion."
        } else {
            Start-Service DNS
            Start-Sleep 2
            $svc.Refresh()
            if ($svc.Status -eq "Running") { ok "Servicio DNS iniciado." }
            else { err "No se pudo iniciar el servicio DNS." }
        }
        Set-Service -Name DNS -StartupType Automatic
    }
}

# --------------------------------------------------------------------------
# Crear zona
# --------------------------------------------------------------------------

function Crear-Zona {
    Write-Host ""

    $ipServidor = Get-IPServidor
    info "IP del servidor DNS: $ipServidor"
    Write-Host ""
    Write-Host "Formatos validos: miempresa.com  |  www.miempresa.com"
    Write-Host "(si escribes www.dominio.com se normaliza a dominio.com)"
    Write-Host ""

    do {
        $entrada = Read-Host "Dominio"
        $dominio = Normalizar-Dominio $entrada
        if (-not (Validar-Dominio $dominio)) {
            err "Dominio invalido: '$dominio'. Ejemplo: miempresa.com"
        }
    } until (Validar-Dominio $dominio)

    do {
        $ipDest = Read-Host "IP de destino [$ipServidor]"
        if ([string]::IsNullOrWhiteSpace($ipDest)) { $ipDest = $ipServidor }
        if (-not (Validar-IP $ipDest)) { err "IP invalida." }
    } until (Validar-IP $ipDest)

    $zonaExiste = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
    if ($zonaExiste) {
        info "La zona '$dominio' ya existe."
        $sobre = Read-Host "Sobreescribir? (s/n)"
        if ($sobre -notmatch '^[Ss]$') { info "Cancelado."; return }
        Remove-DnsServerZone -Name $dominio -Force
        info "Zona anterior eliminada."
    }

    try {
        Add-DnsServerPrimaryZone -Name $dominio -ZoneFile "$dominio.dns" -DynamicUpdate None
        ok "Zona primaria '$dominio' creada."
    } catch {
        err "Error al crear zona: $($_.Exception.Message)"
        return
    }

    # Registro A para el dominio raiz
    try {
        Add-DnsServerResourceRecordA -ZoneName $dominio -Name "@" -IPv4Address $ipDest -TimeToLive 01:00:00
        ok "Registro A: $dominio -> $ipDest"
    } catch {
        err "Error registro A raiz: $($_.Exception.Message)"
    }

    # Registro A para ns1
    try {
        Add-DnsServerResourceRecordA -ZoneName $dominio -Name "ns1" -IPv4Address $ipServidor -TimeToLive 01:00:00
        ok "Registro A: ns1.$dominio -> $ipServidor"
    } catch {
        err "Error registro ns1: $($_.Exception.Message)"
    }

    # Registro CNAME para www
    try {
        Add-DnsServerResourceRecord -ZoneName $dominio -CName -Name "www" -HostNameAlias "$dominio." -TimeToLive 01:00:00
        ok "Registro CNAME: www.$dominio -> $dominio"
    } catch {
        # Si falla CNAME, crear registro A para www
        try {
            Add-DnsServerResourceRecordA -ZoneName $dominio -Name "www" -IPv4Address $ipDest -TimeToLive 01:00:00
            ok "Registro A (alternativo): www.$dominio -> $ipDest"
        } catch {
            err "Error registro www: $($_.Exception.Message)"
        }
    }

    Write-Host ""
    ok "Zona '$dominio' lista."
    Write-Host "  $dominio     -> A     -> $ipDest"
    Write-Host "  www.$dominio -> CNAME -> $dominio"
    Write-Host "  ns1.$dominio -> A     -> $ipServidor"

    Write-Log "Alta zona: $dominio ip=$ipDest dns=$ipServidor"
}

# --------------------------------------------------------------------------
# Alta de registro
# --------------------------------------------------------------------------

function Alta-Registro {
    Write-Host ""

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) {
        info "No hay zonas configuradas."
        return
    }

    Write-Host "Zonas disponibles:"
    $zonas | ForEach-Object { Write-Host "  $($_.ZoneName)" }
    Write-Host ""

    $entrada = Read-Host "Zona (dominio)"
    $dominio = Normalizar-Dominio $entrada

    $zonaExiste = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
    if (-not $zonaExiste) {
        err "La zona '$dominio' no existe."
        return
    }

    Write-Host ""
    Write-Host "Registros actuales en $dominio:"
    Get-DnsServerResourceRecord -ZoneName $dominio -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordType -in @("A","CNAME") } |
        ForEach-Object {
            $dato = if ($_.RecordType -eq "A") { $_.RecordData.IPv4Address } else { $_.RecordData.HostNameAlias }
            Write-Host "  $($_.HostName) $($_.RecordType) $dato"
        }
    Write-Host ""

    $nombre = Read-Host "Nombre del registro (ej: mail, ftp)"

    $tipo = Read-Host "Tipo (A/CNAME) [A]"
    if ([string]::IsNullOrWhiteSpace($tipo)) { $tipo = "A" }
    $tipo = $tipo.ToUpper()

    if ($tipo -eq "A") {
        do {
            $ipDest = Read-Host "IP destino"
            if (-not (Validar-IP $ipDest)) { err "IP invalida." }
        } until (Validar-IP $ipDest)

        $existe = Get-DnsServerResourceRecord -ZoneName $dominio -Name $nombre -RRType A -ErrorAction SilentlyContinue
        if ($existe) { err "Registro A '$nombre' ya existe."; return }

        try {
            Add-DnsServerResourceRecordA -ZoneName $dominio -Name $nombre -IPv4Address $ipDest -TimeToLive 01:00:00
            ok "Registro A agregado: $nombre.$dominio -> $ipDest"
            Write-Log "Alta registro: $nombre.$dominio A $ipDest"
        } catch {
            err "Error: $($_.Exception.Message)"
        }

    } elseif ($tipo -eq "CNAME") {
        $destino = Read-Host "Nombre canonico destino"
        if (-not $destino.EndsWith(".")) { $destino = "$destino." }

        $existe = Get-DnsServerResourceRecord -ZoneName $dominio -Name $nombre -RRType CName -ErrorAction SilentlyContinue
        if ($existe) { err "Registro CNAME '$nombre' ya existe."; return }

        try {
            Add-DnsServerResourceRecord -ZoneName $dominio -CName -Name $nombre -HostNameAlias $destino -TimeToLive 01:00:00
            ok "Registro CNAME agregado: $nombre.$dominio -> $destino"
            Write-Log "Alta registro: $nombre.$dominio CNAME $destino"
        } catch {
            err "Error: $($_.Exception.Message)"
        }

    } else {
        err "Tipo no soportado. Usa A o CNAME."
    }
}

# --------------------------------------------------------------------------
# Baja de registro
# --------------------------------------------------------------------------

function Baja-Registro {
    Write-Host ""

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) { info "No hay zonas configuradas."; return }

    Write-Host "Zonas disponibles:"
    $zonas | ForEach-Object { Write-Host "  $($_.ZoneName)" }
    Write-Host ""

    $entrada = Read-Host "Zona (dominio)"
    $dominio = Normalizar-Dominio $entrada

    $zonaExiste = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
    if (-not $zonaExiste) { err "La zona '$dominio' no existe."; return }

    Write-Host ""
    Write-Host "Registros en $dominio:"
    Get-DnsServerResourceRecord -ZoneName $dominio -ErrorAction SilentlyContinue |
        Where-Object { $_.RecordType -in @("A","CNAME") } |
        ForEach-Object {
            $dato = if ($_.RecordType -eq "A") { $_.RecordData.IPv4Address } else { $_.RecordData.HostNameAlias }
            Write-Host "  $($_.HostName) $($_.RecordType) $dato"
        }
    Write-Host ""

    $nombre = Read-Host "Nombre del registro a eliminar"
    $tipo   = Read-Host "Tipo (A/CNAME) [A]"
    if ([string]::IsNullOrWhiteSpace($tipo)) { $tipo = "A" }
    $tipo = $tipo.ToUpper()

    $rrType = if ($tipo -eq "CNAME") { "CName" } else { "A" }
    $registro = Get-DnsServerResourceRecord -ZoneName $dominio -Name $nombre -RRType $rrType -ErrorAction SilentlyContinue

    if (-not $registro) {
        err "No se encontro el registro '$nombre' ($tipo) en '$dominio'."
        return
    }

    $conf = Read-Host "Eliminar registro '$nombre' ($tipo) de '$dominio'? (s/n)"
    if ($conf -notmatch '^[Ss]$') { info "Cancelado."; return }

    try {
        Remove-DnsServerResourceRecord -ZoneName $dominio -Name $nombre -RRType $rrType -Force
        ok "Registro '$nombre' eliminado."
        Write-Log "Baja registro: $nombre.$dominio $tipo"
    } catch {
        err "Error: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------------
# Baja de zona
# --------------------------------------------------------------------------

function Baja-Zona {
    Write-Host ""

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) { info "No hay zonas configuradas."; return }

    Write-Host "Zonas disponibles:"
    $zonas | ForEach-Object { Write-Host "  $($_.ZoneName)" }
    Write-Host ""

    $entrada = Read-Host "Dominio a eliminar"
    $dominio = Normalizar-Dominio $entrada

    $zonaExiste = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
    if (-not $zonaExiste) { err "La zona '$dominio' no existe."; return }

    $conf = Read-Host "Eliminar zona '$dominio'? (s/n)"
    if ($conf -notmatch '^[Ss]$') { info "Cancelado."; return }

    try {
        Remove-DnsServerZone -Name $dominio -Force
        ok "Zona '$dominio' eliminada."
        Write-Log "Baja zona: $dominio"
    } catch {
        err "Error: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------------
# Consultar zonas
# --------------------------------------------------------------------------

function Consultar-Zonas {
    Write-Host ""

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) { info "No hay zonas configuradas."; return }

    Write-Host "Zonas configuradas:"
    Write-Host ""

    $idx = 1
    foreach ($zona in $zonas) {
        Write-Host "[$idx] $($zona.ZoneName)"
        Get-DnsServerResourceRecord -ZoneName $zona.ZoneName -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordType -in @("A","CNAME","NS") } |
            ForEach-Object {
                $dato = switch ($_.RecordType) {
                    "A"     { $_.RecordData.IPv4Address }
                    "CNAME" { $_.RecordData.HostNameAlias }
                    "NS"    { $_.RecordData.NameServer }
                }
                Write-Host "     $($_.HostName) $($_.RecordType) $dato"
            }
        Write-Host ""
        $idx++
    }

    $svc = Get-Service DNS -ErrorAction SilentlyContinue
    Write-Host "Servicio DNS: $($svc.Status)"
    Write-Host "IP servidor : $(Get-IPServidor)"
}

# --------------------------------------------------------------------------
# Probar resolucion
# --------------------------------------------------------------------------

function Probar-Resolucion {
    Write-Host ""

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) { info "No hay zonas configuradas."; return }

    Write-Host "Zonas disponibles:"
    $zonas | ForEach-Object { Write-Host "  $($_.ZoneName)" }
    Write-Host ""

    $entrada = Read-Host "Dominio a probar"
    $dominio = Normalizar-Dominio $entrada
    if ([string]::IsNullOrWhiteSpace($dominio)) { err "Dominio vacio."; return }

    Write-Host ""
    Write-Host "--- Estado del servicio ---"
    $svc = Get-Service DNS -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { ok "Servicio DNS activo." }
    else { err "Servicio DNS no esta corriendo." }

    Write-Host ""
    Write-Host "--- Zona $dominio ---"
    $z = Get-DnsServerZone -Name $dominio -ErrorAction SilentlyContinue
    if ($z) { ok "Zona encontrada. Tipo: $($z.ZoneType)" }
    else    { err "Zona '$dominio' no encontrada." }

    Write-Host ""
    Write-Host "--- nslookup $dominio ---"
    try {
        $res = Resolve-DnsName -Name $dominio -Server 127.0.0.1 -Type A -ErrorAction Stop
        $res | Format-Table Name, Type, IPAddress -AutoSize
        ok "Resolucion A exitosa."
    } catch {
        err "No se pudo resolver $dominio : $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "--- nslookup www.$dominio ---"
    try {
        $res = Resolve-DnsName -Name "www.$dominio" -Server 127.0.0.1 -ErrorAction Stop
        $res | Format-Table Name, Type, NameHost, IPAddress -AutoSize
        ok "Resolucion www exitosa."
    } catch {
        err "No se pudo resolver www.$dominio : $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "--- ping www.$dominio ---"
    $ping = Test-Connection -ComputerName "www.$dominio" -Count 3 -ErrorAction SilentlyContinue
    if ($ping) {
        $ping | Format-Table Address, ResponseTime -AutoSize
        ok "Conectividad ok."
    } else {
        info "Sin respuesta a ping (puede ser firewall). La resolucion DNS es lo importante."
    }

    Write-Log "Pruebas: $dominio"
}

# --------------------------------------------------------------------------
# Servicio
# --------------------------------------------------------------------------

function Gestionar-Servicio {
    Write-Host ""
    $svc = Get-Service DNS -ErrorAction SilentlyContinue
    Write-Host "Estado actual: $($svc.Status)"
    Write-Host ""
    Write-Host "1) Reiniciar servicio"
    Write-Host "2) Detener servicio"
    Write-Host "3) Iniciar servicio"
    Write-Host "4) Ver estadisticas DNS"
    Write-Host "0) Volver"
    Write-Host ""

    $opc = Read-Host "Opcion"
    switch ($opc) {
        "1" {
            Restart-Service DNS -Force
            Start-Sleep 2
            if ((Get-Service DNS).Status -eq "Running") { ok "Reiniciado." } else { err "Error al reiniciar." }
        }
        "2" { Stop-Service DNS -Force;  ok "Servicio detenido." }
        "3" { Start-Service DNS;        ok "Servicio iniciado." }
        "4" {
            Write-Host ""
            Get-DnsServerStatistics | Select-Object -ExpandProperty PacketStatistics | Format-List
        }
        "0" { return }
        default { info "Opcion no valida." }
    }
}

# --------------------------------------------------------------------------
# Borrar configuracion
# --------------------------------------------------------------------------

function Borrar-DNS {
    Write-Host ""
    Write-Host "Se eliminaran todas las zonas primarias configuradas."
    Write-Host ""
    $conf = Read-Host "Confirma escribiendo BORRAR"
    if ($conf -ne "BORRAR") { info "Cancelado."; return }

    $zonas = Get-DnsServerZone -ErrorAction SilentlyContinue |
             Where-Object { $_.ZoneType -eq "Primary" -and $_.ZoneName -notmatch 'arpa|localhost|TrustAnchors' }

    if (-not $zonas) { info "No habia zonas que eliminar."; return }

    foreach ($zona in $zonas) {
        try {
            Remove-DnsServerZone -Name $zona.ZoneName -Force
            ok "Zona '$($zona.ZoneName)' eliminada."
        } catch {
            err "Error eliminando '$($zona.ZoneName)': $($_.Exception.Message)"
        }
    }

    Write-Log "Borrado completo de zonas."
    ok "Configuracion DNS eliminada."
}

# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

while ($true) {
    Clear-Host
    $ipSrv = Get-IPServidor
    $svcEstado = (Get-Service DNS -ErrorAction SilentlyContinue).Status

    Write-Host "=============================="
    Write-Host " DNS Windows Server"
    Write-Host " IP: $ipSrv"
    Write-Host " Servicio: $svcEstado"
    Write-Host "=============================="
    Write-Host "1) Instalar DNS"
    Write-Host "2) Configurar IP estatica"
    Write-Host "3) Crear zona DNS"
    Write-Host "4) Alta de registro DNS"
    Write-Host "5) Baja de registro DNS"
    Write-Host "6) Consultar zonas"
    Write-Host "7) Probar resolucion"
    Write-Host "8) Eliminar zona DNS"
    Write-Host "9) Borrar configuracion DNS"
    Write-Host "0) Salir"
    Write-Host ""

    $op = Read-Host "Opcion"

    switch ($op) {
        "1" { Instalar-DNS }
        "2" { Configurar-IP }
        "3" { Crear-Zona }
        "4" { Alta-Registro }
        "5" { Baja-Registro }
        "6" { Consultar-Zonas }
        "7" { Probar-Resolucion }
        "8" { Baja-Zona }
        "9" { Borrar-DNS }
        "0" { Write-Host "Saliendo."; exit 0 }
        default { Write-Host "Opcion no valida." }
    }

    Pausar
}

