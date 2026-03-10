# SCRIPT FTP - Windows Server 2022 - IIS FTP Service
# Modo: IsolateAllDirectories con estructura LocalUser\<usuario>
# FIX 1: StartInUsersDirectory fallaba — IIS mostraba raíz completa
# FIX 2: Deny Delete en grupos ahora NO hereda (solo protege la carpeta raíz)

# =================================================================
# VARIABLES GLOBALES
# =================================================================
$FTP_ROOT   = "C:\srv\ftp"
$SITE_NAME  = "FTP_Colaborativo"
$FTP_PORT   = 21
$PASV_MIN   = 40000
$PASV_MAX   = 40100
$GRUPOS     = @("reprobados", "recursadores")
$SERVER     = $env:COMPUTERNAME

# =================================================================
# FUNCIONES AUXILIARES
# =================================================================
function Existe-Grupo($n)   { try { Get-LocalGroup -Name $n -EA Stop | Out-Null; return $true } catch { return $false } }
function Existe-Usuario($n) { try { Get-LocalUser  -Name $n -EA Stop | Out-Null; return $true } catch { return $false } }
function Local($n)          { return "$SERVER\$n" }

function Set-Permiso {
    param([string]$Ruta, [string]$Identidad, [string]$Derechos,
          [string]$Tipo = "Allow",
          [string]$Herencia = "ContainerInherit,ObjectInherit",
          [string]$Propagacion = "None")
    $acl  = Get-Acl $Ruta
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identidad, $Derechos, $Herencia, $Propagacion, $Tipo)
    $acl.AddAccessRule($rule)
    Set-Acl -Path $Ruta -AclObject $acl
}

function Reset-Permisos($Ruta) {
    $acl = Get-Acl $Ruta
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    Set-Acl $Ruta $acl
    Set-Permiso $Ruta "SYSTEM"         "FullControl"
    Set-Permiso $Ruta "Administrators" "FullControl"
}

function New-Junction {
    param([string]$Enlace, [string]$Destino)
    if (Test-Path $Enlace) {
        $i = Get-Item $Enlace -Force -EA SilentlyContinue
        if ($i.LinkType -eq "Junction") { return }
        Remove-Item $Enlace -Recurse -Force
    }
    cmd /c "mklink /J `"$Enlace`" `"$Destino`"" | Out-Null
}

function Remove-Junction($Ruta) {
    if (Test-Path $Ruta) {
        $i = Get-Item $Ruta -Force -EA SilentlyContinue
        if ($i.LinkType -eq "Junction") { cmd /c "rmdir `"$Ruta`"" | Out-Null }
        else { Remove-Item $Ruta -Recurse -Force }
    }
}

function Ocultar-SistemaDe($username) {
    # Ocultar carpetas de sistema al usuario (las que NO son su home)
    $carpetas = @("anon") + $GRUPOS
    foreach ($c in $carpetas) {
        $ruta = "$FTP_ROOT\$c"
        if (Test-Path $ruta) {
            icacls $ruta /deny "$SERVER\${username}:(OI)(CI)(RX)" | Out-Null
        }
    }
}

function Esperar-Identidad($nombre) {
    $max = 15; $i = 0
    while ($i -lt $max) {
        try {
            (New-Object System.Security.Principal.NTAccount("$SERVER\$nombre")).Translate(
                [System.Security.Principal.SecurityIdentifier]) | Out-Null
            return $true
        } catch { Start-Sleep 1; $i++ }
    }
    Write-Host "ADVERTENCIA: No se pudo resolver '$nombre'" -ForegroundColor Yellow
    return $false
}

# =================================================================
# 1. INSTALAR Y CONFIGURAR IIS FTP
# =================================================================
function Instalar-Configurar {
    Write-Host "`n=== Instalando IIS + FTP ===" -ForegroundColor Cyan

    foreach ($f in @("Web-Server","Web-Ftp-Server","Web-Ftp-Service")) {
        if (-not (Get-WindowsFeature -Name $f).Installed) {
            Write-Host "Instalando $f..."
            Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
        } else { Write-Host "$f ya instalado." -ForegroundColor Green }
    }

    Import-Module WebAdministration -EA Stop

    # Crear grupos
    foreach ($g in $GRUPOS) {
        if (-not (Existe-Grupo $g)) {
            New-LocalGroup -Name $g -Description "Grupo FTP $g" | Out-Null
            Write-Host "Grupo '$g' creado." -ForegroundColor Green
        }
    }
    if (-not (Existe-Grupo "ftp_users")) {
        New-LocalGroup -Name "ftp_users" -Description "Grupo comun FTP" | Out-Null
    }

    Esperar-Identidad "ftp_users" | Out-Null
    Start-Sleep 2

    # ------------------------------------------------------------------
    # FIX 1: IsolateAllDirectories requiere esta estructura exacta:
    #   $FTP_ROOT\LocalUser\<usuario>\   <- home visible del usuario
    #   $FTP_ROOT\LocalUser\Public\      <- carpeta anonimo (opcional)
    # ------------------------------------------------------------------
    foreach ($d in @("general","reprobados","recursadores","anon","LocalUser","LocalUser\Public")) {
        New-Item -ItemType Directory "$FTP_ROOT\$d" -Force | Out-Null
    }

    # Junction anon apunta a general (acceso anonimo ve /general)
    New-Junction "$FTP_ROOT\LocalUser\Public\general" "$FTP_ROOT\general"

    # --- Permisos carpetas maestras ---

    # /anon: sin uso directo ahora, pero se mantiene por compatibilidad
    Reset-Permisos "$FTP_ROOT\anon"
    Set-Permiso "$FTP_ROOT\anon" "Everyone"        "ReadAndExecute"
    Set-Permiso "$FTP_ROOT\anon" "NETWORK SERVICE" "ReadAndExecute"

    # /general: ftp_users puede escribir pero NO borrar la raíz
    Reset-Permisos "$FTP_ROOT\general"
    $acl  = Get-Acl "$FTP_ROOT\general"
    # Permiso de escritura heredable a hijos
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        (Local "ftp_users"),
        "CreateFiles,CreateDirectories,WriteData,AppendData,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
        "ContainerInherit,ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    # Deny Delete SOLO en esta carpeta raíz (no hereda)
    # FIX 2: Propagation "None" + Herencia "None" = solo afecta esta carpeta
    $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
        (Local "ftp_users"), "Delete", "None", "None", "Deny")
    $acl.AddAccessRule($deny)
    Set-Acl "$FTP_ROOT\general" $acl

    # /reprobados y /recursadores
    # FIX 2: El Deny Delete solo protege la carpeta raíz del grupo,
    #         NO hereda → los usuarios SÍ pueden borrar archivos dentro
    foreach ($g in $GRUPOS) {
        Reset-Permisos "$FTP_ROOT\$g"
        $acl  = Get-Acl "$FTP_ROOT\$g"

        # Modify completo heredable (incluye Delete en hijos)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (Local $g), "Modify,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
            "ContainerInherit,ObjectInherit","None","Allow")
        $acl.AddAccessRule($rule)

        # Deny Delete SOLO en la carpeta raíz del grupo (no borra la carpeta misma)
        # Herencia "None" + Propagacion "None" = solo este objeto
        $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (Local $g), "Delete", "None", "None", "Deny")
        $acl.AddAccessRule($deny)

        Set-Acl "$FTP_ROOT\$g" $acl
    }

    # NETWORK SERVICE necesita leer raíz y LocalUser
    Reset-Permisos $FTP_ROOT
    Set-Permiso $FTP_ROOT              "SYSTEM"          "FullControl"
    Set-Permiso $FTP_ROOT              "Administrators"  "FullControl"
    Set-Permiso $FTP_ROOT              "NETWORK SERVICE" "ReadAndExecute"

    Reset-Permisos "$FTP_ROOT\LocalUser"
    Set-Permiso "$FTP_ROOT\LocalUser"  "SYSTEM"          "FullControl"
    Set-Permiso "$FTP_ROOT\LocalUser"  "Administrators"  "FullControl"
    Set-Permiso "$FTP_ROOT\LocalUser"  "NETWORK SERVICE" "ReadAndExecute"

    # --- Crear sitio FTP ---
    if (Get-WebSite -Name $SITE_NAME -EA SilentlyContinue) {
        Stop-WebSite   -Name $SITE_NAME -EA SilentlyContinue
        Remove-WebSite -Name $SITE_NAME -EA SilentlyContinue
        Start-Sleep 2
    }

    New-WebFtpSite -Name $SITE_NAME -Port $FTP_PORT -PhysicalPath $FTP_ROOT -Force | Out-Null

    $site = "IIS:\Sites\$SITE_NAME"

    # Autenticacion
    Set-ItemProperty $site -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty $site -Name ftpServer.security.authentication.basicAuthentication.enabled     -Value $true

    # Sin SSL
    Set-ItemProperty $site -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
    Set-ItemProperty $site -Name ftpServer.security.ssl.dataChannelPolicy    -Value 0

    # ------------------------------------------------------------------
    # FIX 1: Usar IsolateAllDirectories
    #   IIS buscara: $FTP_ROOT\LocalUser\<usuario>\ para cada usuario local
    #   El usuario ve SOLO el contenido de esa carpeta como raíz "/"
    # ------------------------------------------------------------------
    [xml]$config = Get-Content "C:\Windows\System32\inetsrv\config\applicationHost.config"
    $s = $config.configuration.'system.applicationHost'.sites.site |
        Where-Object { $_.name -eq $SITE_NAME }
    $s.ftpServer.userIsolation.SetAttribute("mode","IsolateAllDirectories")
    $config.Save("C:\Windows\System32\inetsrv\config\applicationHost.config")

    # Puertos pasivos
    & "C:\Windows\System32\inetsrv\appcmd.exe" set config `
        -section:system.ftpServer/firewallSupport `
        /lowDataChannelPort:$PASV_MIN `
        /highDataChannelPort:$PASV_MAX | Out-Null

    # Autorizacion FTP
    Clear-WebConfiguration "/system.ftpServer/security/authorization" -PSPath "IIS:\" -Location $SITE_NAME
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users="?"; roles=""; permissions="Read"} `
        -PSPath "IIS:\" -Location $SITE_NAME
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users="*"; roles=""; permissions="Read,Write"} `
        -PSPath "IIS:\" -Location $SITE_NAME

    # Firewall
    netsh advfirewall firewall delete rule name="FTP_Puerto21" | Out-Null
    netsh advfirewall firewall delete rule name="FTP_Pasivo"   | Out-Null
    netsh advfirewall firewall add rule name="FTP_Puerto21" protocol=TCP dir=in localport=21          action=allow | Out-Null
    netsh advfirewall firewall add rule name="FTP_Pasivo"   protocol=TCP dir=in localport=40000-40100 action=allow | Out-Null

    net stop ftpsvc | Out-Null
    net start ftpsvc | Out-Null

    Write-Host "`n✓ Servidor FTP configurado en puerto $FTP_PORT (modo IsolateAllDirectories)" -ForegroundColor Green
}

# =================================================================
# 2. CREAR USUARIOS
# Con IsolateAllDirectories IIS busca: C:\srv\ftp\LocalUser\<usuario>\
# El usuario ve en FileZilla:
#   /general        (junction → carpeta maestra general)
#   /reprobados     (junction → carpeta maestra del grupo)
#   /<usuario>      (carpeta privada)
# =================================================================
function Crear-Usuarios {
    $n = [int](Read-Host "Numero de usuarios a crear")

    for ($i = 1; $i -le $n; $i++) {
        Write-Host "`n--- Usuario $i de $n ---" -ForegroundColor Cyan
        $username = Read-Host "Nombre de usuario"
        $password = Read-Host "Contrasena" -AsSecureString
        Write-Host "Grupo: 1) reprobados  2) recursadores"
        $g_opt = Read-Host "Opcion"
        $grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }

        # Deshabilitar complejidad temporalmente
        $tmpCfg = "$env:TEMP\secpol_tmp.cfg"
        secedit /export /cfg $tmpCfg /quiet
        (Get-Content $tmpCfg) -replace "PasswordComplexity = 1","PasswordComplexity = 0" | Set-Content $tmpCfg
        secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tmpCfg /quiet
        Remove-Item $tmpCfg -Force -EA SilentlyContinue

        # Crear usuario
        if (-not (Existe-Usuario $username)) {
            New-LocalUser -Name $username -Password $password `
                -Description "Usuario FTP $grupo" `
                -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
            Write-Host "Usuario '$username' creado."
        } else {
            Set-LocalUser -Name $username -Password $password
            Write-Host "Usuario '$username' ya existe, contrasena actualizada."
        }

        Add-LocalGroupMember -Group $grupo      -Member $username -EA SilentlyContinue
        Add-LocalGroupMember -Group "ftp_users" -Member $username -EA SilentlyContinue

        Esperar-Identidad $username | Out-Null
        Esperar-Identidad $grupo    | Out-Null

        # ------------------------------------------------------------------
        # FIX 1: Home en LocalUser\<usuario>\ (requerido por IsolateAllDirectories)
        # ------------------------------------------------------------------
        $user_home = "$FTP_ROOT\LocalUser\$username"
        $dir_priv  = "$user_home\$username"

        New-Item -ItemType Directory $user_home -Force | Out-Null
        New-Item -ItemType Directory $dir_priv  -Force | Out-Null

        # Junctions a carpetas maestras
        New-Junction "$user_home\general" "$FTP_ROOT\general"
        New-Junction "$user_home\$grupo"  "$FTP_ROOT\$grupo"

        # Permisos HOME raíz (solo listar, no escribir directamente)
        Reset-Permisos $user_home
        Set-Permiso $user_home "NETWORK SERVICE" "ReadAndExecute"
        Set-Permiso $user_home (Local $username) "ReadAndExecute"

        # Permisos carpeta privada (Modify total)
        Reset-Permisos $dir_priv
        Set-Permiso $dir_priv (Local $username) "Modify"
        Set-Permiso $dir_priv (Local $grupo)    "Modify"

        # Ocultar carpetas de sistema a este usuario
        Ocultar-SistemaDe $username

        Write-Host "✓ Usuario '$username' listo en grupo '$grupo'." -ForegroundColor Green
    }

    net stop ftpsvc | Out-Null
    net start ftpsvc | Out-Null
}

# =================================================================
# 3. CAMBIAR GRUPO
# =================================================================
function Cambiar-Grupo {
    $username = Read-Host "Nombre del usuario"
    if (-not (Existe-Usuario $username)) { Write-Host "Usuario no existe."; return }

    $viejo_grupo = $null
    foreach ($g in $GRUPOS) {
        $m = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        if ($m.Name -contains "$SERVER\$username") { $viejo_grupo = $g; break }
    }
    if (-not $viejo_grupo) { Write-Host "Usuario no pertenece a ningun grupo FTP."; return }

    Write-Host "Grupo actual: $viejo_grupo"
    Write-Host "Nuevo grupo: 1) reprobados  2) recursadores"
    $g_opt = Read-Host "Opcion"
    $nuevo_grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }
    if ($nuevo_grupo -eq $viejo_grupo) { Write-Host "Ya pertenece a ese grupo."; return }

    # FIX 1: home ahora en LocalUser\
    $user_home = "$FTP_ROOT\LocalUser\$username"

    # 1. Eliminar junction del grupo viejo
    Remove-Junction "$user_home\$viejo_grupo"

    # 2. Cambiar grupos
    Remove-LocalGroupMember -Group $viejo_grupo -Member $username -EA SilentlyContinue
    Add-LocalGroupMember    -Group $nuevo_grupo -Member $username -EA SilentlyContinue

    # 3. Junction al nuevo grupo
    New-Junction "$user_home\$nuevo_grupo" "$FTP_ROOT\$nuevo_grupo"

    # 4. Actualizar permisos carpeta privada
    $dir_priv = "$user_home\$username"
    if (Test-Path $dir_priv) {
        $acl = Get-Acl $dir_priv
        $acl.Access | Where-Object { $_.IdentityReference -like "*$viejo_grupo*" } |
            ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        Set-Acl $dir_priv $acl
        Set-Permiso $dir_priv (Local $nuevo_grupo) "Modify"
    }

    # 5. Actualizar denys NTFS en carpetas de grupo
    icacls "$FTP_ROOT\$viejo_grupo" /remove:d "$SERVER\$username" | Out-Null
    icacls "$FTP_ROOT\$viejo_grupo" /deny "$SERVER\${username}:(OI)(CI)(RX)" | Out-Null

    net stop ftpsvc | Out-Null
    net start ftpsvc | Out-Null

    Write-Host "✓ '$username' ahora pertenece a '$nuevo_grupo'." -ForegroundColor Green
}

# =================================================================
# 4. LISTAR USUARIOS
# =================================================================
function Listar-Usuarios {
    Write-Host ""
    Write-Host ("{0,-15} {1,-15} {2,-20}" -f "USUARIO","GRUPO","ESTADO") -ForegroundColor Cyan
    Write-Host ("-" * 52)
    foreach ($g in $GRUPOS) {
        $miembros = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        foreach ($m in $miembros) {
            $u     = $m.Name.Split("\")[-1]
            $jpath = "$FTP_ROOT\LocalUser\$u\$g"   # FIX: ruta correcta
            $estado = "DESCONECTADO"; $color = "Red"
            if (Test-Path $jpath) {
                $item = Get-Item $jpath -Force -EA SilentlyContinue
                if ($item.LinkType -eq "Junction") { $estado = "VINCULADO"; $color = "Green" }
                else { $estado = "SIN JUNCTION"; $color = "Yellow" }
            }
            Write-Host ("{0,-15} {1,-15} {2,-20}" -f $u, $g, $estado) -ForegroundColor $color
        }
    }
}

# =================================================================
# 5. BORRAR TODO
# =================================================================
function Borrar-Todo {
    $c = Read-Host "Confirma borrado total (s/N)"
    if ($c -notin @("s","S")) { Write-Host "Cancelado."; return }

    net stop ftpsvc | Out-Null
    Import-Module WebAdministration
    Stop-WebSite   -Name $SITE_NAME -EA SilentlyContinue
    Remove-WebSite -Name $SITE_NAME -EA SilentlyContinue

    foreach ($g in $GRUPOS) {
        $miembros = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        foreach ($m in $miembros) {
            $u = $m.Name.Split("\")[-1]
            Remove-LocalUser -Name $u -EA SilentlyContinue
            Write-Host "Usuario '$u' eliminado."
        }
        Remove-LocalGroup -Name $g -EA SilentlyContinue
    }
    Remove-LocalGroup -Name "ftp_users" -EA SilentlyContinue

    if (Test-Path $FTP_ROOT) { Remove-Item $FTP_ROOT -Recurse -Force }

    netsh advfirewall firewall delete rule name="FTP_Puerto21" | Out-Null
    netsh advfirewall firewall delete rule name="FTP_Pasivo"   | Out-Null

    Write-Host "✓ Limpieza completa." -ForegroundColor Green
}

# =================================================================
# MENU PRINCIPAL
# =================================================================
while ($true) {
    Write-Host "`n===============================" -ForegroundColor Cyan
    Write-Host "      GESTION FTP - IIS        " -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1. Instalar y Configurar IIS FTP"
    Write-Host "2. Crear Usuarios"
    Write-Host "3. Cambiar Grupo de Usuario"
    Write-Host "4. Listar Usuarios"
    Write-Host "5. Borrar Todo"
    Write-Host "6. Salir"
    Write-Host "==============================="
    $op = Read-Host "Opcion"
    switch ($op) {
        "1" { Instalar-Configurar }
        "2" { Crear-Usuarios      }
        "3" { Cambiar-Grupo       }
        "4" { Listar-Usuarios     }
        "5" { Borrar-Todo         }
        "6" { exit 0              }
        default { Write-Host "Opcion no valida." -ForegroundColor Red }
    }
}
