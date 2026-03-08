# =================================================================
# SCRIPT FTP - Windows Server 2022 - IIS FTP Service
# Grupos: reprobados / recursadores
# Acceso anonimo: solo lectura en /general
# Acceso autenticado: escritura en /general, grupo y personal
# =================================================================
# Ejecutar en PowerShell como Administrador
#Requires -RunAsAdministrator

# =================================================================
# VARIABLES GLOBALES
# =================================================================
$FTP_ROOT   = "C:\srv\ftp"
# IIS UserIsolation busca LocalUser\usuario DENTRO de la raiz del sitio FTP
# Por eso USERS_HOME debe apuntar al mismo lugar que FTP_ROOT
$USERS_HOME = "C:\srv\ftp"
$SITE_NAME  = "FTP_Colaborativo"
$FTP_PORT   = 21
$PASV_MIN   = 40000
$PASV_MAX   = 40100
$GRUPOS     = @("reprobados", "recursadores")

# =================================================================
# FUNCIONES AUXILIARES
# =================================================================

function Existe-Grupo($nombre) {
    try { Get-LocalGroup -Name $nombre -EA Stop | Out-Null; return $true }
    catch { return $false }
}

function Existe-Usuario($nombre) {
    try { Get-LocalUser -Name $nombre -EA Stop | Out-Null; return $true }
    catch { return $false }
}

# Aplica una regla de permiso NTFS a una carpeta
function Set-Permiso {
    param(
        [string]$Ruta,
        [string]$Identidad,
        [string]$Derechos,
        [string]$Tipo = "Allow"
    )
    $acl  = Get-Acl $Ruta
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identidad, $Derechos,
        "ContainerInherit,ObjectInherit", "None", $Tipo
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $Ruta -AclObject $acl
}

# Elimina todas las reglas de herencia y parte limpio
function Reset-Permisos($Ruta) {
    $acl = Get-Acl $Ruta
    $acl.SetAccessRuleProtection($true, $false)
    # Limpiar reglas existentes
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    Set-Acl -Path $Ruta -AclObject $acl
    # Siempre dar control total a SYSTEM y Administradores
    Set-Permiso $Ruta "SYSTEM"              "FullControl"
    Set-Permiso $Ruta "Administrators"      "FullControl"
}

# Crea un Junction Point (equivalente a mount --bind en Linux)
function New-Junction {
    param([string]$Enlace, [string]$Destino)
    if (Test-Path $Enlace) {
        $item = Get-Item $Enlace -Force -EA SilentlyContinue
        if ($item.LinkType -eq "Junction") { return }   # ya existe
        Remove-Item $Enlace -Recurse -Force
    }
    cmd /c "mklink /J `"$Enlace`" `"$Destino`"" | Out-Null
}

# Elimina un Junction Point sin borrar el contenido del destino
function Remove-Junction($Ruta) {
    if (Test-Path $Ruta) {
        $item = Get-Item $Ruta -Force -EA SilentlyContinue
        if ($item.LinkType -eq "Junction") {
            cmd /c "rmdir `"$Ruta`"" | Out-Null
        } else {
            Remove-Item $Ruta -Recurse -Force
        }
    }
}

# Nombre completo local: SERVIDOR\nombre
function NombreLocal($nombre) { return "$env:COMPUTERNAME\$nombre" }

# =================================================================
# 1. INSTALAR Y CONFIGURAR IIS FTP
# Equivalente a: instalar vsftpd + escribir vsftpd.conf
# =================================================================
function Instalar-Configurar {
    Write-Host "`n=== Instalando IIS + FTP Service ===" -ForegroundColor Cyan

    # --- Instalar roles (idempotente) ---
    foreach ($f in @("Web-Server","Web-Ftp-Server","Web-Ftp-Service")) {
        if (-not (Get-WindowsFeature -Name $f).Installed) {
            Write-Host "Instalando $f..."
            Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
        } else {
            Write-Host "$f ya instalado." -ForegroundColor Green
        }
    }

    Import-Module WebAdministration -EA Stop

    # --- Crear grupos locales (equivalente a groupadd) ---
    foreach ($g in $GRUPOS) {
        if (-not (Existe-Grupo $g)) {
            New-LocalGroup -Name $g -Description "Grupo FTP $g" | Out-Null
            Write-Host "Grupo '$g' creado." -ForegroundColor Green
        }
    }
    if (-not (Existe-Grupo "ftp_users")) {
        New-LocalGroup -Name "ftp_users" -Description "Grupo comun FTP" | Out-Null
        Write-Host "Grupo 'ftp_users' creado." -ForegroundColor Green
    }

    # Esperar propagacion en SAM de Windows (critico para ACLs)
    Start-Sleep -Seconds 5

    # --- Crear carpetas maestras (equivalente a /srv/ftp/) ---
    foreach ($d in @("general","reprobados","recursadores","anon")) {
        New-Item -ItemType Directory -Path "$FTP_ROOT\$d" -Force | Out-Null
    }

    # Junction de /general dentro de /anon (para acceso anonimo sin chroot escribible)
    New-Junction "$FTP_ROOT\anon\general" "$FTP_ROOT\general"

    # -------------------------------------------------------
    # PERMISOS NTFS DE CARPETAS MAESTRAS
    # Equivalente a chown/chmod en Linux
    # -------------------------------------------------------
    # Verificar que los grupos existen antes de aplicar ACLs
    $maxWait = 15
    $elapsed = 0
    while ($elapsed -lt $maxWait) {
        try {
            $null = [System.Security.Principal.NTAccount]("$env:COMPUTERNAMEtp_users")
            break
        } catch {
            Start-Sleep -Seconds 1
            $elapsed++
        }
    }
    if ($elapsed -ge $maxWait) {
        Write-Host "ADVERTENCIA: Los grupos pueden no estar disponibles aun." -ForegroundColor Yellow
    }

    # /anon → raiz del anonimo, solo lectura para todos (chroot no escribible)
    Reset-Permisos "$FTP_ROOT\anon"
    Set-Permiso "$FTP_ROOT\anon" "Everyone" "ReadAndExecute"

    # /general → grupo ftp_users escribe, nadie borra carpeta raiz
    # Equivalente a chmod 2775 root:ftp_users
    Reset-Permisos "$FTP_ROOT\general"
    $acl  = Get-Acl "$FTP_ROOT\general"
    # Derechos de escritura SIN incluir Delete en la carpeta raiz
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        (NombreLocal "ftp_users"),
        "CreateFiles,CreateDirectories,WriteData,AppendData,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
        "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($rule)
    # Deny Delete solo en esta carpeta (no hereda a subcarpetas) — equivalente al sticky bit
    $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
        (NombreLocal "ftp_users"), "Delete",
        "None", "None", "Deny"
    )
    $acl.AddAccessRule($deny)
    Set-Acl "$FTP_ROOT\general" $acl

    # /reprobados y /recursadores → solo su grupo, pueden borrar archivos de compañeros
    # Equivalente a chmod 2770 root:grupo
    foreach ($g in $GRUPOS) {
        Reset-Permisos "$FTP_ROOT\$g"
        $acl  = Get-Acl "$FTP_ROOT\$g"
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (NombreLocal $g),
            "Modify,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
            "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        # Deny Delete solo en la carpeta raiz del grupo
        $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (NombreLocal $g), "Delete",
            "None", "None", "Deny"
        )
        $acl.AddAccessRule($deny)
        Set-Acl "$FTP_ROOT\$g" $acl
    }

    # -------------------------------------------------------
    # CREAR SITIO FTP EN IIS
    # Equivalente a escribir /etc/vsftpd.conf
    # -------------------------------------------------------
    if (Get-WebSite -Name $SITE_NAME -EA SilentlyContinue) {
        Stop-WebSite   -Name $SITE_NAME -EA SilentlyContinue
        Remove-WebSite -Name $SITE_NAME
    }

    # El sitio apunta a FTP_ROOT (raiz con todas las carpetas)
    New-WebFtpSite -Name $SITE_NAME -Port $FTP_PORT -PhysicalPath $FTP_ROOT -Force | Out-Null

    $sitePath = "IIS:\Sites\$SITE_NAME"

    # Autenticacion: anonima + basica (usuario/password)
    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.basicAuthentication.enabled    -Value $true

    # SSL: permitir sin SSL (igual que vsftpd sin TLS)
    Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
    Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy    -Value "SslAllow"

    # Modo pasivo (equivalente a pasv_min/max_port en vsftpd.conf)
    & "$env:SystemRoot\System32\inetsrv\appcmd.exe" set config -section:system.ftpServer/firewallSupport /lowDataChannelPort:$PASV_MIN /highDataChannelPort:$PASV_MAX | Out-Null

    # Aislamiento de usuarios: cada uno ve solo su carpeta HOME
    # Equivalente a chroot_local_user=YES en vsftpd
    # Modo 3 = IsolateAllDirectories (busca LocalUser\username dentro del sitio)
    Set-ItemProperty $sitePath -Name ftpServer.userIsolation.mode -Value 3

    # Directorio del anonimo: /anon (raiz no escribible)

    # Reglas de autorizacion FTP
    # Limpiar reglas anteriores
    Clear-WebConfiguration "/system.ftpServer/security/authorization" -PSPath "IIS:\" -Location $SITE_NAME

    # Anonimo: solo lectura
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users="?"; roles=""; permissions="Read"} `
        -PSPath "IIS:\" -Location $SITE_NAME

    # Usuarios autenticados: lectura + escritura
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users="*"; roles=""; permissions="Read,Write"} `
        -PSPath "IIS:\" -Location $SITE_NAME

    # Firewall: puertos FTP
    netsh advfirewall firewall delete rule name="FTP_Puerto21"        | Out-Null
    netsh advfirewall firewall delete rule name="FTP_Pasivo"          | Out-Null
    netsh advfirewall firewall add    rule name="FTP_Puerto21"  protocol=TCP dir=in localport=21                action=allow | Out-Null
    netsh advfirewall firewall add    rule name="FTP_Pasivo"    protocol=TCP dir=in localport=40000-40100       action=allow | Out-Null

    Start-WebSite -Name $SITE_NAME -EA SilentlyContinue
    Restart-Service ftpsvc -Force

    Write-Host "`n✓ Servidor FTP configurado en puerto $FTP_PORT" -ForegroundColor Green
    Write-Host "  Carpetas maestras: $FTP_ROOT" -ForegroundColor Green
    Write-Host "  Homes de usuarios: $USERS_HOME\LocalUser\<usuario>" -ForegroundColor Green
}

# =================================================================
# 2. CREAR USUARIOS
# Estructura visible en FileZilla al conectar:
#   /general
#   /reprobados  o  /recursadores
#   /nombre_usuario
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

        # --- Crear usuario local (equivalente a useradd -s /sbin/nologin) ---
        # Deshabilitar temporalmente la politica de complejidad de passwords
        $tmpCfg = "$env:TEMP\secpol_tmp.cfg"
        secedit /export /cfg $tmpCfg /quiet
        (Get-Content $tmpCfg) -replace "PasswordComplexity = 1","PasswordComplexity = 0" |
            Set-Content $tmpCfg
        secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tmpCfg /quiet
        Remove-Item $tmpCfg -Force -EA SilentlyContinue

        if (-not (Existe-Usuario $username)) {
            New-LocalUser -Name $username `
                          -Password $password `
                          -Description "Usuario FTP $grupo" `
                          -PasswordNeverExpires `
                          -UserMayNotChangePassword | Out-Null
            Write-Host "Usuario '$username' creado."
        } else {
            Set-LocalUser -Name $username -Password $password
            Write-Host "Usuario '$username' ya existe, contrasena actualizada."
        }

        # Agregar a su grupo y al grupo ftp_users (para acceso a /general)
        Add-LocalGroupMember -Group $grupo      -Member $username -EA SilentlyContinue
        Add-LocalGroupMember -Group "ftp_users" -Member $username -EA SilentlyContinue
        # Esperar propagacion en SAM antes de aplicar ACLs
        Start-Sleep -Seconds 3

        # -------------------------------------------------------
        # Estructura de carpetas en IIS UserIsolation
        # IIS con modo 3 busca: $FTP_ROOT\LocalUser\$username\
        # Lo que haya dentro es lo que ve el usuario al conectar
        # Equivalente al HOME en Linux con bind mounts
        # -------------------------------------------------------
        $iis_home  = "$USERS_HOME\LocalUser\$username"
        $dir_gen   = "$iis_home\general"
        $dir_grupo = "$iis_home\$grupo"
        $dir_priv  = "$iis_home\$username"

        New-Item -ItemType Directory -Path $iis_home -Force | Out-Null
        New-Item -ItemType Directory -Path $dir_priv -Force | Out-Null

        # Junction Points (equivalente a mount --bind en Linux)
        New-Junction $dir_gen   "$FTP_ROOT\general"
        New-Junction $dir_grupo "$FTP_ROOT\$grupo"

        # -------------------------------------------------------
        # PERMISOS NTFS
        # -------------------------------------------------------

        # Raiz HOME: el usuario puede listar pero no modificar
        # Equivalente a chown root:root $HOME && chmod 755 $HOME
        Reset-Permisos $iis_home
        Set-Permiso $iis_home (NombreLocal $username) "ReadAndExecute"

        # Carpeta personal: solo el usuario y su grupo
        # Equivalente a chown user:grupo $HOME/username && chmod 770
        Reset-Permisos $dir_priv
        Set-Permiso $dir_priv (NombreLocal $username)  "Modify"
        Set-Permiso $dir_priv (NombreLocal $grupo)     "Modify"

        Write-Host "✓ Usuario '$username' listo en grupo '$grupo'." -ForegroundColor Green
    }
}

# =================================================================
# 3. CAMBIAR GRUPO DE USUARIO
# =================================================================
function Cambiar-Grupo {
    $username = Read-Host "Nombre del usuario"
    if (-not (Existe-Usuario $username)) { Write-Host "Usuario no existe."; return }

    # Detectar grupo actual
    $viejo_grupo = $null
    foreach ($g in $GRUPOS) {
        $miembros = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        if ($miembros.Name -contains "$env:COMPUTERNAME\$username") {
            $viejo_grupo = $g; break
        }
    }
    if (-not $viejo_grupo) { Write-Host "El usuario no pertenece a reprobados ni recursadores."; return }

    Write-Host "Grupo actual: $viejo_grupo"
    Write-Host "Nuevo grupo: 1) reprobados  2) recursadores"
    $g_opt = Read-Host "Opcion"
    $nuevo_grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }

    if ($nuevo_grupo -eq $viejo_grupo) { Write-Host "Ya pertenece a ese grupo."; return }

    $iis_home  = "$USERS_HOME\LocalUser\$username"
    $dir_viejo = "$iis_home\$viejo_grupo"
    $dir_nuevo = "$iis_home\$nuevo_grupo"

    # 1. Eliminar junction del grupo viejo
    Write-Host "Desvinculando '$viejo_grupo'..."
    Remove-Junction $dir_viejo

    # 2. Cambiar grupos
    Remove-LocalGroupMember -Group $viejo_grupo -Member $username -EA SilentlyContinue
    Add-LocalGroupMember    -Group $nuevo_grupo -Member $username -EA SilentlyContinue

    # 3. Crear junction al nuevo grupo
    New-Junction $dir_nuevo "$FTP_ROOT\$nuevo_grupo"

    # 4. Actualizar permisos de carpeta personal
    $dir_priv = "$iis_home\$username"
    if (Test-Path $dir_priv) {
        # Quitar permisos del grupo viejo
        $acl = Get-Acl $dir_priv
        $acl.Access | Where-Object { $_.IdentityReference -like "*$viejo_grupo*" } | ForEach-Object {
            $acl.RemoveAccessRule($_) | Out-Null
        }
        Set-Acl $dir_priv $acl
        # Agregar permisos del nuevo grupo
        Set-Permiso $dir_priv (NombreLocal $nuevo_grupo) "Modify"
    }

    Write-Host "✓ '$username' ahora pertenece a '$nuevo_grupo'." -ForegroundColor Green
}

# =================================================================
# 4. LISTAR USUARIOS
# =================================================================
function Listar-Usuarios {
    Write-Host ""
    Write-Host ("{0,-15} {1,-15} {2,-20}" -f "USUARIO","GRUPO","JUNCTION") -ForegroundColor Cyan
    Write-Host ("-" * 55)

    foreach ($g in $GRUPOS) {
        $miembros = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        foreach ($m in $miembros) {
            $uname = $m.Name.Split("\")[-1]
            $jpath = "$USERS_HOME\LocalUser\$uname\$g"
            $estado = "DESCONECTADO"
            $color  = "Red"
            if (Test-Path $jpath) {
                $item = Get-Item $jpath -Force -EA SilentlyContinue
                if ($item.LinkType -eq "Junction") {
                    $estado = "VINCULADO"
                    $color  = "Green"
                } else {
                    $estado = "CARPETA (sin junction)"
                    $color  = "Yellow"
                }
            }
            Write-Host ("{0,-15} {1,-15} {2,-20}" -f $uname, $g, $estado) -ForegroundColor $color
        }
    }
}

# =================================================================
# 5. BORRAR TODO
# =================================================================
function Borrar-Todo {
    $confirm = Read-Host "Confirma borrado total (s/N)"
    if ($confirm -notin @("s","S")) { Write-Host "Cancelado."; return }

    Write-Host "Limpiando sistema..." -ForegroundColor Yellow

    # Detener y eliminar sitio FTP
    Stop-WebSite  -Name $SITE_NAME -EA SilentlyContinue
    Remove-WebSite -Name $SITE_NAME -EA SilentlyContinue
    Stop-Service ftpsvc -EA SilentlyContinue

    # Eliminar usuarios de los grupos FTP
    foreach ($g in $GRUPOS) {
        $miembros = Get-LocalGroupMember -Group $g -EA SilentlyContinue
        foreach ($m in $miembros) {
            $uname = $m.Name.Split("\")[-1]
            Write-Host "Eliminando usuario '$uname'..."
            Remove-LocalUser -Name $uname -EA SilentlyContinue
        }
        Remove-LocalGroup -Name $g -EA SilentlyContinue
    }
    Remove-LocalGroup -Name "ftp_users" -EA SilentlyContinue

    # Borrar directorios
    if (Test-Path $USERS_HOME) { Remove-Item $USERS_HOME -Recurse -Force }
    if (Test-Path $FTP_ROOT)   { Remove-Item $FTP_ROOT   -Recurse -Force }

    # Limpiar reglas de firewall
    netsh advfirewall firewall delete rule name="FTP_Puerto21" | Out-Null
    netsh advfirewall firewall delete rule name="FTP_Pasivo"   | Out-Null

    Write-Host "✓ Limpieza completa." -ForegroundColor Green
}

# =================================================================
# MENU PRINCIPAL
# =================================================================
# Verificar que se ejecuta como Administrador
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Ejecute este script como Administrador." -ForegroundColor Red
    exit 1
}

while ($true) {
    Write-Host ""
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "     GESTION FTP - IIS         " -ForegroundColor Cyan
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
