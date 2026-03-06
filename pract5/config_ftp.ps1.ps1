# =================================================================
# SCRIPT FTP COLABORATIVO - Windows Server 2022 (IIS FTP)
# Equivalente al script Linux con BIND MOUNT + SGID
# =================================================================
# Ejecutar como Administrador en PowerShell

#Requires -RunAsAdministrator

# ---------------------------------------------------------------
# CONFIGURACIÓN GLOBAL
# ---------------------------------------------------------------
$FTP_ROOT    = "C:\srv\ftp"
$USERS_HOME  = "C:\home\ftp_users"
$FTP_SITE    = "FTP_Colaborativo"
$FTP_PORT    = 21
$PASV_MIN    = 40000
$PASV_MAX    = 40100
$GRUPOS      = @("reprobados", "recursadores")

# ---------------------------------------------------------------
# FUNCIONES AUXILIARES
# ---------------------------------------------------------------

function Verificar-Administrador {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: Ejecute este script como Administrador." -ForegroundColor Red
        exit
    }
}

function Grupo-Existe($nombre) {
    try { Get-LocalGroup -Name $nombre -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

function Usuario-Existe($nombre) {
    try { Get-LocalUser -Name $nombre -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

function Set-FolderPermission {
    param(
        [string]$Path,
        [string]$Identity,
        [string]$Rights,        # e.g. "Modify", "ReadAndExecute"
        [string]$Type = "Allow"
    )
    $acl = Get-Acl $Path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity, $Rights, "ContainerInherit,ObjectInherit", "None", $Type
    )
    $acl.SetAccessRule($rule)
    Set-Acl -Path $Path -AclObject $acl
}

function Remove-FolderPermission {
    param([string]$Path, [string]$Identity)
    $acl = Get-Acl $Path
    $acl.Access | Where-Object { $_.IdentityReference -like "*$Identity*" } | ForEach-Object {
        $acl.RemoveAccessRule($_) | Out-Null
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Disable-Inheritance($Path) {
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $true)  # bloquear herencia, copiar reglas existentes
    Set-Acl -Path $Path -AclObject $acl
}

# ---------------------------------------------------------------
# 1. INSTALAR Y CONFIGURAR SERVIDOR FTP
# ---------------------------------------------------------------
function Instalar-Configurar-FTP {
    Write-Host "`n--- Instalando IIS + FTP y configurando carpetas maestras ---" -ForegroundColor Cyan

    # Instalar roles necesarios
    $features = @("Web-Server", "Web-Ftp-Server", "Web-Ftp-Service", "Web-Ftp-Extensibility")
    foreach ($f in $features) {
        $installed = (Get-WindowsFeature -Name $f).Installed
        if (-not $installed) {
            Write-Host "Instalando $f..."
            Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
        } else {
            Write-Host "$f ya instalado." -ForegroundColor Green
        }
    }

    # Importar módulos IIS
    Import-Module WebAdministration -ErrorAction SilentlyContinue

    # Crear grupos locales equivalentes a Linux
    foreach ($g in $GRUPOS) {
        if (-not (Grupo-Existe $g)) {
            New-LocalGroup -Name $g -Description "Grupo FTP $g"
            Write-Host "Grupo '$g' creado." -ForegroundColor Green
        }
    }
    if (-not (Grupo-Existe "ftp_users")) {
        New-LocalGroup -Name "ftp_users" -Description "Grupo general FTP (equivalente a 'ftp' en Linux)"
        Write-Host "Grupo 'ftp_users' creado." -ForegroundColor Green
    }

    # Crear carpetas maestras (equivalente a /srv/ftp/)
    foreach ($dir in @("general", "reprobados", "recursadores")) {
        $path = "$FTP_ROOT\$dir"
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Write-Host "Carpeta '$path' creada."
        }
    }

    # ---------------------------------------------------------------
    # PERMISOS DE CARPETAS MAESTRAS
    # Equivalente a chmod 3775 / 3770 en Linux
    # ---------------------------------------------------------------

    # general: grupo ftp_users puede leer y escribir, NO borrar carpetas raíz
    Disable-Inheritance "$FTP_ROOT\general"
    # Quitar todos primero para partir limpio
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl "$FTP_ROOT\general" $acl

    # SYSTEM y Administradores: control total
    Set-FolderPermission "$FTP_ROOT\general" "SYSTEM"             "FullControl"
    Set-FolderPermission "$FTP_ROOT\general" "Administrators"     "FullControl"
    # ftp_users: puede crear archivos y subcarpetas, pero NO borrar esta carpeta
    # "CreateFiles,CreateDirectories,WriteData,AppendData,ReadAndExecute,Synchronize"
    $acl = Get-Acl "$FTP_ROOT\general"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "ftp_users",
        "CreateFiles,CreateDirectories,WriteData,AppendData,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
        "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($rule)
    # Denegar explícitamente borrar la carpeta raíz (equivalente al sticky bit)
    $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "ftp_users", "Delete", "None", "None", "Deny"
    )
    $acl.AddAccessRule($denyRule)
    Set-Acl "$FTP_ROOT\general" $acl

    # reprobados y recursadores: solo su grupo puede escribir
    foreach ($g in $GRUPOS) {
        $path = "$FTP_ROOT\$g"
        Disable-Inheritance $path
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl $path $acl

        Set-FolderPermission $path "SYSTEM"         "FullControl"
        Set-FolderPermission $path "Administrators" "FullControl"

        $acl = Get-Acl $path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $g,
            "CreateFiles,CreateDirectories,WriteData,AppendData,ReadAndExecute,ListDirectory,ReadAttributes,Synchronize",
            "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($rule)
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $g, "Delete", "None", "None", "Deny"
        )
        $acl.AddAccessRule($denyRule)
        Set-Acl $path $acl
    }

    # ---------------------------------------------------------------
    # CREAR SITIO FTP EN IIS
    # ---------------------------------------------------------------
    Import-Module WebAdministration

    # Eliminar sitio previo si existe (idempotencia)
    if (Get-WebSite -Name $FTP_SITE -ErrorAction SilentlyContinue) {
        Remove-WebSite -Name $FTP_SITE
    }

    # Crear el sitio FTP
    New-WebFtpSite -Name $FTP_SITE -Port $FTP_PORT -PhysicalPath $FTP_ROOT -Force

    # Habilitar acceso anónimo (solo lectura a /general)
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.security.authentication.basicAuthentication.enabled    -Value $true

    # SSL: sin SSL (equivalente a Linux sin TLS)
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.security.ssl.dataChannelPolicy    -Value "SslAllow"

    # Modo pasivo (equivalente a pasv_min/max_port)
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.firewallSupport.pasvMaxPort -Value $PASV_MAX
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" -Name ftpServer.firewallSupport.pasvMinPort -Value $PASV_MIN

    # Autorización: anónimo solo lectura en raíz
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users=""; roles=""; permissions="Read"} `
        -PSPath "IIS:\" -Location $FTP_SITE

    # Autorización: usuarios autenticados tienen lectura+escritura
    Add-WebConfiguration "/system.ftpServer/security/authorization" `
        -Value @{accessType="Allow"; users="*"; roles=""; permissions="Read,Write"} `
        -PSPath "IIS:\" -Location $FTP_SITE

    # Aislamiento de usuarios (chroot equivalente): cada usuario ve solo su carpeta
    Set-ItemProperty "IIS:\Sites\$FTP_SITE" `
        -Name ftpServer.userIsolation.mode -Value 3  # 3 = IsolateAllDirectories (usa carpeta LocalUser\usuario)

    # Firewall: abrir puertos FTP
    netsh advfirewall firewall add rule name="FTP Puerto 21"       protocol=TCP dir=in localport=21          action=allow | Out-Null
    netsh advfirewall firewall add rule name="FTP Pasivo 40000-40100" protocol=TCP dir=in localport=40000-40100 action=allow | Out-Null

    # Iniciar sitio y servicio
    Start-WebSite -Name $FTP_SITE
    Start-Service -Name "ftpsvc" -ErrorAction SilentlyContinue

    Write-Host "`nServidor FTP configurado correctamente en puerto $FTP_PORT." -ForegroundColor Green
    Write-Host "Carpetas maestras en: $FTP_ROOT" -ForegroundColor Green
}

# ---------------------------------------------------------------
# 2. CREAR USUARIOS
# ---------------------------------------------------------------
function Gestionar-Usuarios {
    $n = Read-Host "Numero de usuarios a crear"
    for ($i = 1; $i -le $n; $i++) {
        Write-Host "`n--- Configurando Usuario $i ---" -ForegroundColor Cyan
        $username = Read-Host "Nombre de usuario"
        $password = Read-Host "Password" -AsSecureString
        Write-Host "Grupo: 1) reprobados | 2) recursadores"
        $g_opt = Read-Host "Opcion"
        $grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }

        $user_home = "$USERS_HOME\$username"

        # Crear usuario local (equivalente a useradd -s /sbin/nologin)
        if (-not (Usuario-Existe $username)) {
            New-LocalUser -Name $username -Password $password `
                -Description "Usuario FTP $grupo" `
                -PasswordNeverExpires $true `
                -UserMayNotChangePassword $true | Out-Null
            Write-Host "Usuario '$username' creado."
        } else {
            # Actualizar contraseña si ya existe
            Set-LocalUser -Name $username -Password $password
            Write-Host "Usuario '$username' ya existe, contraseña actualizada."
        }

        # Agregar a su grupo y al grupo ftp_users (para acceso a general)
        Add-LocalGroupMember -Group $grupo       -Member $username -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "ftp_users"  -Member $username -ErrorAction SilentlyContinue

        # Impedir inicio de sesión interactivo (equivalente a /sbin/nologin)
        # Se logra denegando el derecho "Log on locally" vía secedit (opcional avanzado)

        # ---------------------------------------------------------------
        # Crear estructura de carpetas del usuario
        # Equivalente a $user_home/general, $user_home/$grupo, $user_home/$username
        #
        # IIS con UserIsolation mode=3 espera la estructura:
        #   C:\home\ftp_users\LocalUser\username\   <- raíz del chroot
        # Dentro de esa raíz creamos los subdirectorios visibles
        # ---------------------------------------------------------------
        $iis_root  = "$USERS_HOME\LocalUser\$username"
        $dir_gen   = "$iis_root\general"
        $dir_grupo = "$iis_root\$grupo"
        $dir_priv  = "$iis_root\$username"

        New-Item -ItemType Directory -Path $iis_root  -Force | Out-Null
        New-Item -ItemType Directory -Path $dir_gen   -Force | Out-Null
        New-Item -ItemType Directory -Path $dir_grupo -Force | Out-Null
        New-Item -ItemType Directory -Path $dir_priv  -Force | Out-Null

        # ---------------------------------------------------------------
        # Crear Junction Points (equivalente a mount --bind en Linux)
        # Redirigen las subcarpetas al almacén central /srv/ftp/
        # ---------------------------------------------------------------
        # Primero eliminar si ya existen para idempotencia
        if (Test-Path $dir_gen)   { Remove-Item $dir_gen   -Force -Recurse }
        if (Test-Path $dir_grupo) { Remove-Item $dir_grupo -Force -Recurse }

        # Crear junction points (requiere admin)
        cmd /c "mklink /J `"$dir_gen`"   `"$FTP_ROOT\general`""   | Out-Null
        cmd /c "mklink /J `"$dir_grupo`" `"$FTP_ROOT\$grupo`""    | Out-Null
        Write-Host "Junction points creados: general -> $FTP_ROOT\general"
        Write-Host "Junction points creados: $grupo  -> $FTP_ROOT\$grupo"

        # ---------------------------------------------------------------
        # PERMISOS
        # ---------------------------------------------------------------

        # Raíz del chroot: solo Administradores y SYSTEM (el usuario no debe modificarla)
        Disable-Inheritance $iis_root
        $acl = Get-Acl $iis_root
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl $iis_root $acl
        Set-FolderPermission $iis_root "SYSTEM"         "FullControl"
        Set-FolderPermission $iis_root "Administrators" "FullControl"
        # Usuario puede listar (para ver las carpetas) pero no modificar la raíz
        Set-FolderPermission $iis_root $username "ReadAndExecute"

        # Carpeta personal: solo el usuario y su grupo (equivalente a chmod 770)
        Disable-Inheritance $dir_priv
        $acl = Get-Acl $dir_priv
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl $dir_priv $acl
        Set-FolderPermission $dir_priv "SYSTEM"         "FullControl"
        Set-FolderPermission $dir_priv "Administrators" "FullControl"
        Set-FolderPermission $dir_priv $username        "Modify"
        Set-FolderPermission $dir_priv $grupo           "Modify"

        Write-Host "Usuario $username creado exitosamente en grupo $grupo." -ForegroundColor Green
    }
}

# ---------------------------------------------------------------
# 3. CAMBIAR GRUPO DE USUARIO
# ---------------------------------------------------------------
function Cambiar-Grupo-Usuario {
    $username = Read-Host "Nombre del usuario"
    if (-not (Usuario-Existe $username)) { Write-Host "Usuario no existe"; return }

    # Detectar grupo actual
    $viejo_grupo = $null
    foreach ($g in $GRUPOS) {
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        if ($members.Name -like "*$username*") { $viejo_grupo = $g; break }
    }
    if (-not $viejo_grupo) { Write-Host "El usuario no pertenece a reprobados ni recursadores"; return }

    Write-Host "Nuevo Grupo: 1) reprobados | 2) recursadores"
    $g_opt = Read-Host "Opcion"
    $nuevo_grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }

    if ($nuevo_grupo -eq $viejo_grupo) { Write-Host "Ya es de ese grupo"; return }

    $iis_root  = "$USERS_HOME\LocalUser\$username"
    $dir_viejo = "$iis_root\$viejo_grupo"
    $dir_nuevo = "$iis_root\$nuevo_grupo"

    # 1. Eliminar junction del grupo viejo
    Write-Host "Desvinculando grupo $viejo_grupo..."
    if (Test-Path $dir_viejo) {
        cmd /c "rmdir `"$dir_viejo`"" | Out-Null  # rmdir sin /S para no borrar el origen
    }

    # 2. Cambiar grupos
    Remove-LocalGroupMember -Group $viejo_grupo -Member $username -ErrorAction SilentlyContinue
    Add-LocalGroupMember    -Group $nuevo_grupo -Member $username -ErrorAction SilentlyContinue

    # 3. Crear junction al nuevo grupo
    cmd /c "mklink /J `"$dir_nuevo`" `"$FTP_ROOT\$nuevo_grupo`"" | Out-Null

    # 4. Actualizar permisos de carpeta personal
    Set-FolderPermission "$iis_root\$username" $nuevo_grupo "Modify"
    Remove-FolderPermission "$iis_root\$username" $viejo_grupo

    Write-Host "Cambio completado. $username ahora pertenece a $nuevo_grupo." -ForegroundColor Green
}

# ---------------------------------------------------------------
# 4. LISTAR USUARIOS
# ---------------------------------------------------------------
function Listar-Usuarios {
    Write-Host "`nUSUARIO`t`tGRUPO`t`tJUNCTION"
    Write-Host "--------------------------------------------------------"
    foreach ($g in $GRUPOS) {
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            $uname  = $m.Name.Split("\")[-1]
            $jpath  = "$USERS_HOME\LocalUser\$uname\$g"
            $status = if (Test-Path $jpath) { "VINCULADO" } else { "DESCONECTADO" }
            Write-Host "$uname`t`t$g`t`t$status"
        }
    }
}

# ---------------------------------------------------------------
# 5. BORRAR TODO
# ---------------------------------------------------------------
function Borrar-Todo {
    Write-Host "Iniciando limpieza total..." -ForegroundColor Yellow

    # Detener sitio FTP
    Stop-WebSite -Name $FTP_SITE -ErrorAction SilentlyContinue
    Remove-WebSite -Name $FTP_SITE -ErrorAction SilentlyContinue
    Stop-Service -Name "ftpsvc" -ErrorAction SilentlyContinue

    # Borrar usuarios de los grupos FTP
    foreach ($g in $GRUPOS) {
        $members = Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue
        foreach ($m in $members) {
            $uname = $m.Name.Split("\")[-1]
            Write-Host "Eliminando usuario $uname..."
            Remove-LocalUser -Name $uname -ErrorAction SilentlyContinue
        }
        Remove-LocalGroup -Name $g -ErrorAction SilentlyContinue
    }
    Remove-LocalGroup -Name "ftp_users" -ErrorAction SilentlyContinue

    # Borrar directorios
    if (Test-Path $USERS_HOME) { Remove-Item $USERS_HOME -Recurse -Force }
    if (Test-Path $FTP_ROOT)   { Remove-Item $FTP_ROOT   -Recurse -Force }

    # Limpiar reglas de firewall
    netsh advfirewall firewall delete rule name="FTP Puerto 21"          | Out-Null
    netsh advfirewall firewall delete rule name="FTP Pasivo 40000-40100" | Out-Null

    Write-Host "Sistema limpio." -ForegroundColor Green
}

# ---------------------------------------------------------------
# MENU PRINCIPAL
# ---------------------------------------------------------------
Verificar-Administrador

while ($true) {
    Write-Host "`n===== GESTIÓN FTP =====" -ForegroundColor Cyan
    Write-Host "1. Configurar Servidor FTP (IIS)"
    Write-Host "2. Crear Usuarios (n)"
    Write-Host "3. Cambiar Usuario de Grupo"
    Write-Host "4. Listar Usuarios"
    Write-Host "5. Borrar Todo (Limpieza)"
    Write-Host "6. Salir"
    $op = Read-Host "Seleccione una opcion"
    switch ($op) {
        "1" { Instalar-Configurar-FTP }
        "2" { Gestionar-Usuarios }
        "3" { Cambiar-Grupo-Usuario }
        "4" { Listar-Usuarios }
        "5" { Borrar-Todo }
        "6" { exit }
        default { Write-Host "Opcion no valida." -ForegroundColor Red }
    }
}
