param (
    [string] $option,
    [switch] $install,
    [switch] $help,
    [switch] $confirm,
    [int]    $no_users,
    [string] $users,
    [string] $passwords,
    [string] $groups
)

# ============================================================
#  VECTORES DE SEGURIDAD GLOBALES
# ============================================================
$script:gruposSistema = @(
    "Administrators","Users","Guests","Power Users","Remote Desktop Users",
    "IIS_IUSRS","Performance Monitor Users","Performance Log Users",
    "Distributed COM Users","Cryptographic Operators","Backup Operators",
    "Network Configuration Operators","Event Log Readers","Certificate Service DCOM Access"
)

$script:usuariosSistema = @(
    "Administrator","Guest","DefaultAccount","WDAGUtilityAccount","SYSTEM","IUSR"
)

# ============================================================
#  MENSAJE DE AYUDA
# ============================================================
$helpM  = "--- Opciones ---`n`n"
$helpM += "1)  Verificar existencia del servicio FTP`n"
$helpM += "2)  Instalar servicio FTP`n"
$helpM += "3)  Crear sitio FTP y configuracion inicial (IMPORTANTE: ejecutar despues de instalar)`n"
$helpM += "4)  Desinstalar servicio FTP`n"
$helpM += "5)  Estatus del servicio FTP`n"
$helpM += "6)  Mover usuario a un grupo`n`n"
$helpM += "--- ABC Usuarios ---`n`n"
$helpM += "7)  Agregar alumno(s)`n"
$helpM += "8)  Eliminar alumno`n"
$helpM += "9)  Consultar alumnos`n`n"
$helpM += "--- ABC Grupos ---`n`n"
$helpM += "10) Agregar grupo academico`n"
$helpM += "11) Eliminar grupo academico`n"
$helpM += "12) Consultar grupos academicos`n`n"
$helpM += "--- Banderas ---`n`n"
$helpM += "-help       Mostrar este mensaje`n"
$helpM += "-option     Seleccionar opcion (1-12)`n"
$helpM += "-confirm    Confirmar desinstalacion`n"
$helpM += "-install    Confirmar instalacion`n"
$helpM += "-no_users   Numero de usuarios a registrar`n"
$helpM += "-users      Lista de usuarios separados por coma  |  nombre de usuario para cambio de grupo`n"
$helpM += "-passwords  Lista de contrasenas separadas por coma`n"
$helpM += "-groups     Grupo destino (para opcion 6, 10, 11) o lista separada por coma`n`n"
$helpM += "Ejemplos:`n"
$helpM += "  .\ftp_manager.ps1 -option 7 -no_users 2 -users 'juan,ana' -passwords 'Pass1!,Pass2!'`n"
$helpM += "  .\ftp_manager.ps1 -option 6 -users 'juan' -groups 'Recursadores'`n"
$helpM += "  .\ftp_manager.ps1 -option 8 -users 'juan'`n"

if ($help) { Write-Host $helpM; exit 0 }

$color = "Yellow"

# ============================================================
#  FUNCIONES AUXILIARES (reemplazo de power_fun_par.ps1)
# ============================================================

# Verifica si un string esta vacio o nulo
function validateEmpty {
    param([string]$valor, [string]$nombreCampo = "El campo")
    if ([string]::IsNullOrWhiteSpace($valor)) {
        Write-Host "Error: $nombreCampo no puede estar vacio." -ForegroundColor Red
        exit 1
    }
}

# Verifica que todos los elementos de un array no sean vacios
function validateEmptyArray {
    param([array]$arr)
    foreach ($item in $arr) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            Write-Host "Error: Se encontro un valor vacio en la lista." -ForegroundColor Red
            exit 1
        }
    }
}

# Valida que el nombre de usuario cumpla reglas basicas de Windows
function validateUserName {
    param([string]$nombre)
    if ($nombre.Length -lt 1 -or $nombre.Length -gt 20) {
        Write-Host "Error: El nombre '$nombre' debe tener entre 1 y 20 caracteres." -ForegroundColor Red
        return $false
    }
    # Caracteres prohibidos en nombres de usuario Windows
    $invalidos = '["/\\\[\]:;|=,+*?<>@]'
    if ($nombre -match $invalidos) {
        Write-Host "Error: El nombre '$nombre' contiene caracteres no permitidos." -ForegroundColor Red
        return $false
    }
    if ($script:usuariosSistema -contains $nombre) {
        Write-Host "Error: '$nombre' es un usuario reservado del sistema." -ForegroundColor Red
        return $false
    }
    return $true
}

# Valida que la contrasena cumpla politica minima
function validatePassword {
    param([string]$pass)
    if ($pass.Length -lt 8) {
        Write-Host "Error: La contrasena debe tener al menos 8 caracteres." -ForegroundColor Red
        return $false
    }
    if ($pass -notmatch '[A-Z]') {
        Write-Host "Error: La contrasena debe contener al menos una letra mayuscula." -ForegroundColor Red
        return $false
    }
    if ($pass -notmatch '[a-z]') {
        Write-Host "Error: La contrasena debe contener al menos una letra minuscula." -ForegroundColor Red
        return $false
    }
    if ($pass -notmatch '[0-9]') {
        Write-Host "Error: La contrasena debe contener al menos un numero." -ForegroundColor Red
        return $false
    }
    if ($pass -notmatch '[^a-zA-Z0-9]') {
        Write-Host "Error: La contrasena debe contener al menos un caracter especial (!@#$%...)." -ForegroundColor Red
        return $false
    }
    return $true
}

# Verifica si un usuario local existe
function UserExist {
    param([string]$nombre)
    return ($null -ne (Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue))
}

# Verifica que los usuarios del array NO existan ya (para creacion)
function validateUserCreated {
    param([array]$arr)
    foreach ($u in $arr) {
        $u = $u.Trim()
        if (UserExist -nombre $u) {
            Write-Host "Error: El usuario '$u' ya existe en el sistema." -ForegroundColor Red
            exit 1
        }
    }
}

# ============================================================
#  FUNCION AUXILIAR DE PERMISOS NTFS
# ============================================================
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
    if ($Type -eq "Deny") { $acl.AddAccessRule($rule) }
    else                  { $acl.SetAccessRule($rule) }
    Set-Acl -Path $Path -AclObject $acl
}

# ============================================================
#  OPCION 1 — Verificar servicio
# ============================================================
function checkService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "El servicio FTPSVC NO esta instalado." -ForegroundColor Red
    } else {
        Write-Host "El servicio FTPSVC esta instalado. Estado: $($svc.Status)" -ForegroundColor $color
    }
}

# ============================================================
#  OPCION 2 — Instalar servicio
# ============================================================
function installService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        Write-Host "El servicio FTPSVC ya esta instalado." -ForegroundColor $color
        return
    }
    Write-Host "El servicio FTPSVC no esta instalado." -ForegroundColor Red
    if ($install) {
        Write-Host "Iniciando instalacion..." -ForegroundColor $color
        Install-WindowsFeature -Name Web-Server, Web-FTP-Server, Web-FTP-Ext -IncludeManagementTools
        Write-Host "Instalacion completada correctamente." -ForegroundColor Green
    } else {
        Write-Host "Usa la bandera -install para confirmar la instalacion." -ForegroundColor $color
    }
}

# ============================================================
#  OPCION 3 — Configuracion inicial del sitio FTP
# ============================================================
function configureService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "Error: El servicio FTPSVC no esta instalado. Ejecuta la opcion 2 primero." -ForegroundColor Red
        exit 1
    }

    $Name           = "FTP Service"
    $Ruta           = "C:\FTP"
    $RutaLocalUser  = "$Ruta\LocalUser"
    $CarpetaPublica = "$Ruta\Publica"
    $CarpetaRepro   = "$Ruta\Reprobados"
    $CarpetaRecurs  = "$Ruta\Recursadores"
    $PublicJailPath = "$RutaLocalUser\Public"
    $PublicJunction = "$PublicJailPath\Publica"

    Write-Host "Creando estructura de directorios..." -ForegroundColor Cyan

    foreach ($dir in @($Ruta, $RutaLocalUser, $CarpetaPublica, $CarpetaRepro, $CarpetaRecurs, $PublicJailPath)) {
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    }

    # Junction para usuario anonimo
    if (-not (Test-Path $PublicJunction)) {
        New-Item -ItemType Junction -Path $PublicJunction -Target $CarpetaPublica -Force | Out-Null
    }

    # Limpiar configuracion previa
    icacls $Ruta /reset /T /C /Q > $null 2>&1
    if (Test-Path "$Ruta\web.config") { Remove-Item "$Ruta\web.config" -Force -ErrorAction SilentlyContinue }

    Write-Host "Creando grupos del sistema..." -ForegroundColor Cyan

    $gruposBase = @(
        @{Name="Alumnos";      Desc="Identificador Alumnos"},
        @{Name="Reprobados";   Desc="Grupo Academico"},
        @{Name="Recursadores"; Desc="Grupo Academico"}
    )
    foreach ($g in $gruposBase) {
        if (-not (Get-LocalGroup -Name $g.Name -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $g.Name -Description $g.Desc | Out-Null
            Write-Host "  Grupo '$($g.Name)' creado." -ForegroundColor Yellow
        } else {
            Write-Host "  Grupo '$($g.Name)' ya existe, omitiendo." -ForegroundColor DarkGray
        }
    }

    Write-Host "Configurando IIS / FTP..." -ForegroundColor Cyan
    Import-Module WebAdministration -ErrorAction Stop

    New-WebFtpSite -Name $Name -Port 21 -PhysicalPath $Ruta -Force | Out-Null

    # Autenticacion
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.basicAuthentication.enabled"   -Value $true
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.userIsolation.mode" -Value "IsolateAllDirectories"

    # SSL auto-firmado
    $cert = New-SelfSignedCertificate -DnsName "MiServidorFTP" -CertStoreLocation "cert:\LocalMachine\My"
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.serverCertHash"       -Value $cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslRequire"
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslRequire"

    # Firewall
    if (-not (Get-NetFirewallRule -Name "Regla_FTP_In" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name "Regla_FTP_In" -DisplayName "Permitir FTP (Puerto 21)" `
            -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow | Out-Null
    }

    Write-Host "Configurando reglas de autorizacion IIS..." -ForegroundColor Cyan
    Clear-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -ErrorAction SilentlyContinue
    Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name `
        -Value @{accessType="Allow"; users="?"; permissions="Read"}
    Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name `
        -Value @{accessType="Allow"; roles="Alumnos"; permissions="Read, Write"}

    Write-Host "Aplicando permisos NTFS..." -ForegroundColor Cyan

    # Raiz C:\FTP
    $acl = Get-Acl $Ruta; $acl.SetAccessRuleProtection($true,$false); Set-Acl $Ruta $acl
    Set-NtfsRule $Ruta "Administrators"      "FullControl"
    Set-NtfsRule $Ruta "SYSTEM"              "FullControl"
    Set-NtfsRule $Ruta "IIS_IUSRS"           "ReadAndExecute"
    Set-NtfsRule $Ruta "IUSR"               "ReadAndExecute"
    Set-NtfsRule $Ruta "Authenticated Users" "ReadAndExecute"

    # LocalUser
    Set-NtfsRule $RutaLocalUser "Authenticated Users" "ReadAndExecute"
    Set-NtfsRule $RutaLocalUser "IUSR"               "ReadAndExecute"

    # Jaula anonima
    Set-NtfsRule $PublicJailPath "IUSR" "ReadAndExecute"
    Set-NtfsRule $PublicJunction "IUSR" "ReadAndExecute"

    # Carpeta Publica (todos leen, autenticados modifican)
    $acl = Get-Acl $CarpetaPublica; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaPublica $acl
    Set-NtfsRule $CarpetaPublica "Administrators"      "FullControl"
    Set-NtfsRule $CarpetaPublica "SYSTEM"              "FullControl"
    Set-NtfsRule $CarpetaPublica "IUSR"               "ReadAndExecute"
    Set-NtfsRule $CarpetaPublica "Authenticated Users" "Modify"

    # Carpeta Reprobados
    $acl = Get-Acl $CarpetaRepro; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaRepro $acl
    Set-NtfsRule $CarpetaRepro "Administrators" "FullControl"
    Set-NtfsRule $CarpetaRepro "SYSTEM"         "FullControl"
    Set-NtfsRule $CarpetaRepro "Reprobados"     "Modify"
    Set-NtfsRule $CarpetaRepro "Recursadores"   "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"
    Set-NtfsRule $CarpetaRepro "IUSR"           "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"

    # Carpeta Recursadores
    $acl = Get-Acl $CarpetaRecurs; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaRecurs $acl
    Set-NtfsRule $CarpetaRecurs "Administrators" "FullControl"
    Set-NtfsRule $CarpetaRecurs "SYSTEM"         "FullControl"
    Set-NtfsRule $CarpetaRecurs "Recursadores"   "Modify"
    Set-NtfsRule $CarpetaRecurs "Reprobados"     "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"
    Set-NtfsRule $CarpetaRecurs "IUSR"           "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"

    Restart-WebItem "IIS:\Sites\$Name"
    Write-Host "Configuracion inicial completada con exito." -ForegroundColor Green
}

# ============================================================
#  OPCION 4 — Desinstalar servicio
# ============================================================
function uninstallService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "El servicio FTPSVC no esta instalado." -ForegroundColor Red
        return
    }
    Write-Host "El servicio FTPSVC esta instalado." -ForegroundColor $color
    if ($confirm) {
        Write-Host "Desinstalando..." -ForegroundColor $color
        Uninstall-WindowsFeature -Name Web-FTP-Server, Web-FTP-Ext
        Write-Host "Desinstalacion completada." -ForegroundColor Red
    } else {
        Write-Host "Usa la bandera -confirm para confirmar la desinstalacion." -ForegroundColor $color
    }
}

# ============================================================
#  OPCION 5 — Monitoreo / estatus
# ============================================================
function monitoreo {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "El servicio FTPSVC no esta instalado." -ForegroundColor Red
        return
    }
    Write-Host "`n=== Estado del servicio FTPSVC ===" -ForegroundColor $color
    Get-Service -Name "FTPSVC" | Format-Table -AutoSize

    Write-Host "=== Sitios FTP en IIS ===" -ForegroundColor $color
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Get-WebSite | Where-Object { $_.serverAutoStart -ne $null } | Format-Table Name, State, PhysicalPath -AutoSize
}

# ============================================================
#  OPCION 6 — Cambiar usuario de grupo
# ============================================================
function changeGroup {
    param(
        [string]$usuario,
        [string]$grupoDestino
    )

    $usuario      = $usuario.Trim()
    $grupoDestino = $grupoDestino.Trim()
    $Ruta         = "C:\FTP"
    $RutaUsuario  = "$Ruta\LocalUser\$usuario"

    validateEmpty $usuario      "El parametro -users (usuario)"
    validateEmpty $grupoDestino "El parametro -groups (grupo destino)"

    if (-not (UserExist $usuario)) {
        Write-Host "Error: El usuario '$usuario' no existe." -ForegroundColor Red
        return
    }
    if (-not (Get-LocalGroup -Name $grupoDestino -ErrorAction SilentlyContinue)) {
        Write-Host "Error: El grupo '$grupoDestino' no existe." -ForegroundColor Red
        return
    }
    if ($script:gruposSistema -contains $grupoDestino) {
        Write-Host "Error de seguridad: No puedes mover alumnos a grupos del sistema." -ForegroundColor Red
        return
    }

    # Quitar de grupos academicos anteriores
    $gruposActuales = Get-LocalGroup | Where-Object {
        ($_.Name -notin $script:gruposSistema) -and ($_.Name -ne "Alumnos") -and
        ((Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -match $usuario)
    }

    foreach ($grupoViejo in $gruposActuales) {
        Remove-LocalGroupMember -Group $grupoViejo.Name -Member $usuario -ErrorAction SilentlyContinue
        $rutaTunel = "$RutaUsuario\$($grupoViejo.Name)"
        if (Test-Path $rutaTunel) { Remove-Item -Path $rutaTunel -Recurse -Force -Confirm:$false | Out-Null }
    }

    # Asignar nuevo grupo
    Add-LocalGroupMember -Group $grupoDestino -Member $usuario -ErrorAction SilentlyContinue

    # Crear junction al nuevo grupo
    $rutaNuevaTunel = "$RutaUsuario\$grupoDestino"
    if (-not (Test-Path $rutaNuevaTunel)) {
        New-Item -ItemType Junction -Path $rutaNuevaTunel -Target "$Ruta\$grupoDestino" -Force | Out-Null
    }

    # Reiniciar FTP para aplicar cambios
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -ne $svc) { Restart-Service ftpsvc }

    Write-Host "Usuario '$usuario' movido al grupo '$grupoDestino' correctamente." -ForegroundColor Green
}

# ============================================================
#  OPCION 7 — Crear alumno(s)
# ============================================================
function crearAlumno {
    $Ruta          = "C:\FTP"
    $RutaLocalUser = "$Ruta\LocalUser"

    $arrUsers  = $users     -split ","
    $arrPasswd = $passwords -split ","

    if ($arrUsers.Length -ne $no_users -or $arrPasswd.Length -ne $no_users) {
        Write-Host "Error: El numero de usuarios y contrasenas debe coincidir con -no_users ($no_users)." -ForegroundColor Red
        exit 1
    }

    validateEmptyArray $arrUsers
    validateEmptyArray $arrPasswd
    validateUserCreated $arrUsers

    if (-not (Test-Path $RutaLocalUser)) { New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null }

    for ($i = 0; $i -lt $no_users; $i++) {
        $uActual = $arrUsers[$i].Trim()
        $pActual = $arrPasswd[$i].Trim()

        if (-not (validateUserName $uActual)) { exit 1 }
        if (-not (validatePassword  $pActual)) { exit 1 }

        Write-Host "Creando usuario '$uActual'..." -ForegroundColor Cyan

        $secPass = ConvertTo-SecureString -String $pActual -AsPlainText -Force
        New-LocalUser -Name $uActual -Description "Alumno" -Password $secPass -PasswordNeverExpires | Out-Null
        Add-LocalGroupMember -Group "Alumnos" -Member $uActual -ErrorAction SilentlyContinue

        if (-not (UserExist $uActual)) {
            Write-Host "Error critico: No se pudo crear el usuario '$uActual'." -ForegroundColor Red
            exit 1
        }

        $RutaUsuario = "$RutaLocalUser\$uActual"
        if (-not (Test-Path $RutaUsuario)) { New-Item -Path $RutaUsuario -ItemType Directory -Force | Out-Null }

        # ── Resetear y configurar herencia ──────────────────────────────────────
        @($RutaUsuario) + (Get-ChildItem $RutaUsuario -Recurse -Force -ErrorAction SilentlyContinue).FullName |
        ForEach-Object {
            $r = $_
            $a = Get-Acl $r
            $a.SetAccessRuleProtection($false, $false)
            $a.Access | ForEach-Object { $a.RemoveAccessRule($_) } | Out-Null
            Set-Acl -Path $r -AclObject $a
        }

        $acl = Get-Acl $RutaUsuario
        $acl.SetAccessRuleProtection($true, $false)   # Romper herencia
        Set-Acl -Path $RutaUsuario -AclObject $acl

        # Permisos base de la jaula
        Set-NtfsRule $RutaUsuario "Administrators"      "FullControl"
        Set-NtfsRule $RutaUsuario "SYSTEM"              "FullControl"
        Set-NtfsRule $RutaUsuario "Authenticated Users" "ReadAndExecute"

        # Candado: no puede borrar la raiz de su jaula
        $aclDeny = Get-Acl $RutaUsuario
        $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users",
            [System.Security.AccessControl.FileSystemRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            "Deny")
        $aclDeny.AddAccessRule($denyRule)
        Set-Acl -Path $RutaUsuario -AclObject $aclDeny

        # Junction a carpeta publica
        if (-not (Test-Path "$RutaUsuario\Publica")) {
            New-Item -ItemType Junction -Path "$RutaUsuario\Publica" -Target "$Ruta\Publica" -Force | Out-Null
        }

        # Carpeta personal del alumno (puede modificar, no puede borrarla)
        $carpetaPersonal = "$RutaUsuario\$uActual"
        if (-not (Test-Path $carpetaPersonal)) {
            New-Item -ItemType Directory -Path $carpetaPersonal -Force | Out-Null
        }

        Set-NtfsRule $carpetaPersonal "Administrators"      "FullControl"
        Set-NtfsRule $carpetaPersonal "SYSTEM"              "FullControl"
        Set-NtfsRule $carpetaPersonal "Authenticated Users" "Modify"

        $aclDenyP = Get-Acl $carpetaPersonal
        $denyRuleP = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users",
            [System.Security.AccessControl.FileSystemRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            "Deny")
        $aclDenyP.AddAccessRule($denyRuleP)
        Set-Acl -Path $carpetaPersonal -AclObject $aclDenyP

        Write-Host "  Usuario '$uActual' creado correctamente." -ForegroundColor Green
    }

    Write-Host "Proceso de creacion de alumno(s) finalizado." -ForegroundColor Green
}

# ============================================================
#  OPCION 8 — Eliminar alumno
# ============================================================
function deleteUser {
    param([string]$nombre)
    $nombre = $nombre.Trim()

    if ($script:usuariosSistema -contains $nombre) {
        Write-Host "Error: '$nombre' es un usuario del sistema y no puede eliminarse." -ForegroundColor Red
        exit 1
    }

    $usr = Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue |
           Where-Object { $_.Description -eq "Alumno" }

    if ($null -eq $usr) {
        Write-Host "No se encontro un alumno con el nombre '$nombre'." -ForegroundColor Red
        exit 1
    }

    # Eliminar carpeta de la jaula
    $rutaJaula = "C:\FTP\LocalUser\$nombre"
    if (Test-Path $rutaJaula) {
        icacls $rutaJaula /reset /T /C /Q > $null
        Remove-Item -Path $rutaJaula -Recurse -Force -Confirm:$false | Out-Null
    }

    Remove-LocalUser -Name $nombre -ErrorAction SilentlyContinue

    if (UserExist $nombre) {
        Write-Host "Error: No se pudo eliminar el usuario '$nombre'." -ForegroundColor Red
    } else {
        Write-Host "Usuario '$nombre' eliminado correctamente." -ForegroundColor Green
    }
}

# ============================================================
#  OPCION 9 — Consultar alumnos
# ============================================================
function consultarAlumnos {
    Write-Host "`n--- Listado de Alumnos ---" -ForegroundColor Cyan
    $lista = Get-LocalUser | Where-Object { $_.Description -eq "Alumno" }
    if ($lista) {
        $lista | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize
    } else {
        Write-Host "No hay alumnos registrados." -ForegroundColor Yellow
    }
}

# ============================================================
#  OPCION 10 — Crear grupo academico
# ============================================================
function crearGrupo {
    param([string]$nombreGrupo, [string]$descripcion)
    $nombreGrupo = $nombreGrupo.Trim()

    validateEmpty $nombreGrupo "El parametro -groups (nombre de grupo)"

    if ($script:gruposSistema -contains $nombreGrupo) {
        Write-Host "Error: '$nombreGrupo' es un nombre reservado del sistema." -ForegroundColor Red
        return
    }
    if (Get-LocalGroup -Name $nombreGrupo -ErrorAction SilentlyContinue) {
        Write-Host "El grupo '$nombreGrupo' ya existe." -ForegroundColor Yellow
        return
    }

    $rutaGrupo = "C:\FTP\$nombreGrupo"

    New-LocalGroup -Name $nombreGrupo -Description $descripcion | Out-Null

    if (-not (Test-Path $rutaGrupo)) { New-Item -Path $rutaGrupo -ItemType Directory -Force | Out-Null }

    # Permisos de la carpeta del grupo
    $acl = Get-Acl $rutaGrupo
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl $rutaGrupo $acl

    Set-NtfsRule $rutaGrupo "Administrators" "FullControl"
    Set-NtfsRule $rutaGrupo "SYSTEM"         "FullControl"
    Set-NtfsRule $rutaGrupo $nombreGrupo     "Modify"

    # Denegar acceso al resto de alumnos (IUSR y usuarios no miembros no pueden leer)
    Set-NtfsRule $rutaGrupo "IUSR" "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"

    Write-Host "Grupo academico '$nombreGrupo' creado correctamente." -ForegroundColor Green
}

# ============================================================
#  OPCION 11 — Eliminar grupo academico
# ============================================================
function deleteGroup {
    param([string]$nombre, [string]$descripcion)
    $nombre = $nombre.Trim()

    if ($script:gruposSistema -contains $nombre) {
        Write-Host "Error: '$nombre' es un grupo del sistema." -ForegroundColor Red
        return
    }

    $grp = Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue |
           Where-Object { $_.Description -eq $descripcion }

    if ($null -eq $grp) {
        Write-Host "No se encontro un grupo llamado '$nombre' con descripcion '$descripcion'." -ForegroundColor Yellow
        return
    }

    # Eliminar junctions en las jaulas de los miembros
    Write-Host "Limpiando referencias de usuarios miembros..." -ForegroundColor Cyan
    $miembros = Get-LocalGroupMember -Group $nombre -ErrorAction SilentlyContinue
    foreach ($m in $miembros) {
        $mNombre     = $m.Name.Split('\')[-1]
        $rutaJuncion = "C:\FTP\LocalUser\$mNombre\$nombre"
        if (Test-Path $rutaJuncion) {
            Remove-Item -Path $rutaJuncion -Recurse -Force -Confirm:$false | Out-Null
        }
    }

    # Eliminar carpeta raiz del grupo
    $rutaGrupo = "C:\FTP\$nombre"
    if (Test-Path $rutaGrupo) {
        Remove-Item -Path $rutaGrupo -Recurse -Force -Confirm:$false | Out-Null
    }

    Remove-LocalGroup -Name $nombre

    if (Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue) {
        Write-Host "Error: No se pudo eliminar el grupo '$nombre'." -ForegroundColor Red
    } else {
        Write-Host "Grupo '$nombre' eliminado correctamente." -ForegroundColor Green
    }
}

# ============================================================
#  OPCION 12 — Consultar grupos academicos
# ============================================================
function consultarGrupos {
    Write-Host "`n--- Grupos Academicos ---" -ForegroundColor Cyan
    $lista = Get-LocalGroup | Where-Object { $_.Description -eq "Grupo Academico" }
    if ($lista) {
        $lista | Select-Object Name, Description | Format-Table -AutoSize
    } else {
        Write-Host "No hay grupos academicos registrados." -ForegroundColor Yellow
    }
}

# ============================================================
#  SWITCH PRINCIPAL
# ============================================================
switch ($option) {
    "1"  { checkService;                                              break }
    "2"  { installService;                                            break }
    "3"  { configureService;                                          break }
    "4"  { uninstallService;                                          break }
    "5"  { monitoreo;                                                 break }
    "6"  { changeGroup -usuario $users -grupoDestino $groups;         break }
    "7"  { crearAlumno;                                               break }
    "8"  { deleteUser -nombre $users;                                 break }
    "9"  { consultarAlumnos;                                          break }
    "10" { crearGrupo -nombreGrupo $groups -descripcion "Grupo Academico"; break }
    "11" { deleteGroup -nombre $groups -descripcion "Grupo Academico"; break }
    "12" { consultarGrupos;                                           break }
    default {
        Write-Host "Opcion invalida. Usa -help para ver las opciones disponibles." -ForegroundColor Red
    }
}
