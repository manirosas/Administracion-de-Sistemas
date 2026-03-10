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
    "Access Control Assistance Operators", "Administrators", "Backup Operators",
    "Certificate Service DCOM Access", "Cryptographic Operators", "Device Owners",
    "Distributed COM Users", "Event Log Readers", "Guests", "Hyper-V Administrators",
    "IIS_IUSRS", "Network Configuration Operators", "Performance Log Users",
    "Performance Monitor Users", "Power Users", "Print Operators", "RDS Endpoint Servers",
    "RDS Management Servers", "RDS Remote Access Servers", "Remote Desktop Users",
    "Remote Management Users", "Replicator", "Storage Replica Administrators",
    "System Managed Accounts Group", "Users"
)

$script:usuariosSistema = @(
    "Administrator",
    "Guest",
    "DefaultAccount",
    "WDAGUtilityAccount",
    "IUSR",
    "utilityaccount"
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
$helpM += "-groups     Grupo destino (opcion 6, 10, 11)`n`n"
$helpM += "Ejemplos:`n"
$helpM += "  .\ftp_manager.ps1 -option 7 -no_users 2 -users 'juan,ana' -passwords 'Pass1!,Pass2!'`n"
$helpM += "  .\ftp_manager.ps1 -option 6 -users 'juan' -groups 'Recursadores'`n"
$helpM += "  .\ftp_manager.ps1 -option 8 -users 'juan'`n"

if ($help) { Write-Host $helpM; exit 0 }

$color = "Yellow"

# ============================================================
#  FUNCIONES DE VALIDACION (power_fun_par.ps1 — integradas)
# ============================================================

function validateEmpty {
    param ([string]$value, [string]$var)
    $value = $value.Trim()
    if ($value -eq "") {
        Write-Host "`nSe ha detectado un espacio vacio, saliendo del programa (variable: '$var')" -ForegroundColor Red
        exit 1
    }
}


function validateEmptyArray {
    param ([array]$array)
    foreach ($element in $array) {
        if ($element.Trim() -eq "") {
            Write-Host "Se ha detectado un valor vacio en el arreglo" -ForegroundColor Red
            exit 1
        }
    }
}


function UserExist {
    param ([string]$nombre)
    $nombre = $nombre.Trim()
    return ($null -ne (Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue))
}

function validateUserCreated {
    param ([array]$array)
    foreach ($element in $array) {
        $element = $element.Trim()
        if (UserExist $element) {
            Write-Host "Se ha encontrado que el usuario '$element' ya ha sido creado" -ForegroundColor Red
            exit 1
        }
    }
}

function validateUserName {
    param ([string]$userName)
    if ($userName.Length -lt 3 -or $userName.Length -gt 20) {
        Write-Host "Error: El usuario '$userName' debe tener entre 3 y 20 caracteres." -ForegroundColor Red
        return $false
    }
    if ($userName -match '[\\/\[\]:;|=,+*?<>]') {
        Write-Host "Error: El usuario '$userName' contiene caracteres no permitidos." -ForegroundColor Red
        return $false
    }
    return $true
}

function validatePassword {
    param ([string]$password)
    $isStrong = $true; $msg = ""
    if ($password.Length -lt 8)     { $isStrong = $false; $msg += " - Minimo 8 caracteres.`n" }
    if ($password -notmatch '[A-Z]') { $isStrong = $false; $msg += " - Al menos una mayuscula.`n" }
    if ($password -notmatch '[0-9]') { $isStrong = $false; $msg += " - Al menos un numero.`n" }
    if ($password -notmatch '[\W_]') { $isStrong = $false; $msg += " - Al menos un caracter especial.`n" }
    if (-not $isStrong) {
        Write-Host "Contrasena invalida. Debe cumplir:`n$msg" -ForegroundColor Red
        return $false
    }
    return $true
}

# ============================================================
# OPCION 10 — Crear grupo academico
# ============================================================
function crearGrupo {
    param ([string]$nombreGrupo, [string]$descripcion)
    $nombreGrupo = $nombreGrupo.Trim()

    if ($script:gruposSistema -contains $nombreGrupo) {
        Write-Host "Error: No puedes crear el grupo '$nombreGrupo' porque es un grupo reservado del sistema." -ForegroundColor Red
        return $false
    }
    if ($null -ne (Get-LocalGroup -Name $nombreGrupo -ErrorAction SilentlyContinue)) {
        Write-Host "Aviso: El grupo '$nombreGrupo' ya existe en el servidor." -ForegroundColor Yellow
        return $false
    }

    New-LocalGroup -Name $nombreGrupo -Description $descripcion | Out-Null

    $rutaDirectorio = "C:\FTP\$nombreGrupo"
    if (-not (Test-Path $rutaDirectorio)) { New-Item -Path $rutaDirectorio -ItemType Directory -Force | Out-Null }

    icacls $rutaDirectorio /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "${nombreGrupo}:(OI)(CI)M" /grant "Authenticated Users:(OI)(CI)M" /T /C /Q > $null 2>&1
    icacls $rutaDirectorio /deny "IUSR:(OI)(CI)F" /T /C /Q > $null 2>&1

    Write-Host "El grupo '$nombreGrupo' y su carpeta han sido creados correctamente!" -ForegroundColor Green
    return $true
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
        Write-Host "Se ha detectado que no se tiene instalado el servicio FTPSVC" -ForegroundColor Red
    } else {
        Write-Host "Se ha detectado el servicio FTPSVC instalado. Estado: $($svc.Status)" -ForegroundColor $color
    }
}

# ============================================================
#  OPCION 2 — Instalar servicio
# ============================================================
function installService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        Write-Host "Se ha detectado el servicio FTPSVC instalado" -ForegroundColor $color
        return
    }
    Write-Host "Se ha detectado que no se tiene instalado el FTPSVC Server" -ForegroundColor Red
    if ($install) {
        Write-Host "Iniciando instalacion..." -ForegroundColor $color
        Install-WindowsFeature -Name Web-Server, Web-FTP-Server, Web-FTP-Ext -IncludeManagementTools
        Write-Host "La instalacion ha finalizado correctamente" -ForegroundColor Green
    } else {
        Write-Host "Use la bandera -install para activar la instalacion" -ForegroundColor $color
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

    Write-Host "Preparando estructura de directorios..." -ForegroundColor Cyan

    foreach ($dir in @($Ruta, $RutaLocalUser, $CarpetaPublica, $CarpetaRepro, $CarpetaRecurs, $PublicJailPath)) {
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    }
    if (-not (Test-Path $PublicJunction)) {
        New-Item -ItemType Junction -Path $PublicJunction -Target $CarpetaPublica -Force | Out-Null
    }

    icacls $Ruta /reset /T /C /Q > $null 2>&1
    if (Test-Path "$Ruta\web.config") { Remove-Item "$Ruta\web.config" -Force -ErrorAction SilentlyContinue }

    Write-Host "Creando grupos base del sistema..." -ForegroundColor Cyan
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

    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.basicAuthentication.enabled"   -Value $true
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.userIsolation.mode" -Value "IsolateAllDirectories"

    $cert = New-SelfSignedCertificate -DnsName "MiServidorFTP" -CertStoreLocation "cert:\LocalMachine\My"
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.serverCertHash"       -Value $cert.Thumbprint
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.dataChannelPolicy"    -Value "SslAllow"

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

    $acl = Get-Acl $Ruta; $acl.SetAccessRuleProtection($true,$false); Set-Acl $Ruta $acl
    Set-NtfsRule $Ruta "Administrators"      "FullControl"
    Set-NtfsRule $Ruta "SYSTEM"              "FullControl"
    Set-NtfsRule $Ruta "IIS_IUSRS"           "ReadAndExecute"
    Set-NtfsRule $Ruta "IUSR"               "ReadAndExecute"
    Set-NtfsRule $Ruta "Authenticated Users" "ReadAndExecute"

    Set-NtfsRule $RutaLocalUser "Authenticated Users" "ReadAndExecute"
    Set-NtfsRule $RutaLocalUser "IUSR"               "ReadAndExecute"
    Set-NtfsRule $PublicJailPath "IUSR" "ReadAndExecute"
    Set-NtfsRule $PublicJunction "IUSR" "ReadAndExecute"

    $acl = Get-Acl $CarpetaPublica; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaPublica $acl
    Set-NtfsRule $CarpetaPublica "Administrators"      "FullControl"
    Set-NtfsRule $CarpetaPublica "SYSTEM"              "FullControl"
    Set-NtfsRule $CarpetaPublica "IUSR"               "ReadAndExecute"
    Set-NtfsRule $CarpetaPublica "Authenticated Users" "Modify"

    $acl = Get-Acl $CarpetaRepro; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaRepro $acl
    Set-NtfsRule $CarpetaRepro "Administrators" "FullControl"
    Set-NtfsRule $CarpetaRepro "SYSTEM"         "FullControl"
    Set-NtfsRule $CarpetaRepro "Reprobados"     "Modify"
    Set-NtfsRule $CarpetaRepro "Recursadores"   "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"
    Set-NtfsRule $CarpetaRepro "IUSR"           "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"

    $acl = Get-Acl $CarpetaRecurs; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaRecurs $acl
    Set-NtfsRule $CarpetaRecurs "Administrators" "FullControl"
    Set-NtfsRule $CarpetaRecurs "SYSTEM"         "FullControl"
    Set-NtfsRule $CarpetaRecurs "Recursadores"   "Modify"
    Set-NtfsRule $CarpetaRecurs "Reprobados"     "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"
    Set-NtfsRule $CarpetaRecurs "IUSR"           "FullControl" "ContainerInherit,ObjectInherit" "None" "Deny"

    Restart-WebItem "IIS:\Sites\$Name"
    Write-Host "Configuracion completada con exito." -ForegroundColor Green
}

# ============================================================
#  OPCION 4 — Desinstalar servicio
# ============================================================
function uninstallService {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "Se ha detectado que no se tiene instalado el servicio FTPSVC" -ForegroundColor Red
        return
    }
    Write-Host "Se ha detectado el servicio FTPSVC instalado" -ForegroundColor $color
    if ($confirm) {
        Write-Host "Iniciando desinstalacion..." -ForegroundColor $color
        Uninstall-WindowsFeature -Name Web-FTP-Server, Web-FTP-Ext
        Write-Host "La desinstalacion ha finalizado correctamente" -ForegroundColor Red
    } else {
        Write-Host "Use la bandera -confirm para confirmar la desinstalacion" -ForegroundColor $color
    }
}

# ============================================================
#  OPCION 5 — Monitoreo / estatus
# ============================================================
function monitoreo {
    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Host "Se ha detectado que no se tiene instalado el servicio FTPSVC" -ForegroundColor Red
        return
    }
    Write-Host "`n=== Estado del servicio ===" -ForegroundColor $color
    Get-Service -Name "FTPSVC" | Format-Table -AutoSize
}

# ============================================================
#  OPCION 6 — Cambiar usuario de grupo
# ============================================================
function changeGroup {
    param ([string]$usuario, [string]$grupoDestino)

    $usuario      = $usuario.Trim()
    $grupoDestino = $grupoDestino.Trim()
    $Ruta         = "C:\FTP"
    $RutaUsuario  = "$Ruta\LocalUser\$usuario"

    validateEmpty $usuario      "users"
    validateEmpty $grupoDestino "groups"

    if (-not (UserExist $usuario)) {
        Write-Host "Error: El usuario '$usuario' no existe en el sistema." -ForegroundColor Red
        return
    }
    if (-not (Get-LocalGroup -Name $grupoDestino -ErrorAction SilentlyContinue)) {
        Write-Host "Error: El grupo academico '$grupoDestino' no existe." -ForegroundColor Red
        return
    }
    if ($script:gruposSistema -contains $grupoDestino) {
        Write-Host "Error de seguridad: No puedes mover alumnos a grupos del sistema ($grupoDestino)." -ForegroundColor Red
        return
    }

    $gruposActuales = Get-LocalGroup | Where-Object {
        ($_.Name -notin $script:gruposSistema) -and ($_.Name -ne "Alumnos") -and
        ((Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -match $usuario)
    }
    foreach ($grupoViejo in $gruposActuales) {
        Remove-LocalGroupMember -Group $grupoViejo.Name -Member $usuario -ErrorAction SilentlyContinue
        $rutaTunel = "$RutaUsuario\$($grupoViejo.Name)"
        if (Test-Path $rutaTunel) { Remove-Item -Path $rutaTunel -Recurse -Force -Confirm:$false | Out-Null }
    }

    Add-LocalGroupMember -Group $grupoDestino -Member $usuario -ErrorAction SilentlyContinue

    $rutaNuevaTunel = "$RutaUsuario\$grupoDestino"
    if (-not (Test-Path $rutaNuevaTunel)) {
        New-Item -ItemType Junction -Path $rutaNuevaTunel -Target "$Ruta\$grupoDestino" -Force | Out-Null
    }

    $svc = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
    if ($null -ne $svc) { Restart-Service ftpsvc }

    Write-Host "Se ha cambiado al usuario '$usuario' al grupo '$grupoDestino' con exito" -ForegroundColor Green
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
        Write-Host "El numero de usuarios y contrasenas debe coincidir con -no_users ($no_users)." -ForegroundColor Red
        exit 1
    }

    validateEmptyArray $arrUsers
    validateEmptyArray $arrPasswd
    validateUserCreated $arrUsers
    validateUsernameArray $arrUsers

    if (-not (Test-Path $RutaLocalUser)) { New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null }

    for ($i = 0; $i -lt $no_users; $i++) {
        $uActual = $arrUsers[$i].Trim()
        $pActual = $arrPasswd[$i].Trim()

        if (-not (validatePassword $pActual)) { exit 1 }

        Write-Host "Creando usuario '$uActual'..." -ForegroundColor Cyan

        $secPass = ConvertTo-SecureString -String $pActual -AsPlainText -Force
        New-LocalUser -Name $uActual -Description "Alumno" -Password $secPass -PasswordNeverExpires | Out-Null
        Add-LocalGroupMember -Group "Alumnos" -Member $uActual -ErrorAction SilentlyContinue

        if (-not (UserExist $uActual)) {
            Write-Host "No se ha detectado el registro del usuario '$uActual', abortando..." -ForegroundColor Red
            exit 1
        }

        $RutaUsuario = "$RutaLocalUser\$uActual"
        if (-not (Test-Path $RutaUsuario)) { New-Item -Path $RutaUsuario -ItemType Directory -Force | Out-Null }

        # Resetear herencia en todo el arbol
        @($RutaUsuario) + @((Get-ChildItem $RutaUsuario -Recurse -Force -ErrorAction SilentlyContinue).FullName) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object {
            $r = $_
            $a = Get-Acl $r
            $a.SetAccessRuleProtection($false, $false)
            $a.Access | ForEach-Object { $a.RemoveAccessRule($_) } | Out-Null
            Set-Acl -Path $r -AclObject $a
        }

        $acl = Get-Acl $RutaUsuario
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl -Path $RutaUsuario -AclObject $acl

        Set-NtfsRule $RutaUsuario "Administrators"      "FullControl"
        Set-NtfsRule $RutaUsuario "SYSTEM"              "FullControl"
        Set-NtfsRule $RutaUsuario "Authenticated Users" "ReadAndExecute"

        # Candado: no puede borrar la raiz de la jaula
        $aclDeny = Get-Acl $RutaUsuario
        $aclDeny.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users",
            [System.Security.AccessControl.FileSystemRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            "Deny")))
        Set-Acl -Path $RutaUsuario -AclObject $aclDeny

        # Junction a carpeta publica
        if (-not (Test-Path "$RutaUsuario\Publica")) {
            New-Item -ItemType Junction -Path "$RutaUsuario\Publica" -Target "$Ruta\Publica" -Force | Out-Null
        }

        # Carpeta personal (puede modificar, no puede borrarla)
        $carpetaPersonal = "$RutaUsuario\$uActual"
        if (-not (Test-Path $carpetaPersonal)) {
            New-Item -ItemType Directory -Path $carpetaPersonal -Force | Out-Null
        }

        Set-NtfsRule $carpetaPersonal "Administrators"      "FullControl"
        Set-NtfsRule $carpetaPersonal "SYSTEM"              "FullControl"
        Set-NtfsRule $carpetaPersonal "Authenticated Users" "Modify"

        $aclDenyP = Get-Acl $carpetaPersonal
        $aclDenyP.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Authenticated Users",
            [System.Security.AccessControl.FileSystemRights]::Delete,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            "Deny")))
        Set-Acl -Path $carpetaPersonal -AclObject $aclDenyP

        Write-Host "  Usuario '$uActual' creado correctamente." -ForegroundColor Green
    }

    Write-Host "Se ha terminado de anadir a el/los usuario(s) correctamente." -ForegroundColor Green
}

# ============================================================
#  OPCION 8 — Eliminar alumno
# ============================================================
function deleteUser {
    param ([string]$nombre)
    $nombre = $nombre.Trim()

    if ($script:usuariosSistema -contains $nombre) {
        Write-Host "Se ha detectado que el usuario es un usuario del sistema" -ForegroundColor Red
        exit 1
    }

    $usr = Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue |
           Where-Object { $_.Description -eq "Alumno" }

    if ($null -eq $usr) {
        Write-Host "No se ha encontrado al usuario con ese nombre y descripcion" -ForegroundColor Red
        exit 1
    }

    $rutaJaula = "C:\FTP\LocalUser\$nombre"
    if (Test-Path $rutaJaula) {
        icacls $rutaJaula /reset /T /C /Q > $null
        Remove-Item -Path $rutaJaula -Recurse -Force -Confirm:$false | Out-Null
    }

    Remove-LocalUser -Name $nombre -ErrorAction SilentlyContinue

    if (UserExist $nombre) {
        Write-Host "No se ha eliminado el usuario correctamente" -ForegroundColor Red
    } else {
        Write-Host "Se ha eliminado el usuario correctamente" -ForegroundColor Green
    }
}

# ============================================================
#  OPCION 9 — Consultar alumnos
# ============================================================
function consultarAlumnos {
    Write-Host "`n--- Listado Oficial de Alumnos (FTP) ---" -ForegroundColor Cyan
    $lista = Get-LocalUser | Where-Object { $_.Description -eq "Alumno" }
    if ($lista) {
        $lista | Select-Object Name, Description, Enabled | Format-Table -AutoSize
    } else {
        Write-Host "No hay alumnos registrados." -ForegroundColor Yellow
    }
}

# ============================================================
#  OPCION 10 — Crear grupo academico  (funcion original de power_fun_par.ps1)
# ============================================================
# (ya definida arriba como crearGrupo, se llama directamente en el switch)

# ============================================================
#  OPCION 11 — Eliminar grupo academico
# ============================================================
function deleteGroup {
    param ([string]$nombre, [string]$descripcion)
    $nombre = $nombre.Trim()

    if ($script:gruposSistema -contains $nombre) {
        Write-Host "Se ha detectado que el grupo es un grupo del sistema" -ForegroundColor Red
        return
    }

    $grp = Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue |
           Where-Object { $_.Description -eq $descripcion }

    if ($null -eq $grp) {
        Write-Host "No se encontro un grupo llamado '$nombre' con la descripcion '$descripcion'" -ForegroundColor Yellow
        return
    }

    Write-Host "Limpiando carpetas de usuarios miembros de '$nombre'..." -ForegroundColor Cyan
    $miembros = Get-LocalGroupMember -Group $nombre -ErrorAction SilentlyContinue
    foreach ($m in $miembros) {
        $mNombre     = $m.Name.Split('\')[-1]
        $rutaJuncion = "C:\FTP\LocalUser\$mNombre\$nombre"
        if (Test-Path $rutaJuncion) {
            Remove-Item -Path $rutaJuncion -Recurse -Force -Confirm:$false | Out-Null
        }
    }

    if (Test-Path "C:\FTP\$nombre") {
        Remove-Item -Path "C:\FTP\$nombre" -Recurse -Force -Confirm:$false | Out-Null
    }

    Remove-LocalGroup -Name $nombre

    if ($null -ne (Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue)) {
        Write-Host "No se ha eliminado el grupo correctamente" -ForegroundColor Red
    } else {
        Write-Host "Se ha eliminado el grupo '$nombre' y sus subcarpetas correctamente" -ForegroundColor Green
    }
}

# ============================================================
#  OPCION 12 — Consultar grupos academicos
# ============================================================
function consultarGrupos {
    Write-Host "`n--- Grupos Academicos del Servidor ---" -ForegroundColor Cyan
    $lista = Get-LocalGroup | Where-Object { $_.Description -eq "Grupo Academico" }
    if ($lista) {
        $lista | Select-Object Name, Description | Format-Table -AutoSize
    } else {
        Write-Host "No hay grupos academicos registrados." -ForegroundColor Yellow
    }
}

# ============================================================
# ============================================================
#  MODO INTERACTIVO — ciclo continuo si no se pasa -option
# ============================================================
if ([string]::IsNullOrWhiteSpace($option)) {
    do {
        # Resetear variables en cada iteracion
        $users = ""; $passwords = ""; $groups = ""; $no_users = 0
        $install = $false; $confirm = $false

        Write-Host "`n╔══════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║       ADMINISTRADOR SERVIDOR FTP     ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  --- Servicio ---" -ForegroundColor Yellow
        Write-Host "  1)  Verificar servicio FTP"
        Write-Host "  2)  Instalar servicio FTP"
        Write-Host "  3)  Configuracion inicial (ejecutar tras instalar)"
        Write-Host "  4)  Desinstalar servicio FTP"
        Write-Host "  5)  Estatus del servicio"
        Write-Host ""
        Write-Host "  --- Usuarios ---" -ForegroundColor Yellow
        Write-Host "  6)  Mover usuario a un grupo"
        Write-Host "  7)  Agregar alumno(s)"
        Write-Host "  8)  Eliminar alumno"
        Write-Host "  9)  Consultar alumnos"
        Write-Host ""
        Write-Host "  --- Grupos ---" -ForegroundColor Yellow
        Write-Host "  10) Agregar grupo academico"
        Write-Host "  11) Eliminar grupo academico"
        Write-Host "  12) Consultar grupos academicos"
        Write-Host ""
        Write-Host "  0)  Salir" -ForegroundColor Red
        Write-Host ""

        $opMenu = (Read-Host "  Selecciona una opcion").Trim()

        if ($opMenu -eq "0") {
            Write-Host "`nHasta luego." -ForegroundColor Cyan
            exit 0
        }

        # Pedir parametros adicionales segun la opcion
        switch ($opMenu) {
            "2"  { $install = $true }
            "4"  { $confirm = $true }
            "6"  {
                $users  = (Read-Host "  Nombre del usuario a mover").Trim()
                consultarGrupos
                $groups = (Read-Host "  Nombre del grupo destino").Trim()
            }
            "7"  {
                $no_users  = [int](Read-Host "  Cuantos alumnos deseas registrar")
                $users     = (Read-Host "  Nombres separados por coma (ej: juan,ana)").Trim()
                $passwords = (Read-Host "  Contrasenas separadas por coma (ej: Pass1!,Pass2!)").Trim()
            }
            "8"  {
                consultarAlumnos
                $users = (Read-Host "  Nombre del alumno a eliminar").Trim()
            }
            "10" { $groups = (Read-Host "  Nombre del nuevo grupo academico").Trim() }
            "11" {
                consultarGrupos
                $groups = (Read-Host "  Nombre del grupo a eliminar").Trim()
            }
        }

        # Ejecutar la opcion elegida
        switch ($opMenu) {
            "1"  { checkService }
            "2"  { installService }
            "3"  { configureService }
            "4"  { uninstallService }
            "5"  { monitoreo }
            "6"  { changeGroup -usuario $users -grupoDestino $groups }
            "7"  { crearAlumno }
            "8"  { deleteUser -nombre $users }
            "9"  { consultarAlumnos }
            "10" { crearGrupo  -nombreGrupo $groups -descripcion "Grupo Academico" }
            "11" { deleteGroup -nombre $groups -descripcion "Grupo Academico" }
            "12" { consultarGrupos }
            default { Write-Host "Opcion invalida, intenta de nuevo." -ForegroundColor Red }
        }

        Write-Host ""
        Read-Host "  Presiona Enter para continuar"

    } while ($true)
}

# ============================================================
#  MODO PARAMETROS — ejecucion directa con -option
# ============================================================
switch ($option) {
    "1"  { checkService;                                                    break }
    "2"  { installService;                                                  break }
    "3"  { configureService;                                                break }
    "4"  { uninstallService;                                                break }
    "5"  { monitoreo;                                                       break }
    "6"  { changeGroup -usuario $users -grupoDestino $groups;               break }
    "7"  { crearAlumno;                                                     break }
    "8"  { deleteUser -nombre $users;                                       break }
    "9"  { consultarAlumnos;                                                break }
    "10" { crearGrupo  -nombreGrupo $groups -descripcion "Grupo Academico"; break }
    "11" { deleteGroup -nombre $groups -descripcion "Grupo Academico";      break }
    "12" { consultarGrupos;                                                 break }
    default {
        Write-Host "Se ha detectado una opcion invalida, vuelve a intentarlo" -ForegroundColor Red
    }
}
