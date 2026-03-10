param (
    [string] $option,
    [switch] $install,
    [switch] $help,
    [switch] $confirm,
    [int] $no_users,
    [array] $users,
    [array] $passwords,
    [array] $groups
)

. ../Funciones/power_fun_par.ps1


$helpM="--- Opciones ---`n`n"
$helpM="${helpM}1) Verificar existencia del servicio FTP`n"
$helpM="${helpM}2) Instalar servicio FTP`n"
$helpM="${helpM}3) Crear sitio ftp, grupos reprobados y recursadores (configuracion inicial) (IMPORTANTE despues de instalar el servicio)`n"
$helpM="${helpM}4) Desinstalar servicio FTP`n" # Verificar sintaxis y ver estado del servicio
$helpM="${helpM}5) Estatus servicio FTP`n"
$helpM="${helpM}6) Seleccionar usuario para colocarlo en un grupo`n`n"
$helpM="${helpM}--- ABC Usuarios ---`n`n"
$helpM="${helpM}7) Agregar usuario`n"
$helpM="${helpM}8) Eliminar usuario`n"
$helpM="${helpM}9) Consultar usuario`n`n"
$helpM="${helpM}--- ABC Grupos ---`n`n"
$helpM="${helpM}10) Agregar grupo`n`n"
$helpM="${helpM}11) Eliminar grupo`n`n"
$helpM="${helpM}12) Consultar grupos existentes`n`n"
$helpM="${helpM}--- Banderas ---`n`n"
$helpM="${helpM}-help (mostrar este mensaje)`n"
$helpM="${helpM}-option (seleccionar opcion)`n"
$helpM="${helpM}-confirm (confirmar desinstalacion)`n"
$helpM="${helpM}-install (confirmar instalacion)`n"
$helpM="${helpM}-no_users (numero de usuarios a registrar)`n" # Verificar sintaxis y ver estado del servicio
$helpM="${helpM}-users (lista de usuarios separados por una coma | nombre de usuario para cambiarlo de grupo)`n"
$helpM="${helpM}-passwords (lista de contrase�as separadas por una coma)`n"
$helpM="${helpM}-groups (grupo al que pertenece separado por comas)`n"

if ($help) {
    Write-Host $helpM
    exit 1
}

$color="yellow"
$ipLocal=""

# ─── Función auxiliar ───────────────────────────────────────────────────────
function Set-NtfsRule {
    param(
        [string]$Path,
        [string]$Identity,
        [string]$Rights,          # e.g. "FullControl","ReadAndExecute","Modify"
        [string]$Inheritance = "ContainerInherit,ObjectInherit",
        [string]$Propagation = "None",
        [string]$Type = "Allow"   # "Allow" | "Deny"
    )
    $acl   = Get-Acl -Path $Path
    $rule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity, $Rights, $Inheritance, $Propagation, $Type)
    if ($Type -eq "Deny") { $acl.AddAccessRule($rule) }
    else                  { $acl.SetAccessRule($rule) }
    Set-Acl -Path $Path -AclObject $acl
}

function checkService {
	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

	if ($aux -eq $null) {
		Write-Host "Se ha detectado que no se tiene instalado el servicio FTPSVC" -Foregroundcolor "red"
	} else {
        Write-Host "Se ha detectado el servicio FTPSVC instalado" -Foreground $color
    } 
}

function installService {
	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

	if ($aux -eq $null) {
        Write-Host "Se ha detectado que no se tiene instalado el FTPSVC Server" -Foregroundcolor "red"

        if ($install) {
            Write-Host "Iniciando instalacion..." -Foregroundcolor $color
		    Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools	
		    Write-Host "La instalacion ha finalizado correctamente" -Foregroundcolor "green"   
        } else {
            Write-Host "Use la bandera -install para activar la instalacion" -ForegroundColor $color
        }

	} else {
        Write-Host "Se ha detectado el servicio FTPSVC instalado" -Foreground $color
    } 
}

function uninstallService {
	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

	if ($aux -eq $null) {
        Write-Host "Se ha detectado que no se tiene instalado el servicio FTPSVC" -Foregroundcolor "red"

	} else {
        Write-Host "Se ha detectado el servicio FTPSVC instalado" -Foreground $color

        if ($confirm) {
            Write-Host "Iniciando desinstalacion..." -Foregroundcolor $color
            Uninstall-WindowsFeature -Name Web-FTP-Server, Web-FTP-Ext	
		    Write-Host "La desinstalacion ha finalizado correctamente" -Foregroundcolor red   
        } else {
            Write-Host "Use la bandera -c para confirmar " -ForegroundColor $color
        }
    } 
}
# function changeGroup {
#     validateEmpty $users
#     validateEmpty $groups

#     $Ruta="C:\FTP"
#     $RutaLocalUser = "$Ruta\LocalUser"
#     $RutaUsuario = "$RutaLocalUser\$users"

#     # Eliminar grupos a los que pertenecia antes el usuario
#     Get-LocalGroup | Where-Object { `
#     (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -match $users `
#     } | ForEach-Object {Remove-LocalGroupMember -Member $users -Group $_.Name}

#     if (-not (Test-Path -Path "$RutaUsuario\$grupos")) { New-Item -ItemType Junction -Path "$RutaUsuario\$grupos" -Target "$Ruta\$grupos" -Force | Out-Null }
#     if (Test-Path -Path "$RutaUsuario\$grupos") { Remove-Item -Path "$RutaUsuario\$grupos" -Recurse -Confirm:$false | Out-Null }

#     icacls "$RutaUsuario\$grupos" /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "${grupos}:(OI)(CI)M" /T /C /Q 
#     #icacls "$RutaUsuario\Reprobados" /grant "Authenticated Users:(OI)(CI)(M)" /C /Q

#     Add-LocalGroupMember -Group "$groups" -Member "$users"
#     Write-Host "Se ha cambiando el grupo del usuario a $groups" -Foregroundcolor green
# }

function changeGroup {
    param (
        [string]$usuario,
        [string]$grupoDestino
    )

    $Name="FTP Service";
    $usuario = $usuario.Trim()
    $grupoDestino = $grupoDestino.Trim()
    $Ruta = "C:\FTP"
    $RutaUsuario = "$Ruta\LocalUser\$usuario"

    # 1. VERIFICACIÓN: ¿Existe el usuario?
    if ($null -eq (Get-LocalUser -Name $usuario -ErrorAction SilentlyContinue)) {
        Write-Host "Error: El usuario '$usuario' no existe en el sistema." -ForegroundColor Red
        return
    }

    # 2. VERIFICACIÓN: ¿Existe el grupo?
    if ($null -eq (Get-LocalGroup -Name $grupoDestino -ErrorAction SilentlyContinue)) {
        Write-Host "Error: El grupo académico '$grupoDestino' no existe." -ForegroundColor Red
        return
    }

    # 3. VERIFICACIÓN DE SEGURIDAD: Que no lo metan a un grupo del sistema
    if ($script:gruposSistema -contains $grupoDestino) {
        Write-Host "Error de seguridad: No puedes mover alumnos a grupos del sistema ($grupoDestino)." -ForegroundColor Red
        return
    }

    # 4. LIMPIEZA SEGURA: Sacarlo solo de los grupos académicos viejos
    # Usamos tu vector global para NUNCA sacarlo de "Users" u otros grupos vitales
    $gruposActuales = Get-LocalGroup | Where-Object { 
        ($.Name -notin $script:gruposSistema) -and ($.Name -ne "Alumnos") -and
        ((Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -match $usuario) 
    }

    foreach ($grupoViejo in $gruposActuales) {
        Remove-LocalGroupMember -Group $grupoViejo.Name -Member $usuario -ErrorAction SilentlyContinue
        
        # Borramos el túnel (Junction) viejo de su jaula para que ya no lo vea
        $rutaTunelViejo = "$RutaUsuario\$($grupoViejo.Name)"
        if (Test-Path -Path $rutaTunelViejo) {
            Remove-Item -Path $rutaTunelViejo -Recurse -Force -Confirm:$false | Out-Null
        }
    }

    # 5. ASIGNACIÓN: Lo metemos al nuevo grupo
    Add-LocalGroupMember -Group $grupoDestino -Member $usuario -ErrorAction SilentlyContinue

    # 6. CREACIÓN DEL TÚNEL: Le ponemos el acceso directo a su nueva materia/grupo
    $rutaNuevoTunel = "$RutaUsuario\$grupoDestino"
    if (-not (Test-Path -Path $rutaNuevoTunel)) { 
        New-Item -ItemType Junction -Path $rutaNuevoTunel -Target "$Ruta\$grupoDestino" -Force -Confirm:$false | Out-Null 
    }

    # 7. PERMISOS: Aseguramos el túnel en silencio
    #icacls $rutaNuevoTunel /grant "${grupoDestino}:(OI)(CI)(RX)" /T /C /Q
    #icacls $rutaNuevoTunel /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "Authenticated Users:(OI)(CI)(RX)" /T /C /Q > $null 2>&1 



	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

	if ($aux -ne $null) {
		Restart-Service ftpsvc
    }

    Write-Host "Se ha cambiado al usuario '$usuario' al grupo '$grupoDestino' con éxito" -ForegroundColor Green
}

function deleteUser {
    param (
        [string] $nombre,
        [string] $descripcion
    )

    $nombre=$nombre.Trim();

    if ($nombre -contains $script:usuariosSistema) {
        Write-Host "Se ha detectado que el usuario es un usuario del sistema" -ForegroundColor red
        exit 1;
    }

    $aux = $aux = Get-LocalUser -Name $nombre -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq $descripcion }

    if ($aux -ne $null) {
         if (Test-Path -Path "C:\FTP\LocalUser\$nombre") {
            icacls "C:\FTP\LocalUser\$nombre" /reset /T /c /q > $null
            Remove-Item -Path "C:\FTP\LocalUser\$nombre" -Recurse -Confirm:$false | Out-Null 
        }

        Remove-LocalUser -Name "$nombre" -ErrorAction SilentlyContinue
        
        if (UserExist -nombre $nombre) {
            Write-Host "No se ha eliminado el usuario correctamente" -ForegroundColor red
        } else {
            Write-Host "Se ha eliminado el usuario correctamente" -ForegroundColor green      
        }
    } else {
        Write-Host "No se ha encontrado al usuario con ese nombre y descripcion" -ForegroundColor Red
        exit 1
    }
}

function deleteGroup {
    param (
        [string] $nombre,
        [string] $descripcion
    )

    $nombre = $nombre.Trim()

    # 1. Validamos contra los grupos del sistema
    if ($script:gruposSistema -contains $nombre) {
        Write-Host "Se ha detectado que el grupo es un grupo del sistema" -ForegroundColor red
        return 
    }

    # 2. Buscamos el grupo y verificamos su descripción
    $aux = Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq $descripcion }

    if ($aux -ne $null) {
        
        ### NUEVO: Borrar carpetas de los usuarios pertenecientes al grupo ###
        Write-Host "Limpiando carpetas de usuarios miembros de '$nombre'..." -ForegroundColor Cyan
        
        $miembros = Get-LocalGroupMember -Group $nombre -ErrorAction SilentlyContinue
        
        foreach ($miembro in $miembros) {
            # Asumimos la ruta: C:\FTP\LocalUser\NombreUsuario\NombreGrupo
            $miembroNombre = $miembro.Name.Split('\')[-1]
            $rutaCarpetaUsuario = "C:\FTP\LocalUser\$($miembroNombre)\$nombre"
            
            if (Test-Path -Path $rutaCarpetaUsuario) {
                Write-Host " -> Eliminando carpeta de usuario: $rutaCarpetaUsuario" -ForegroundColor Gray
                Remove-Item -Path $rutaCarpetaUsuario -Recurse -Force -Confirm:$false | Out-Null
            }
        }
        ######################################################################

        # 3. Borramos la carpeta raíz compartida del grupo (C:\FTP\Reprobados)
        if (Test-Path -Path "C:\FTP\$nombre") {
            Remove-Item -Path "C:\FTP\$nombre" -Recurse -Force -Confirm:$false | Out-Null 
        }
        
        # 4. Borramos el grupo de Windows
        Remove-LocalGroup -Name $nombre 
        
        # 5. Verificamos eliminación
        $comprobacion = Get-LocalGroup -Name $nombre -ErrorAction SilentlyContinue
        if ($comprobacion -ne $null) {
            Write-Host "No se ha eliminado el grupo correctamente" -ForegroundColor red
        } else {
            Write-Host "Se ha eliminado el grupo '$nombre' y sus subcarpetas correctamente" -ForegroundColor green      
        }
    } else {
        Write-Host "No se encontró un grupo llamado '$nombre' con la descripción '$descripcion'" -ForegroundColor yellow
    }
}

#function consultarGrupos {
#    Write-Host "--- Grupos del Servidor FTP ---" -ForegroundColor Cyan
#    # La función 'lee' el vector que está afuera
#    Get-LocalGroup | Where-Object { $_.Name -notin $script:gruposSistema } | Select-Object Name | Format-Table -AutoSize
#}

function consultarAlumnos {
    Write-Host "--- Listado Oficial de Alumnos (FTP) ---" -ForegroundColor Cyan

    # Filtramos por el campo Description
    Get-LocalUser | Where-Object { $_.Description -eq "Alumno" } | 
        Select-Object Name, Description, Enabled | 
        Format-Table -AutoSize
}

function consultarGrupos {
    Write-Host "--- Grupos Academicos del Servidor ---" -ForegroundColor Cyan
    Get-LocalGroup | Where-Object { $_.Description -eq "Grupo Academico" } | 
        Select-Object Name, Description | 
        Format-Table -AutoSize
}

function crearAlumno {
    param (
        [string] $descripcion
    )
    $Ruta="C:\FTP"
    $users = $users -split ","
    $passwords = $passwords -split ","

    # 1. Mensaje corregido (ya no menciona grupos)
    if ($users.Length -ne $no_users -or $passwords.Length -ne $no_users ) {
        Write-Host "El número de usuarios y contraseñas debe coincidir con -no_users" -ForegroundColor red
        exit 1
    }

    validateEmptyArray $users
    validateEmptyArray $passwords
    validateUserCreated $users # Asumo que esta función ya maneja el array completo

    $RutaLocalUser = "$Ruta\LocalUser"
    if (-not (Test-Path -Path $RutaLocalUser)) { New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null }

    for($i=0; $i -lt $no_users; $i++) {
        $usuarioActual = $users[$i].Trim()
        $passActual = $passwords[$i]

        # 2. Validamos el formato individualmente antes de crear nada
        if (-not (validateUserName $usuarioActual)) { exit 1 }
        if (-not (validatePassword $passActual)) { exit 1 }

        # Creación del usuario con su etiqueta
        $aux = ConvertTo-SecureString -String "$passActual" -AsPlainText -Force
        New-LocalUser -Name $usuarioActual -Description "Alumno" -Password $aux -PasswordNeverExpires | Out-Null

        Add-LocalGroupMember -Group "Alumnos" -Member $usuarioActual -ErrorAction SilentlyContinue

        if (-not (UserExist $usuarioActual)) {
            Write-Host "No se ha detectado el registro del usuario '$usuarioActual', abortando..." -ForegroundColor Red
            exit 1
        }

        # Rutas de aislamiento
        $RutaUsuario = "$RutaLocalUser\$usuarioActual"

        if (-not (Test-Path -Path "$RutaUsuario")) { 
            New-Item -Path "$RutaUsuario" -ItemType Directory -Force | Out-Null
        }

        # 3. Permisos de la jaula en silencio total
        # ─── $RutaUsuario : deshabilitar herencia y aplicar permisos base ────────────
        $acl = Get-Acl -Path $RutaUsuario
        $acl.SetAccessRuleProtection($true, $false)   # /inheritance:r  (rompe herencia, no copia reglas existentes)
        Set-Acl -Path $RutaUsuario -AclObject $acl

        Set-NtfsRule $RutaUsuario "Administrators"       "FullControl"
        Set-NtfsRule $RutaUsuario "SYSTEM"               "FullControl"
        Set-NtfsRule $RutaUsuario "Authenticated Users"  "ReadAndExecute"
        Set-NtfsRule $RutaUsuario $usuarioActual         "ReadAndExecute"

        # ─── Aplicar recursivo a todo el árbol (/T) ──────────────────────────────────
        Get-ChildItem -Path $RutaUsuario -Recurse -Force | ForEach-Object {
            Set-NtfsRule $_.FullName "Authenticated Users" "ReadAndExecute"
        }
        #Write-Host "el valor de rutausuario es $RutaUsuario"
        #Write-Host "el valor de rutausuario es $RutaUsuario"
        #Write-Host "el valor de rutausuario es $RutaUsuario"

        # Implementar Junctions
        if (-not (Test-Path -Path "$RutaUsuario\Publica")) { 
            New-Item -ItemType Junction -Path "$RutaUsuario\Publica" -Target "$Ruta\Publica" -Force | Out-Null 
        }

        # Crear subcarpeta personal
        if (-not (Test-Path -Path "$RutaUsuario\$usuarioActual")) { 
            New-Item -ItemType Directory -Path "$RutaUsuario\$usuarioActual" -Force | Out-Null 
        }


        # 1. RESET /T : eliminar reglas explícitas y re-habilitar herencia en todo el árbol
        @($RutaUsuario) + (Get-ChildItem $RutaUsuario -Recurse -Force).FullName | ForEach-Object {
            $rutaActual = $_                          # ← guardamos la ruta aquí
            $acl = Get-Acl $rutaActual
            $acl.SetAccessRuleProtection($false, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
            Set-Acl -Path $rutaActual -AclObject $acl  # ← usamos la variable, no $_
        }

        # 2. Romper herencia SIN copiar reglas del padre  (/inheritance:r)
        $acl = Get-Acl $RutaUsuario
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl -Path $RutaUsuario -AclObject $acl

        # 3. Authenticated Users : Modify heredable  (OI)(CI)M
        Set-NtfsRule $RutaUsuario "Authenticated Users" "ReadAndExecute" "ContainerInherit,ObjectInherit" "None" "Allow"

        # 4. Administrators y SYSTEM : FullControl heredable  (OI)(CI)F
        Set-NtfsRule $RutaUsuario "Administrators" "FullControl" "ContainerInherit,ObjectInherit" "None" "Allow"
        Set-NtfsRule $RutaUsuario "SYSTEM"         "FullControl" "ContainerInherit,ObjectInherit" "None" "Allow"

        # 5. CANDADO: Denegar Delete SOLO en esta carpeta raíz (sin (OI)(CI) → sin herencia)
        $acl  = Get-Acl $RutaUsuario
        $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "Authenticated Users",
                    [System.Security.AccessControl.FileSystemRights]::Delete,
                    [System.Security.AccessControl.InheritanceFlags]::None,      # sin (OI)(CI)
                    [System.Security.AccessControl.PropagationFlags]::None,
                    "Deny")
        $acl.AddAccessRule($deny)
        Set-Acl -Path $RutaUsuario -AclObject $acl

        Set-NtfsRule "$RutaUsuario\$usuarioActual" "Authenticated Users" "Modify" "ContainerInherit,ObjectInherit" "None" "Allow"

        # 4. Administrators y SYSTEM : FullControl heredable  (OI)(CI)F
        Set-NtfsRule "$RutaUsuario\$usuarioActual" "Administrators" "FullControl" "ContainerInherit,ObjectInherit" "None" "Allow"
        Set-NtfsRule "$RutaUsuario\$usuarioActual" "SYSTEM"         "FullControl" "ContainerInherit,ObjectInherit" "None" "Allow"

        $acl  = Get-Acl "$RutaUsuario\$usuarioActual"
        $deny = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "Authenticated Users",
                    [System.Security.AccessControl.FileSystemRights]::Delete,
                    [System.Security.AccessControl.InheritanceFlags]::None,      # sin (OI)(CI)
                    [System.Security.AccessControl.PropagationFlags]::None,
                    "Deny")
        $acl.AddAccessRule($deny)
        Set-Acl -Path "$RutaUsuario\$usuarioActual" -AclObject $acl

        # Permisos de la subcarpeta personal en silencio total
        #icacls "$RutaUsuario\$usuarioActual" /inheritance:r /grant "Authenticated Users:(OI)(CI)(M)" /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /T /C /Q > $null 2>&1
        # 2. Permisos en la CARPETA PERSONAL (Escribir SI, Borrar carpeta NO)
        # AD = Append Data (Crear carpetas)
        # WD = Write Data (Crear archivos)
        # S = Synchronize
        #icacls "$RutaUsuario\$usuarioActual" /grant "$($usuarioActual):(OI)(CI)(M)" /T /C /Q 
        #icacls "$RutaUsuario\$usuarioActual" /grant "Authenticated Users:(OI)(CI)(M)" /T /C /Q 

        # 3. Quitamos explícitamente el permiso de eliminar (D = Delete)
        #icacls "$RutaUsuario\$usuarioActual" /deny "$($usuarioActual):(D)" /C /Q 
        #icacls "$RutaUsuario\$usuarioActual" /deny "Authenticated Users:(D)" /C /Q 

    }

    Write-Host "Se ha terminado de añadir a el/los usuario(s) correctamente." -Foregroundcolor green    
}

function GroupExist {
    param ([string]$nombreGrupo)
    # Ya no necesitas declarar el vector aquí, solo lo usas
    return $nombreGrupo.Trim() -in $script:gruposSistema
}

# function addUsers {
#     $Ruta="C:\FTP"
#     $users = $users -split ","
#     $passwords = $passwords -split ","
#     $groups = $groups -split ","

#     if ($users.Length -ne $no_users -or $passwords.Length -ne $no_users -or $groups.Length -ne $no_users) {
#         Write-Host "El número de usuarios, contraseñas y grupos debe coincidir con -no_users" -ForegroundColor red
#         exit 1
#     }

#     validateEmptyArray $users
#     validateEmptyArray $passwords
#     validateEmptyArray $groups

#     validateGroupNumber $groups 
#     validateUserCreated $users 

#     # 1. Crear la carpeta maestra de aislamiento obligatoria de IIS
#     $RutaLocalUser = "$Ruta\LocalUser"
#     if (-not (Test-Path -Path $RutaLocalUser)) { New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null }

#     for($i=0; $i -lt $no_users; $i++) {

#         # 2. La nueva ruta del usuario ahora estará enjaulada
#         $RutaUsuario = "$RutaLocalUser\$($users[$i])"

#         if (-not (Test-Path -Path "$RutaUsuario")) {
#             New-Item -Path "$RutaUsuario" -ItemType Directory -Force | Out-Null
#         }

#         # 3. Permisos de su jaula personal (Solo el usuario, SYSTEM y Admin entran) # F -> RX
#         icacls $RutaUsuario /inheritance:r /grant "$($users[$i]):(OI)(CI)(RX)" /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /T /C /Q

#         # 4. IMPLEMENTAR LOS "MOUNTS" (Junctions) hacia las carpetas compartidas
#         if (-not (Test-Path -Path "$RutaUsuario\Publica")) { New-Item -ItemType Junction -Path "$RutaUsuario\Publica" -Target "$Ruta\Publica" -Force | Out-Null }

#         # 5. Asignar el usuario a su grupo
#         if ( "$($groups[$i])" -eq "1" ) {
#             if (-not (Test-Path -Path "$RutaUsuario\Reprobados")) { New-Item -ItemType Junction -Path "$RutaUsuario\Reprobados" -Target "$Ruta\Reprobados" -Force | Out-Null }
#             Add-LocalGroupMember -Group "Reprobados" -Member "$($users[$i])"
#             Add-LocalGroupMember -Group "Users" -Member "$($users[$i])"
#         } elseif ( "$($groups[$i])" -eq "2" ) {
#             if (-not (Test-Path -Path "$RutaUsuario\Recursadores")) { New-Item -ItemType Junction -Path "$RutaUsuario\Recursadores" -Target "$Ruta\Recursadores" -Force | Out-Null }
#             Add-LocalGroupMember -Group "Recursadores" -Member "$($users[$i])"
#             Add-LocalGroupMember -Group "Users" -Member "$($users[$i])"
#         }

#         # 6. Crear la carpeta personal
#         if (-not (Test-Path -Path "$RutaUsuario\$($users[$i])")) { New-Item -ItemType Directory -Path "$RutaUsuario\$($users[$i])" -Force | Out-Null }
#     }

#     Write-Host "Se ha terminado de añadir a los usuarios correctamente." -Foregroundcolor green
# }

# function configureService {
# 	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

# 	if ($aux -eq $null) {
#         exit 1
# 	}

#     $Name="FTP Service"
#     $Ruta="C:\FTP"
#     $CarpetaA="$Ruta\Reprobados"
#     $CarpetaB="$Ruta\Recursadores"
#     $CarpetaC="$Ruta\Publica"

#     # Crear la carpeta
#     New-Item -Path $Ruta -ItemType Directory -Force    

#     # Creación del sitio FTP
#     New-WebFtpSite -Name $Name -Port 21 -PhysicalPath $Ruta -Force

#     # Creación de grupos
#     $aux = Get-LocalGroup | findstr "Reprobados"

#     if($aux -eq $null) {
#         New-LocalGroup -Name "Reprobados" -Description "Reprobados"
#     } 

#     $aux = Get-LocalGroup | findstr "Recursadores"

#     if($aux -eq $null) {
#         New-LocalGroup -Name "Recursadores" -Description "Recursadores"
#     }

# # 1. Borrar el archivo maldito para que deje de estorbar
#     if (Test-Path "$Ruta\web.config") { 
#         Remove-Item "$Ruta\web.config" -Force -ErrorAction SilentlyContinue 
#     }

#     # 2. Limpiar cualquier regla previa apuntando al cerebro central de IIS
#     Clear-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -ErrorAction SilentlyContinue

#     # 3. Añadir permisos apuntando al cerebro central (usando -Location $Name)
#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; users="?"; permissions="Read"}

#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; users="*"; permissions="Read"}

#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; roles="Reprobados, Recursadores"; permissions="Read, Write"}

#     # 2. Rompemos la herencia de la raíz
#     icacls $Ruta /inheritance:r /C /Q

#     # 3. Damos permisos totales al Sistema y Administradores (para que PowerShell no falle)
#     icacls $Ruta /grant "Administrators:(OI)(CI)F" /C /Q
#     icacls $Ruta /grant "SYSTEM:(OI)(CI)F" /C /Q

#     # 4. Le damos permiso a IIS para que pueda leer su configuración
#     icacls $Ruta /grant "IIS_IUSRS:(OI)(CI)RX" /C /Q

#     # 5. Permisos de lectura base para usuarios anónimos y registrados
#     icacls $Ruta /grant "IUSR:(OI)(CI)RX" /C /Q
#     icacls $Ruta /grant "Authenticated Users:(OI)(CI)RX" /C /Q

#     # Permitir acceso anónimo
#     Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true

#     # Habilitar autenticación básica
#     Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.basicAuthentication.enabled" -Value $true

#     # Dar permisos de lectura y escritura a todos los usuarios de Windows (*)
#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -Value @{accessType="Allow"; users="*"; permissions="Read, Write"} 

#     $aux = Get-NetFirewallRule -Name "Regla_FTP_In" -ErrorAction SilentlyContinue

#     if ($aux -eq $null) {
#         New-NetFirewallRule -Name "Regla_FTP_In" -DisplayName "Permitir FTP (Puerto 21)" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow
#     }

#     if (-not (Test-Path -Path "$CarpetaA" -PathType Container)) {
#         New-Item -Path "$CarpetaA" -ItemType Directory -Force
#     }

#     if (-not (Test-Path -Path "$CarpetaB" -PathType Container)) {
#         New-Item -Path "$CarpetaB" -ItemType Directory -Force
#     }

#     if (-not (Test-Path -Path "$CarpetaC" -PathType Container)) {
#         New-Item -Path "$CarpetaC" -ItemType Directory -Force
#     }



#     # 1. Configurar Carpeta A (Solo Grupo A, Administradores y Sistema)
#     icacls $CarpetaA /inheritance:r /T /C /Q  # Rompe la herencia
#     icacls $CarpetaA /grant "Reprobados:(OI)(CI)M" /T /C /Q # 'M' es permiso de Modificar (Lectura/Escritura)
#     icacls $CarpetaA /grant "Administrators:(OI)(CI)F" /T /C /Q # 'F' es Control Total
#     icacls $CarpetaA /grant "SYSTEM:(OI)(CI)F" /T /C /Q

#     # 2. Configurar Carpeta B (Solo Grupo B, Administradores y Sistema)
#     icacls $CarpetaB /inheritance:r /T /C /Q
#     icacls $CarpetaB /grant "Recursadores:(OI)(CI)M" /T /C /Q
#     icacls $CarpetaB /grant "Administrators:(OI)(CI)F" /T /C /Q
#     icacls $CarpetaB /grant "SYSTEM:(OI)(CI)F" /T /C /Q

#     # 1. Romper la herencia de la carpeta
#     icacls $CarpetaC /inheritance:r /T /C /Q

#     # 2. Permisos base para el sistema y administradores (Control Total)
#     icacls $CarpetaC /grant "Administrators:(OI)(CI)F" /T /C /Q
#     icacls $CarpetaC /grant "SYSTEM:(OI)(CI)F" /T /C /Q

#     # 3. Permiso de SOLO LECTURA para el usuario anónimo
#     icacls $CarpetaC /grant "IUSR:(OI)(CI)R" /T /C /Q

#     # 4. Permiso de LECTURA Y ESCRITURA para cualquier usuario que inicie sesión
#     icacls $CarpetaC /grant "Authenticated Users:(OI)(CI)M" /T /C /Q

#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -Value @{accessType="Allow"; users="*"; permissions="Read, Write"} -ErrorAction SilentlyContinue

#     Import-Module WebAdministration

#     # 1. Crear un certificado SSL auto-firmado
#     $Cert = New-SelfSignedCertificate -DnsName "MiServidorFTP" -CertStoreLocation "cert:\LocalMachine\My"

#     # 2. Asignar el certificado al servidor FTP usando su "huella digital" (Thumbprint)
#     Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.serverCertHash" -Value $Cert.Thumbprint

#     # 3. Obligar al servidor a requerir SSL para todo
#     Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslRequire"
#     Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.dataChannelPolicy" -Value "SslRequire"
#     Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.userIsolation.mode" -Value "None"
    
#     # 1. Limpiar cualquier regla previa que pudiera existir en esa carpeta específica
#     Clear-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -ErrorAction SilentlyContinue

#     # 2. Permitir Leer a los usuarios anónimos
#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -Value @{accessType="Allow"; users="?"; permissions="Read"}

#     # 3. Permitir Leer y Escribir a los usuarios autenticados
#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -Value @{accessType="Allow"; users="*"; permissions="Read, Write"}

#     Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\Sites\$Name" -Value @{accessType="Allow"; roles="Reprobados, Recursadores"; permissions="Read, Write"} 
    
#     Restart-WebItem "IIS:\Sites\$Name"
# }
function configureService {
    $aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

    if ($aux -eq $null) {
        exit 1
    }

    $Name="FTP Service"
    $Ruta="C:\FTP"
    $Anonymous="$Ruta\Anonymous"
    $RutaLocalUser = "$Ruta\LocalUser"
    $AnonymousJunction="$RutaLocalUser\Public\Publica"
    $CarpetaA="$Ruta\Reprobados"
    $CarpetaB="$Ruta\Recursadores"
    $CarpetaC="$Ruta\Publica"

    Write-Host "Preparando estructura de directorios..." -ForegroundColor Cyan

    # 1. Crear las carpetas si no existen
    if (-not (Test-Path -Path $Ruta)) { New-Item -Path $Ruta -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -Path $CarpetaA)) { New-Item -Path $CarpetaA -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -Path $CarpetaB)) { New-Item -Path $CarpetaB -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -Path $CarpetaC)) { New-Item -Path $CarpetaC -ItemType Directory -Force | Out-Null }

    #1.1 Crear carpeta para aislamiento de usuarios
    if (-not (Test-Path -Path $RutaLocalUser)) { New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null }

    #1.2 Crear carpeta para anonymous
    #        New-Item -ItemType Junction -Path $rutaNuevoTunel -Target "$Ruta\$grupoDestino" -Force -Confirm:$false | Out-Null 
    if (-not (Test-Path -Path "$Anonymous")) { New-Item -Path "$Anonymous" -ItemType Directory -Force | Out-Null} # eliminar
    if (-not (Test-Path -Path "$RutaLocalUser\Public")) { New-Item -Path "$RutaLocalUser\Public" -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path -Path "$AnonymousJunction")) { New-Item -ItemType Junction -Path "$RutaLocalUser\Public\Publica" -Target "$CarpetaC" -Force | Out-Null }

    # 2. ¡EL PASO CLAVE! Restaurar permisos a la normalidad para que IIS no se trabe por pruebas anteriores
    icacls $Ruta /reset /T /C /Q > $null 2>&1
    if (Test-Path "$Ruta\web.config") { Remove-Item "$Ruta\web.config" -Force -ErrorAction SilentlyContinue }

    Write-Host "Configurando el servicio IIS y FTP..." -ForegroundColor Cyan

    # 3. Creación de grupos
    $gruposNecesarios = @(
        @{Name="Alumnos"; Desc="Identificador Alumnos"},
        @{Name="Reprobados"; Desc="Grupo Academico"},
        @{Name="Recursadores"; Desc="Grupo Academico"}
    )

    foreach ($grupo in $gruposNecesarios) {
        if (-not (Get-LocalGroup -Name $grupo.Name -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $grupo.Name -Description $grupo.Desc | Out-Null
            Write-Host "Grupo '$($grupo.Name)' creado." -ForegroundColor Yellow
        }
    }
    # 4. Creación del sitio FTP en IIS
    Import-Module WebAdministration
    New-WebFtpSite -Name $Name -Port 21 -PhysicalPath $Ruta -Force | Out-Null

    # 5. Configuración de Autenticación y SSL
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.anonymousAuthentication.enabled" -Value $true > $null 2>&1
    Set-ItemProperty "IIS:\Sites\$Name" -Name "ftpServer.security.authentication.basicAuthentication.enabled" -Value $true > $null 2>&1
    Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.userIsolation.mode" -Value "IsolateAllDirectories" > $null 2>&1

    $Cert = New-SelfSignedCertificate -DnsName "MiServidorFTP" -CertStoreLocation "cert:\LocalMachine\My"
    Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.serverCertHash" -Value $Cert.Thumbprint > $null 2>&1
    Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.controlChannelPolicy" -Value "SslRequire" > $null 2>&1
    Set-ItemProperty -Path "IIS:\Sites\$Name" -Name "ftpServer.security.ssl.dataChannelPolicy" -Value "SslRequire" > $null 2>&1

    # 6. Firewall
    if ((Get-NetFirewallRule -Name "Regla_FTP_In" -ErrorAction SilentlyContinue) -eq $null) {
        New-NetFirewallRule -Name "Regla_FTP_In" -DisplayName "Permitir FTP (Puerto 21)" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow > $null 2>&1
    }

    Write-Host "Aplicando reglas de autorizacion de IIS..." -ForegroundColor Cyan

    # 7. Reglas de Autorización de IIS (Ahora se ejecutan sin error porque la carpeta no está bloqueada)
    Clear-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -ErrorAction SilentlyContinue
    #Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; users="?"; permissions="Read"}
# 2. Tu idea: DENEGAR explícitamente la escritura al usuario anónimo
# El acceso 'Deny' siempre tiene prioridad en IIS
# Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Deny"; users="anonymous"; permissions="Write"} > $null 2>&1

# 3. Permitir que Anonymous pueda al menos LEER
Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; users="?"; permissions="Read"} > $null 2>&1

# 4. Permitir a todos los demás (usuarios autenticados) Leer y Escribir
# Como el 'Deny' de arriba ya bloqueó al anónimo, este '*' solo afectará con escritura a los alumnos logueados
    Add-WebConfiguration -Filter /system.ftpServer/security/authorization -PSPath "IIS:\" -Location $Name -Value @{accessType="Allow"; roles="Alumnos"; permissions="Read, Write"} > $null 2>&1

    
    Write-Host "Aplicando candados de seguridad NTFS..." -ForegroundColor Cyan

    # 8. HASTA EL FINAL: Aseguramos la carpeta raíz
#     icacls $Ruta /inheritance:r /C /Q > $null 2>&1
#     icacls $Ruta /grant "Administrators:(OI)(CI)F" /C /Q > $null 2>&1
#     icacls $Ruta /grant "SYSTEM:(OI)(CI)F" /C /Q > $null 2>&1
#     icacls $Ruta /grant "IIS_IUSRS:(OI)(CI)RX" /C /Q > $null 2>&1
#     icacls $Ruta /grant "IUSR:(OI)(CI)(RX)" /C /Q > $null 2>&1
#     icacls $Ruta /grant "Authenticated Users:(OI)(CI)(RX)" /C /Q > $null 2>&1

#     # "$RutaLocalUser\ftp" icacls "$RutaLocalUser\ftp"  /grant "IUSR:(OI)(CI)(RX)" /C /Q

#     icacls $RutaLocalUser  /grant "Authenticated Users:(OI)(CI)(RX)" /C /Q > $null 2>&1
#     icacls $RutaLocalUser  /grant "IUSR:(OI)(CI)(RX)" /C /Q > $null 2>&1

#     icacls $Anonymous /grant "IUSR:(OI)(CI)(RX)" /T /C /Q > $null 2>&1
#     icacls $AnonymousJunction /grant "IUSR:(OI)(CI)(RX)" /T /C /Q > $null 2>&1
#     icacls "$RutaLocalUser\Public" /grant "IUSR:(OI)(CI)(RX)" /T /C /Q > $null 2>&1
#     icacls "$RutaLocalUser\Public\Publica" /grant "IUSR:(OI)(CI)(RX)" /T /C /Q > $null 2>&1

# # Permiso de paso en la raíz para que IIS pueda llegar a la subcarpeta
# #icacls $Ruta /grant "IUSR:(RX)" /Q
# #icacls $RutaLocalUser /grant "IUSR:(RX)" /Q

# # Permiso total de lectura en la jaula pública de Anonymous
# #icacls "$RutaLocalUser\Public" /grant "IUSR:(OI)(CI)(RX)" /T /C /Q > $null 2>&1

# # 9. HASTA EL FINAL: Aseguramos las subcarpetas (TODO EN UNA SOLA LÍNEA)
#     icacls $CarpetaA /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "Reprobados:(OI)(CI)M" /T /C /Q > $null 2>&1
#     icacls $CarpetaB /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "Recursadores:(OI)(CI)M" /T /C /Q > $null 2>&1
#     icacls $CarpetaC /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "IUSR:(OI)(CI)R" /grant "Authenticated Users:(OI)(CI)M" /T /C /Q > $null 2>&1

#     icacls $CarpetaA /deny "Recursadores:(OI)(CI)F" /T /C /Q > $null 2>&1
#     icacls $CarpetaB /deny "Reprobados:(OI)(CI)F" /T /C /Q > $null 2>&1
#     icacls $CarpetaA /deny "IUSR:(OI)(CI)F" /T /C /Q > $null 2>&1
#     icacls $CarpetaB /deny "IUSR:(OI)(CI)F" /T /C /Q > $null 2>&1

    # ─── $Ruta : deshabilitar herencia y permisos base ──────────────────────────
    $acl = Get-Acl -Path $Ruta
    $acl.SetAccessRuleProtection($true, $false)   # /inheritance:r
    Set-Acl -Path $Ruta -AclObject $acl

    Set-NtfsRule $Ruta "Administrators"       "FullControl"
    Set-NtfsRule $Ruta "SYSTEM"              "FullControl"
    Set-NtfsRule $Ruta "IIS_IUSRS"           "ReadAndExecute"
    Set-NtfsRule $Ruta "IUSR"               "ReadAndExecute"
    Set-NtfsRule $Ruta "Authenticated Users" "ReadAndExecute"

    # ─── $RutaLocalUser ─────────────────────────────────────────────────────────
    Set-NtfsRule $RutaLocalUser "Authenticated Users" "ReadAndExecute"
    Set-NtfsRule $RutaLocalUser "IUSR"               "ReadAndExecute"

    # ─── $Anonymous y $AnonymousJunction (/T = recursivo) ───────────────────────
    Get-ChildItem -Path $Anonymous        -Recurse -Force | ForEach-Object { Set-NtfsRule $_.FullName "IUSR" "ReadAndExecute" }
    Set-NtfsRule $Anonymous        "IUSR" "ReadAndExecute"
    Get-ChildItem -Path $AnonymousJunction -Recurse -Force | ForEach-Object { Set-NtfsRule $_.FullName "IUSR" "ReadAndExecute" }
    Set-NtfsRule $AnonymousJunction "IUSR" "ReadAndExecute"

    Set-NtfsRule "$RutaLocalUser\Public"         "IUSR" "ReadAndExecute"
    Set-NtfsRule "$RutaLocalUser\Public\Publica" "IUSR" "ReadAndExecute"

    # ─── $CarpetaA  (Reprobados:M, denegar Recursadores y IUSR) ─────────────────
    $acl = Get-Acl $CarpetaA; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaA $acl
    Set-NtfsRule $CarpetaA "Administrators" "FullControl"
    Set-NtfsRule $CarpetaA "SYSTEM"        "FullControl"
    Set-NtfsRule $CarpetaA "Reprobados"    "Modify"
    Set-NtfsRule $CarpetaA "Recursadores"  "FullControl" -Type "Deny"
    Set-NtfsRule $CarpetaA "IUSR"         "FullControl" -Type "Deny"

    # ─── $CarpetaB  (Recursadores:M, denegar Reprobados y IUSR) ─────────────────
    $acl = Get-Acl $CarpetaB; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaB $acl
    Set-NtfsRule $CarpetaB "Administrators" "FullControl"
    Set-NtfsRule $CarpetaB "SYSTEM"        "FullControl"
    Set-NtfsRule $CarpetaB "Recursadores"  "Modify"
    Set-NtfsRule $CarpetaB "Reprobados"    "FullControl" -Type "Deny"
    Set-NtfsRule $CarpetaB "IUSR"         "FullControl" -Type "Deny"

    # ─── $CarpetaC  (Authenticated Users:M, IUSR:R) ─────────────────────────────
    $acl = Get-Acl $CarpetaC; $acl.SetAccessRuleProtection($true,$false); Set-Acl $CarpetaC $acl
    Set-NtfsRule $CarpetaC "Administrators"      "FullControl"
    Set-NtfsRule $CarpetaC "SYSTEM"             "FullControl"
    Set-NtfsRule $CarpetaC "IUSR"              "ReadAndExecute"
    Set-NtfsRule $CarpetaC "Authenticated Users" "Modify"

    Restart-WebItem "IIS:\Sites\$Name"
    Write-Host "Configuracion completada con exito." -ForegroundColor Green
}

function monitoreo {
	$aux = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

	if ($aux -eq $null) {
		Write-Host "Se ha detectado que no se tiene instalado el DNS Server" -Foregroundcolor "red"
	} else {
        Write-Host "`n=== Estado del servicio ===" -ForegroundColor $color
        Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue | ft -Autosize
    } 
}

switch ($option) {
    "1" {checkService; break;}
	"2" {installService; break;}
	"3" {configureService; break;}
	"4" {uninstallService; break;}
    "5" {monitoreo; break;}
    "6" {changeGroup -usuario $users -grupoDestino $groups; break;}
    "7" {crearAlumno -descripcion "Alumno"; break;}
    "8" {deleteUser -nombre "$users" -descripcion "Alumno"; break;}
    "9" {consultarAlumnos; break;}
    "10" {crearGrupo -nombreGrupo "$groups" -descripcion "Grupo Academico"; break;}
    "11" {deleteGroup -nombre "$groups" -descripcion "Grupo Academico"; break;}
    "12" {consultarGrupos; break;}
	default {Write-Host "Se ha detectado una opcion invalida, vuelve a intentarlo" -Foregroundcolor red}
}
