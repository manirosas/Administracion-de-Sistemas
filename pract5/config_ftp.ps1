<#
.SYNOPSIS
    Script de automatización para servidor FTP en Windows Server con IIS
.DESCRIPTION
    Configura FTP en IIS con acceso anónimo y autenticado por grupos
.NOTES
    Requiere ejecutarse con privilegios de administrador
    Compatible con Windows Server 2016/2019/2022
#>

#Requires -RunAsAdministrator

# Configuración de colores para output
$Host.UI.RawUI.ForegroundColor = "White"

# Variables globales
$Script:FTPSiteName = "Servidor FTP Empresarial"
$Script:FTPRootPath = "C:\FTP"
$Script:Groups = @("reprobados", "recursadores")
$Script:Users = @()
$Script:FTPUserList = "C:\FTP\ftp_users.txt"

# Función para mostrar menú
function Show-Menu {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "    SERVIDOR FTP - WINDOWS SERVER (IIS)  " -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "1. Instalar y configurar FTP (idempotente)" -ForegroundColor Green
    Write-Host "2. Agregar nuevo usuario" -ForegroundColor Green
    Write-Host "3. Listar usuarios y sus grupos" -ForegroundColor Green
    Write-Host "4. Cambiar grupo de usuario" -ForegroundColor Green
    Write-Host "5. Eliminar configuración FTP" -ForegroundColor Green
    Write-Host "6. Salir" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Cyan
}

# Función para instalar características de Windows
function Install-WindowsFeaturesIfNeeded {
    Write-Host "Verificando características de Windows necesarias..." -ForegroundColor Yellow
    
    $features = @(
        "Web-Server",
        "Web-Ftp-Server",
        "Web-Mgmt-Console",
        "Web-Ftp-Service"
    )
    
    foreach ($feature in $features) {
        $installed = Get-WindowsFeature -Name $feature | Select-Object -ExpandProperty Installed
        if (-not $installed) {
            Write-Host "Instalando característica: $feature" -ForegroundColor Yellow
            Install-WindowsFeature -Name $feature -IncludeManagementTools
        } else {
            Write-Host "Característica ya instalada: $feature" -ForegroundColor Green
        }
    }
    
    # Importar módulo de administración de IIS
    Import-Module WebAdministration -ErrorAction Stop
    Write-Host "Módulo WebAdministration cargado" -ForegroundColor Green
}

# Función para crear estructura de directorios
function Create-DirectoryStructure {
    param([string]$Path)
    
    Write-Host "Creando estructura de directorios..." -ForegroundColor Yellow
    
    # Directorio raíz
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Host "Directorio raíz creado: $Path" -ForegroundColor Green
    }
    
    # Directorio público (anónimo)
    $publicPath = Join-Path $Path "general"
    if (-not (Test-Path $publicPath)) {
        New-Item -ItemType Directory -Path $publicPath -Force | Out-Null
        Write-Host "Directorio general creado: $publicPath" -ForegroundColor Green
    }
    
    # Directorios de grupos
    foreach ($group in $Script:Groups) {
        $groupPath = Join-Path $Path $group
        if (-not (Test-Path $groupPath)) {
            New-Item -ItemType Directory -Path $groupPath -Force | Out-Null
            Write-Host "Directorio de grupo creado: $groupPath" -ForegroundColor Green
        }
    }
    
    # Archivo de bienvenida para anónimo
    $welcomeFile = Join-Path $publicPath "LEEME.txt"
    if (-not (Test-Path $welcomeFile)) {
        "Bienvenido al servidor FTP - Directorio General" | Out-File -FilePath $welcomeFile -Encoding UTF8
    }
}

# Función para crear grupos locales
function Create-LocalGroups {
    Write-Host "Creando grupos locales..." -ForegroundColor Yellow
    
    foreach ($group in $Script:Groups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $group -Description "Grupo FTP $group"
            Write-Host "Grupo local creado: $group" -ForegroundColor Green
        } else {
            Write-Host "Grupo local ya existe: $group" -ForegroundColor Green
        }
    }
}

# Función para configurar permisos NTFS
function Set-NTFSPermissions {
    Write-Host "Configurando permisos NTFS..." -ForegroundColor Yellow
    
    # Permisos para directorio general (anónimo)
    $publicPath = Join-Path $Script:FTPRootPath "general"
    $acl = Get-Acl -Path $publicPath
    
    # Quitar herencia
    $acl.SetAccessRuleProtection($true, $false)
    
    # Permisos para IUSR (anónimo) - solo lectura
    $iusr = New-Object System.Security.Principal.NTAccount("IUSR")
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($iusr, "Read", "ContainerInherit, ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    
    # Permisos para usuarios autenticados - lectura/escritura
    foreach ($group in $Script:Groups) {
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($group, "Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
    }
    
    Set-Acl -Path $publicPath -AclObject $acl
    Write-Host "Permisos configurados para directorio general" -ForegroundColor Green
    
    # Permisos para directorios de grupos
    foreach ($group in $Script:Groups) {
        $groupPath = Join-Path $Script:FTPRootPath $group
        $acl = Get-Acl -Path $groupPath
        $acl.SetAccessRuleProtection($true, $false)
        
        # Acceso total para el grupo
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($group, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        
        # Denegar acceso a otros grupos
        $otherGroups = $Script:Groups | Where-Object { $_ -ne $group }
        foreach ($otherGroup in $otherGroups) {
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($otherGroup, "Read", "ContainerInherit, ObjectInherit", "None", "Deny")
            $acl.AddAccessRule($accessRule)
        }
        
        Set-Acl -Path $groupPath -AclObject $acl
        Write-Host "Permisos configurados para directorio: $group" -ForegroundColor Green
    }
}

# Función para configurar sitio FTP
function Configure-FtpSite {
    Write-Host "Configurando sitio FTP en IIS..." -ForegroundColor Yellow
    
    # Crear sitio FTP si no existe
    if (-not (Get-Website -Name $Script:FTPSiteName -ErrorAction SilentlyContinue)) {
        New-WebFtpSite -Name $Script:FTPSiteName -Port 21 -PhysicalPath $Script:FTPRootPath
        Write-Host "Sitio FTP creado: $Script:FTPSiteName" -ForegroundColor Green
    } else {
        Write-Host "Sitio FTP ya existe: $Script:FTPSiteName" -ForegroundColor Green
    }
    
    $sitePath = "IIS:\Sites\$Script:FTPSiteName"
    
    # Configurar autenticación
    Set-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/anonymousAuthentication" -Name enabled -Value $true -PSPath $sitePath
    Set-WebConfigurationProperty -Filter "/system.ftpServer/security/authentication/basicAuthentication" -Name enabled -Value $true -PSPath $sitePath
    Write-Host "Autenticación configurada" -ForegroundColor Green
    
    # Configurar reglas de autorización
    # Limpiar reglas existentes
    Clear-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath $sitePath
    
    # Regla para anónimo (solo lectura en general)
    Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath $sitePath -Value @{
        accessType="Allow"
        users="?"
        permissions="Read"
    }
    
    # Reglas para grupos autenticados
    foreach ($group in $Script:Groups) {
        Add-WebConfiguration -Filter "/system.ftpServer/security/authorization" -PSPath $sitePath -Value @{
            accessType="Allow"
            roles=$group
            permissions="Read, Write"
        }
    }
    
    Write-Host "Reglas de autorización configuradas" -ForegroundColor Green
    
    # Iniciar sitio
    Start-WebSite -Name $Script:FTPSiteName
}

# Función para crear usuario
function Create-User {
    Write-Host "--- Crear Nuevo Usuario ---" -ForegroundColor Yellow
    
    $username = Read-Host "Nombre de usuario"
    
    # Verificar si usuario existe
    try {
        $existingUser = Get-LocalUser -Name $username -ErrorAction Stop
        Write-Host "El usuario $username ya existe" -ForegroundColor Red
        return
    } catch {
        # Usuario no existe, continuar
    }
    
    $password = Read-Host "Contraseña" -AsSecureString
    $password2 = Read-Host "Confirmar contraseña" -AsSecureString
    
    # Convertir a texto plano para comparar
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password2)
    $plainPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
    
    if ($plainPassword -ne $plainPassword2) {
        Write-Host "Las contraseñas no coinciden" -ForegroundColor Red
        return
    }
    
    Write-Host "Seleccione grupo:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Script:Groups.Count; $i++) {
        Write-Host "$($i+1). $($Script:Groups[$i])"
    }
    $groupChoice = Read-Host "Opción"
    $group = $Script:Groups[$groupChoice - 1]
    
    if (-not $group) {
        Write-Host "Selección inválida" -ForegroundColor Red
        return
    }
    
    # Crear usuario local
    try {
        New-LocalUser -Name $username -Password $password -FullName $username -Description "Usuario FTP"
        Write-Host "Usuario local creado: $username" -ForegroundColor Green
        
        # Agregar al grupo
        Add-LocalGroupMember -Group $group -Member $username
        Write-Host "Usuario agregado al grupo: $group" -ForegroundColor Green
        
        # Crear directorio personal
        $userDir = Join-Path $Script:FTPRootPath $username
        New-Item -ItemType Directory -Path $userDir -Force | Out-Null
        
        # Configurar permisos del directorio personal
        $acl = Get-Acl -Path $userDir
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $userDir -AclObject $acl
        
        # Agregar a lista de usuarios FTP
        "$username,$group" | Out-File -FilePath $Script:FTPUserList -Append
        
        # Crear archivo de bienvenida
        $welcomeFile = Join-Path $userDir "README.txt"
        "Directorio personal de $username" | Out-File -FilePath $welcomeFile -Encoding UTF8
        
        Write-Host "Usuario $username creado exitosamente en grupo $group" -ForegroundColor Green
        
        # Configurar reglas de autorización específicas para el usuario
        $sitePath = "IIS:\Sites\$Script:FTPSiteName"
        
        # Crear aplicación virtual para el usuario
        New-WebApplication -Site $Script:FTPSiteName -Name $username -PhysicalPath $userDir
        
    } catch {
        Write-Host "Error al crear usuario: $_" -ForegroundColor Red
    }
}

# Función para listar usuarios
function List-Users {
    Write-Host "=== Usuarios FTP y sus grupos ===" -ForegroundColor Cyan
    
    if (Test-Path $Script:FTPUserList) {
        $users = Get-Content $Script:FTPUserList
        foreach ($user in $users) {
            $parts = $user.Split(',')
            if ($parts.Count -eq 2) {
                Write-Host "$($parts[0]): $($parts[1])" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "No hay usuarios FTP configurados" -ForegroundColor Yellow
    }
}

# Función para cambiar grupo de usuario
function Change-UserGroup {
    Write-Host "--- Cambiar Grupo de Usuario ---" -ForegroundColor Yellow
    
    List-Users
    Write-Host ""
    $username = Read-Host "Nombre del usuario"
    
    # Verificar si usuario existe en lista
    if (-not (Test-Path $Script:FTPUserList)) {
        Write-Host "No hay usuarios configurados" -ForegroundColor Red
        return
    }
    
    $users = Get-Content $Script:FTPUserList
    $userFound = $false
    $newContent = @()
    
    foreach ($user in $users) {
        $parts = $user.Split(',')
        if ($parts[0] -eq $username) {
            $userFound = $true
            
            Write-Host "Seleccione nuevo grupo:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $Script:Groups.Count; $i++) {
                Write-Host "$($i+1). $($Script:Groups[$i])"
            }
            $groupChoice = Read-Host "Opción"
            $newGroup = $Script:Groups[$groupChoice - 1]
            
            if ($newGroup) {
                # Actualizar grupo en sistema
                foreach ($group in $Script:Groups) {
                    try {
                        Remove-LocalGroupMember -Group $group -Member $username -ErrorAction SilentlyContinue
                    } catch {}
                }
                Add-LocalGroupMember -Group $newGroup -Member $username
                
                # Actualizar archivo de lista
                $newContent += "$username,$newGroup"
                Write-Host "Usuario $username ahora pertenece al grupo $newGroup" -ForegroundColor Green
            } else {
                $newContent += $user
                Write-Host "Selección inválida" -ForegroundColor Red
            }
        } else {
            $newContent += $user
        }
    }
    
    if ($userFound) {
        $newContent | Out-File -FilePath $Script:FTPUserList
    } else {
        Write-Host "Usuario no encontrado" -ForegroundColor Red
    }
}

# Función para instalación completa
function Install-Ftp {
    Write-Host "Iniciando instalación completa..." -ForegroundColor Yellow
    
    Install-WindowsFeaturesIfNeeded
    Create-DirectoryStructure -Path $Script:FTPRootPath
    Create-LocalGroups
    Set-NTFSPermissions
    Configure-FtpSite
    
    $createUsers = Read-Host "¿Desea crear usuarios ahora? (s/N)"
    if ($createUsers -eq 's') {
        $numUsers = Read-Host "Número de usuarios a crear"
        for ($i = 1; $i -le [int]$numUsers; $i++) {
            Write-Host "Usuario $i de $numUsers" -ForegroundColor Yellow
            Create-User
        }
    }
    
    Write-Host "Instalación completada" -ForegroundColor Green
}

# Función para eliminar configuración
function Uninstall-Ftp {
    Write-Host "--- Eliminar Configuración FTP ---" -ForegroundColor Red
    
    $confirm = Read-Host "¿Esta seguro? (s/N)"
    if ($confirm -eq 's') {
        # Detener y eliminar sitio web
        if (Get-Website -Name $Script:FTPSiteName -ErrorAction SilentlyContinue) {
            Stop-WebSite -Name $Script:FTPSiteName
            Remove-Website -Name $Script:FTPSiteName
            Write-Host "Sitio FTP eliminado" -ForegroundColor Green
        }
        
        # Eliminar usuarios
        if (Test-Path $Script:FTPUserList) {
            $users = Get-Content $Script:FTPUserList
            foreach ($user in $users) {
                $parts = $user.Split(',')
                try {
                    Remove-LocalUser -Name $parts[0] -ErrorAction SilentlyContinue
                    Write-Host "Usuario $($parts[0]) eliminado" -ForegroundColor Green
                } catch {}
            }
        }
        
        # Eliminar grupos
        foreach ($group in $Script:Groups) {
            try {
                Remove-LocalGroup -Name $group -ErrorAction SilentlyContinue
                Write-Host "Grupo $group eliminado" -ForegroundColor Green
            } catch {}
        }
        
        # Eliminar directorios
        $removeDirs = Read-Host "¿Eliminar directorio $Script:FTPRootPath? (s/N)"
        if ($removeDirs -eq 's') {
            if (Test-Path $Script:FTPRootPath) {
                Remove-Item -Path $Script:FTPRootPath -Recurse -Force
                Write-Host "Directorios eliminados" -ForegroundColor Green
            }
        }
        
        Write-Host "Configuración FTP eliminada" -ForegroundColor Green
    } else {
        Write-Host "Operación cancelada" -ForegroundColor Yellow
    }
}

# Main
do {
    Show-Menu
    $choice = Read-Host "Seleccione una opción"
    
    switch ($choice) {
        '1' { Install-Ftp; Read-Host "Presione Enter para continuar..." }
        '2' { Create-User; Read-Host "Presione Enter para continuar..." }
        '3' { List-Users; Read-Host "Presione Enter para continuar..." }
        '4' { Change-UserGroup; Read-Host "Presione Enter para continuar..." }
        '5' { Uninstall-Ftp; Read-Host "Presione Enter para continuar..." }
        '6' { Write-Host "¡Hasta luego!" -ForegroundColor Green }
        default { Write-Host "Opción inválida" -ForegroundColor Red; Read-Host "Presione Enter para continuar..." }
    }
} while ($choice -ne '6')
