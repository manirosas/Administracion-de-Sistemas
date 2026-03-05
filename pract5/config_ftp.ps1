# =================================================================
# SCRIPT FTP IIS - WINDOWS SERVER 2022 (POWERSHELL)
# =================================================================

# 1. Instalación Idempotente de Roles
echo "Instalando Roles de Servidor Web (IIS) y Servicio FTP..."
Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console, Web-Ftp-Server -IncludeManagementTools

Import-Module WebAdministration

# 2. Configuración de Estructura Física
$basePath = "C:\inetpub\ftproot\SistemaFTP"
$sharedPath = "C:\ftp_maestro"

# Crear carpetas maestras (Los "Orígenes")
$carpetasMaestras = @("general", "reprobados", "recursadores")
foreach ($folder in $carpetasMaestras) {
    if (!(Test-Path "$sharedPath\$folder")) { 
        New-Item -ItemType Directory -Path "$sharedPath\$folder" | Out-Null 
    }
}

# 3. Crear Grupos Locales
$grupos = @("reprobados", "recursadores")
foreach ($g in $grupos) {
    if (!(Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $g -Description "Grupo FTP $g"
    }
}

# 4. Configurar Sitio FTP en IIS
$siteName = "ServidorFTP_Clase"
if (!(Get-FtpSite -Name $siteName -ErrorAction SilentlyContinue)) {
    New-FtpSite -Name $siteName -BindingInformation "*:21:" -PhysicalPath $basePath
}

# Habilitar Autenticación Básica
Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true

# Configurar Aislamiento de Usuarios (User Isolation)
# Esto hace que busquen la carpeta con su nombre de usuario al entrar
Set-ItemProperty "IIS:\Sites\$siteName" -Name ftpServer.userIsolation.mode -Value "IsolateUsers"

# --- FUNCIONES DEL MENÚ ---

function Gestionar-Usuarios {
    $n = Read-Host "Número de usuarios a crear"
    for ($i=1; $i -le $n; $i++) {
        $username = Read-Host "Nombre de usuario"
        $password = Read-Host -AsSecureString "Contraseña"
        $g_opt = Read-Host "Grupo: 1) reprobados | 2) recursadores"
        $grupo = if ($g_opt -eq "1") { "reprobados" } else { "recursadores" }

        # Crear Usuario Local
        if (!(Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $username -Password $password -FullName $username -Description "Usuario FTP" | Out-Null
            Add-LocalGroupMember -Group $grupo -Member $username
        }

        # Crear Directorio Físico del Usuario (Para el aislamiento)
        $userPath = "$basePath\LocalUser\$username"
        if (!(Test-Path $userPath)) { New-Item -ItemType Directory -Path $userPath | Out-Null }

        # --- DIRECTORIOS VIRTUALES (Equivalente a BIND MOUNT) ---
        # 1. Carpeta Personal
        $personalPath = "$userPath\$username"
        if (!(Test-Path $personalPath)) { New-Item -ItemType Directory -Path $personalPath | Out-Null }
        
        # 2. Virtual para General
        if (!(Get-WebVirtualDirectory -Site $siteName -Name "general" -Resource "LocalUser/$username")) {
            New-WebVirtualDirectory -Site $siteName -Name "general" -PhysicalPath "$sharedPath\general" -Resource "LocalUser/$username"
        }

        # 3. Virtual para Grupo
        if (!(Get-WebVirtualDirectory -Site $siteName -Name $grupo -Resource "LocalUser/$username")) {
            New-WebVirtualDirectory -Site $siteName -Name $grupo -PhysicalPath "$sharedPath\$grupo" -Resource "LocalUser/$username"
        }

        # --- PERMISOS NTFS ---
        # Permiso en su carpeta personal
        $acl = Get-Acl $personalPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($rule)
        Set-Acl $personalPath $acl

        # Permisos en las carpetas maestras (para que el grupo escriba)
        $aclMaster = Get-Acl "$sharedPath\$grupo"
        $ruleG = New-Object System.Security.AccessControl.FileSystemAccessRule($grupo, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $aclMaster.SetAccessRule($ruleG)
        Set-Acl "$sharedPath\$grupo" $aclMaster

        # Reglas de Autorización FTP en IIS
        Add-WebConfiguration "/system.ftpServer/security/authorization" -value @{accessType="Allow";roles=$grupo;permissions="Read, Write"} -PSPath "IIS:\Sites\$siteName/LocalUser/$username"

        echo "Usuario $username configurado y vinculado."
    }
}

function Listar-Usuarios {
    echo "`nUSUARIO`t`tGRUPO"
    echo "--------------------------"
    Get-LocalGroupMember -Group "reprobados" | Select-Object @{Name="User";Expression={$_.Name}}, @{Name="Group";Expression={"reprobados"}}
    Get-LocalGroupMember -Group "recursadores" | Select-Object @{Name="User";Expression={$_.Name}}, @{Name="Group";Expression={"recursadores"}}
}

function Borrar-Todo {
    $confirm = Read-Host "¿Eliminar TODA la configuración y usuarios? (S/N)"
    if ($confirm -eq "S") {
        Remove-WebSite -Name $siteName -Confirm:$false
        Remove-Item $basePath -Recurse -Force -ErrorAction SilentlyContinue
        # Nota: Los usuarios deben borrarse manualmente o con Remove-LocalUser
        echo "Sitio FTP eliminado. Directorios limpiados."
    }
}

# --- MENÚ ---
do {
    echo "`n1. Instalar/Configurar FTP`n2. Crear Usuarios`n3. Listar Usuarios`n4. Borrar Todo`n5. Salir"
    $op = Read-Host "Seleccione"
    switch ($op) {
        "1" { instalar_configurar_ftp }
        "2" { Gestionar-Usuarios }
        "3" { Listar-Usuarios }
        "4" { Borrar-Todo }
    }
} while ($op -ne "5")
