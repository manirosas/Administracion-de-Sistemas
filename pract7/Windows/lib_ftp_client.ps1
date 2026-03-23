# =============================================================================
# lib_ftp_client.ps1 - Cliente FTP dinamico para repositorio privado
# =============================================================================

# Ignorar errores de certificado SSL (certs autofirmados en el servidor FTP)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# -----------------------------------------------------------------------------
# Funcion base: ejecutar una solicitud FTP y devolver la respuesta como texto
# -----------------------------------------------------------------------------
function Invoke-FTPRequest {
    param(
        [string]$Url,
        [string]$Method,
        [System.Net.NetworkCredential]$Credenciales,
        [bool]$UseSSL = $false
    )
    $req              = [System.Net.WebRequest]::Create($Url)
    $req.Credentials  = $Credenciales
    $req.EnableSsl    = $UseSSL
    $req.Method       = $Method
    try {
        $resp   = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $texto  = $reader.ReadToEnd()
        $reader.Close(); $resp.Close()
        return $texto
    } catch {
        # Si falla con SSL, reintentar sin SSL
        if ($UseSSL) {
            $req2              = [System.Net.WebRequest]::Create($Url)
            $req2.Credentials  = $Credenciales
            $req2.EnableSsl    = $false
            $req2.Method       = $Method
            $resp2   = $req2.GetResponse()
            $reader2 = New-Object System.IO.StreamReader($resp2.GetResponseStream())
            $texto2  = $reader2.ReadToEnd()
            $reader2.Close(); $resp2.Close()
            return $texto2
        }
        throw
    }
}

# -----------------------------------------------------------------------------
# Listar contenido de un directorio FTP
# Devuelve array de strings con los nombres (archivos y carpetas)
# -----------------------------------------------------------------------------
function Get-FTPDirectoryListing {
    param(
        [string]$Url,
        [System.Net.NetworkCredential]$Credenciales
    )
    if (-not $Url.EndsWith("/")) { $Url += "/" }
    try {
        $listado = Invoke-FTPRequest -Url $Url `
            -Method ([System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails) `
            -Credenciales $Credenciales -UseSSL $true
        # Parsear lineas tipo: drwxr-xr-x ... NombreCarpeta
        $items = @()
        foreach ($linea in ($listado -split "`n")) {
            $linea = $linea.Trim()
            if ([string]::IsNullOrWhiteSpace($linea)) { continue }
            $partes = $linea -split '\s+'
            $nombre = $partes[-1]
            $esDir  = $linea.StartsWith("d")
            $items += [PSCustomObject]@{ Nombre=$nombre; EsDirectorio=$esDir; LineaCompleta=$linea }
        }
        return $items
    } catch {
        Write-Host "  ERROR al listar $Url : $_"
        return @()
    }
}

# -----------------------------------------------------------------------------
# Descargar un archivo desde FTP
# -----------------------------------------------------------------------------
function Descargar-Archivo-FTP {
    param(
        [string]$Url,
        [System.Net.NetworkCredential]$Credenciales,
        [string]$Destino
    )
    try {
        $req           = [System.Net.WebRequest]::Create($Url)
        $req.Credentials = $Credenciales
        $req.EnableSsl  = $true
        $req.Method     = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        try { $resp = $req.GetResponse() }
        catch {
            $req2           = [System.Net.WebRequest]::Create($Url)
            $req2.Credentials = $Credenciales
            $req2.EnableSsl  = $false
            $req2.Method     = [System.Net.WebRequestMethods+Ftp]::DownloadFile
            $resp = $req2.GetResponse()
        }
        $stream  = $resp.GetResponseStream()
        $archivo = [System.IO.File]::Create($Destino)
        $stream.CopyTo($archivo)
        $archivo.Close(); $stream.Close(); $resp.Close()
        Write-Host "  Descargado: $Destino"
        return $true
    } catch {
        Write-Host "  ERROR al descargar: $_"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Obtener el hash SHA256 remoto desde el archivo .sha256 del repositorio FTP
# -----------------------------------------------------------------------------
function Obtener-Hash-Remoto-FTP {
    param(
        [string]$UrlBase,
        [string]$NombreArchivo,
        [System.Net.NetworkCredential]$Credenciales
    )
    $urlHash = "$UrlBase$NombreArchivo.sha256"
    try {
        $contenido = Invoke-FTPRequest -Url $urlHash `
            -Method ([System.Net.WebRequestMethods+Ftp]::DownloadFile) `
            -Credenciales $Credenciales -UseSSL $true
        # El archivo .sha256 tiene formato: "SHA256: AABBCC..."
        if ($contenido -match "SHA256:\s*([A-Fa-f0-9]{64})") {
            return $Matches[1].ToUpper()
        }
        # O puede ser solo el hash en la primera linea
        $primera = ($contenido -split "`n")[0].Trim()
        if ($primera -match "^[A-Fa-f0-9]{64}$") { return $primera.ToUpper() }
        return $null
    } catch {
        return $null
    }
}

# -----------------------------------------------------------------------------
# Navegacion interactiva del repositorio FTP
# Devuelve objeto con Url, UrlBase, Nombre del archivo seleccionado
# -----------------------------------------------------------------------------
function Navegar-Y-Seleccionar-FTP {
    param(
        [string]$Servidor,
        [System.Net.NetworkCredential]$Credenciales,
        [string]$RutaInicial = "/"
    )
    if (-not $Servidor.EndsWith("/")) { $Servidor += "/" }
    $rutaActual = $Servidor.TrimEnd("/") + $RutaInicial
    if (-not $rutaActual.EndsWith("/")) { $rutaActual += "/" }

    Write-Host ""
    Write-Host "  Navegando repositorio FTP. Escribe 'exit' para cancelar."

    while ($true) {
        Write-Host ""
        Write-Host "  Ruta actual: $rutaActual"
        Write-Linea

        $items = Get-FTPDirectoryListing -Url $rutaActual -Credenciales $Credenciales

        if ($items.Count -eq 0) {
            Write-Host "  (directorio vacio o error de acceso)"
            $opc = Read-Host "  [exit=cancelar, ..=subir]"
            if ($opc -eq "exit") { return $null }
            if ($opc -eq "..") {
                $rutaActual = $rutaActual.TrimEnd("/")
                $rutaActual = $rutaActual.Substring(0, $rutaActual.LastIndexOf("/") + 1)
            }
            continue
        }

        # Separar directorios y archivos instaladores (.zip, .msi, .exe)
        $directorios = @($items | Where-Object { $_.EsDirectorio })
        $archivos    = @($items | Where-Object { -not $_.EsDirectorio -and
            ($_.Nombre -match "\.(zip|msi|exe|tar\.gz|deb|rpm)$") })

        $indice = 1
        $mapa   = @{}

        if ($directorios.Count -gt 0) {
            Write-Host "  --- Carpetas ---"
            foreach ($d in $directorios) {
                Write-Host ("  {0,3}) [DIR] {1}" -f $indice, $d.Nombre)
                $mapa[$indice] = @{ Tipo="DIR"; Item=$d }
                $indice++
            }
        }

        if ($archivos.Count -gt 0) {
            Write-Host "  --- Archivos instaladores ---"
            foreach ($a in $archivos) {
                Write-Host ("  {0,3}) [FILE] {1}" -f $indice, $a.Nombre)
                $mapa[$indice] = @{ Tipo="FILE"; Item=$a }
                $indice++
            }
        }

        Write-Host ("  {0,3}) Subir un nivel (..)" -f 0)
        Write-Linea

        $sel = Read-Host "  Seleccione"
        if ($sel -eq "exit") { return $null }

        if ($sel -eq "0") {
            $sinFin = $rutaActual.TrimEnd("/")
            if ($sinFin.Length -gt $Servidor.TrimEnd("/").Length) {
                $rutaActual = $sinFin.Substring(0, $sinFin.LastIndexOf("/") + 1)
            } else {
                Write-Host "  Ya estas en la raiz del servidor."
            }
            continue
        }

        if ($sel -notmatch '^\d+$' -or -not $mapa.ContainsKey([int]$sel)) {
            Write-Host "  Opcion invalida."
            continue
        }

        $elegido = $mapa[[int]$sel]

        if ($elegido.Tipo -eq "DIR") {
            $rutaActual = $rutaActual + $elegido.Item.Nombre + "/"
        } else {
            # Es un archivo: devolver info para descarga
            return @{
                Nombre  = $elegido.Item.Nombre
                Url     = $rutaActual + $elegido.Item.Nombre
                UrlBase = $rutaActual
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Instalar un binario descargado desde FTP
# -----------------------------------------------------------------------------
function Instalar-Desde-Archivo {
    param(
        [string]$Archivo,
        [string]$Tipo   # "Apache", "Nginx", "IIS"
    )
    if (-not (Test-Path $Archivo)) {
        Write-Host "  ERROR: Archivo no encontrado: $Archivo"
        return
    }

    $ext = [System.IO.Path]::GetExtension($Archivo).ToLower()

    switch ($Tipo) {
        "Apache" {
            if ($ext -eq ".zip") {
                $destino = "C:\Apache24"
                Write-Host "  Extrayendo Apache en $destino..."
                Expand-Archive -Path $Archivo -DestinationPath "C:\" -Force
                # Chocolatey deja la carpeta Apache24\Apache24, ajustar
                $sub = Get-ChildItem "C:\" -Filter "Apache24" -Directory | Select-Object -First 1
                if ($sub -and (Test-Path "$($sub.FullName)\Apache24")) {
                    Move-Item "$($sub.FullName)\Apache24\*" $sub.FullName -Force
                }
                $httpdExe = "$destino\bin\httpd.exe"
                if (Test-Path $httpdExe) {
                    & $httpdExe -k install
                    Start-Service Apache -ErrorAction SilentlyContinue
                    Write-Host "  Apache instalado y servicio iniciado."
                }
            }
        }
        "Nginx" {
            if ($ext -eq ".zip") {
                Write-Host "  Extrayendo Nginx en C:\tools..."
                New-Item -ItemType Directory "C:\tools" -Force | Out-Null
                Expand-Archive -Path $Archivo -DestinationPath "C:\tools" -Force
                $nginxDir = Get-ChildItem "C:\tools" -Filter "nginx*" -Directory |
                            Sort-Object Name -Descending | Select-Object -First 1
                if ($nginxDir) {
                    Start-Process "$($nginxDir.FullName)\nginx.exe" `
                        -WorkingDirectory $nginxDir.FullName -WindowStyle Hidden
                    Write-Host "  Nginx iniciado desde $($nginxDir.FullName)."
                }
            }
        }
        "IIS" {
            # IIS no tiene instalador separado; es un rol de Windows
            Write-Host "  IIS se instala como rol de Windows, no desde binario."
            Write-Host "  Ejecutando instalacion por rol..."
            Instalar-Servicio-IIS
        }
        default {
            if ($ext -eq ".msi") {
                Write-Host "  Instalando .msi silenciosamente..."
                Start-Process msiexec -ArgumentList "/i `"$Archivo`" /quiet /norestart" -Wait
            } elseif ($ext -eq ".exe") {
                Write-Host "  Ejecutando instalador .exe silenciosamente..."
                Start-Process $Archivo -ArgumentList "/S /silent /quiet" -Wait
            } else {
                Write-Host "  Extension '$ext' no soportada para instalacion automatica."
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Flujo interactivo del cliente FTP (opcion 4 del menu)
# -----------------------------------------------------------------------------
function Flujo-Cliente-FTP {
    Write-Host ""
    Write-Linea
    Write-Host "  CLIENTE FTP DINAMICO - REPOSITORIO PRIVADO"
    Write-Linea
    Write-Host "  1) Navegar y descargar archivo del repositorio"
    Write-Host "  2) Consola FTP interactiva (ls / cd / get)"
    Write-Host "  0) Volver"
    Write-Linea
    $opc = Read-Host "  Opcion"

    switch ($opc) {
        "1" {
            $cred = Pedir-Credenciales-FTP
            if (-not $cred) { return }
            $archivo = Navegar-Y-Seleccionar-FTP `
                -Servidor $cred.Servidor -Credenciales $cred.Cred -RutaInicial "/"
            if (-not $archivo) { Write-Host "  Cancelado."; Pausar; return }
            $destino = "$env:TEMP\$($archivo.Nombre)"
            Descargar-Archivo-FTP -Url $archivo.Url -Credenciales $cred.Cred -Destino $destino

            $hashRemoto = Obtener-Hash-Remoto-FTP `
                -UrlBase $archivo.UrlBase -NombreArchivo $archivo.Nombre -Credenciales $cred.Cred
            if ($hashRemoto) {
                Verificar-Hash -Archivo $destino -HashEsperado $hashRemoto | Out-Null
            } else {
                Write-Host "  AVISO: Sin .sha256 en el servidor. No se verifico integridad."
            }
            Pausar
        }
        "2" {
            $cred = Pedir-Credenciales-FTP
            if (-not $cred) { return }
            Consola-FTP-Interactiva -Servidor $cred.Servidor -Credenciales $cred.Cred
        }
        "0" { return }
        default { Write-Host "  Opcion invalida." }
    }
}

# -----------------------------------------------------------------------------
# Consola FTP interactiva (ls / cd / get / exit)
# -----------------------------------------------------------------------------
function Consola-FTP-Interactiva {
    param(
        [string]$Servidor,
        [System.Net.NetworkCredential]$Credenciales
    )
    if (-not $Servidor.EndsWith("/")) { $Servidor += "/" }
    $rutaActual = $Servidor
    Write-Host "  Consola FTP. Comandos: ls | cd <dir> | cd .. | get <archivo> | exit"

    while ($true) {
        $cmd = Read-Host "  FTP [$rutaActual]>"
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $partes  = $cmd.Trim() -split '\s+', 2
        $comando = $partes[0].ToLower()
        $param   = if ($partes.Count -gt 1) { $partes[1] } else { "" }

        switch ($comando) {
            "ls" {
                $items = Get-FTPDirectoryListing -Url $rutaActual -Credenciales $Credenciales
                if ($items.Count -eq 0) { Write-Host "  (vacio)"; break }
                $items | ForEach-Object {
                    $tipo = if ($_.EsDirectorio) { "[DIR] " } else { "[FILE]" }
                    Write-Host "  $tipo $($_.Nombre)"
                }
            }
            "cd" {
                if ($param -eq "..") {
                    $sinFin = $rutaActual.TrimEnd("/")
                    if ($sinFin -ne $Servidor.TrimEnd("/")) {
                        $rutaActual = $sinFin.Substring(0, $sinFin.LastIndexOf("/") + 1)
                    }
                } elseif ($param) {
                    $rutaActual = $rutaActual + $param + "/"
                } else { Write-Host "  Uso: cd <carpeta> o cd .." }
            }
            "get" {
                if (-not $param) { Write-Host "  Uso: get <archivo>"; break }
                $destino = Join-Path (Get-Location).Path $param
                Descargar-Archivo-FTP -Url "$rutaActual$param" `
                    -Credenciales $Credenciales -Destino $destino
            }
            "exit" { return }
            default { Write-Host "  Comando '$comando' no reconocido." }
        }
    }
}
