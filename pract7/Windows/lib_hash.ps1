# =============================================================================
# lib_hash.ps1 - Verificacion de integridad de archivos (SHA256 / MD5)
# =============================================================================

# -----------------------------------------------------------------------------
# Calcular hash local de un archivo
# -----------------------------------------------------------------------------
function Get-HashArchivo {
    param(
        [string]$Archivo,
        [string]$Algoritmo = "SHA256"
    )
    if (-not (Test-Path $Archivo)) {
        Write-Host "  ERROR: Archivo no encontrado para calcular hash: $Archivo"
        return $null
    }
    $resultado = Get-FileHash -Path $Archivo -Algorithm $Algoritmo
    return $resultado.Hash.ToUpper()
}

# -----------------------------------------------------------------------------
# Comparar hash local contra hash esperado
# Devuelve $true si coinciden, $false si no
# -----------------------------------------------------------------------------
function Verificar-Hash {
    param(
        [string]$Archivo,
        [string]$HashEsperado,
        [string]$Algoritmo = "SHA256"
    )
    Write-Host "  Verificando integridad de: $(Split-Path $Archivo -Leaf)"
    $hashLocal = Get-HashArchivo -Archivo $Archivo -Algoritmo $Algoritmo
    if ($null -eq $hashLocal) { return $false }

    $esperado = $HashEsperado.Trim().ToUpper()
    # El archivo .sha256 puede tener formato "SHA256: HASH" o solo el hash
    if ($esperado -match "SHA256:\s*([A-F0-9]{64})") { $esperado = $Matches[1] }

    Write-Host "  Hash calculado : $hashLocal"
    Write-Host "  Hash esperado  : $esperado"

    if ($hashLocal -eq $esperado) {
        Write-Host "  RESULTADO: OK - El archivo es integro."
        return $true
    } else {
        Write-Host "  RESULTADO: FALLO - El archivo puede estar corrupto o modificado."
        return $false
    }
}

# -----------------------------------------------------------------------------
# Leer hash desde un archivo .sha256 local (usado al instalar desde FTP)
# Formato soportado:
#   SHA256: AABB...
#   o solo: AABB...
# -----------------------------------------------------------------------------
function Leer-HashDesdeArchivo {
    param([string]$ArchivoHash)
    if (-not (Test-Path $ArchivoHash)) { return $null }
    $contenido = Get-Content $ArchivoHash -Raw
    if ($contenido -match "SHA256:\s*([A-Fa-f0-9]{64})") { return $Matches[1].ToUpper() }
    $primera = ($contenido -split "`n")[0].Trim()
    if ($primera -match "^[A-Fa-f0-9]{64}$") { return $primera.ToUpper() }
    return $null
}

# -----------------------------------------------------------------------------
# Generar archivo .sha256 para un binario (usado al preparar el repositorio FTP)
# -----------------------------------------------------------------------------
function Generar-Archivo-Hash {
    param(
        [string]$Archivo,
        [string]$Algoritmo = "SHA256"
    )
    $hash       = Get-HashArchivo -Archivo $Archivo -Algoritmo $Algoritmo
    if ($null -eq $hash) { return }
    $archivoOut = "$Archivo.sha256"
    $nombre     = Split-Path $Archivo -Leaf
    @"
SHA256: $hash
Archivo: $nombre
Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@ | Set-Content $archivoOut -Encoding UTF8
    Write-Host "  Hash guardado en: $archivoOut"
}

# -----------------------------------------------------------------------------
# Flujo interactivo: verificar integridad de un archivo local (opcion 5 menu)
# -----------------------------------------------------------------------------
function Flujo-Verificar-Hash {
    Write-Host ""
    Write-Linea
    Write-Host "  VERIFICACION DE INTEGRIDAD"
    Write-Linea
    Write-Host "  1) Verificar archivo con hash ingresado manualmente"
    Write-Host "  2) Verificar archivo con archivo .sha256 local"
    Write-Host "  3) Generar archivo .sha256 para un binario"
    Write-Host "  0) Volver"
    Write-Linea
    $opc = Read-Host "  Opcion"

    switch ($opc) {
        "1" {
            $archivo = Read-Host "  Ruta del archivo a verificar"
            $hash    = Read-Host "  Hash SHA256 esperado"
            Verificar-Hash -Archivo $archivo -HashEsperado $hash
            Pausar
        }
        "2" {
            $archivo     = Read-Host "  Ruta del archivo a verificar"
            $archivoHash = Read-Host "  Ruta del archivo .sha256 (Enter = mismo nombre + .sha256)"
            if ([string]::IsNullOrWhiteSpace($archivoHash)) { $archivoHash = "$archivo.sha256" }
            $hashLeido = Leer-HashDesdeArchivo -ArchivoHash $archivoHash
            if ($null -eq $hashLeido) {
                Write-Host "  No se pudo leer el hash desde: $archivoHash"
            } else {
                Verificar-Hash -Archivo $archivo -HashEsperado $hashLeido
            }
            Pausar
        }
        "3" {
            $archivo = Read-Host "  Ruta del binario para generar .sha256"
            Generar-Archivo-Hash -Archivo $archivo
            Pausar
        }
        "0" { return }
        default { Write-Host "  Opcion invalida." }
    }
}
