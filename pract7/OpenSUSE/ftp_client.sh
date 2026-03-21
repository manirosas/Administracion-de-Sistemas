#!/bin/bash
# =================================================================
# FTP_CLIENT.SH — Cliente FTP dinámico
# Navega /http/Linux/{Servicio}/, descarga binario y verifica hash
# Importar con: source ftp_client.sh
# REQUIERE: source ssl_utils.sh (para linea/titulo)
# =================================================================

FTP_DESCARGA_DIR="/tmp/pract7_descargas"

# =================================================================
# VERIFICAR QUE CURL ESTÁ DISPONIBLE
# =================================================================
_ftp_verificar_curl() {
    if ! command -v curl &>/dev/null; then
        echo "  Instalando curl..."
        zypper install -y curl &>/dev/null
        if ! command -v curl &>/dev/null; then
            echo "  ERROR CRÍTICO: No se pudo instalar curl."
            return 1
        fi
    fi
    return 0
}

# =================================================================
# LISTAR CONTENIDO DE UNA RUTA FTP
# Devuelve lista de nombres (un elemento por línea)
# =================================================================
ftp_listar() {
    local ruta="$1"
    _ftp_verificar_curl || return 1

    curl --silent \
         --connect-timeout 10 \
         --user "${FTP_USER}:${FTP_PASS}" \
         --list-only \
         "ftp://${FTP_HOST}${ruta}" 2>/dev/null
}

# =================================================================
# DESCARGAR UN ARCHIVO DESDE FTP
# $1 = ruta remota completa (ej: /http/Linux/Apache/apache2.rpm)
# $2 = ruta local destino
# =================================================================
ftp_descargar() {
    local ruta_remota="$1"
    local ruta_local="$2"

    _ftp_verificar_curl || return 1

    echo "  Descargando: $(basename "$ruta_remota")"

    curl --silent \
         --show-error \
         --connect-timeout 15 \
         --user "${FTP_USER}:${FTP_PASS}" \
         --output "$ruta_local" \
         "ftp://${FTP_HOST}${ruta_remota}" 2>&1

    local rc=$?
    if [[ $rc -eq 0 && -f "$ruta_local" && -s "$ruta_local" ]]; then
        local tam; tam=$(du -sh "$ruta_local" 2>/dev/null | cut -f1)
        echo "  ✓ $(basename "$ruta_local") ($tam)"
        return 0
    else
        echo "  ✗ Fallo al descargar (curl rc=$rc)"
        # Limpiar archivo vacío si quedó
        [[ -f "$ruta_local" ]] && rm -f "$ruta_local"
        return 1
    fi
}

# =================================================================
# VERIFICAR INTEGRIDAD SHA256
# $1 = ruta del binario descargado
# $2 = ruta del archivo .sha256 descargado
# =================================================================
verificar_integridad() {
    local archivo="$1"
    local hash_file="$2"

    if [[ ! -f "$hash_file" ]]; then
        echo "  ✗ No se encontró el .sha256 para verificación."
        return 1
    fi

    if [[ ! -f "$archivo" ]]; then
        echo "  ✗ No se encontró el archivo a verificar: $archivo"
        return 1
    fi

    # El .sha256 puede contener solo el hash O "hash  nombre_archivo"
    # Normalizamos extrayendo solo el hash (primer campo)
    local hash_esperado; hash_esperado=$(awk '{print $1}' "$hash_file" \
        | tr '[:upper:]' '[:lower:]')
    local hash_real;     hash_real=$(sha256sum "$archivo" \
        | awk '{print $1}' | tr '[:upper:]' '[:lower:]')

    echo ""
    echo "  ┌── Verificación de integridad SHA256 ──────────────┐"
    echo "  │ Archivo  : $(basename "$archivo")"
    printf "  │ Esperado : %.52s\n" "$hash_esperado"
    printf "  │ Calculado: %.52s\n" "$hash_real"

    if [[ "$hash_esperado" == "$hash_real" ]]; then
        echo "  │ Resultado: ✓ ÍNTEGRO — archivo no fue corrompido  │"
        echo "  └────────────────────────────────────────────────────┘"
        return 0
    else
        echo "  │ Resultado: ✗ FALLO — hashes no coinciden          │"
        echo "  └────────────────────────────────────────────────────┘"
        return 1
    fi
}

# =================================================================
# NAVEGACIÓN INTERACTIVA DEL REPOSITORIO FTP
# $1 = servicio sugerido (Apache|Nginx|Tomcat) — puede estar vacío
# Resultado: escribe ruta local del binario en $ARCHIVO_DESCARGADO
# =================================================================
ftp_seleccionar_e_instalar() {
    local servicio_solicitado="${1:-}"

    mkdir -p "$FTP_DESCARGA_DIR"

    # --- Verificar conectividad básica al FTP ---
    echo ""
    echo "  Verificando conexión FTP: $FTP_HOST ..."
    _ftp_verificar_curl || return 1

    if ! curl --silent \
              --connect-timeout 10 \
              --user "${FTP_USER}:${FTP_PASS}" \
              --list-only \
              "ftp://${FTP_HOST}/" &>/dev/null; then
        echo "  ✗ No se puede conectar al servidor FTP."
        echo ""
        echo "  Verifique:"
        echo "    - IP/hostname: $FTP_HOST"
        echo "    - Usuario    : $FTP_USER"
        echo "    - vsftpd activo en el servidor FTP"
        echo "    - Puerto 21 abierto en firewall"
        return 1
    fi
    echo "  ✓ Conexión FTP OK."

    # --- Verificar que existe el repositorio HTTP en el FTP ---
    local lista_servicios
    lista_servicios=$(ftp_listar "/http/Linux/")

    if [[ -z "$lista_servicios" ]]; then
        echo ""
        echo "  ✗ No se encontró el repositorio en /http/Linux/"
        echo ""
        echo "  El servidor FTP no tiene la estructura esperada."
        echo "  Ejecute setup_repo.sh en el servidor FTP primero:"
        echo "    sudo bash setup_repo.sh   (opción 1)"
        return 1
    fi

    # --- Listar servicios disponibles ---
    echo ""
    echo "  Servicios en /http/Linux/:"
    local servicios=()
    local i=1
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        servicios+=("$item")
        printf "    %2d) %s\n" "$i" "$item"
        (( i++ ))
    done <<< "$lista_servicios"

    if [[ ${#servicios[@]} -eq 0 ]]; then
        echo "  ✗ No hay servicios listados."
        return 1
    fi

    # Auto-seleccionar si se pasó un servicio como parámetro
    local servicio_dir=""
    if [[ -n "$servicio_solicitado" ]]; then
        for s in "${servicios[@]}"; do
            if [[ "${s,,}" == "${servicio_solicitado,,}" ]]; then
                servicio_dir="$s"
                echo "  → Auto-seleccionado: $servicio_dir"
                break
            fi
        done
    fi

    # Selección manual si no se auto-seleccionó
    if [[ -z "$servicio_dir" ]]; then
        echo ""
        read -rp "  Seleccione servicio [1-${#servicios[@]}]: " sel_srv
        if ! [[ "$sel_srv" =~ ^[0-9]+$ ]] || \
           (( sel_srv < 1 || sel_srv > ${#servicios[@]} )); then
            echo "  Selección inválida."
            return 1
        fi
        servicio_dir="${servicios[$((sel_srv-1))]}"
    fi

    local ruta_srv="/http/Linux/$servicio_dir"

    # --- Listar archivos instalables en el servicio ---
    echo ""
    echo "  Archivos en $ruta_srv/:"
    local lista_archivos; lista_archivos=$(ftp_listar "${ruta_srv}/")

    local archivos=()
    i=1
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        # Solo binarios, excluir .sha256 e INDEX.txt
        if [[ "$item" =~ \.(rpm|deb|tar\.gz|tgz|zip|msi)$ ]]; then
            archivos+=("$item")
            printf "    %2d) %s\n" "$i" "$item"
            (( i++ ))
        fi
    done <<< "$lista_archivos"

    if [[ ${#archivos[@]} -eq 0 ]]; then
        echo "  ✗ No hay binarios instalables en $ruta_srv."
        echo "  (Solo se encontraron .sha256 o el directorio está vacío)"
        return 1
    fi

    # --- Seleccionar archivo ---
    echo ""
    read -rp "  Seleccione archivo [1-${#archivos[@]}]: " sel_arch
    if ! [[ "$sel_arch" =~ ^[0-9]+$ ]] || \
       (( sel_arch < 1 || sel_arch > ${#archivos[@]} )); then
        echo "  Selección inválida."
        return 1
    fi

    local nombre_bin="${archivos[$((sel_arch-1))]}"
    local local_bin="$FTP_DESCARGA_DIR/$nombre_bin"
    local local_sha="$FTP_DESCARGA_DIR/${nombre_bin}.sha256"

    # --- Descargar binario ---
    echo ""
    ftp_descargar "${ruta_srv}/${nombre_bin}" "$local_bin" || return 1

    # --- Descargar .sha256 (no fatal si falla) ---
    echo "  Descargando checksum..."
    ftp_descargar "${ruta_srv}/${nombre_bin}.sha256" "$local_sha" 2>/dev/null
    local tiene_sha=$?

    # --- Verificar integridad ---
    if [[ $tiene_sha -eq 0 && -f "$local_sha" ]]; then
        if ! verificar_integridad "$local_bin" "$local_sha"; then
            echo ""
            read -rp "  ¿Continuar de todas formas? [s/N]: " forzar
            [[ ! "$forzar" =~ ^[sS]$ ]] && return 1
        fi
    else
        echo "  AVISO: No hay .sha256 en el servidor. Omitiendo verificación."
    fi

    # Exportar para el llamador
    ARCHIVO_DESCARGADO="$local_bin"
    SERVICIO_FTP_DIR="$servicio_dir"
    echo ""
    echo "  ✓ Listo: $ARCHIVO_DESCARGADO"
    return 0
}

# =================================================================
# INSTALAR ARCHIVO .RPM DESCARGADO DESDE FTP
# =================================================================
instalar_rpm_ftp() {
    local archivo="$1"

    if [[ ! -f "$archivo" ]]; then
        echo "  ERROR: Archivo no encontrado: $archivo"
        return 1
    fi

    echo ""
    echo "  Instalando: $(basename "$archivo")"

    # Detectar si es placeholder de texto
    if file "$archivo" 2>/dev/null | grep -qE "ASCII|text"; then
        echo "  (Archivo es placeholder — usando zypper como fallback)"
        local paquete; paquete=$(basename "$archivo" | sed 's/-placeholder.*//' \
            | sed 's/-[0-9].*//')
        zypper install -y "$paquete" 2>&1 | tail -5
        return $?
    fi

    # Instalación real del .rpm con rpm
    rpm --install --nodeps --replacepkgs "$archivo" 2>&1 | tail -10
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        echo "  rpm falló (rc=$rc). Intentando con zypper..."
        zypper install -y "$archivo" 2>&1 | tail -5
        rc=$?
    fi

    if [[ $rc -eq 0 ]]; then
        echo "  ✓ Instalación desde FTP completada."
    else
        echo "  ✗ La instalación falló."
    fi
    return $rc
}

# =================================================================
# CONFIGURAR SERVIDOR FTP DE ORIGEN (pedir credenciales)
# =================================================================
configurar_ftp_origen() {
    echo ""
    echo "  ┌─────── Servidor FTP de origen ────────┐"
    read -rp "  │ Host/IP  : " FTP_HOST
    read -rp "  │ Usuario  : " FTP_USER
    read -srp "  │ Contraseña: " FTP_PASS; echo ""
    echo "  └────────────────────────────────────────┘"
    export FTP_HOST FTP_USER FTP_PASS

    echo ""
    echo "  Verificando conexión..."
    _ftp_verificar_curl || return 1

    if curl --silent \
            --connect-timeout 10 \
            --user "${FTP_USER}:${FTP_PASS}" \
            --list-only \
            "ftp://${FTP_HOST}/" &>/dev/null; then
        echo "  ✓ Conexión FTP verificada."
        return 0
    else
        echo "  ✗ No se pudo conectar. Verifique los datos."
        return 1
    fi
}
