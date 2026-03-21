#!/bin/bash
# =================================================================
# SETUP_REPO.SH — Prepara el repositorio FTP para la Práctica 7
# Estructura: /srv/ftp/http/Linux/{Apache,Nginx,Tomcat}/
# Ejecutar en el SERVIDOR FTP antes de usar main.sh
# =================================================================

[ "$EUID" -ne 0 ] && echo "Ejecute como root." && exit 1

REPO_BASE="/srv/ftp/http/Linux"
CACHE_ZYPP="/var/cache/zypp/packages"

linea()  { echo "------------------------------------------------------------"; }
titulo() { echo ""; linea; echo "  $1"; linea; }
pausar() { echo ""; read -rp "  Presione Enter para continuar..." _; }

# =================================================================
# VERIFICAR DEPENDENCIAS
# =================================================================
verificar_deps() {
    local faltantes=()
    command -v sha256sum &>/dev/null || faltantes+=("coreutils")
    command -v find      &>/dev/null || faltantes+=("findutils")

    if [[ ${#faltantes[@]} -gt 0 ]]; then
        echo "  Instalando: ${faltantes[*]}"
        zypper install -y "${faltantes[@]}" &>/dev/null
    fi
}

# =================================================================
# DESCARGAR PAQUETE CON ZYPPER Y COPIAR AL REPOSITORIO
# Devuelve el nombre del archivo copiado en $ARCHIVO_COPIADO
# =================================================================
descargar_paquete() {
    local paquete="$1"
    local destino="$2"

    mkdir -p "$destino"
    ARCHIVO_COPIADO=""

    echo "  Buscando '$paquete' en cache de zypper..."

    # Intentar descarga — zypper download guarda en la caché de zypp
    zypper --no-gpg-checks download "$paquete" &>/dev/null
    local rc_download=$?

    # Buscar el .rpm: el nombre puede variar (apache2-2.4.x-lp154.x86_64.rpm)
    # Usamos el nombre del paquete como prefijo flexible
    local rpm_encontrado=""

    # Búsqueda 1: directamente en el caché de zypp (ruta estándar Leap)
    rpm_encontrado=$(find "$CACHE_ZYPP" -name "${paquete}-[0-9]*.rpm" 2>/dev/null | head -1)

    # Búsqueda 2: si el paquete tiene guion en el nombre (ej: apache2)
    if [[ -z "$rpm_encontrado" ]]; then
        rpm_encontrado=$(find "$CACHE_ZYPP" -name "${paquete}*.rpm" 2>/dev/null \
            | grep -v "debuginfo\|debugsource\|devel\|doc\|lang" \
            | head -1)
    fi

    # Búsqueda 3: buscar en TODO /var/cache por si la ruta difiere
    if [[ -z "$rpm_encontrado" ]]; then
        rpm_encontrado=$(find /var/cache -name "${paquete}*.rpm" 2>/dev/null \
            | grep -v "debuginfo\|debugsource\|devel\|doc\|lang" \
            | head -1)
    fi

    if [[ -n "$rpm_encontrado" && -f "$rpm_encontrado" ]]; then
        local nombre_archivo; nombre_archivo=$(basename "$rpm_encontrado")
        cp "$rpm_encontrado" "$destino/$nombre_archivo"

        # Generar SHA256 (solo el hash, sin la ruta)
        sha256sum "$destino/$nombre_archivo" | awk '{print $1}' \
            > "$destino/${nombre_archivo}.sha256"

        ARCHIVO_COPIADO="$nombre_archivo"
        echo "  ✓ Copiado     : $nombre_archivo"
        echo "  ✓ SHA256      : $(cat "$destino/${nombre_archivo}.sha256")"
        return 0
    fi

    # Fallback: si no se encontró el .rpm, crear placeholder informativo
    echo "  AVISO: No se encontró .rpm de '$paquete' en caché."
    echo "  Posibles causas:"
    echo "    - El paquete no está en los repositorios configurados"
    echo "    - Falta conexión a internet"
    echo "    - zypper refresh no se ha ejecutado"
    echo ""
    echo "  Creando placeholder para pruebas..."

    local placeholder="${paquete}-placeholder.rpm"
    echo "PLACEHOLDER: instalar con: zypper install ${paquete}" \
        > "$destino/$placeholder"
    sha256sum "$destino/$placeholder" | awk '{print $1}' \
        > "$destino/${placeholder}.sha256"

    ARCHIVO_COPIADO="$placeholder"
    echo "  ✓ Placeholder creado: $placeholder"
    return 0
}

# =================================================================
# CREAR ÍNDICE DE ARCHIVOS DISPONIBLES
# =================================================================
crear_indice() {
    local directorio="$1"
    local servicio="$2"
    local indice="$directorio/INDEX.txt"

    {
        echo "# Repositorio Práctica 7 — $servicio"
        echo "# Generado: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Formato: nombre_archivo|hash_sha256"
        echo ""
    } > "$indice"

    while IFS= read -r f; do
        local nombre; nombre=$(basename "$f")
        local hash
        if [[ -f "${f}.sha256" ]]; then
            hash=$(cat "${f}.sha256")
        else
            hash=$(sha256sum "$f" | awk '{print $1}')
            echo "$hash" > "${f}.sha256"
        fi
        echo "${nombre}|${hash}" >> "$indice"
    done < <(find "$directorio" -maxdepth 1 \
        \( -name "*.rpm" -o -name "*.deb" -o -name "*.tar.gz" -o -name "*.zip" \) \
        | sort)

    echo "  ✓ Índice actualizado: $indice"
}

# =================================================================
# CONSTRUIR TODA LA ESTRUCTURA DEL REPOSITORIO
# =================================================================
construir_repositorio() {
    titulo "Construyendo repositorio FTP"

    verificar_deps

    # Refrescar repositorios
    echo "  Actualizando repositorios zypper..."
    zypper refresh 2>&1 | tail -3

    echo ""

    local servicios=("apache2:Apache" "nginx:Nginx" "tomcat:Tomcat")
    local total=${#servicios[@]}
    local i=1

    for entrada in "${servicios[@]}"; do
        local paquete; paquete=$(echo "$entrada" | cut -d: -f1)
        local nombre;  nombre=$(echo  "$entrada" | cut -d: -f2)
        local dir="$REPO_BASE/$nombre"

        echo "  [$i/$total] Procesando $nombre (paquete: $paquete)..."
        descargar_paquete "$paquete" "$dir"
        crear_indice "$dir" "$nombre"
        echo ""
        (( i++ ))
    done

    # Permisos para acceso FTP anónimo (lectura)
    echo "  Aplicando permisos de acceso FTP..."
    chown -R root:ftp "$REPO_BASE" 2>/dev/null || chown -R root:root "$REPO_BASE"
    find "$REPO_BASE" -type d -exec chmod 755 {} \;
    find "$REPO_BASE" -type f -exec chmod 644 {} \;

    echo ""
    linea
    echo "  Repositorio listo en: $REPO_BASE"
    echo ""
    echo "  Estructura:"
    find "$REPO_BASE" -maxdepth 3 \( -name "*.rpm" -o -name "*.sha256" -o \
         -name "INDEX.txt" -o -type d \) \
        | sort | sed "s|$REPO_BASE||" | sed 's|^/||' \
        | awk -F'/' '{
            depth = NF - 1
            indent = ""
            for(i=0; i<depth; i++) indent = indent "  "
            print "  " indent "└─ " $NF
        }'
    linea
}

# =================================================================
# AGREGAR BINARIO MANUALMENTE
# =================================================================
agregar_binario_manual() {
    titulo "Agregar binario manualmente"

    echo "  Servicios:"
    echo "  1) Apache"
    echo "  2) Nginx"
    echo "  3) Tomcat"
    read -rp "  Servicio [1-3]: " srv

    local dir_servicio
    case "$srv" in
        1) dir_servicio="$REPO_BASE/Apache" ;;
        2) dir_servicio="$REPO_BASE/Nginx"  ;;
        3) dir_servicio="$REPO_BASE/Tomcat" ;;
        *) echo "  Opción inválida."; return 1 ;;
    esac

    read -rp "  Ruta del archivo a copiar: " ruta_bin
    if [[ ! -f "$ruta_bin" ]]; then
        echo "  ERROR: No se encontró: $ruta_bin"
        return 1
    fi

    local nombre; nombre=$(basename "$ruta_bin")
    mkdir -p "$dir_servicio"
    cp "$ruta_bin" "$dir_servicio/$nombre"
    sha256sum "$dir_servicio/$nombre" | awk '{print $1}' \
        > "$dir_servicio/${nombre}.sha256"
    chmod 644 "$dir_servicio/$nombre" "$dir_servicio/${nombre}.sha256"
    crear_indice "$dir_servicio" "$(basename "$dir_servicio")"

    echo ""
    echo "  ✓ $nombre agregado"
    echo "  ✓ SHA256 generado: $(cat "$dir_servicio/${nombre}.sha256")"
}

# =================================================================
# VERIFICAR INTEGRIDAD DE TODO EL REPOSITORIO
# =================================================================
verificar_repositorio() {
    titulo "Verificación de integridad del repositorio"

    if [[ ! -d "$REPO_BASE" ]]; then
        echo "  El repositorio no existe. Ejecute la opción 1 primero."
        return 1
    fi

    local errores=0 ok=0

    while IFS= read -r archivo; do
        local hash_file="${archivo}.sha256"
        local nombre; nombre=$(basename "$archivo")

        if [[ ! -f "$hash_file" ]]; then
            printf "  ⚠  Sin .sha256  : %s\n" "$nombre"
            (( errores++ ))
            continue
        fi

        local hash_esperado; hash_esperado=$(cat "$hash_file" | awk '{print $1}')
        local hash_real;     hash_real=$(sha256sum "$archivo" | awk '{print $1}')

        if [[ "$hash_esperado" == "$hash_real" ]]; then
            printf "  ✓  OK           : %s\n" "$nombre"
            (( ok++ ))
        else
            printf "  ✗  CORRUPTO     : %s\n" "$nombre"
            (( errores++ ))
        fi
    done < <(find "$REPO_BASE" -type f \
        \( -name "*.rpm" -o -name "*.deb" -o -name "*.tar.gz" \))

    echo ""
    if [[ $errores -eq 0 ]]; then
        echo "  ✓ Todos los archivos están íntegros ($ok archivos)."
    else
        echo "  Resultado: $ok correctos, $errores con problemas."
    fi
}

# =================================================================
# MENÚ
# =================================================================
while true; do
    echo ""
    echo "╔══════════════════════════════════════╗"
    echo "║   SETUP REPOSITORIO FTP — Práct. 7  ║"
    echo "╠══════════════════════════════════════╣"
    echo "║  1. Construir repositorio completo   ║"
    echo "║  2. Agregar binario manualmente      ║"
    echo "║  3. Verificar integridad             ║"
    echo "║  4. Mostrar estructura actual        ║"
    echo "║  0. Salir                            ║"
    echo "╚══════════════════════════════════════╝"
    read -rp "  Opción: " op
    case "$op" in
        1) construir_repositorio  ;;
        2) agregar_binario_manual ;;
        3) verificar_repositorio  ;;
        4)
            if [[ -d "$REPO_BASE" ]]; then
                find "$REPO_BASE" -maxdepth 4 | sort \
                    | sed "s|$REPO_BASE||" | sed 's|^/||' \
                    | awk -F'/' '{
                        depth = NF - 1
                        indent = ""
                        for(i=0; i<depth; i++) indent = indent "  "
                        print "  " indent "└─ " $NF
                    }'
            else
                echo "  El repositorio no existe aún."
            fi
            ;;
        0) exit 0 ;;
        *) echo "  Opción no válida." ;;
    esac
done
