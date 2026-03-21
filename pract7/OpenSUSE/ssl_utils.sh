#!/bin/bash
# =================================================================
# SSL_UTILS.SH — Funciones compartidas de SSL/TLS
# Importar con: source ssl_utils.sh
# Auto-instala dependencias si faltan
# =================================================================

SSL_BASE_DIR="/etc/pract7/ssl"
DOMINIO="reprobados.com"
PAIS="MX"
ESTADO_SSL="Sinaloa"
CIUDAD_SSL="Los Mochis"
ORG_SSL="reprobados.com"

# =================================================================
# UTILIDADES COMPARTIDAS
# Definidas aquí para que todos los módulos las tengan disponibles
# independientemente del orden de source
# =================================================================
linea()   { echo "------------------------------------------------------------"; }
titulo()  { echo ""; linea; echo "  $1"; linea; }
pausar()  { echo ""; read -rp "  Presione Enter para continuar..." _; }

# =================================================================
# VERIFICAR E INSTALAR DEPENDENCIAS NECESARIAS
# =================================================================
verificar_dependencias_ssl() {
    local faltantes=()

    # openssl — para generar certificados y verificar SSL
    if ! command -v openssl &>/dev/null; then
        faltantes+=("openssl")
    fi

    # curl — para cliente FTP y verificaciones HTTP
    if ! command -v curl &>/dev/null; then
        faltantes+=("curl")
    fi

    if [[ ${#faltantes[@]} -gt 0 ]]; then
        echo "  Instalando dependencias faltantes: ${faltantes[*]}"
        zypper install -y "${faltantes[@]}" 2>&1 | tail -3
    fi

    # Verificar que openssl realmente funciona
    if ! openssl version &>/dev/null; then
        echo "  ERROR CRÍTICO: openssl no funciona después de la instalación."
        echo "  Ejecute manualmente: zypper install -y openssl"
        return 1
    fi

    return 0
}

# =================================================================
# GENERAR CERTIFICADO AUTOFIRMADO
# Parámetros:
#   $1 = nombre del servicio (apache, nginx, tomcat, vsftpd)
#   $2 = nombre DNS (ej: www.reprobados.com)
# Salida:
#   Variables globales SSL_CERT y SSL_KEY con las rutas generadas
# =================================================================
generar_certificado() {
    local servicio="$1"
    local dns_name="${2:-www.$DOMINIO}"

    local cert_dir="$SSL_BASE_DIR/$servicio"
    mkdir -p "$cert_dir"

    # Exportar las rutas ANTES de intentar generar
    # así los llamadores siempre tienen las rutas correctas
    SSL_CERT="$cert_dir/cert.pem"
    SSL_KEY="$cert_dir/key.pem"
    export SSL_CERT SSL_KEY

    # Verificar dependencias
    verificar_dependencias_ssl || return 1

    echo ""
    echo "  Generando certificado SSL para $servicio ($dns_name)..."

    openssl req -x509 \
        -nodes \
        -days 365 \
        -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out    "$SSL_CERT" \
        -subj "/C=${PAIS}/ST=${ESTADO_SSL}/L=${CIUDAD_SSL}/O=${ORG_SSL}/CN=${dns_name}" \
        2>/dev/null

    if [[ $? -ne 0 ]]; then
        echo "  ERROR: openssl falló. Intentando con sintaxis alternativa..."
        # Sintaxis compatible con openssl 1.0.x y 1.1.x
        openssl req -x509 \
            -nodes \
            -days 365 \
            -newkey rsa:2048 \
            -keyout "$SSL_KEY" \
            -out    "$SSL_CERT" \
            -subj "/C=${PAIS}/ST=${ESTADO_SSL}/L=${CIUDAD_SSL}/O=${ORG_SSL}/CN=${dns_name}" \
            2>&1
        if [[ $? -ne 0 ]]; then
            echo "  ERROR CRÍTICO: No se pudo generar el certificado."
            return 1
        fi
    fi

    # Verificar que los archivos existen y no están vacíos
    if [[ ! -s "$SSL_CERT" || ! -s "$SSL_KEY" ]]; then
        echo "  ERROR: Los archivos de certificado están vacíos."
        return 1
    fi

    chmod 600 "$SSL_KEY"
    chmod 644 "$SSL_CERT"

    echo "  ✓ Certificado : $SSL_CERT"
    echo "  ✓ Llave privada: $SSL_KEY"
    echo "  ✓ CN           : $dns_name"
    echo "  ✓ Validez      : 365 días"
    return 0
}

# =================================================================
# VERIFICAR CERTIFICADO EXISTENTE Y VIGENTE
# =================================================================
certificado_existe() {
    local servicio="$1"
    local cert="$SSL_BASE_DIR/$servicio/cert.pem"
    [[ -f "$cert" ]] && \
    [[ -s "$cert" ]] && \
    openssl x509 -checkend 86400 -noout -in "$cert" &>/dev/null
}

# =================================================================
# RESTAURAR RUTAS SSL_CERT / SSL_KEY desde archivos existentes
# Útil cuando se llama a configurar_ssl_* sin pasar por generar_certificado
# =================================================================
cargar_rutas_cert() {
    local servicio="$1"
    SSL_CERT="$SSL_BASE_DIR/$servicio/cert.pem"
    SSL_KEY="$SSL_BASE_DIR/$servicio/key.pem"
    export SSL_CERT SSL_KEY
}

# =================================================================
# MOSTRAR INFO DEL CERTIFICADO
# =================================================================
info_certificado() {
    local servicio="$1"
    local cert="$SSL_BASE_DIR/$servicio/cert.pem"

    if [[ ! -f "$cert" ]]; then
        printf "  %-10s Sin certificado generado.\n" "$servicio"
        return 1
    fi

    echo ""
    echo "  --- Certificado: $servicio ---"
    openssl x509 -noout \
        -subject \
        -issuer  \
        -dates   \
        -in "$cert" 2>/dev/null | sed 's/^/    /'
}

# =================================================================
# VERIFICAR CONEXIÓN SSL EN UN PUERTO
# =================================================================
verificar_ssl_puerto() {
    local host="${1:-localhost}"
    local puerto="$2"
    local protocolo="${3:-https}"

    echo "  Verificando SSL en $host:$puerto (puede tardar hasta 8s)..."

    local resultado rc

    if [[ "$protocolo" == "ftp" ]]; then
        resultado=$(timeout 8 openssl s_client \
            -connect "${host}:${puerto}" \
            -starttls ftp \
            </dev/null 2>&1)
    else
        resultado=$(timeout 8 openssl s_client \
            -connect "${host}:${puerto}" \
            </dev/null 2>&1)
    fi
    rc=$?

    if echo "$resultado" | grep -qE "CONNECTED|Certificate chain|SSL handshake"; then
        echo "  ✓ SSL activo en puerto $puerto"
        # Mostrar protocolo y cipher usados
        echo "$resultado" | grep -E "Protocol|Cipher" | head -2 | sed 's/^/    /'
        return 0
    else
        echo "  ✗ SSL no responde en puerto $puerto"
        # Mostrar el error real para diagnóstico
        echo "$resultado" | grep -iE "error|errno|refused|timeout" | head -3 | sed 's/^/    /'
        return 1
    fi
}

# =================================================================
# ABRIR PUERTO EN FIREWALL
# =================================================================
ssl_firewall_abrir() {
    local puerto="$1"
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-port="${puerto}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo "  Firewall: puerto $puerto/tcp abierto."
    fi
}
