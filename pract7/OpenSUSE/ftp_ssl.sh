#!/bin/bash
# =================================================================
# FTP_SSL.SH — FTPS para vsftpd en OpenSUSE Leap
# REQUIERE: source ssl_utils.sh ANTES de este archivo
# =================================================================

VSFTPD_CONF="/etc/vsftpd.conf"

# =================================================================
# CONFIGURAR FTPS EN VSFTPD
# =================================================================
configurar_ssl_vsftpd() {
    titulo "SSL/TLS (FTPS) — vsftpd"

    if ! rpm -q vsftpd &>/dev/null; then
        echo "  ERROR: vsftpd no está instalado."
        echo "  Instálelo primero con el script de la Práctica 5."
        return 1
    fi

    if [[ ! -f "$VSFTPD_CONF" ]]; then
        echo "  ERROR: $VSFTPD_CONF no existe."
        return 1
    fi

    # Generar certificado → establece SSL_CERT y SSL_KEY
    generar_certificado "vsftpd" "ftp.$DOMINIO" || return 1

    # Backup antes de modificar
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak7"
    echo "  Backup: ${VSFTPD_CONF}.bak7"

    # Eliminar bloque SSL anterior si ya existe (idempotente)
    sed -i '/# SSL_P7_START/,/# SSL_P7_END/d' "$VSFTPD_CONF"

    # Agregar bloque SSL al final
    cat >> "$VSFTPD_CONF" <<SSLBLOCK

# SSL_P7_START — Configuración SSL/TLS Práctica 7
ssl_enable=YES
rsa_cert_file=${SSL_CERT}
rsa_private_key_file=${SSL_KEY}

# Forzar SSL en login y transferencia de datos
force_local_logins_ssl=YES
force_local_data_ssl=YES

# Anónimos: sin SSL (acceso de solo lectura al repositorio)
allow_anon_ssl=NO

# Desactivar versiones inseguras
ssl_sslv2=NO
ssl_sslv3=NO
ssl_tlsv1=YES

# Compatibilidad con FileZilla y clientes modernos
require_ssl_reuse=NO
ssl_ciphers=HIGH
# SSL_P7_END
SSLBLOCK

    echo "  vsftpd.conf: bloque FTPS agregado."

    ssl_firewall_abrir 21
    ssl_firewall_abrir 990

    mkdir -p /etc/pract7
    {
        echo "SSL=ACTIVO"
        echo "CERT=${SSL_CERT}"
        echo "KEY=${SSL_KEY}"
    } > /etc/pract7/vsftpd_ssl.conf

    if systemctl restart vsftpd 2>/dev/null; then
        echo "  ✓ vsftpd reiniciado con FTPS."
    else
        echo "  ✗ Error al reiniciar vsftpd."
        echo ""
        echo "  Diagnóstico:"
        journalctl -u vsftpd -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
        return 1
    fi

    # Verificar FTPS con STARTTLS en puerto 21
    echo ""
    echo "  Verificando FTPS (STARTTLS en puerto 21)..."
    sleep 2

    local salida
    salida=$(timeout 10 openssl s_client \
        -connect "localhost:21" \
        -starttls ftp \
        </dev/null 2>&1)

    if echo "$salida" | grep -qE "CONNECTED|Certificate chain"; then
        echo "  ✓ FTPS activo y respondiendo."
        echo "$salida" | grep -E "Protocol|Cipher|subject" | head -4 | sed 's/^/    /'
    else
        echo "  ⚠ No se pudo verificar FTPS automáticamente."
        echo "  Verifique manualmente con FileZilla:"
        echo "    Host    : $DOMINIO (o IP del servidor)"
        echo "    Puerto  : 21"
        echo "    Cifrado : Requiere FTP explícito sobre TLS"
        echo "    Usuario : (usuario FTP de la práctica 5)"
    fi

    echo ""
    echo "  Resumen FTPS:"
    echo "  ┌──────────────────────────────────────────┐"
    echo "  │ Protocolo : FTPS Explícito (STARTTLS)    │"
    echo "  │ Puerto    : 21 (control cifrado)         │"
    echo "  │ Datos     : cifrados también             │"
    printf "  │ Cert CN   : ftp.%-25s│\n" "${DOMINIO}   "
    echo "  └──────────────────────────────────────────┘"
}

# =================================================================
# MOSTRAR ESTADO ACTUAL DE FTPS
# =================================================================
verificar_ftps() {
    titulo "Estado FTPS — vsftpd"

    local activo; activo=$(systemctl is-active vsftpd 2>/dev/null || echo "inactivo")
    echo "  Estado vsftpd   : $activo"

    if grep -q "^ssl_enable=YES" "$VSFTPD_CONF" 2>/dev/null; then
        echo "  SSL en config   : ✓ ssl_enable=YES"
    else
        echo "  SSL en config   : ✗ No está activado"
    fi

    local cert_path
    cert_path=$(grep "^rsa_cert_file=" "$VSFTPD_CONF" 2>/dev/null | cut -d= -f2)
    if [[ -n "$cert_path" && -f "$cert_path" ]]; then
        echo "  Certificado     : ✓ $cert_path"
        openssl x509 -noout -subject -enddate -in "$cert_path" 2>/dev/null \
            | sed 's/^/    /'
    else
        echo "  Certificado     : ✗ No encontrado ($cert_path)"
    fi

    echo ""
    echo "  Test STARTTLS en puerto 21..."
    timeout 10 openssl s_client \
        -connect "localhost:21" \
        -starttls ftp \
        </dev/null 2>&1 \
        | grep -E "CONNECTED|Protocol|Cipher|subject|error" \
        | head -5 \
        | sed 's/^/    /'
}
