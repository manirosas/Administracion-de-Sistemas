#!/bin/bash
# dns.sh - Módulo de administración del servidor DNS (BIND)

[[ -z "$_COMMON_SH_SOURCED" ]] && source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

DNS_IFACE="enp0s8"
DNS_BIND_CONF="/etc/named.conf"
DNS_NAMED_D="/etc/named.d"
DNS_ZONES_FILE="${DNS_NAMED_D}/zonas_locales.conf"
DNS_ZONES_DIR="/var/lib/named/master"
DNS_LOG_FILE="/var/log/dns_manager.log"
DNS_SERVICE="named"
DNS_SERVER_IP=""

# Logging interno
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$DNS_LOG_FILE" 2>/dev/null
}

# Normalizar nombre de dominio (minúsculas, quitar www)
_normalize_domain() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

# Obtener ruta del archivo de zona para un dominio
_zone_file() {
    echo "${DNS_ZONES_DIR}/db.${1}"
}

# Validar formato de dominio
_validate_domain() {
    local d="$1"
    [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]
}

# Recargar BIND (rndc o systemctl)
_reload_bind() {
    if rndc reload &>/dev/null; then
        echo "Zonas recargadas (rndc)."
        log "Zonas recargadas con rndc"
    elif systemctl reload "$DNS_SERVICE" &>/dev/null; then
        echo "Servicio recargado."
        log "Servicio named recargado"
    else
        systemctl restart "$DNS_SERVICE" &>/dev/null
        sleep 2
        if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
            echo "Servicio reiniciado."
            log "Servicio named reiniciado"
        else
            echo "ERROR: No se pudo reiniciar named." >&2
            log "ERROR: No se pudo reiniciar named"
            return 1
        fi
    fi
    return 0
}

# Crear archivos base de zona (root.hint, localhost, etc.)
_crear_archivos_base() {
    local root_hint="/var/lib/named/root.hint"
    local localhost_zone="/var/lib/named/localhost.zone"
    local reverse_zone="/var/lib/named/127.0.0.zone"

    if [[ ! -f "$root_hint" ]]; then
        cat > "$root_hint" <<'EOF'
. 3600000 IN NS A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4
B.ROOT-SERVERS.NET. 3600000 A 199.9.14.201
C.ROOT-SERVERS.NET. 3600000 A 192.33.4.12
D.ROOT-SERVERS.NET. 3600000 A 199.7.91.13
M.ROOT-SERVERS.NET. 3600000 A 202.12.27.33
EOF
        chown named:named "$root_hint" 2>/dev/null || true
    fi

    if [[ ! -f "$localhost_zone" ]]; then
        cat > "$localhost_zone" <<'EOF'
$TTL 1D
@ IN SOA localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@ IN NS localhost.
@ IN A 127.0.0.1
EOF
        chown named:named "$localhost_zone" 2>/dev/null || true
    fi

    if [[ ! -f "$reverse_zone" ]]; then
        cat > "$reverse_zone" <<'EOF'
$TTL 1D
@ IN SOA localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@ IN NS localhost.
1 IN PTR localhost.
EOF
        chown named:named "$reverse_zone" 2>/dev/null || true
    fi
}

# Configurar named.conf (incluir zonas locales, deshabilitar dnssec)
_configurar_named_conf() {
    if grep -q "zonas_locales.conf" "$DNS_BIND_CONF" 2>/dev/null; then
        sed -i 's/dnssec-validation yes/dnssec-validation no/' "$DNS_BIND_CONF"
        sed -i 's/dnssec-validation auto/dnssec-validation no/' "$DNS_BIND_CONF"
        return
    fi

    if [[ -f "$DNS_BIND_CONF" ]]; then
        cp "$DNS_BIND_CONF" "${DNS_BIND_CONF}.bak_$(date +%Y%m%d%H%M%S)"
        sed -i 's/dnssec-validation yes/dnssec-validation no/' "$DNS_BIND_CONF"
        sed -i 's/dnssec-validation auto/dnssec-validation no/' "$DNS_BIND_CONF"
        echo -e '\n// Zonas personalizadas\ninclude "/etc/named.d/zonas_locales.conf";' >> "$DNS_BIND_CONF"
    else
        cat > "$DNS_BIND_CONF" <<'NAMEDCONF'
options {
    directory "/var/lib/named";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    allow-recursion { localhost; localnets; };
    recursion yes;
    forwarders { 8.8.8.8; 8.8.4.4; };
    dnssec-validation no;
};

logging {
    channel default_log {
        file "/var/log/named.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
    };
    category default { default_log; };
};

zone "." IN {
    type hint;
    file "root.hint";
};

zone "localhost" IN {
    type master;
    file "localhost.zone";
    notify no;
};

zone "0.0.127.in-addr.arpa" IN {
    type master;
    file "127.0.0.zone";
    notify no;
};

// Zonas personalizadas
include "/etc/named.d/zonas_locales.conf";
NAMEDCONF
    fi
}

# Configurar IP estática en la interfaz (soporta wicked, nmcli o ip)
dns_set_static_ip() {
    local ip_actual prefijo gw
    ip_actual=$(get_current_ip "$DNS_IFACE")
    prefijo=$(get_current_prefix "$DNS_IFACE")
    gw=$(get_default_gateway "$DNS_IFACE")

    echo "Interfaz: $DNS_IFACE"
    echo "IP actual: ${ip_actual:-ninguna}"
    echo "Prefijo : ${prefijo:-?}"
    echo "Gateway : ${gw:-?}"

    # Verificar si ya es estática (simplificado)
    local cfg="/etc/sysconfig/network/ifcfg-${DNS_IFACE}"
    if [[ -f "$cfg" ]] && grep -qi "BOOTPROTO=.static." "$cfg"; then
        echo "La interfaz ya tiene IP estática configurada."
        DNS_SERVER_IP="$ip_actual"
        return 0
    fi

    read -rp "Configurar IP estática? (s/n): " resp
    [[ ! "$resp" =~ ^[Ss]$ ]] && { DNS_SERVER_IP="${ip_actual:-127.0.0.1}"; return 0; }

    local nueva_ip nuevo_pfx nuevo_gw nuevo_dns_ext
    while true; do
        read -rp "Nueva IP [${ip_actual:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_actual:-192.168.1.10}}"
        validate_ip "$nueva_ip" && break
    done

    while true; do
        read -rp "Prefijo CIDR [${prefijo:-24}]: " nuevo_pfx
        nuevo_pfx="${nuevo_pfx:-${prefijo:-24}}"
        [[ "$nuevo_pfx" =~ ^[0-9]+$ ]] && (( nuevo_pfx >= 8 && nuevo_pfx <= 30 )) && break
    done

    while true; do
        read -rp "Gateway [${gw:-192.168.1.1}]: " nuevo_gw
        nuevo_gw="${nuevo_gw:-${gw:-192.168.1.1}}"
        validate_ip "$nuevo_gw" && break
    done

    while true; do
        read -rp "DNS externo [8.8.8.8]: " nuevo_dns_ext
        nuevo_dns_ext="${nuevo_dns_ext:-8.8.8.8}"
        validate_ip "$nuevo_dns_ext" && break
    done

    echo "Aplicando configuración..."
    # Escribir ifcfg
    cat > "$cfg" <<EOF
BOOTPROTO='static'
STARTMODE='auto'
IPADDR='${nueva_ip}'
PREFIXLEN='${nuevo_pfx}'
EOF
    echo "default ${nuevo_gw} - -" > /etc/sysconfig/network/routes

    # Configurar resolv.conf
    chattr -i /etc/resolv.conf 2>/dev/null
    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
nameserver ${nuevo_dns_ext}
EOF
    chattr +i /etc/resolv.conf 2>/dev/null || true

    # Deshabilitar systemd-resolved si está activo
    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
    fi

    # Aplicar según gestor de red
    if systemctl is-active wicked &>/dev/null; then
        wicked ifdown "$DNS_IFACE" &>/dev/null; sleep 1
        wicked ifup "$DNS_IFACE" &>/dev/null; sleep 3
    elif command -v nmcli &>/dev/null; then
        nmcli connection reload
        nmcli connection up "$DNS_IFACE" &>/dev/null; sleep 2
    else
        ip addr flush dev "$DNS_IFACE"
        ip addr add "${nueva_ip}/${nuevo_pfx}" dev "$DNS_IFACE"
        ip link set "$DNS_IFACE" up
        ip route add default via "$nuevo_gw"
    fi

    local ip_check
    ip_check=$(get_current_ip "$DNS_IFACE")
    if [[ "$ip_check" == "$nueva_ip" ]]; then
        echo "IP estática aplicada: $nueva_ip/$nuevo_pfx"
    else
        echo "Configuración guardada. Verifica con: ip addr show $DNS_IFACE"
    fi
    DNS_SERVER_IP="$nueva_ip"
    log "IP estática: $nueva_ip/$nuevo_pfx gw=$nuevo_gw en $DNS_IFACE"
}

# Instalar BIND y preparar archivos base
dns_install() {
    ensure_package bind || return 1
    ensure_package bind-utils || return 1

    mkdir -p "$DNS_NAMED_D" "$DNS_ZONES_DIR"
    chown -R named:named "$DNS_ZONES_DIR" 2>/dev/null || true
    [[ ! -f "$DNS_ZONES_FILE" ]] && touch "$DNS_ZONES_FILE"

    _crear_archivos_base
    _configurar_named_conf

    # Deshabilitar systemd-resolved
    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
    fi

    systemctl enable "$DNS_SERVICE" &>/dev/null
    systemctl start "$DNS_SERVICE"
    sleep 2
    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        echo "Servicio named iniciado."
    else
        echo "ERROR: No se pudo iniciar named. Revisa journalctl." >&2
        log "ERROR: named no inició"
    fi

    # Firewall
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo "Puerto 53 abierto en firewall."
    fi
}

# Alta de zona (dominio)
dns_create_zone() {
    if [[ -z "$DNS_SERVER_IP" ]]; then
        DNS_SERVER_IP=$(get_current_ip "$DNS_IFACE")
        if [[ -z "$DNS_SERVER_IP" ]]; then
            echo "ERROR: No se pudo determinar la IP del servidor. Configure IP estática primero." >&2
            return 1
        fi
    fi
    echo "IP del servidor DNS: $DNS_SERVER_IP"

    local entrada dominio
    while true; do
        read -rp "Dominio: " entrada
        entrada=$(echo "$entrada" | xargs)
        [[ -z "$entrada" ]] && { echo "El dominio no puede estar vacío."; continue; }
        dominio=$(_normalize_domain "$entrada")
        _validate_domain "$dominio" && break
        echo "Dominio inválido: '$dominio'. Ejemplo: miempresa.com"
    done

    local ip_destino
    while true; do
        read -rp "IP de destino [${DNS_SERVER_IP}]: " ip_destino
        ip_destino="${ip_destino:-$DNS_SERVER_IP}"
        validate_ip "$ip_destino" && break
    done

    local archivo_z
    archivo_z=$(_zone_file "$dominio")

    if grep -q "\"$dominio\"" "$DNS_ZONES_FILE" 2>/dev/null; then
        echo "La zona '$dominio' ya existe."
        read -rp "Sobreescribir? (s/n): " sobre
        [[ ! "$sobre" =~ ^[Ss]$ ]] && { echo "Cancelado."; return; }
        # Eliminar bloque de configuración anterior
        dns_delete_zone "$dominio" --quiet
    fi

    local serial
    serial=$(date +%Y%m%d01)

    cat > "$archivo_z" <<EOF
; Zona: $dominio
; Generado: $(date '+%Y-%m-%d %H:%M:%S')
\$TTL 86400
@ IN SOA ns1.${dominio}. admin.${dominio}. (
    ${serial} ; Serial
    3600      ; Refresh
    1800      ; Retry
    604800    ; Expire
    86400 )   ; Minimum TTL
@ IN NS ns1.${dominio}.
ns1 IN A ${DNS_SERVER_IP}
@ IN A ${ip_destino}
www IN CNAME ${dominio}.
EOF
    chown named:named "$archivo_z" 2>/dev/null || true
    chmod 644 "$archivo_z"

    cat >> "$DNS_ZONES_FILE" <<EOF

// Zona: $dominio - $(date '+%Y-%m-%d %H:%M:%S')
zone "$dominio" IN {
    type master;
    file "$archivo_z";
    allow-update { none; };
    allow-query { any; };
    notify no;
};
EOF

    # Verificar configuración
    if ! named-checkconf "$DNS_BIND_CONF" 2>&1; then
        echo "ERROR en named.conf. Revise." >&2
        log "ERROR en named.conf al crear $dominio"
        return 1
    fi
    if ! named-checkzone "$dominio" "$archivo_z" 2>&1; then
        echo "ERROR en archivo de zona." >&2
        log "ERROR en zona $dominio"
        return 1
    fi

    _reload_bind
    echo "Zona '$dominio' creada."
    log "Alta: $dominio ip=$ip_destino dns=$DNS_SERVER_IP"
}

# Eliminar zona
dns_delete_zone() {
    local dominio="$1"
    local quiet="$2"
    if [[ -z "$dominio" ]]; then
        read -rp "Dominio a eliminar: " entrada
        dominio=$(_normalize_domain "$entrada")
    fi
    [[ -z "$dominio" ]] && { echo "Dominio vacío."; return 1; }

    if ! grep -q "\"$dominio\"" "$DNS_ZONES_FILE" 2>/dev/null; then
        [[ "$quiet" != "--quiet" ]] && echo "La zona '$dominio' no existe."
        return 1
    fi

    if [[ "$quiet" != "--quiet" ]]; then
        read -rp "Eliminar zona '$dominio'? (s/n): " conf
        [[ ! "$conf" =~ ^[Ss]$ ]] && { echo "Cancelado."; return; }
    fi

    # Eliminar bloque de configuración
    local archivo_z archivos=("$DNS_ZONES_FILE" "/etc/named.d/zonas.conf")
    archivo_z=$(_zone_file "$dominio")

    for zf in "${archivos[@]}"; do
        [[ -f "$zf" ]] || continue
        grep -q "\"$dominio\"" "$zf" 2>/dev/null || continue
        local linea total inicio fin
        linea=$(grep -n "\"$dominio\"" "$zf" | head -1 | cut -d: -f1)
        [[ -z "$linea" ]] && continue
        total=$(wc -l < "$zf")
        inicio="$linea"
        if (( linea > 1 )); then
            local prev
            prev=$(sed -n "$(( linea - 1 ))p" "$zf")
            echo "$prev" | grep -q '^//' && inicio=$(( linea - 1 ))
        fi
        fin="$linea"
        while (( fin <= total )); do
            sed -n "${fin}p" "$zf" | grep -qE '^\s*\};\s*$' && break
            fin=$(( fin + 1 ))
        done
        sed -i "${inicio},${fin}d" "$zf"
    done

    [[ -f "$archivo_z" ]] && rm -f "$archivo_z"
    echo "Zona '$dominio' eliminada."
    log "Baja: $dominio"
    _reload_bind
}

# Listar zonas configuradas
dns_list_zones() {
    if ! grep -q 'zone "' "$DNS_ZONES_FILE" 2>/dev/null; then
        echo "No hay zonas configuradas."
        return
    fi

    local dominios
    mapfile -t dominios < <(grep 'zone "' "$DNS_ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/\1/')
    echo "Zonas configuradas:"
    for dom in "${dominios[@]}"; do
        local archivo_z=$(_zone_file "$dom")
        echo "- $dom"
        if [[ -f "$archivo_z" ]]; then
            grep -E '\s+(A|CNAME|NS)\s+' "$archivo_z" | grep -v '^;' | while read -r linea; do
                echo "    $linea"
            done
        else
            echo "    (archivo no encontrado)"
        fi
    done
    echo ""
    echo "Servicio named: $(systemctl is-active $DNS_SERVICE 2>/dev/null)"
    echo "IP del servidor: $(get_current_ip "$DNS_IFACE")"
}

# Probar resolución de un dominio
dns_test_zone() {
    local dominio
    read -rp "Dominio a probar: " entrada
    dominio=$(_normalize_domain "$entrada")
    [[ -z "$dominio" ]] && { echo "Dominio vacío."; return; }

    local archivo_z=$(_zone_file "$dominio")
    echo ""
    echo "--- named-checkconf ---"
    named-checkconf "$DNS_BIND_CONF" 2>&1 && echo "OK" || echo "ERROR"

    echo ""
    echo "--- named-checkzone $dominio ---"
    if [[ -f "$archivo_z" ]]; then
        named-checkzone "$dominio" "$archivo_z" 2>&1
    else
        echo "Archivo no encontrado: $archivo_z"
    fi

    echo ""
    echo "--- nslookup $dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "$dominio" 127.0.0.1 || echo "nslookup no disponible."

    echo ""
    echo "--- dig @127.0.0.1 $dominio A +short ---"
    command -v dig &>/dev/null && dig @127.0.0.1 "$dominio" A +short || echo "dig no disponible."
}

# Menú de servicio named
dns_service_menu() {
    while true; do
        echo ""
        echo "--- Servicio named ---"
        echo "1) Recargar zonas"
        echo "2) Reiniciar servicio"
        echo "3) Detener servicio"
        echo "4) Ver log de named"
        echo "5) Ver log del script"
        echo "0) Volver"
        read -rp "Opción: " opc
        case "$opc" in
            1) _reload_bind ;;
            2) systemctl restart "$DNS_SERVICE"; sleep 2
               systemctl is-active "$DNS_SERVICE" &>/dev/null && echo "Reiniciado." || echo "Error." ;;
            3) systemctl stop "$DNS_SERVICE" && echo "Detenido." ;;
            4) if [[ -f /var/log/named.log ]]; then
                   tail -30 /var/log/named.log
               else
                   journalctl -u named -n 30 --no-pager
               fi ;;
            5) [[ -f "$DNS_LOG_FILE" ]] && tail -30 "$DNS_LOG_FILE" || echo "Sin log todavía." ;;
            0) break ;;
            *) echo "Opción no válida." ;;
        esac
        pause
    done
}

# Borrar toda la configuración DNS
dns_clean_config() {
    echo "Se eliminará:"
    echo " - Todas las zonas en $DNS_ZONES_FILE"
    echo " - Archivos de zona en $DNS_ZONES_DIR"
    echo " - Servicio named se detiene"
    read -rp "Confirma escribiendo BORRAR: " conf
    [[ "$conf" != "BORRAR" ]] && { echo "Cancelado."; return; }

    systemctl stop "$DNS_SERVICE" 2>/dev/null
    [[ -f "$DNS_ZONES_FILE" ]] && > "$DNS_ZONES_FILE"
    local old="/etc/named.d/zonas.conf"
    [[ -f "$old" ]] && > "$old"
    find "$DNS_ZONES_DIR" -maxdepth 1 -name 'db.*' 2>/dev/null -delete
    systemctl disable "$DNS_SERVICE" &>/dev/null
    echo "Configuración DNS eliminada."
    log "Borrado completo de configuración DNS."
}

# Inicialización del módulo DNS (llamar al inicio)
dns_init() {
    mkdir -p "$(dirname "$DNS_LOG_FILE")" "$DNS_NAMED_D" "$DNS_ZONES_DIR" 2>/dev/null
    touch "$DNS_LOG_FILE" 2>/dev/null || true
    [[ ! -f "$DNS_ZONES_FILE" ]] && touch "$DNS_ZONES_FILE"
    DNS_SERVER_IP=$(get_current_ip "$DNS_IFACE")

    # Migrar zonas desde posible archivo antiguo
    local old="/etc/named.d/zonas.conf"
    if [[ -f "$old" ]] && grep -q 'zone "' "$old" 2>/dev/null; then
        while IFS= read -r dom; do
            [[ -z "$dom" ]] && continue
            grep -q "\"$dom\"" "$DNS_ZONES_FILE" 2>/dev/null || continue
            local ln total inicio fin prev
            ln=$(grep -n "\"$dom\"" "$old" | head -1 | cut -d: -f1)
            [[ -z "$ln" ]] && continue
            total=$(wc -l < "$old")
            inicio="$ln"
            (( ln > 1 )) && { prev=$(sed -n "$(( ln - 1 ))p" "$old"); echo "$prev" | grep -q '^//' && inicio=$(( ln - 1 )); }
            fin="$ln"
            while (( fin <= total )); do
                sed -n "${fin}p" "$old" | grep -qE '^\s*\};\s*$' && break
                fin=$(( fin + 1 ))
            done
            sed -i "${inicio},${fin}d" "$old"
            log "Duplicado resuelto: '$dom' en zonas.conf"
        done < <(grep 'zone "' "$old" | sed 's/.*zone "\(.*\)" IN.*/\1/')
    fi
}