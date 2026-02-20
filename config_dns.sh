#!/bin/bash

[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

IFACE="enp0s8"
BIND_CONF="/etc/named.conf"
NAMED_D="/etc/named.d"
ZONES_FILE="${NAMED_D}/zonas_locales.conf"
ZONES_DIR="/var/lib/named/master"
LOG_FILE="/var/log/dns_manager.log"
DNS_SERVICE="named"
DNS_SERVER_IP=""

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null; }
ok()   { echo "OK: $*";    log "OK: $*"; }
err()  { echo "ERROR: $*"; log "ERROR: $*"; }
info() { echo "$*";        log "$*"; }
pausar() { echo ""; read -rp "ENTER para continuar..."; }

# --------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------

obtener_ip_actual() {
    ip addr show "$IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1
}

obtener_prefijo_actual() {
    ip addr show "$IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f2 | head -1
}

obtener_gateway() {
    ip route | grep "^default.*$IFACE" | awk '{print $3}' | head -1 \
    || ip route | grep '^default' | awk '{print $3}' | head -1
}

_validar_ip() {
    local ip="$1"
    local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    [[ "$ip" =~ $regex ]]
}

verificar_ip_estatica() {
    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    [[ -f "$cfg" ]] && grep -qi "BOOTPROTO=.static." "$cfg" && return 0
    command -v nmcli &>/dev/null && \
        nmcli -g IP4.METHOD con show --active 2>/dev/null | grep -qi "manual" && return 0
    return 1
}

modulo_ip_fija() {
    echo ""

    if ! ip link show "$IFACE" &>/dev/null; then
        err "La interfaz '$IFACE' no existe."
        echo "Interfaces disponibles:"
        ip link show | grep '^[0-9]' | awk -F': ' '{print "  " $2}'
        pausar; return 1
    fi

    local ip_actual prefijo gw
    ip_actual=$(obtener_ip_actual)
    prefijo=$(obtener_prefijo_actual)
    gw=$(obtener_gateway)

    echo "Interfaz : $IFACE"
    echo "IP actual: ${ip_actual:-ninguna}"
    echo "Prefijo  : ${prefijo:-?}"
    echo "Gateway  : ${gw:-?}"
    echo ""

    if verificar_ip_estatica; then
        ok "La interfaz ya tiene IP estatica configurada."
        DNS_SERVER_IP="$ip_actual"
        pausar; return 0
    fi

    info "La interfaz usa DHCP."
    read -rp "Configurar IP estatica? (s/n): " resp
    [[ ! "$resp" =~ ^[Ss]$ ]] && {
        DNS_SERVER_IP="${ip_actual:-127.0.0.1}"
        pausar; return 0
    }

    _solicitar_y_aplicar_ip "$ip_actual" "$prefijo" "$gw"
}

_solicitar_y_aplicar_ip() {
    local ip_sug="$1" pfx_sug="$2" gw_sug="$3"
    local nueva_ip nuevo_pfx nuevo_gw nuevo_dns_ext

    echo ""

    while true; do
        read -rp "Nueva IP [${ip_sug:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_sug:-192.168.1.10}}"
        _validar_ip "$nueva_ip" && break
        err "IP invalida. Ejemplo: 192.168.1.10"
    done

    while true; do
        read -rp "Prefijo CIDR [${pfx_sug:-24}]: " nuevo_pfx
        nuevo_pfx="${nuevo_pfx:-${pfx_sug:-24}}"
        [[ "$nuevo_pfx" =~ ^[0-9]+$ ]] && (( nuevo_pfx >= 8 && nuevo_pfx <= 30 )) && break
        err "Prefijo invalido (8-30)."
    done

    while true; do
        read -rp "Gateway [${gw_sug:-192.168.1.1}]: " nuevo_gw
        nuevo_gw="${nuevo_gw:-${gw_sug:-192.168.1.1}}"
        _validar_ip "$nuevo_gw" && break
        err "Gateway invalido."
    done

    while true; do
        read -rp "DNS externo [8.8.8.8]: " nuevo_dns_ext
        nuevo_dns_ext="${nuevo_dns_ext:-8.8.8.8}"
        _validar_ip "$nuevo_dns_ext" && break
        err "DNS invalido."
    done

    echo ""
    echo "IP      : $nueva_ip/$nuevo_pfx"
    echo "Gateway : $nuevo_gw"
    echo "DNS ext : $nuevo_dns_ext"
    read -rp "Aplicar? (s/n): " ok_r
    [[ ! "$ok_r" =~ ^[Ss]$ ]] && { info "Cancelado."; return; }

    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    [[ -f "$cfg" ]] && cp "$cfg" "${cfg}.bak_$(date +%Y%m%d%H%M%S)"

    cat > "$cfg" <<EOF
BOOTPROTO='static'
STARTMODE='auto'
IPADDR='${nueva_ip}'
PREFIXLEN='${nuevo_pfx}'
EOF

    echo "default ${nuevo_gw} - -" > /etc/sysconfig/network/routes

    chattr -i /etc/resolv.conf 2>/dev/null
    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
nameserver ${nuevo_dns_ext}
EOF
    chattr +i /etc/resolv.conf 2>/dev/null || true

    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        ok "systemd-resolved deshabilitado."
    fi

    if systemctl is-active wicked &>/dev/null; then
        wicked ifdown "$IFACE" &>/dev/null; sleep 1
        wicked ifup "$IFACE" &>/dev/null; sleep 3
    elif command -v nmcli &>/dev/null; then
        nmcli connection reload
        nmcli connection up "$IFACE" &>/dev/null; sleep 2
    else
        ip addr flush dev "$IFACE"
        ip addr add "${nueva_ip}/${nuevo_pfx}" dev "$IFACE"
        ip link set "$IFACE" up
        ip route add default via "$nuevo_gw"
    fi

    local ip_check
    ip_check=$(obtener_ip_actual)
    [[ "$ip_check" == "$nueva_ip" ]] \
        && ok "IP estatica aplicada: $nueva_ip/$nuevo_pfx" \
        || info "Configuracion guardada. Verifica con: ip addr show $IFACE"

    DNS_SERVER_IP="$nueva_ip"
    log "IP estatica: $nueva_ip/$nuevo_pfx gw=$nuevo_gw en $IFACE"
    pausar
}

# --------------------------------------------------------------------------
# Instalacion
# --------------------------------------------------------------------------

modulo_instalar() {
    echo ""
    local instalar=()

    for pkg in bind bind-utils; do
        if rpm -q "$pkg" &>/dev/null; then
            ok "$pkg ya esta instalado."
        else
            instalar+=("$pkg")
        fi
    done

    if [[ ${#instalar[@]} -gt 0 ]]; then
        info "Instalando: ${instalar[*]}"
        zypper --non-interactive refresh
        zypper --non-interactive install -y "${instalar[@]}"
        [[ $? -eq 0 ]] && ok "Paquetes instalados." || { err "Error al instalar."; pausar; return 1; }
    fi

    mkdir -p "$NAMED_D" "$ZONES_DIR"
    chown -R named:named "$ZONES_DIR" 2>/dev/null || true
    [[ ! -f "$ZONES_FILE" ]] && touch "$ZONES_FILE"

    _crear_archivos_base
    _configurar_named_conf

    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        ok "systemd-resolved deshabilitado."
    fi

    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        ok "El servicio named ya esta activo."
    else
        systemctl enable "$DNS_SERVICE" &>/dev/null
        systemctl start "$DNS_SERVICE"
        sleep 2
        systemctl is-active "$DNS_SERVICE" &>/dev/null \
            && ok "Servicio named iniciado." \
            || err "No se pudo iniciar named. Revisa: journalctl -u named -n 30"
    fi

    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        ok "Puerto 53 abierto en firewall."
    fi

    pausar
}

_crear_archivos_base() {
    if [[ ! -f "/var/lib/named/root.hint" ]]; then
        cat > "/var/lib/named/root.hint" <<'EOF'
.   3600000  IN  NS  A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.  3600000  A  198.41.0.4
B.ROOT-SERVERS.NET.  3600000  A  199.9.14.201
C.ROOT-SERVERS.NET.  3600000  A  192.33.4.12
D.ROOT-SERVERS.NET.  3600000  A  199.7.91.13
M.ROOT-SERVERS.NET.  3600000  A  202.12.27.33
EOF
        chown named:named "/var/lib/named/root.hint"
        ok "root.hint creado."
    fi

    if [[ ! -f "/var/lib/named/localhost.zone" ]]; then
        cat > "/var/lib/named/localhost.zone" <<'EOF'
$TTL 1D
@  IN  SOA  localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@  IN  NS   localhost.
@  IN  A    127.0.0.1
EOF
        chown named:named "/var/lib/named/localhost.zone"
        ok "localhost.zone creado."
    fi

    if [[ ! -f "/var/lib/named/127.0.0.zone" ]]; then
        cat > "/var/lib/named/127.0.0.zone" <<'EOF'
$TTL 1D
@  IN  SOA  localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@  IN  NS   localhost.
1  IN  PTR  localhost.
EOF
        chown named:named "/var/lib/named/127.0.0.zone"
        ok "127.0.0.zone creado."
    fi
}

_configurar_named_conf() {
    if grep -q "zonas_locales.conf" "$BIND_CONF" 2>/dev/null; then
        # Asegurar DNSSEC deshabilitado
        sed -i 's/dnssec-validation yes/dnssec-validation no/' "$BIND_CONF"
        sed -i 's/dnssec-validation auto/dnssec-validation no/' "$BIND_CONF"
        ok "named.conf ya tiene el include."
        return
    fi

    if [[ -f "$BIND_CONF" ]]; then
        cp "$BIND_CONF" "${BIND_CONF}.bak_$(date +%Y%m%d%H%M%S)"
        sed -i 's/dnssec-validation yes/dnssec-validation no/' "$BIND_CONF"
        sed -i 's/dnssec-validation auto/dnssec-validation no/' "$BIND_CONF"
        echo -e '\n// Zonas personalizadas\ninclude "/etc/named.d/zonas_locales.conf";' >> "$BIND_CONF"
        ok "Include agregado a named.conf."
    else
        cat > "$BIND_CONF" <<'NAMEDCONF'
options {
    directory           "/var/lib/named";
    listen-on           { any; };
    listen-on-v6        { any; };
    allow-query         { any; };
    allow-recursion     { localhost; localnets; };
    recursion           yes;
    forwarders { 8.8.8.8; 8.8.4.4; };
    dnssec-validation   no;
};

logging {
    channel default_log {
        file "/var/log/named.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
    };
    category default { default_log; };
};

zone "." IN { type hint; file "root.hint"; };
zone "localhost" IN { type master; file "localhost.zone"; notify no; };
zone "0.0.127.in-addr.arpa" IN { type master; file "127.0.0.zone"; notify no; };

// Zonas personalizadas
include "/etc/named.d/zonas_locales.conf";
NAMEDCONF
        ok "named.conf generado."
    fi
}

# --------------------------------------------------------------------------
# Dominio
# --------------------------------------------------------------------------

_normalizar_dominio() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

_archivo_zona() { echo "${ZONES_DIR}/db.${1}"; }

_validar_dominio() {
    local d="$1"
    [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]
}

# --------------------------------------------------------------------------
# Alta de zona
# --------------------------------------------------------------------------

modulo_alta() {
    echo ""

    if [[ -z "$DNS_SERVER_IP" ]]; then
        DNS_SERVER_IP=$(obtener_ip_actual)
        if [[ -z "$DNS_SERVER_IP" ]]; then
            err "No se pudo determinar la IP del servidor."
            info "Usa la opcion 2 para configurar la IP primero."
            pausar; return 1
        fi
    fi

    echo "IP del servidor DNS: $DNS_SERVER_IP"
    echo ""
    echo "Formatos validos: miempresa.com  |  www.miempresa.com"
    echo "(si escribes www.dominio.com se normaliza a dominio.com)"
    echo ""

    local entrada dominio
    while true; do
        read -rp "Dominio: " entrada
        entrada=$(echo "$entrada" | xargs)
        [[ -z "$entrada" ]] && { err "El dominio no puede estar vacio."; continue; }
        dominio=$(_normalizar_dominio "$entrada")
        _validar_dominio "$dominio" && break
        err "Dominio invalido: '$dominio'. Ejemplo: miempresa.com"
    done

    info "Dominio: $dominio"
    echo "  $dominio     -> A     -> <IP destino>"
    echo "  www.$dominio -> CNAME -> $dominio"
    echo ""

    local ip_destino
    while true; do
        read -rp "IP de destino [${DNS_SERVER_IP}]: " ip_destino
        ip_destino="${ip_destino:-$DNS_SERVER_IP}"
        _validar_ip "$ip_destino" && break
        err "IP invalida."
    done

    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    if grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        info "La zona '$dominio' ya existe."
        read -rp "Sobreescribir? (s/n): " sobre
        [[ ! "$sobre" =~ ^[Ss]$ ]] && { info "Cancelado."; pausar; return; }
        _eliminar_zona_conf "$dominio"
    fi

    local serial
    serial=$(date +%Y%m%d01)

    cat > "$archivo_z" <<EOF
; Zona: $dominio
; Generado: $(date '+%Y-%m-%d %H:%M:%S')

\$TTL 86400
@   IN  SOA  ns1.${dominio}. admin.${dominio}. (
            ${serial}   ; Serial
            3600        ; Refresh
            1800        ; Retry
            604800      ; Expire
            86400 )     ; Minimum TTL

@       IN  NS   ns1.${dominio}.
ns1     IN  A    ${DNS_SERVER_IP}
@       IN  A    ${ip_destino}
www     IN  CNAME  ${dominio}.
EOF

    chown named:named "$archivo_z" 2>/dev/null || true
    chmod 644 "$archivo_z"

    cat >> "$ZONES_FILE" <<EOF

// Zona: $dominio - $(date '+%Y-%m-%d %H:%M:%S')
zone "$dominio" IN {
    type   master;
    file   "$archivo_z";
    allow-update { none; };
    allow-query  { any; };
    notify no;
};
EOF

    echo ""
    named-checkconf "$BIND_CONF" 2>&1 && ok "named-checkconf sin errores." || { err "Error en named.conf."; pausar; return 1; }
    named-checkzone "$dominio" "$archivo_z" 2>&1 && ok "named-checkzone sin errores." || { err "Error en zona."; pausar; return 1; }

    _recargar_bind

    echo ""
    ok "Zona '$dominio' creada."
    echo "  $dominio     -> A     -> $ip_destino"
    echo "  www.$dominio -> CNAME -> $dominio"
    echo "  ns1.$dominio -> A     -> $DNS_SERVER_IP"

    log "Alta: $dominio ip=$ip_destino dns=$DNS_SERVER_IP"
    pausar
}

# --------------------------------------------------------------------------
# Baja de zona
# --------------------------------------------------------------------------

modulo_baja() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausar; return
    fi

    echo "Zonas actuales:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/  \1/'
    echo ""

    local entrada dominio
    read -rp "Dominio a eliminar: " entrada
    dominio=$(_normalizar_dominio "$entrada")

    [[ -z "$dominio" ]] && { err "Dominio vacio."; pausar; return; }

    if ! grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        err "La zona '$dominio' no existe."
        pausar; return
    fi

    echo ""
    echo "Se eliminara la zona: $dominio"
    echo "Archivo: $(_archivo_zona "$dominio")"
    read -rp "Confirmar? (s/n): " conf
    [[ ! "$conf" =~ ^[Ss]$ ]] && { info "Cancelado."; pausar; return; }

    _eliminar_zona_conf "$dominio"

    named-checkconf "$BIND_CONF" &>/dev/null && _recargar_bind
    ok "Zona '$dominio' eliminada."

    log "Baja: $dominio"
    pausar
}

_eliminar_zona_conf() {
    local dominio="$1"
    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    local archivos=("$ZONES_FILE" "/etc/named.d/zonas.conf")

    for zf in "${archivos[@]}"; do
        [[ -f "$zf" ]] || continue
        grep -q "\"$dominio\"" "$zf" 2>/dev/null || continue

        local linea total inicio fin
        linea=$(grep -n "\"$dominio\"" "$zf" | head -1 | cut -d: -f1)
        [[ -z "$linea" ]] && continue
        total=$(wc -l < "$zf")
        inicio="$linea"

        if [[ "$linea" -gt 1 ]]; then
            local prev
            prev=$(sed -n "$(( linea - 1 ))p" "$zf")
            echo "$prev" | grep -q '^//' && inicio=$(( linea - 1 ))
        fi

        fin="$linea"
        while [[ "$fin" -le "$total" ]]; do
            sed -n "${fin}p" "$zf" | grep -qE '^\s*\};\s*$' && break
            fin=$(( fin + 1 ))
        done

        sed -i "${inicio},${fin}d" "$zf"
        ok "Bloque de '$dominio' eliminado de $(basename "$zf")."
    done

    [[ -f "$archivo_z" ]] && rm -f "$archivo_z" && ok "Archivo de zona eliminado."
}

# --------------------------------------------------------------------------
# Consulta
# --------------------------------------------------------------------------

modulo_consultar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausar; return
    fi

    local dominios
    mapfile -t dominios < <(grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/\1/')

    echo "Zonas configuradas:"
    echo ""

    local idx=1
    for dom in "${dominios[@]}"; do
        local archivo_z
        archivo_z=$(_archivo_zona "$dom")
        echo "[$idx] $dom"
        if [[ -f "$archivo_z" ]]; then
            grep -E '\s+(A|CNAME|NS)\s+' "$archivo_z" | grep -v '^;' | while IFS= read -r linea; do
                echo "     $linea"
            done
        else
            echo "     (archivo no encontrado: $archivo_z)"
        fi
        echo ""
        (( idx++ ))
    done

    echo "Servicio named: $(systemctl is-active $DNS_SERVICE 2>/dev/null)"
    echo "IP del servidor: $(obtener_ip_actual)"

    pausar
}

# --------------------------------------------------------------------------
# Pruebas
# --------------------------------------------------------------------------

modulo_probar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausar; return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/  \1/'
    echo ""

    local entrada dominio
    read -rp "Dominio a probar: " entrada
    dominio=$(_normalizar_dominio "$entrada")

    [[ -z "$dominio" ]] && { err "Dominio vacio."; pausar; return; }

    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    echo ""
    echo "--- named-checkconf ---"
    named-checkconf "$BIND_CONF" 2>&1 && ok "Sin errores." || err "Errores de sintaxis."

    echo ""
    echo "--- named-checkzone $dominio ---"
    if [[ -f "$archivo_z" ]]; then
        named-checkzone "$dominio" "$archivo_z" 2>&1
    else
        err "Archivo no encontrado: $archivo_z"
    fi

    echo ""
    echo "--- nslookup $dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "$dominio" 127.0.0.1 || err "nslookup no disponible."

    echo ""
    echo "--- nslookup www.$dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "www.$dominio" 127.0.0.1

    echo ""
    echo "--- dig @127.0.0.1 $dominio A ---"
    command -v dig &>/dev/null && dig @127.0.0.1 "$dominio" A +short || err "dig no disponible."

    echo ""
    echo "--- ping -c3 www.$dominio ---"
    ping -c 3 -W 2 "www.$dominio" 2>&1 || true

    log "Pruebas: $dominio"
    pausar
}

# --------------------------------------------------------------------------
# Servicio
# --------------------------------------------------------------------------

_recargar_bind() {
    if rndc reload &>/dev/null; then
        ok "Zonas recargadas (rndc reload)."
    elif systemctl reload "$DNS_SERVICE" &>/dev/null; then
        ok "Servicio recargado."
    else
        systemctl restart "$DNS_SERVICE" &>/dev/null; sleep 2
        systemctl is-active "$DNS_SERVICE" &>/dev/null \
            && ok "Servicio reiniciado." \
            || err "Error al reiniciar."
    fi
}

modulo_servicio() {
    echo ""
    echo "Estado del servicio named:"
    echo ""
    systemctl status "$DNS_SERVICE" --no-pager -l
    echo ""
    echo "1) Recargar zonas"
    echo "2) Reiniciar servicio"
    echo "3) Detener servicio"
    echo "4) Ver log de named"
    echo "5) Ver log del script"
    echo "0) Volver"
    echo ""
    read -rp "Opcion: " opc

    case "$opc" in
        1) _recargar_bind ;;
        2) systemctl restart "$DNS_SERVICE"; sleep 2
           systemctl is-active "$DNS_SERVICE" &>/dev/null && ok "Reiniciado." || err "Error." ;;
        3) systemctl stop "$DNS_SERVICE" && ok "Detenido." ;;
        4) [[ -f /var/log/named.log ]] \
               && tail -30 /var/log/named.log \
               || journalctl -u named -n 30 --no-pager ;;
        5) [[ -f "$LOG_FILE" ]] && tail -30 "$LOG_FILE" || info "Sin log todavia." ;;
        0) return ;;
        *) info "Opcion no valida." ;;
    esac
    pausar
}

# --------------------------------------------------------------------------
# Borrar configuracion
# --------------------------------------------------------------------------

modulo_borrar() {
    echo ""
    echo "Se eliminara:"
    echo "  - Todas las zonas en $ZONES_FILE"
    echo "  - Archivos de zona en $ZONES_DIR"
    echo "  - Servicio named se detiene"
    echo ""
    read -rp "Confirma escribiendo BORRAR: " conf
    [[ "$conf" != "BORRAR" ]] && { info "Cancelado."; pausar; return; }

    systemctl stop "$DNS_SERVICE" 2>/dev/null

    [[ -f "$ZONES_FILE" ]] && > "$ZONES_FILE" && ok "zonas_locales.conf vaciado."
    local old="/etc/named.d/zonas.conf"
    [[ -f "$old" ]] && > "$old" && ok "zonas.conf vaciado."

    local count
    count=$(find "$ZONES_DIR" -maxdepth 1 -name 'db.*' 2>/dev/null | wc -l)
    [[ "$count" -gt 0 ]] && rm -f "$ZONES_DIR"/db.* && ok "$count archivo(s) de zona eliminados."

    systemctl disable "$DNS_SERVICE" &>/dev/null
    ok "Servicio deshabilitado."
    echo ""
    ok "Configuracion DNS eliminada."
    info "Para reiniciar usa la opcion 1."

    log "Borrado completo de configuracion."
    pausar
}

# --------------------------------------------------------------------------
# Inicializacion
# --------------------------------------------------------------------------

_inicializar() {
    mkdir -p "$(dirname "$LOG_FILE")" "$NAMED_D" "$ZONES_DIR" 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null || true
    [[ ! -f "$ZONES_FILE" ]] && touch "$ZONES_FILE" 2>/dev/null || true
    DNS_SERVER_IP=$(obtener_ip_actual)

    # Resolver duplicados entre zonas_locales.conf y zonas.conf
    local old="/etc/named.d/zonas.conf"
    if [[ -f "$old" ]] && grep -q 'zone "' "$old" 2>/dev/null; then
        while IFS= read -r dom; do
            [[ -z "$dom" ]] && continue
            grep -q "\"$dom\"" "$ZONES_FILE" 2>/dev/null || continue
            local ln total inicio fin prev
            ln=$(grep -n "\"$dom\"" "$old" | head -1 | cut -d: -f1)
            [[ -z "$ln" ]] && continue
            total=$(wc -l < "$old")
            inicio="$ln"
            [[ "$ln" -gt 1 ]] && {
                prev=$(sed -n "$(( ln - 1 ))p" "$old")
                echo "$prev" | grep -q '^//' && inicio=$(( ln - 1 ))
            }
            fin="$ln"
            while [[ "$fin" -le "$total" ]]; do
                sed -n "${fin}p" "$old" | grep -qE '^\s*\};\s*$' && break
                fin=$(( fin + 1 ))
            done
            sed -i "${inicio},${fin}d" "$old"
            log "Duplicado resuelto: '$dom' en zonas.conf"
        done < <(grep 'zone "' "$old" | sed 's/.*zone "\(.*\)" IN.*/\1/')
    fi
}

# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

_inicializar

while true; do
    clear
    echo "=============================="
    echo " Gestor DNS - BIND9 - $IFACE"
    echo " IP: ${DNS_SERVER_IP:-no detectada}"
    echo "=============================="
    echo "1) Instalar BIND9"
    echo "2) Configurar IP estatica"
    echo "3) Alta de zona"
    echo "4) Baja de zona"
    echo "5) Consultar zonas"
    echo "6) Probar resolucion"
    echo "7) Servicio named"
    echo "8) Borrar configuracion"
    echo "0) Salir"
    echo ""
    read -rp "Opcion: " opcion

    case "$opcion" in
        1) modulo_instalar ;;
        2) modulo_ip_fija ;;
        3) modulo_alta ;;
        4) modulo_baja ;;
        5) modulo_consultar ;;
        6) modulo_probar ;;
        7) modulo_servicio ;;
        8) modulo_borrar ;;
        0) echo "Saliendo."; exit 0 ;;
        *) echo "Opcion no valida."; sleep 1 ;;
    esac
done
