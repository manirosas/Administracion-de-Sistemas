#!/bin/bash
# dns_manager.sh - Gestor DNS con BIND9 para OpenSUSE Leap
# Interfaz: enp0s8
# Requiere: root

IFACE="enp0s8"
BIND_CONF="/etc/named.conf"
NAMED_D="/etc/named.d"
ZONES_FILE="/etc/named.d/zonas.conf"
ZONES_DIR="/var/lib/named/master"
LOG="/var/log/dns_manager.log"
SVC="named"
SERVER_IP=""

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null; }
ok()   { echo "  OK: $*";   log "OK: $*"; }
err()  { echo "  ERROR: $*"; log "ERR: $*"; }
info() { echo "  $*";       log "$*"; }
pausa() { echo ""; read -rp "  Enter para continuar..." x; }

verificar_root() {
    [ $EUID -ne 0 ] && { echo "Ejecutar como root: sudo $0"; exit 1; }
}

# ── IP ────────────────────────────────────────────────────────────────────────

get_ip() {
    ip addr show "$IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1
}

get_prefix() {
    ip addr show "$IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f2 | head -1
}

get_gw() {
    ip route | grep "default.*$IFACE" | awk '{print $3}' | head -1 || \
    ip route | grep '^default' | awk '{print $3}' | head -1
}

validar_ip() {
    echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    local IFS='.'
    read -ra o <<< "$1"
    for x in "${o[@]}"; do [ "$x" -le 255 ] || return 1; done
    return 0
}

es_estatica() {
    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    [ -f "$cfg" ] && grep -qi "BOOTPROTO=.static." "$cfg" && return 0
    command -v nmcli &>/dev/null && \
        nmcli -g IP4.METHOD con show --active 2>/dev/null | grep -qi "manual" && return 0
    return 1
}

menu_ip() {
    echo ""
    echo "Interfaz: $IFACE"

    if ! ip link show "$IFACE" &>/dev/null; then
        err "La interfaz $IFACE no existe."
        echo "  Interfaces disponibles:"
        ip link show | grep '^[0-9]' | awk -F': ' '{print "    " $2}'
        pausa; return 1
    fi

    local ip_act prefix gw
    ip_act=$(get_ip)
    prefix=$(get_prefix)
    gw=$(get_gw)

    echo "  IP actual:  ${ip_act:-ninguna}"
    echo "  Prefijo:    ${prefix:-?}"
    echo "  Gateway:    ${gw:-?}"
    echo ""

    if es_estatica; then
        ok "La IP ya es estática."
        SERVER_IP="$ip_act"
        pausa; return 0
    fi

    echo "  La interfaz usa DHCP."
    read -rp "  Configurar IP estática? (s/n): " r
    [ "$r" != "s" ] && [ "$r" != "S" ] && {
        SERVER_IP="${ip_act:-127.0.0.1}"
        pausa; return 0
    }

    configurar_ip_estatica "$ip_act" "$prefix" "$gw"
}

configurar_ip_estatica() {
    local ip_sug="$1" pfx_sug="$2" gw_sug="$3"
    local nueva_ip nuevo_pfx nuevo_gw dns_ext

    while true; do
        read -rp "  Nueva IP [${ip_sug:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_sug:-192.168.1.10}}"
        validar_ip "$nueva_ip" && break
        err "IP inválida."
    done

    while true; do
        read -rp "  Prefijo CIDR [${pfx_sug:-24}]: " nuevo_pfx
        nuevo_pfx="${nuevo_pfx:-${pfx_sug:-24}}"
        echo "$nuevo_pfx" | grep -qE '^[0-9]+$' && \
            [ "$nuevo_pfx" -ge 8 ] && [ "$nuevo_pfx" -le 30 ] && break
        err "Prefijo inválido (8-30)."
    done

    while true; do
        read -rp "  Gateway [${gw_sug:-192.168.1.1}]: " nuevo_gw
        nuevo_gw="${nuevo_gw:-${gw_sug:-192.168.1.1}}"
        validar_ip "$nuevo_gw" && break
        err "Gateway inválido."
    done

    while true; do
        read -rp "  DNS externo [8.8.8.8]: " dns_ext
        dns_ext="${dns_ext:-8.8.8.8}"
        validar_ip "$dns_ext" && break
        err "DNS inválido."
    done

    echo ""
    echo "  IP:      $nueva_ip/$nuevo_pfx"
    echo "  Gateway: $nuevo_gw"
    echo "  DNS ext: $dns_ext"
    read -rp "  Aplicar? (s/n): " ok_r
    [ "$ok_r" != "s" ] && [ "$ok_r" != "S" ] && { info "Cancelado."; return; }

    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    [ -f "$cfg" ] && cp "$cfg" "${cfg}.bak_$(date +%Y%m%d%H%M%S)"

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
nameserver ${dns_ext}
EOF
    chattr +i /etc/resolv.conf 2>/dev/null

    # Detener systemd-resolved si está activo (interfiere con BIND9)
    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        info "systemd-resolved deshabilitado."
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
    ip_check=$(get_ip)
    if [ "$ip_check" = "$nueva_ip" ]; then
        ok "IP estática aplicada: $nueva_ip/$nuevo_pfx"
    else
        info "IP configurada. Puede tardar unos segundos en sincronizarse."
        info "Ejecuta 'ip addr show $IFACE' para verificar."
    fi

    SERVER_IP="$nueva_ip"
    log "IP estática: $nueva_ip/$nuevo_pfx gw=$nuevo_gw iface=$IFACE"
    pausa
}

# ── BIND9 ─────────────────────────────────────────────────────────────────────

menu_instalar() {
    echo ""
    echo "Instalando BIND9..."
    echo ""

    local instalar=()
    for pkg in bind bind-utils; do
        if rpm -q "$pkg" &>/dev/null; then
            ok "$pkg ya instalado."
        else
            instalar+=("$pkg")
        fi
    done

    if [ ${#instalar[@]} -gt 0 ]; then
        info "Instalando: ${instalar[*]}"
        zypper --non-interactive refresh
        zypper --non-interactive install -y "${instalar[@]}"
        [ $? -eq 0 ] && ok "Paquetes instalados." || { err "Error al instalar."; pausa; return 1; }
    fi

    mkdir -p "$NAMED_D" "$ZONES_DIR"
    chown -R named:named "$ZONES_DIR" 2>/dev/null

    [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE"

    # Agregar include a named.conf si no está
    if ! grep -q "zonas.conf" "$BIND_CONF" 2>/dev/null; then
        if [ -f "$BIND_CONF" ]; then
            cp "$BIND_CONF" "${BIND_CONF}.bak_$(date +%Y%m%d%H%M%S)"
            echo -e '\ninclude "/etc/named.d/zonas.conf";' >> "$BIND_CONF"
            ok "Include agregado a named.conf."
        else
            cat > "$BIND_CONF" <<'EOF'
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

zone "." IN { type hint; file "root.hint"; };
zone "localhost" IN { type master; file "localhost.zone"; notify no; };
zone "0.0.127.in-addr.arpa" IN { type master; file "127.0.0.zone"; notify no; };

include "/etc/named.d/zonas.conf";
EOF
            ok "named.conf generado."
        fi
    else
        ok "named.conf ya tiene el include."
    fi

    # Deshabilitar systemd-resolved si está activo
    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        ok "systemd-resolved deshabilitado (conflicto con BIND9)."
    fi

    # Servicio
    if systemctl is-active "$SVC" &>/dev/null; then
        ok "El servicio named ya está activo."
    else
        systemctl enable "$SVC" &>/dev/null
        systemctl start "$SVC"
        sleep 2
        systemctl is-active "$SVC" &>/dev/null && ok "Servicio named iniciado." || \
            err "No se pudo iniciar named. Revisa: journalctl -u named -n 30"
    fi

    # Firewall
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        ok "Puerto 53 abierto en firewalld."
    fi

    pausa
}

# ── Zona ──────────────────────────────────────────────────────────────────────

normalizar() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

validar_dominio() {
    echo "$1" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
}

archivo_zona() { echo "${ZONES_DIR}/db.${1}"; }

menu_alta() {
    echo ""

    [ -z "$SERVER_IP" ] && SERVER_IP=$(get_ip)
    if [ -z "$SERVER_IP" ]; then
        err "No se detectó IP del servidor. Configura la IP primero."
        pausa; return 1
    fi

    echo "IP del servidor DNS: $SERVER_IP"
    echo ""
    echo "Puedes ingresar: reprobados.com  o  www.reprobados.com"
    echo "En ambos casos se crean registros A y CNAME para www."
    echo ""

    local entrada dominio
    while true; do
        read -rp "  Dominio: " entrada
        [ -z "$entrada" ] && { err "El dominio no puede estar vacío."; continue; }
        dominio=$(normalizar "$entrada")
        validar_dominio "$dominio" && break
        err "Dominio inválido: '$dominio'. Ejemplo: reprobados.com"
    done

    echo "  Dominio: $dominio"
    echo "  Se crearán: $dominio (A) y www.$dominio (CNAME)"
    echo ""

    local ip_dest
    while true; do
        read -rp "  IP destino [${SERVER_IP}]: " ip_dest
        ip_dest="${ip_dest:-$SERVER_IP}"
        validar_ip "$ip_dest" && break
        err "IP inválida."
    done

    local az
    az=$(archivo_zona "$dominio")

    if grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        echo ""
        info "La zona '$dominio' ya existe."
        read -rp "  Sobreescribir? (s/n): " over
        [ "$over" != "s" ] && [ "$over" != "S" ] && { info "Cancelado."; pausa; return; }
        eliminar_zona_conf "$dominio"
    fi

    local serial
    serial=$(date +%Y%m%d01)

    cat > "$az" <<EOF
; Zona: $dominio
; Generado: $(date '+%Y-%m-%d %H:%M:%S')

\$TTL 86400
@   IN  SOA  ns1.${dominio}. admin.${dominio}. (
            ${serial}  ; Serial
            3600       ; Refresh
            1800       ; Retry
            604800     ; Expire
            86400 )    ; Minimum TTL

@       IN  NS     ns1.${dominio}.
ns1     IN  A      ${SERVER_IP}
@       IN  A      ${ip_dest}
www     IN  CNAME  ${dominio}.
EOF

    chown named:named "$az" 2>/dev/null
    chmod 644 "$az"

    cat >> "$ZONES_FILE" <<EOF

// Zona: $dominio - $(date '+%Y-%m-%d %H:%M:%S')
zone "$dominio" IN {
    type master;
    file "$az";
    allow-update { none; };
    allow-query { any; };
    notify no;
};
EOF

    echo ""
    # Validar
    if ! named-checkconf "$BIND_CONF" 2>&1; then
        err "Error en named.conf."; pausa; return 1
    fi
    ok "named-checkconf sin errores."

    if ! named-checkzone "$dominio" "$az" 2>&1; then
        err "Error en el archivo de zona."; pausa; return 1
    fi
    ok "named-checkzone sin errores."

    recargar_bind

    echo ""
    ok "Zona '$dominio' creada."
    echo "  $dominio     -> A     -> $ip_dest"
    echo "  www.$dominio -> CNAME -> $dominio"

    log "Alta: $dominio ip=$ip_dest dns=$SERVER_IP"
    pausa
}

menu_baja() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa; return
    fi

    echo "Zonas actuales:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/    \1/'
    echo ""

    local entrada dominio
    read -rp "  Dominio a eliminar: " entrada
    dominio=$(normalizar "$entrada")

    [ -z "$dominio" ] && { err "Dominio vacío."; pausa; return; }

    if ! grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        err "La zona '$dominio' no existe."
        pausa; return
    fi

    echo ""
    read -rp "  Eliminar zona '$dominio'? (s/n): " conf
    [ "$conf" != "s" ] && [ "$conf" != "S" ] && { info "Cancelado."; pausa; return; }

    eliminar_zona_conf "$dominio"

    named-checkconf "$BIND_CONF" &>/dev/null && recargar_bind
    ok "Zona '$dominio' eliminada."

    log "Baja: $dominio"
    pausa
}

eliminar_zona_conf() {
    local dom="$1"
    local az
    az=$(archivo_zona "$dom")

    python3 <<PYEOF
import re
path = "$ZONES_FILE"
dom  = "$dom"
try:
    with open(path) as f:
        c = f.read()
    c = re.sub(
        r'// Zona: ' + re.escape(dom) + r'.*?^};',
        '', c,
        flags=re.MULTILINE|re.DOTALL
    )
    with open(path, 'w') as f:
        f.write(c)
except Exception as e:
    print(f"Error: {e}")
PYEOF

    [ -f "$az" ] && rm -f "$az" && ok "Archivo de zona eliminado: $az"
}

# ── Consulta ──────────────────────────────────────────────────────────────────

menu_consultar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa; return
    fi

    echo "Zonas configuradas:"
    echo ""

    local dominios
    mapfile -t dominios < <(grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/\1/')

    for dom in "${dominios[@]}"; do
        local az
        az=$(archivo_zona "$dom")
        echo "  $dom"
        if [ -f "$az" ]; then
            grep -E '\s+(A|CNAME|NS)\s+' "$az" | grep -v '^;' | while read -r l; do
                echo "    $l"
            done
        else
            echo "    (archivo de zona no encontrado)"
        fi
        echo ""
    done

    echo "Servicio named:"
    systemctl is-active "$SVC" &>/dev/null && echo "  activo" || echo "  inactivo"
    echo "IP servidor: $(get_ip)"

    pausa
}

# ── Pruebas ───────────────────────────────────────────────────────────────────

menu_probar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa; return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/    \1/'
    echo ""

    local entrada dominio
    read -rp "  Dominio a probar: " entrada
    dominio=$(normalizar "$entrada")

    [ -z "$dominio" ] && { err "Dominio vacío."; pausa; return; }

    echo ""
    echo "--- named-checkconf ---"
    named-checkconf "$BIND_CONF" 2>&1 && ok "Sin errores." || err "Errores en named.conf."

    echo ""
    echo "--- named-checkzone ---"
    local az
    az=$(archivo_zona "$dominio")
    if [ -f "$az" ]; then
        named-checkzone "$dominio" "$az" 2>&1
    else
        err "Archivo de zona no encontrado: $az"
    fi

    echo ""
    echo "--- nslookup $dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "$dominio" 127.0.0.1 || err "nslookup no disponible."

    echo ""
    echo "--- nslookup www.$dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "www.$dominio" 127.0.0.1

    echo ""
    echo "--- dig $dominio A ---"
    command -v dig &>/dev/null && dig @127.0.0.1 "$dominio" A +short || err "dig no disponible."

    echo ""
    echo "--- ping www.$dominio ---"
    ping -c 3 -W 2 "www.$dominio" 2>&1 || true

    log "Pruebas ejecutadas: $dominio"
    pausa
}

# ── Servicio ──────────────────────────────────────────────────────────────────

menu_servicio() {
    echo ""
    echo "Estado del servicio named:"
    systemctl status "$SVC" --no-pager -l
    echo ""
    echo "1) Recargar zonas (sin downtime)"
    echo "2) Reiniciar servicio"
    echo "3) Detener servicio"
    echo "4) Ver log named"
    echo "0) Volver"
    echo ""
    read -rp "  Opcion: " opc

    case "$opc" in
        1) recargar_bind ;;
        2) systemctl restart "$SVC"; sleep 2
           systemctl is-active "$SVC" &>/dev/null && ok "Reiniciado." || err "Error." ;;
        3) systemctl stop "$SVC" && ok "Detenido." ;;
        4) [ -f /var/log/named.log ] && tail -30 /var/log/named.log || \
               journalctl -u named -n 30 --no-pager ;;
        0) return ;;
        *) info "Opción no válida." ;;
    esac
    pausa
}

recargar_bind() {
    if rndc reload &>/dev/null; then
        ok "Zonas recargadas (rndc reload)."
    elif systemctl reload "$SVC" &>/dev/null; then
        ok "Servicio recargado."
    else
        systemctl restart "$SVC" &>/dev/null; sleep 2
        systemctl is-active "$SVC" &>/dev/null && ok "Servicio reiniciado." || err "Error al reiniciar."
    fi
}

# ── Inicio ────────────────────────────────────────────────────────────────────

init() {
    mkdir -p "$(dirname "$LOG")" "$NAMED_D" "$ZONES_DIR" 2>/dev/null
    touch "$LOG" 2>/dev/null
    [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE" 2>/dev/null
    SERVER_IP=$(get_ip)
}

# ── Menú ──────────────────────────────────────────────────────────────────────

menu() {
    while true; do
        clear
        echo "================================"
        echo " Gestor DNS - BIND9 - $IFACE"
        echo " IP: ${SERVER_IP:-no detectada}"
        echo "================================"
        echo "1) Instalar BIND9"
        echo "2) Configurar IP estatica"
        echo "3) Alta de dominio"
        echo "4) Baja de dominio"
        echo "5) Consultar dominios"
        echo "6) Probar resolucion"
        echo "7) Servicio named"
        echo "0) Salir"
        echo ""
        read -rp "Opcion: " op

        case "$op" in
            1) menu_instalar ;;
            2) menu_ip ;;
            3) menu_alta ;;
            4) menu_baja ;;
            5) menu_consultar ;;
            6) menu_probar ;;
            7) menu_servicio ;;
            0) echo "Saliendo."; exit 0 ;;
            *) echo "Opcion no valida."; sleep 1 ;;
        esac
    done
}

# ── CLI ───────────────────────────────────────────────────────────────────────

verificar_root
init

case "${1:-}" in
    --instalar)  menu_instalar ;;
    --ip)        menu_ip ;;
    --alta)
        [ -z "${2:-}" ] || [ -z "${3:-}" ] && { err "Uso: $0 --alta dominio ip"; exit 1; }
        SERVER_IP=$(get_ip)
        entrada="$2"; ip_dest="$3"
        dominio=$(normalizar "$entrada")
        validar_dominio "$dominio" || { err "Dominio inválido."; exit 1; }
        validar_ip "$ip_dest"     || { err "IP inválida."; exit 1; }
        az=$(archivo_zona "$dominio")
        serial=$(date +%Y%m%d01)
        mkdir -p "$ZONES_DIR"
        [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE"
        cat > "$az" <<EOF
\$TTL 86400
@ IN SOA ns1.${dominio}. admin.${dominio}. (${serial} 3600 1800 604800 86400)
@ IN NS  ns1.${dominio}.
ns1 IN A   ${SERVER_IP}
@   IN A   ${ip_dest}
www IN CNAME ${dominio}.
EOF
        cat >> "$ZONES_FILE" <<EOF
// Zona: $dominio - $(date '+%Y-%m-%d %H:%M:%S')
zone "$dominio" IN { type master; file "$az"; allow-update { none; }; allow-query { any; }; notify no; };
EOF
        named-checkconf && recargar_bind && ok "Zona '$dominio' creada."
        ;;
    --baja)
        [ -z "${2:-}" ] && { err "Uso: $0 --baja dominio"; exit 1; }
        dominio=$(normalizar "$2")
        eliminar_zona_conf "$dominio"
        recargar_bind && ok "Zona '$dominio' eliminada."
        ;;
    --consultar) menu_consultar ;;
    --probar)
        [ -z "${2:-}" ] && { err "Uso: $0 --probar dominio"; exit 1; }
        dominio=$(normalizar "$2")
        menu_probar <<< "$dominio"
        ;;
    --estado) menu_servicio ;;
    "") menu ;;
    *) err "Opcion desconocida: $1"; exit 1 ;;
esac

