!/bin/bash
# dns_manager.sh
# Gestor de servidor DNS con BIND9 para OpenSUSE Leap
# Interfaz de red: enp0s8
# Requiere ejecutarse como root

IFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
NAMED_D="/etc/named.d"
ZONES_FILE="/etc/named.d/zonas.conf"
ZONES_DIR="/var/lib/named/master"
LOG="/var/log/dns_manager.log"
SVC="named"
SERVER_IP=""

# mensajes
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG" 2>/dev/null; }
ok()   { echo "OK: $*";    log "OK: $*"; }
err()  { echo "ERROR: $*"; log "ERROR: $*"; }
info() { echo "$*";        log "$*"; }
pausa() { echo ""; read -rp "Presiona Enter para continuar..." _x; }

verificar_root() {
    [ "$EUID" -ne 0 ] && { echo "Ejecutar como root: sudo $0"; exit 1; }
}

# --------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------

get_ip() {
    ip addr show "$IFACE" 2>/dev/null \
        | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1
}

get_prefix() {
    ip addr show "$IFACE" 2>/dev/null \
        | grep 'inet ' | awk '{print $2}' | cut -d'/' -f2 | head -1
}

get_gw() {
    ip route | grep "default.*$IFACE" | awk '{print $3}' | head -1
    [ -z "$(ip route | grep "default.*$IFACE" | awk '{print $3}' | head -1)" ] && \
        ip route | grep '^default' | awk '{print $3}' | head -1
}

validar_ip() {
    local ip="$1"
    echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
    local IFS='.'
    read -ra octs <<< "$ip"
    for o in "${octs[@]}"; do
        [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
    done
    return 0
}

es_estatica() {
    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    if [ -f "$cfg" ]; then
        grep -qi "BOOTPROTO=.static." "$cfg" && return 0
    fi
    if command -v nmcli &>/dev/null; then
        nmcli -g IP4.METHOD con show --active 2>/dev/null \
            | grep -qi "manual" && return 0
    fi
    return 1
}

menu_ip() {
    echo ""
    echo "Interfaz: $IFACE"
    echo ""

    if ! ip link show "$IFACE" &>/dev/null; then
        err "La interfaz $IFACE no existe en este sistema."
        echo "Interfaces disponibles:"
        ip link show | grep '^[0-9]' | awk -F': ' '{print "  " $2}'
        pausa
        return 1
    fi

    local ip_act pfx gw
    ip_act=$(get_ip)
    pfx=$(get_prefix)
    gw=$(get_gw)

    echo "IP actual : ${ip_act:-ninguna}"
    echo "Prefijo   : ${pfx:-?}"
    echo "Gateway   : ${gw:-?}"
    echo ""

    if es_estatica; then
        ok "La interfaz ya tiene IP estatica configurada."
        SERVER_IP="$ip_act"
        pausa
        return 0
    fi

    echo "La interfaz usa DHCP."
    read -rp "Configurar IP estatica ahora? (s/n): " resp
    if [ "$resp" != "s" ] && [ "$resp" != "S" ]; then
        SERVER_IP="${ip_act:-127.0.0.1}"
        pausa
        return 0
    fi

    configurar_ip_estatica "$ip_act" "$pfx" "$gw"
}

configurar_ip_estatica() {
    local ip_sug="$1" pfx_sug="$2" gw_sug="$3"
    local nueva_ip nuevo_pfx nuevo_gw dns_ext

    echo ""

    while true; do
        read -rp "Nueva IP [${ip_sug:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_sug:-192.168.1.10}}"
        validar_ip "$nueva_ip" && break
        err "IP invalida. Ejemplo: 192.168.1.10"
    done

    while true; do
        read -rp "Prefijo CIDR [${pfx_sug:-24}]: " nuevo_pfx
        nuevo_pfx="${nuevo_pfx:-${pfx_sug:-24}}"
        echo "$nuevo_pfx" | grep -qE '^[0-9]+$' \
            && [ "$nuevo_pfx" -ge 8 ] && [ "$nuevo_pfx" -le 30 ] && break
        err "Prefijo invalido. Rango permitido: 8 a 30"
    done

    while true; do
        read -rp "Gateway [${gw_sug:-192.168.1.1}]: " nuevo_gw
        nuevo_gw="${nuevo_gw:-${gw_sug:-192.168.1.1}}"
        validar_ip "$nuevo_gw" && break
        err "Gateway invalido."
    done

    while true; do
        read -rp "DNS externo secundario [8.8.8.8]: " dns_ext
        dns_ext="${dns_ext:-8.8.8.8}"
        validar_ip "$dns_ext" && break
        err "DNS invalido."
    done

    echo ""
    echo "Configuracion a aplicar:"
    echo "  IP      : $nueva_ip/$nuevo_pfx"
    echo "  Gateway : $nuevo_gw"
    echo "  DNS ext : $dns_ext"
    echo ""
    read -rp "Aplicar? (s/n): " conf
    if [ "$conf" != "s" ] && [ "$conf" != "S" ]; then
        info "Cancelado."
        return
    fi

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

    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        ok "systemd-resolved deshabilitado (conflicto con BIND9)."
    fi

    if systemctl is-active wicked &>/dev/null; then
        wicked ifdown "$IFACE" &>/dev/null
        sleep 1
        wicked ifup "$IFACE" &>/dev/null
        sleep 3
    elif command -v nmcli &>/dev/null; then
        nmcli connection reload
        nmcli connection up "$IFACE" &>/dev/null
        sleep 2
    else
        ip addr flush dev "$IFACE"
        ip addr add "${nueva_ip}/${nuevo_pfx}" dev "$IFACE"
        ip link set "$IFACE" up
        ip route add default via "$nuevo_gw" 2>/dev/null
    fi

    local ip_check
    ip_check=$(get_ip)
    if [ "$ip_check" = "$nueva_ip" ]; then
        ok "IP estatica aplicada: $nueva_ip/$nuevo_pfx"
    else
        info "Configuracion guardada. Puede tardar unos segundos."
        info "Verifica con: ip addr show $IFACE"
    fi

    SERVER_IP="$nueva_ip"
    log "IP estatica configurada: $nueva_ip/$nuevo_pfx gw=$nuevo_gw"
    pausa
}

# --------------------------------------------------------------------------
# Instalacion de BIND9
# --------------------------------------------------------------------------

menu_instalar() {
    echo ""
    echo "Verificando paquetes de BIND9..."
    echo ""

    local falta=()
    for pkg in bind bind-utils; do
        if rpm -q "$pkg" &>/dev/null; then
            ok "$pkg ya esta instalado."
        else
            falta+=("$pkg")
        fi
    done

    if [ "${#falta[@]}" -gt 0 ]; then
        info "Instalando: ${falta[*]}"
        zypper --non-interactive refresh
        zypper --non-interactive install -y "${falta[@]}"
        if [ $? -ne 0 ]; then
            err "Fallo la instalacion. Verifica los repositorios."
            pausa
            return 1
        fi
        ok "Paquetes instalados."
    fi

    mkdir -p "$NAMED_D" "$ZONES_DIR"
    chown -R named:named "$ZONES_DIR" 2>/dev/null
    [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE"

    # Vaciar archivo de zonas del script anterior si existe
    local old="/etc/named.d/zonas_locales.conf"
    if [ -f "$old" ] && grep -q 'zone "' "$old" 2>/dev/null; then
        > "$old"
        ok "Archivo de zonas anterior vaciado para evitar conflictos."
    fi

    # Asegurar que named.conf incluya el archivo de zonas
    if ! grep -q "zonas.conf" "$NAMED_CONF" 2>/dev/null; then
        if [ -f "$NAMED_CONF" ]; then
            cp "$NAMED_CONF" "${NAMED_CONF}.bak_$(date +%Y%m%d%H%M%S)"
            # Quitar includes viejos que puedan causar conflicto
            sed -i '/zonas_locales\.conf/d' "$NAMED_CONF"
            echo '' >> "$NAMED_CONF"
            echo 'include "/etc/named.d/zonas.conf";' >> "$NAMED_CONF"
            ok "Include agregado a named.conf."
        else
            cat > "$NAMED_CONF" <<'EOF'
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
        ok "named.conf ya tiene el include correcto."
    fi

    # Quitar include de zonas_locales si está en named.conf
    if grep -q "zonas_locales" "$NAMED_CONF" 2>/dev/null; then
        sed -i '/zonas_locales/d' "$NAMED_CONF"
        ok "Referencia a zonas_locales.conf eliminada de named.conf."
    fi

    # Deshabilitar systemd-resolved
    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        ok "systemd-resolved deshabilitado."
    fi

    # Iniciar servicio
    if systemctl is-active "$SVC" &>/dev/null; then
        ok "El servicio named ya esta activo."
    else
        systemctl enable "$SVC" &>/dev/null
        systemctl start "$SVC"
        sleep 2
        if systemctl is-active "$SVC" &>/dev/null; then
            ok "Servicio named iniciado."
        else
            err "No se pudo iniciar named."
            info "Diagnostico: journalctl -u named -n 30"
        fi
    fi

    # Firewall
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        ok "Puerto 53 abierto en firewall."
    fi

    pausa
}

# --------------------------------------------------------------------------
# Utilidades de zona
# --------------------------------------------------------------------------

normalizar() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

validar_dominio() {
    echo "$1" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
}

archivo_zona() {
    echo "${ZONES_DIR}/db.${1}"
}

# Elimina el bloque de una zona de todos los archivos de configuracion
eliminar_bloque_zona() {
    local dom="$1"
    local archivos=("$ZONES_FILE" "/etc/named.d/zonas_locales.conf")

    for zf in "${archivos[@]}"; do
        [ -f "$zf" ] || continue
        grep -q "\"$dom\"" "$zf" 2>/dev/null || continue

        # Encontrar la línea donde está la zona
        local linea_zona total
        linea_zona=$(grep -n "\"$dom\"" "$zf" | head -1 | cut -d: -f1)
        total=$(wc -l < "$zf")

        [ -z "$linea_zona" ] && continue

        # Ver si la línea anterior es un comentario del bloque
        local inicio="$linea_zona"
        if [ "$linea_zona" -gt 1 ]; then
            local prev
            prev=$(sed -n "$(( linea_zona - 1 ))p" "$zf")
            echo "$prev" | grep -q '^//' && inicio=$(( linea_zona - 1 ))
        fi

        # Buscar el cierre }; desde la línea de la zona
        local fin="$linea_zona"
        while [ "$fin" -le "$total" ]; do
            local linea_actual
            linea_actual=$(sed -n "${fin}p" "$zf")
            echo "$linea_actual" | grep -qE '^\s*\};\s*$' && break
            fin=$(( fin + 1 ))
        done

        sed -i "${inicio},${fin}d" "$zf"
        ok "Bloque de '$dom' eliminado de $(basename "$zf")."
    done

    # Eliminar archivo de zona
    local az
    az=$(archivo_zona "$dom")
    if [ -f "$az" ]; then
        rm -f "$az"
        ok "Archivo de zona eliminado: $az"
    fi
}

recargar_bind() {
    if rndc reload &>/dev/null; then
        ok "Zonas recargadas con rndc reload."
    elif systemctl reload "$SVC" &>/dev/null; then
        ok "Servicio recargado."
    else
        systemctl restart "$SVC" &>/dev/null
        sleep 2
        systemctl is-active "$SVC" &>/dev/null \
            && ok "Servicio reiniciado." \
            || err "Error al reiniciar el servicio."
    fi
}

# --------------------------------------------------------------------------
# Alta de zona
# --------------------------------------------------------------------------

menu_alta() {
    echo ""

    [ -z "$SERVER_IP" ] && SERVER_IP=$(get_ip)
    if [ -z "$SERVER_IP" ]; then
        err "No se pudo detectar la IP del servidor."
        info "Usa la opcion 2 para configurar la IP primero."
        pausa
        return 1
    fi

    echo "IP del servidor DNS: $SERVER_IP"
    echo ""
    echo "Ingresa el dominio a registrar."
    echo "Ejemplos validos: miempresa.com  |  www.miempresa.com"
    echo "(si escribes www.dominio.com se normaliza a dominio.com)"
    echo ""

    local entrada dominio
    while true; do
        read -rp "Dominio: " entrada
        entrada=$(echo "$entrada" | xargs)
        if [ -z "$entrada" ]; then
            err "El dominio no puede estar vacio."
            continue
        fi
        dominio=$(normalizar "$entrada")
        if ! validar_dominio "$dominio"; then
            err "Dominio invalido: '$dominio'"
            info "Formato esperado: nombre.tld  Ejemplo: miempresa.com"
            continue
        fi
        break
    done

    echo ""
    echo "Dominio registrado: $dominio"
    echo "Se crearan los registros:"
    echo "  $dominio     -> A     -> (IP que ingreses)"
    echo "  www.$dominio -> CNAME -> $dominio"
    echo ""

    local ip_dest
    while true; do
        read -rp "IP de destino [${SERVER_IP}]: " ip_dest
        ip_dest="${ip_dest:-$SERVER_IP}"
        validar_ip "$ip_dest" && break
        err "IP invalida. Ejemplo: 192.168.1.20"
    done

    # Verificar si ya existe
    local az
    az=$(archivo_zona "$dominio")

    if grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        echo ""
        info "La zona '$dominio' ya existe."
        read -rp "Sobreescribir? (s/n): " over
        if [ "$over" != "s" ] && [ "$over" != "S" ]; then
            info "Cancelado."
            pausa
            return
        fi
        eliminar_bloque_zona "$dominio"
    fi

    local serial
    serial=$(date +%Y%m%d01)

    cat > "$az" <<EOF
; Zona: $dominio
; Fecha: $(date '+%Y-%m-%d %H:%M:%S')

\$TTL 86400
@   IN  SOA  ns1.${dominio}. admin.${dominio}. (
            ${serial}  ; Serial
            3600       ; Refresh
            1800       ; Retry
            604800     ; Expire
            86400 )    ; Minimum TTL

@    IN  NS     ns1.${dominio}.
ns1  IN  A      ${SERVER_IP}
@    IN  A      ${ip_dest}
www  IN  CNAME  ${dominio}.
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
    if ! named-checkconf "$NAMED_CONF" 2>&1; then
        err "Error de sintaxis en named.conf."
        pausa
        return 1
    fi
    ok "named-checkconf sin errores."

    if ! named-checkzone "$dominio" "$az" 2>&1; then
        err "Error en el archivo de zona."
        pausa
        return 1
    fi
    ok "named-checkzone sin errores."

    recargar_bind

    echo ""
    ok "Zona '$dominio' creada correctamente."
    echo "  $dominio     -> A     -> $ip_dest"
    echo "  www.$dominio -> CNAME -> $dominio"
    echo "  ns1.$dominio -> A     -> $SERVER_IP"

    log "Alta: $dominio ip_destino=$ip_dest dns=$SERVER_IP"
    pausa
}

# --------------------------------------------------------------------------
# Baja de zona
# --------------------------------------------------------------------------

menu_baja() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa
        return
    fi

    echo "Zonas actuales:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/  \1/'
    echo ""

    local entrada dominio
    read -rp "Dominio a eliminar: " entrada
    dominio=$(normalizar "$entrada")

    if [ -z "$dominio" ]; then
        err "Dominio vacio."
        pausa
        return
    fi

    if ! grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        err "La zona '$dominio' no existe en la configuracion."
        pausa
        return
    fi

    echo ""
    read -rp "Eliminar zona '$dominio'? (s/n): " conf
    if [ "$conf" != "s" ] && [ "$conf" != "S" ]; then
        info "Cancelado."
        pausa
        return
    fi

    eliminar_bloque_zona "$dominio"

    if named-checkconf "$NAMED_CONF" &>/dev/null; then
        recargar_bind
    else
        err "Error en named.conf tras la baja. Revisa manualmente."
    fi

    log "Baja: $dominio"
    pausa
}

# --------------------------------------------------------------------------
# Consulta de zonas
# --------------------------------------------------------------------------

menu_consultar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa
        return
    fi

    echo "Zonas configuradas:"
    echo ""

    local doms
    mapfile -t doms < <(
        grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/\1/'
    )

    for dom in "${doms[@]}"; do
        local az
        az=$(archivo_zona "$dom")
        echo "Dominio: $dom"
        if [ -f "$az" ]; then
            grep -E '\s+(A|CNAME|NS)\s+' "$az" \
                | grep -v '^;' \
                | while IFS= read -r linea; do
                    echo "  $linea"
                done
        else
            echo "  (archivo de zona no encontrado: $az)"
        fi
        echo ""
    done

    echo "Servicio named : $(systemctl is-active $SVC 2>/dev/null || echo inactivo)"
    echo "IP del servidor: $(get_ip)"

    pausa
}

# --------------------------------------------------------------------------
# Pruebas de resolucion
# --------------------------------------------------------------------------

menu_probar() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        info "No hay zonas configuradas."
        pausa
        return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/  \1/'
    echo ""

    local entrada dominio
    read -rp "Dominio a probar: " entrada
    dominio=$(normalizar "$entrada")

    if [ -z "$dominio" ]; then
        err "Dominio vacio."
        pausa
        return
    fi

    echo ""
    echo "--- named-checkconf ---"
    if named-checkconf "$NAMED_CONF" 2>&1; then
        ok "Sin errores de sintaxis."
    else
        err "Errores en named.conf."
    fi

    echo ""
    echo "--- named-checkzone $dominio ---"
    local az
    az=$(archivo_zona "$dominio")
    if [ -f "$az" ]; then
        named-checkzone "$dominio" "$az" 2>&1
    else
        err "Archivo de zona no encontrado: $az"
    fi

    echo ""
    echo "--- nslookup $dominio 127.0.0.1 ---"
    if command -v nslookup &>/dev/null; then
        nslookup "$dominio" 127.0.0.1
    else
        err "nslookup no disponible. Instala bind-utils."
    fi

    echo ""
    echo "--- nslookup www.$dominio 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "www.$dominio" 127.0.0.1

    echo ""
    echo "--- dig @127.0.0.1 $dominio A ---"
    if command -v dig &>/dev/null; then
        dig @127.0.0.1 "$dominio" A +short
    else
        err "dig no disponible."
    fi

    echo ""
    echo "--- ping -c3 www.$dominio ---"
    ping -c 3 -W 2 "www.$dominio" 2>&1 || true

    log "Pruebas ejecutadas para: $dominio"
    pausa
}

# --------------------------------------------------------------------------
# Gestion del servicio
# --------------------------------------------------------------------------

menu_servicio() {
    echo ""
    echo "Estado del servicio named:"
    echo ""
    systemctl status "$SVC" --no-pager -l
    echo ""
    echo "1) Recargar zonas (sin downtime)"
    echo "2) Reiniciar servicio"
    echo "3) Detener servicio"
    echo "4) Ver log de named"
    echo "0) Volver"
    echo ""
    read -rp "Opcion: " opc

    case "$opc" in
        1)
            recargar_bind
            ;;
        2)
            systemctl restart "$SVC"
            sleep 2
            systemctl is-active "$SVC" &>/dev/null \
                && ok "Servicio reiniciado." \
                || err "No se pudo reiniciar."
            ;;
        3)
            systemctl stop "$SVC" && ok "Servicio detenido."
            ;;
        4)
            echo ""
            if [ -f /var/log/named.log ]; then
                tail -30 /var/log/named.log
            else
                journalctl -u named -n 30 --no-pager
            fi
            ;;
        0)
            return
            ;;
        *)
            info "Opcion no valida."
            ;;
    esac
    pausa
}

# --------------------------------------------------------------------------
# Borrar toda la configuracion DNS
# --------------------------------------------------------------------------

menu_borrar_todo() {
    echo ""
    echo "Esta opcion elimina toda la configuracion DNS gestionada por este script:"
    echo "  - Todas las zonas en $ZONES_FILE"
    echo "  - Todos los archivos de zona en $ZONES_DIR"
    echo "  - El include de named.conf apuntando a zonas.conf"
    echo "  - Detiene y deshabilita el servicio named"
    echo ""
    echo "Los paquetes bind y bind-utils NO se desinstalan."
    echo ""
    read -rp "Confirmar borrado completo? (escribe BORRAR para confirmar): " conf

    if [ "$conf" != "BORRAR" ]; then
        info "Cancelado."
        pausa
        return
    fi

    # Detener servicio
    if systemctl is-active "$SVC" &>/dev/null; then
        systemctl stop "$SVC"
        ok "Servicio named detenido."
    fi

    # Vaciar archivo de zonas
    if [ -f "$ZONES_FILE" ]; then
        > "$ZONES_FILE"
        ok "Archivo $ZONES_FILE vaciado."
    fi

    # Vaciar zonas_locales si existe
    local old="/etc/named.d/zonas_locales.conf"
    if [ -f "$old" ]; then
        > "$old"
        ok "Archivo $old vaciado."
    fi

    # Eliminar todos los archivos de zona en ZONES_DIR
    if [ -d "$ZONES_DIR" ]; then
        local count
        count=$(find "$ZONES_DIR" -name 'db.*' | wc -l)
        if [ "$count" -gt 0 ]; then
            rm -f "$ZONES_DIR"/db.*
            ok "$count archivo(s) de zona eliminados de $ZONES_DIR."
        else
            info "No habia archivos de zona en $ZONES_DIR."
        fi
    fi

    # Quitar el include de zonas.conf en named.conf
    if [ -f "$NAMED_CONF" ]; then
        cp "$NAMED_CONF" "${NAMED_CONF}.bak_$(date +%Y%m%d%H%M%S)"
        sed -i '/zonas\.conf/d' "$NAMED_CONF"
        sed -i '/zonas_locales/d' "$NAMED_CONF"
        ok "Includes eliminados de named.conf (backup guardado)."
    fi

    # Deshabilitar servicio
    systemctl disable "$SVC" &>/dev/null
    ok "Servicio named deshabilitado del arranque."

    echo ""
    ok "Configuracion DNS borrada completamente."
    info "Para volver a usar el script, ejecuta la opcion 1 (Instalar BIND9)."

    log "Borrado completo de configuracion DNS."
    pausa
}

# --------------------------------------------------------------------------
# Inicio y deteccion de conflictos
# --------------------------------------------------------------------------

init() {
    mkdir -p "$(dirname "$LOG")" "$NAMED_D" "$ZONES_DIR" 2>/dev/null
    touch "$LOG" 2>/dev/null
    [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE" 2>/dev/null
    SERVER_IP=$(get_ip)

    # Resolver conflicto si el mismo dominio aparece en zonas.conf
    # y en zonas_locales.conf al mismo tiempo
    local old="/etc/named.d/zonas_locales.conf"
    if [ -f "$old" ] && grep -q 'zone "' "$old" 2>/dev/null; then
        local doms_old doms_new
        mapfile -t doms_old < <(
            grep 'zone "' "$old" | sed 's/.*zone "\(.*\)" IN.*/\1/'
        )
        for d in "${doms_old[@]}"; do
            [ -z "$d" ] && continue
            if grep -q "\"$d\"" "$ZONES_FILE" 2>/dev/null; then
                # Dominio duplicado: quitarlo del archivo viejo
                local ln total
                ln=$(grep -n "\"$d\"" "$old" | head -1 | cut -d: -f1)
                total=$(wc -l < "$old")
                [ -z "$ln" ] && continue
                local inicio="$ln"
                [ "$ln" -gt 1 ] && {
                    prev=$(sed -n "$(( ln - 1 ))p" "$old")
                    echo "$prev" | grep -q '^//' && inicio=$(( ln - 1 ))
                }
                local fin="$ln"
                while [ "$fin" -le "$total" ]; do
                    local la
                    la=$(sed -n "${fin}p" "$old")
                    echo "$la" | grep -qE '^\s*\};\s*$' && break
                    fin=$(( fin + 1 ))
                done
                sed -i "${inicio},${fin}d" "$old"
                log "Conflicto resuelto: '$d' quitado de zonas_locales.conf"
            fi
        done
    fi
}

# --------------------------------------------------------------------------
# Menu principal
# --------------------------------------------------------------------------

menu_principal() {
    while true; do
        clear
        echo "================================"
        echo " Gestor DNS - BIND9 - $IFACE"
        echo " IP: ${SERVER_IP:-no detectada}"
        echo "================================"
        echo "1) Instalar BIND9"
        echo "2) Configurar IP estatica"
        echo "3) Alta de zona"
        echo "4) Baja de zona"
        echo "5) Consultar zonas"
        echo "6) Probar resolucion"
        echo "7) Servicio named"
        echo "8) Borrar toda la configuracion"
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
            8) menu_borrar_todo ;;
            0) echo "Saliendo."; exit 0 ;;
            *) echo "Opcion no valida."; sleep 1 ;;
        esac
    done
}

# --------------------------------------------------------------------------
# Soporte de parametros por linea de comandos
# --------------------------------------------------------------------------

uso() {
    echo "Uso: $0 [opcion] [argumentos]"
    echo ""
    echo "Sin argumentos    Menu interactivo"
    echo "--instalar        Instalar BIND9"
    echo "--ip              Configurar IP estatica"
    echo "--alta DOM IP     Dar de alta una zona"
    echo "--baja DOM        Dar de baja una zona"
    echo "--consultar       Listar zonas"
    echo "--probar DOM      Probar resolucion de un dominio"
    echo "--estado          Ver estado del servicio"
    echo "--borrar          Borrar toda la configuracion (sin confirmacion interactiva)"
}

# --------------------------------------------------------------------------
# Punto de entrada
# --------------------------------------------------------------------------

verificar_root
init

case "${1:-}" in
    --instalar)
        menu_instalar
        ;;
    --ip)
        menu_ip
        ;;
    --alta)
        if [ -z "${2:-}" ] || [ -z "${3:-}" ]; then
            err "Uso: $0 --alta dominio ip_destino"
            exit 1
        fi
        dominio=$(normalizar "$2")
        ip_dest="$3"
        validar_dominio "$dominio" || { err "Dominio invalido: $dominio"; exit 1; }
        validar_ip "$ip_dest"      || { err "IP invalida: $ip_dest"; exit 1; }
        [ -z "$SERVER_IP" ] && SERVER_IP=$(get_ip)
        az=$(archivo_zona "$dominio")
        serial=$(date +%Y%m%d01)
        mkdir -p "$ZONES_DIR"
        [ ! -f "$ZONES_FILE" ] && touch "$ZONES_FILE"
        if grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
            eliminar_bloque_zona "$dominio"
        fi
        cat > "$az" <<EOF
\$TTL 86400
@   IN  SOA  ns1.${dominio}. admin.${dominio}. (${serial} 3600 1800 604800 86400)
@   IN  NS   ns1.${dominio}.
ns1 IN  A    ${SERVER_IP}
@   IN  A    ${ip_dest}
www IN  CNAME ${dominio}.
EOF
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
        named-checkconf "$NAMED_CONF" && recargar_bind && ok "Zona '$dominio' creada."
        ;;
    --baja)
        if [ -z "${2:-}" ]; then
            err "Uso: $0 --baja dominio"
            exit 1
        fi
        dominio=$(normalizar "$2")
        eliminar_bloque_zona "$dominio"
        named-checkconf "$NAMED_CONF" &>/dev/null && recargar_bind
        ok "Zona '$dominio' eliminada."
        ;;
    --consultar)
        menu_consultar
        ;;
    --probar)
        if [ -z "${2:-}" ]; then
            err "Uso: $0 --probar dominio"
            exit 1
        fi
        dominio=$(normalizar "$2")
        # Llamar pruebas sin menu interactivo
        echo ""
        echo "--- named-checkconf ---"
        named-checkconf "$NAMED_CONF" 2>&1
        az=$(archivo_zona "$dominio")
        echo ""
        echo "--- named-checkzone $dominio ---"
        [ -f "$az" ] && named-checkzone "$dominio" "$az" 2>&1 || err "Archivo no encontrado."
        echo ""
        echo "--- nslookup $dominio 127.0.0.1 ---"
        nslookup "$dominio" 127.0.0.1 2>&1
        echo ""
        echo "--- nslookup www.$dominio 127.0.0.1 ---"
        nslookup "www.$dominio" 127.0.0.1 2>&1
        ;;
    --estado)
        menu_servicio
        ;;
    --borrar)
        # Version no interactiva para scripts
        systemctl stop "$SVC" 2>/dev/null
        [ -f "$ZONES_FILE" ] && > "$ZONES_FILE"
        [ -f "/etc/named.d/zonas_locales.conf" ] && > "/etc/named.d/zonas_locales.conf"
        rm -f "$ZONES_DIR"/db.* 2>/dev/null
        [ -f "$NAMED_CONF" ] && sed -i '/zonas/d' "$NAMED_CONF"
        systemctl disable "$SVC" &>/dev/null
        ok "Configuracion borrada."
        ;;
    --ayuda|-h|--help)
        uso
        ;;
    "")
        menu_principal
        ;;
    *)
        err "Opcion desconocida: $1"
        uso
        exit 1
        ;;
esac
