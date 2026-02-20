#!/bin/bash

[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

INTERFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
ZONES_CONF="/etc/named.d/zonas.conf"
ZONE_DIR="/var/lib/named"
SERIAL_DIR="/var/lib/named/serial"

pause() { read -rp "ENTER para continuar..."; }

# --------------------------------------------------------------------------
# IP
# --------------------------------------------------------------------------

get_ip() {
    ip -4 addr show "$INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1
}

es_estatica() {
    local cfg="/etc/sysconfig/network/ifcfg-${INTERFACE}"
    [[ -f "$cfg" ]] && grep -qi "BOOTPROTO=.static." "$cfg" && return 0
    command -v nmcli &>/dev/null && \
        nmcli -g IP4.METHOD con show --active 2>/dev/null | grep -qi "manual" && return 0
    return 1
}

validar_ip_formato() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra octs <<< "$ip"
    for o in "${octs[@]}"; do
        [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
    done
    return 0
}

configurar_ip() {
    local ip_act pfx gw dns_ext
    ip_act=$(get_ip)

    echo ""
    echo "Interfaz : $INTERFACE"
    echo "IP actual: ${ip_act:-ninguna}"
    echo ""

    if ! ip link show "$INTERFACE" &>/dev/null; then
        echo "ERROR: La interfaz $INTERFACE no existe."
        echo "Interfaces disponibles:"
        ip link show | grep '^[0-9]' | awk -F': ' '{print "  " $2}'
        return 1
    fi

    if es_estatica; then
        echo "La interfaz ya tiene IP estatica: $ip_act"
        return 0
    fi

    echo "La interfaz usa DHCP."
    read -rp "Configurar IP estatica? (s/n): " resp
    [[ "$resp" != "s" && "$resp" != "S" ]] && return 0

    echo ""

    while true; do
        read -rp "Nueva IP [${ip_act:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_act:-192.168.1.10}}"
        validar_ip_formato "$nueva_ip" && break
        echo "IP invalida."
    done

    while true; do
        read -rp "Prefijo CIDR [24]: " pfx
        pfx="${pfx:-24}"
        [[ "$pfx" =~ ^[0-9]+$ ]] && [[ "$pfx" -ge 8 && "$pfx" -le 30 ]] && break
        echo "Prefijo invalido (8-30)."
    done

    while true; do
        read -rp "Gateway: " gw
        validar_ip_formato "$gw" && break
        echo "Gateway invalido."
    done

    while true; do
        read -rp "DNS externo [8.8.8.8]: " dns_ext
        dns_ext="${dns_ext:-8.8.8.8}"
        validar_ip_formato "$dns_ext" && break
        echo "DNS invalido."
    done

    echo ""
    echo "IP      : $nueva_ip/$pfx"
    echo "Gateway : $gw"
    echo "DNS ext : $dns_ext"
    read -rp "Aplicar? (s/n): " conf
    [[ "$conf" != "s" && "$conf" != "S" ]] && echo "Cancelado." && return

    local cfg="/etc/sysconfig/network/ifcfg-${INTERFACE}"
    [[ -f "$cfg" ]] && cp "$cfg" "${cfg}.bak_$(date +%Y%m%d%H%M%S)"

    cat > "$cfg" <<EOF
BOOTPROTO='static'
STARTMODE='auto'
IPADDR='${nueva_ip}'
PREFIXLEN='${pfx}'
EOF

    echo "default ${gw} - -" > /etc/sysconfig/network/routes

    chattr -i /etc/resolv.conf 2>/dev/null
    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
nameserver ${dns_ext}
EOF
    chattr +i /etc/resolv.conf 2>/dev/null

    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        echo "systemd-resolved deshabilitado."
    fi

    if systemctl is-active wicked &>/dev/null; then
        wicked ifdown "$INTERFACE" &>/dev/null; sleep 1
        wicked ifup "$INTERFACE" &>/dev/null; sleep 3
    elif command -v nmcli &>/dev/null; then
        nmcli connection reload
        nmcli connection up "$INTERFACE" &>/dev/null; sleep 2
    else
        ip addr flush dev "$INTERFACE"
        ip addr add "${nueva_ip}/${pfx}" dev "$INTERFACE"
        ip link set "$INTERFACE" up
        ip route add default via "$gw" 2>/dev/null
    fi

    local check
    check=$(get_ip)
    [[ "$check" == "$nueva_ip" ]] \
        && echo "IP aplicada: $nueva_ip/$pfx" \
        || echo "Configuracion guardada. Verifica con: ip addr show $INTERFACE"
}

# --------------------------------------------------------------------------
# Serial
# --------------------------------------------------------------------------

next_serial() {
    local domain="$1"
    local file="$SERIAL_DIR/$domain.serial"
    mkdir -p "$SERIAL_DIR"
    if [[ ! -f "$file" ]]; then
        date +%Y%m%d01 > "$file"
    else
        echo $(( $(cat "$file") + 1 )) > "$file"
    fi
    cat "$file"
}

# --------------------------------------------------------------------------
# Instalacion
# --------------------------------------------------------------------------

instalar_dns() {
    if rpm -q bind &>/dev/null; then
        echo "BIND ya esta instalado."
    else
        zypper --non-interactive refresh
        zypper --non-interactive install -y bind bind-utils || exit 1
        echo "BIND instalado."
    fi

    mkdir -p /etc/named.d "$ZONE_DIR" "$SERIAL_DIR"
    chown -R named:named "$ZONE_DIR" 2>/dev/null
    [[ ! -f "$ZONES_CONF" ]] && touch "$ZONES_CONF"

    local old="/etc/named.d/zonas_locales.conf"
    if [[ -f "$old" ]] && grep -q 'zone "' "$old" 2>/dev/null; then
        > "$old"
        echo "Archivo de zonas anterior vaciado."
    fi

    _crear_archivos_base

    if ! grep -q "zonas.conf" "$NAMED_CONF" 2>/dev/null; then
        [[ -f "$NAMED_CONF" ]] && cp "$NAMED_CONF" "${NAMED_CONF}.bak_$(date +%Y%m%d%H%M%S)"
        cat > "$NAMED_CONF" <<EOF
options {
    directory "$ZONE_DIR";
    listen-on port 53 { any; };
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

include "$ZONES_CONF";
EOF
        echo "named.conf generado."
    else
        sed -i 's/dnssec-validation yes/dnssec-validation no/' "$NAMED_CONF"
        sed -i 's/dnssec-validation auto/dnssec-validation no/' "$NAMED_CONF"
        sed -i '/zonas_locales/d' "$NAMED_CONF"
        echo "named.conf actualizado."
    fi

    if systemctl is-active systemd-resolved &>/dev/null; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved &>/dev/null
        echo "systemd-resolved deshabilitado."
    fi

    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo "Puerto 53 abierto."
    fi

    systemctl enable named &>/dev/null
    systemctl restart named
    sleep 2
    systemctl is-active named &>/dev/null \
        && echo "Servicio named activo." \
        || echo "ERROR: named no inicio. Revisa: journalctl -u named -n 30"
}

_crear_archivos_base() {
    if [[ ! -f "$ZONE_DIR/root.hint" ]]; then
        cat > "$ZONE_DIR/root.hint" <<'EOF'
.   3600000  IN  NS  A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.  3600000  A  198.41.0.4
B.ROOT-SERVERS.NET.  3600000  A  199.9.14.201
C.ROOT-SERVERS.NET.  3600000  A  192.33.4.12
D.ROOT-SERVERS.NET.  3600000  A  199.7.91.13
M.ROOT-SERVERS.NET.  3600000  A  202.12.27.33
EOF
        chown named:named "$ZONE_DIR/root.hint"
        echo "root.hint creado."
    fi

    if [[ ! -f "$ZONE_DIR/localhost.zone" ]]; then
        cat > "$ZONE_DIR/localhost.zone" <<'EOF'
$TTL 1D
@  IN  SOA  localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@  IN  NS   localhost.
@  IN  A    127.0.0.1
EOF
        chown named:named "$ZONE_DIR/localhost.zone"
        echo "localhost.zone creado."
    fi

    if [[ ! -f "$ZONE_DIR/127.0.0.zone" ]]; then
        cat > "$ZONE_DIR/127.0.0.zone" <<'EOF'
$TTL 1D
@  IN  SOA  localhost. root.localhost. ( 2025010101 1D 1H 1W 1D )
@  IN  NS   localhost.
1  IN  PTR  localhost.
EOF
        chown named:named "$ZONE_DIR/127.0.0.zone"
        echo "127.0.0.zone creado."
    fi
}

# --------------------------------------------------------------------------
# Normalizar dominio
# --------------------------------------------------------------------------

normalizar_dominio() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

validar_dominio() {
    echo "$1" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
}

# --------------------------------------------------------------------------
# Crear zona
# --------------------------------------------------------------------------

crear_zona() {
    local IP
    IP=$(get_ip)

    echo ""
    echo "IP del servidor DNS: ${IP:-no detectada}"
    echo ""
    echo "Ingresa el dominio. Ejemplo: miempresa.com"
    echo "Si escribes www.dominio.com se registra como dominio.com"
    echo ""

    local entrada DOMAIN
    while true; do
        read -rp "Dominio: " entrada
        entrada=$(echo "$entrada" | xargs)
        [[ -z "$entrada" ]] && echo "El dominio no puede estar vacio." && continue
        DOMAIN=$(normalizar_dominio "$entrada")
        validar_dominio "$DOMAIN" && break
        echo "Dominio invalido: '$DOMAIN'. Ejemplo valido: miempresa.com"
    done

    local ip_dest
    while true; do
        read -rp "IP de destino [${IP}]: " ip_dest
        ip_dest="${ip_dest:-$IP}"
        validar_ip_formato "$ip_dest" && break
        echo "IP invalida."
    done

    local ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    if grep -q "zone \"$DOMAIN\"" "$ZONES_CONF" 2>/dev/null; then
        echo "La zona '$DOMAIN' ya existe."
        read -rp "Sobreescribir? (s/n): " over
        [[ "$over" != "s" && "$over" != "S" ]] && echo "Cancelado." && return
        _eliminar_bloque_zona "$DOMAIN"
    fi

    cat >> "$ZONES_CONF" <<EOF

// Zona: $DOMAIN
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    local SERIAL
    SERIAL=$(next_serial "$DOMAIN")

    cat > "$ZONE_FILE" <<EOF
\$TTL 86400
@ IN SOA ns1.$DOMAIN. admin.$DOMAIN. (
    $SERIAL ; Serial
    3600    ; Refresh
    1800    ; Retry
    604800  ; Expire
    86400 ) ; Minimum TTL

@   IN NS  ns1.$DOMAIN.
ns1 IN A   $IP
@   IN A   $ip_dest
www IN CNAME $DOMAIN.
EOF

    chown named:named "$ZONE_FILE"
    chmod 644 "$ZONE_FILE"

    echo ""
    named-checkconf "$NAMED_CONF" 2>&1 && echo "named-checkconf OK" || { echo "ERROR en named.conf"; return 1; }
    named-checkzone "$DOMAIN" "$ZONE_FILE" 2>&1 && echo "named-checkzone OK" || { echo "ERROR en zona"; return 1; }

    systemctl restart named
    sleep 1
    echo ""
    echo "Zona '$DOMAIN' creada."
    echo "  $DOMAIN     -> A     -> $ip_dest"
    echo "  www.$DOMAIN -> CNAME -> $DOMAIN"
    echo "  ns1.$DOMAIN -> A     -> $IP"
}

# --------------------------------------------------------------------------
# Alta de registro
# --------------------------------------------------------------------------

alta_registro() {
    echo ""
    read -rp "Zona (dominio): " entrada
    local DOMAIN
    DOMAIN=$(normalizar_dominio "$entrada")
    local ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    [[ ! -f "$ZONE_FILE" ]] && echo "La zona '$DOMAIN' no existe." && return

    echo "Registros actuales:"
    grep -E '\s+(A|CNAME)\s+' "$ZONE_FILE" | grep -v '^;'
    echo ""

    read -rp "Nombre del registro (ej: mail, ftp, @ para raiz): " NAME

    local HOST
    if [[ "$NAME" == "$DOMAIN" || "$NAME" == "@" ]]; then
        HOST="@"
    else
        HOST="${NAME%%.$DOMAIN}"
    fi

    read -rp "Tipo (A/CNAME) [A]: " tipo
    tipo="${tipo:-A}"
    tipo=$(echo "$tipo" | tr '[:lower:]' '[:upper:]')

    if [[ "$tipo" == "A" ]]; then
        local ip_dest
        while true; do
            read -rp "IP destino: " ip_dest
            validar_ip_formato "$ip_dest" && break
            echo "IP invalida."
        done
        grep -qE "^$HOST\s+IN\s+A" "$ZONE_FILE" && echo "Registro ya existe." && return
        echo "$HOST IN A $ip_dest" >> "$ZONE_FILE"
        [[ "$HOST" == "@" ]] && ! grep -q "^www " "$ZONE_FILE" && \
            echo "www IN CNAME $DOMAIN." >> "$ZONE_FILE"
    elif [[ "$tipo" == "CNAME" ]]; then
        read -rp "Nombre canonico destino: " destino
        grep -qE "^$HOST\s+IN\s+CNAME" "$ZONE_FILE" && echo "Registro ya existe." && return
        echo "$HOST IN CNAME $destino." >> "$ZONE_FILE"
    else
        echo "Tipo no soportado. Usa A o CNAME."
        return
    fi

    next_serial "$DOMAIN" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named && echo "Registro agregado."
}

# --------------------------------------------------------------------------
# Baja de registro
# --------------------------------------------------------------------------

baja_registro() {
    echo ""
    read -rp "Zona (dominio): " entrada
    local DOMAIN
    DOMAIN=$(normalizar_dominio "$entrada")
    local ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    [[ ! -f "$ZONE_FILE" ]] && echo "La zona '$DOMAIN' no existe." && return

    echo "Registros en $DOMAIN:"
    grep -E '\s+(A|CNAME|NS)\s+' "$ZONE_FILE" | grep -v '^;'
    echo ""

    read -rp "Nombre del registro a eliminar (ej: mail, @ para raiz): " HOST

    if ! grep -qE "^$HOST\s+" "$ZONE_FILE"; then
        echo "No se encontro el registro '$HOST'."
        return
    fi

    sed -i "/^$HOST\s/d" "$ZONE_FILE"
    [[ "$HOST" == "@" ]] && sed -i "/^www\s/d" "$ZONE_FILE"

    next_serial "$DOMAIN" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named && echo "Registro eliminado."
}

# --------------------------------------------------------------------------
# Eliminar bloque de zona del archivo de configuracion
# --------------------------------------------------------------------------

_eliminar_bloque_zona() {
    local dom="$1"
    local archivos=("$ZONES_CONF" "/etc/named.d/zonas_locales.conf")

    for zf in "${archivos[@]}"; do
        [[ -f "$zf" ]] || continue
        grep -q "\"$dom\"" "$zf" 2>/dev/null || continue

        local linea total inicio fin
        linea=$(grep -n "\"$dom\"" "$zf" | head -1 | cut -d: -f1)
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
        echo "Bloque de '$dom' eliminado de $(basename "$zf")."
    done

    rm -f "$ZONE_DIR/db.$dom"
    rm -f "$SERIAL_DIR/$dom.serial"
    echo "Archivos de zona y serial eliminados."
}

# --------------------------------------------------------------------------
# Baja de zona completa
# --------------------------------------------------------------------------

baja_zona() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_CONF" 2>/dev/null; then
        echo "No hay zonas configuradas."
        return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_CONF" | sed 's/.*zone "\(.*\)".*/  \1/'
    echo ""

    read -rp "Dominio a eliminar: " entrada
    local DOMAIN
    DOMAIN=$(normalizar_dominio "$entrada")
    [[ -z "$DOMAIN" ]] && echo "Dominio vacio." && return

    if ! grep -q "\"$DOMAIN\"" "$ZONES_CONF" 2>/dev/null; then
        echo "La zona '$DOMAIN' no existe."
        return
    fi

    read -rp "Eliminar zona '$DOMAIN'? (s/n): " conf
    [[ "$conf" != "s" && "$conf" != "S" ]] && echo "Cancelado." && return

    _eliminar_bloque_zona "$DOMAIN"
    named-checkconf "$NAMED_CONF" &>/dev/null && systemctl restart named
    echo "Zona '$DOMAIN' eliminada."
}

# --------------------------------------------------------------------------
# Consultar zona
# --------------------------------------------------------------------------

consultar_zona() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_CONF" 2>/dev/null; then
        echo "No hay zonas configuradas."
        return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_CONF" | sed 's/.*zone "\(.*\)".*/  \1/'
    echo ""

    read -rp "Dominio (ENTER para ver todos): " entrada

    if [[ -z "$entrada" ]]; then
        local doms
        mapfile -t doms < <(grep 'zone "' "$ZONES_CONF" | sed 's/.*zone "\(.*\)".*/\1/')
        for d in "${doms[@]}"; do
            echo "--- $d ---"
            local f="$ZONE_DIR/db.$d"
            [[ -f "$f" ]] && cat "$f" || echo "  Archivo no encontrado: $f"
            echo ""
        done
    else
        local DOMAIN
        DOMAIN=$(normalizar_dominio "$entrada")
        local ZONE_FILE="$ZONE_DIR/db.$DOMAIN"
        [[ ! -f "$ZONE_FILE" ]] && echo "Zona '$DOMAIN' no encontrada." && return
        cat "$ZONE_FILE"
    fi
}

# --------------------------------------------------------------------------
# Probar resolucion
# --------------------------------------------------------------------------

probar_resolucion() {
    echo ""

    if ! grep -q 'zone "' "$ZONES_CONF" 2>/dev/null; then
        echo "No hay zonas configuradas."
        return
    fi

    echo "Zonas disponibles:"
    grep 'zone "' "$ZONES_CONF" | sed 's/.*zone "\(.*\)".*/  \1/'
    echo ""

    read -rp "Dominio a probar: " entrada
    local DOMAIN
    DOMAIN=$(normalizar_dominio "$entrada")
    [[ -z "$DOMAIN" ]] && echo "Dominio vacio." && return

    local ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    echo ""
    echo "--- named-checkconf ---"
    named-checkconf "$NAMED_CONF" 2>&1 && echo "Sin errores." || echo "ERROR de sintaxis."

    echo ""
    echo "--- named-checkzone $DOMAIN ---"
    [[ -f "$ZONE_FILE" ]] \
        && named-checkzone "$DOMAIN" "$ZONE_FILE" 2>&1 \
        || echo "Archivo no encontrado: $ZONE_FILE"

    echo ""
    echo "--- nslookup $DOMAIN 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "$DOMAIN" 127.0.0.1 || echo "nslookup no disponible."

    echo ""
    echo "--- nslookup www.$DOMAIN 127.0.0.1 ---"
    command -v nslookup &>/dev/null && nslookup "www.$DOMAIN" 127.0.0.1

    echo ""
    echo "--- dig @127.0.0.1 $DOMAIN A ---"
    command -v dig &>/dev/null && dig @127.0.0.1 "$DOMAIN" A +short || echo "dig no disponible."

    echo ""
    echo "--- ping -c3 www.$DOMAIN ---"
    ping -c 3 -W 2 "www.$DOMAIN" 2>&1 || true
}

# --------------------------------------------------------------------------
# Borrar configuracion
# --------------------------------------------------------------------------

borrar_dns() {
    echo ""
    echo "Se eliminara:"
    echo "  - Todas las zonas en $ZONES_CONF"
    echo "  - Archivos db.* en $ZONE_DIR"
    echo "  - Seriales en $SERIAL_DIR"
    echo "  - El servicio named se detiene"
    echo ""
    read -rp "Confirma escribiendo BORRAR: " conf
    [[ "$conf" != "BORRAR" ]] && echo "Cancelado." && return

    systemctl stop named 2>/dev/null
    [[ -f "$ZONES_CONF" ]] && > "$ZONES_CONF" && echo "zonas.conf vaciado."
    local old="/etc/named.d/zonas_locales.conf"
    [[ -f "$old" ]] && > "$old"
    local count
    count=$(find "$ZONE_DIR" -maxdepth 1 -name 'db.*' 2>/dev/null | wc -l)
    [[ "$count" -gt 0 ]] && rm -f "$ZONE_DIR"/db.* && echo "$count archivo(s) de zona eliminados."
    [[ -d "$SERIAL_DIR" ]] && rm -f "$SERIAL_DIR"/* && echo "Seriales eliminados."
    systemctl disable named &>/dev/null
    echo "Configuracion DNS eliminada."
    echo "Para reiniciar usa la opcion 1."
}

# --------------------------------------------------------------------------
# Resolver conflictos de zonas duplicadas al arrancar
# --------------------------------------------------------------------------

_resolver_conflictos() {
    local old="/etc/named.d/zonas_locales.conf"
    [[ -f "$old" ]] && grep -q 'zone "' "$old" 2>/dev/null || return
    [[ -f "$ZONES_CONF" ]] || return

    while IFS= read -r dom; do
        [[ -z "$dom" ]] && continue
        grep -q "\"$dom\"" "$ZONES_CONF" 2>/dev/null || continue
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
    done < <(grep 'zone "' "$old" | sed 's/.*zone "\(.*\)".*/\1/')
}

# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

_resolver_conflictos

while true; do
    clear
    echo "=============================="
    echo " DNS openSUSE Leap - BIND9"
    echo " IP: $(get_ip)"
    echo "=============================="
    echo "1) Instalar DNS"
    echo "2) Configurar IP estatica"
    echo "3) Crear zona DNS"
    echo "4) Alta de registro DNS"
    echo "5) Baja de registro DNS"
    echo "6) Consultar zona"
    echo "7) Probar resolucion"
    echo "8) Eliminar zona DNS"
    echo "9) Borrar configuracion DNS"
    echo "0) Salir"
    echo ""
    read -rp "Opcion: " op

    case $op in
        1) instalar_dns ;;
        2) configurar_ip ;;
        3) crear_zona ;;
        4) alta_registro ;;
        5) baja_registro ;;
        6) consultar_zona ;;
        7) probar_resolucion ;;
        8) baja_zona ;;
        9) borrar_dns ;;
        0) exit 0 ;;
        *) echo "Opcion invalida." ;;
    esac

    pause
done

