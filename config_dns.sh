#!/bin/bash

# ===============================
# VALIDAR ROOT
# ===============================
[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

# ===============================
# VARIABLES
# ===============================
INTERFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
ZONES_CONF="/etc/named.d/zonas.conf"
ZONE_DIR="/var/lib/named"
SERIAL_DIR="/var/lib/named/serial"

pause() { read -p "ENTER para continuar..."; }

# ===============================
# OBTENER IP
# ===============================
get_ip() {
    ip -4 addr show "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

# ===============================
# VALIDAR IP ESTÁTICA
# ===============================
validar_ip() {
    IP=$(get_ip)
    if [[ -z "$IP" ]]; then
        echo "La interfaz $INTERFACE no tiene IP fija"
        read -p "IP estática: " IP
        read -p "Prefijo (ej. 24): " MASK
        ip addr add "$IP/$MASK" dev "$INTERFACE"
        ip link set "$INTERFACE" up
    fi
}

# ===============================
# SERIAL
# ===============================
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

# ===============================
# INSTALAR DNS (IDEMPOTENTE)
# ===============================
instalar_dns() {
    rpm -q bind &>/dev/null && echo "BIND ya instalado" && return

    zypper install -y bind bind-utils bind-doc || exit 1

    mkdir -p /etc/named.d
    touch "$ZONES_CONF"

    cat > "$NAMED_CONF" <<EOF
options {
    directory "$ZONE_DIR";
    listen-on port 53 { any; };
    allow-query { any; };
    recursion yes;
};

include "$ZONES_CONF";
EOF

    systemctl enable named
    systemctl restart named

    cat > /etc/resolv.conf <<EOF
nameserver 127.0.0.1
EOF

    echo "DNS instalado y configurado"
}

# ===============================
# CREAR ZONA
# ===============================
crear_zona() {
    validar_ip

    read -p "Dominio (ej. ejemplo.com): " DOMAIN
    [[ -z "$DOMAIN" ]] && echo "Dominio inválido" && return

    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    grep -q "zone \"$DOMAIN\"" "$ZONES_CONF" && echo "Zona ya existe" && return

    cat >> "$ZONES_CONF" <<EOF
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    SERIAL=$(next_serial "$DOMAIN")
    IP=$(get_ip)

    cat > "$ZONE_FILE" <<EOF
\$TTL 86400
@ IN SOA ns1.$DOMAIN. admin.$DOMAIN. (
$SERIAL
3600
1800
604800
86400 )

@   IN NS ns1.$DOMAIN.
ns1 IN A  $IP
@   IN A  $IP
www IN CNAME @
EOF

    chown named:named "$ZONE_FILE"

    named-checkconf && named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named

    echo "Zona $DOMAIN creada correctamente"
}

# ===============================
# BAJA ZONA
# ===============================
baja_zona() {
    read -p "Dominio a eliminar: " DOMAIN
    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    sed -i "/zone \"$DOMAIN\"/,+3d" "$ZONES_CONF"
    rm -f "$ZONE_FILE" "$SERIAL_DIR/$DOMAIN.serial"

    systemctl restart named
    echo "Zona eliminada"
}

# ===============================
# CONSULTAR ZONAS
# ===============================
consultar_zonas() {
    cat "$ZONES_CONF"
}

# ===============================
# BORRAR CONFIGURACIÓN DNS
# ===============================
borrar_dns() {
    systemctl stop named
    rm -f "$ZONE_DIR"/db.*
    rm -f "$SERIAL_DIR"/*
    > "$ZONES_CONF"
    systemctl start named
    echo "Configuración DNS eliminada"
}

# ===============================
# MENÚ
# ===============================
while true; do
    clear
    echo " DNS openSUSE Leap - BIND9"
    echo " Interfaz: $INTERFACE"
    echo "1) Instalar DNS"
    echo "2) Crear zona DNS"
    echo "3) Eliminar zona DNS"
    echo "4) Consultar zonas"
    echo "5) Borrar configuración DNS"
    echo "0) Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) baja_zona ;;
        4) consultar_zonas ;;
        5) borrar_dns ;;
        0) exit ;;
        *) echo "Opción inválida" ;;
    esac

    pause
done
