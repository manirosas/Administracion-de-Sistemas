#!/bin/bash

[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

INTERFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
ZONES_CONF="/etc/named.d/zonas.conf"
ZONE_DIR="/var/lib/named"
SERIAL_DIR="/var/lib/named/serial"

pause() { read -p "ENTER para continuar..."; }

get_ip() {
    ip -4 addr show "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

validar_ip() {
    IP=$(get_ip)
    if [[ -z "$IP" ]]; then
        read -p "IP estática: " IP
        read -p "Prefijo (ej. 24): " MASK
        ip addr add "$IP/$MASK" dev "$INTERFACE"
        ip link set "$INTERFACE" up
    fi
}

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

    echo "DNS instalado"
}

crear_zona() {
    validar_ip
    read -p "Dominio (ej. ejemplo.com): " DOMAIN
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

    echo "Zona creada"
}

alta_registro() {
    read -p "Zona (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"
    [[ ! -f "$ZONE_FILE" ]] && echo "Zona no existe" && return

    read -p "Nombre (ej. host o ejemplo.com): " NAME
    read -p "IP destino: " IP

    if [[ "$NAME" == "$DOMAIN" ]]; then
        HOST="@"
    else
        HOST="$NAME"
    fi

    grep -q "^$HOST " "$ZONE_FILE" && echo "Registro ya existe" && return

    echo "$HOST IN A $IP" >> "$ZONE_FILE"

    if [[ "$HOST" == "@" ]]; then
        echo "www IN CNAME @" >> "$ZONE_FILE"
    fi

    next_serial "$DOMAIN" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named

    echo "Registro agregado"
}

baja_registro() {
    read -p "Zona: " DOMAIN
    read -p "Registro a eliminar (ej. host o @): " HOST

    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"
    [[ ! -f "$ZONE_FILE" ]] && echo "Zona no existe" && return

    sed -i "/^$HOST /d" "$ZONE_FILE"

    [[ "$HOST" == "@" ]] && sed -i "/^www /d" "$ZONE_FILE"

    next_serial "$DOMAIN" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named

    echo "Registro eliminado"
}

baja_zona() {
    read -p "Dominio a eliminar: " DOMAIN
    sed -i "/zone \"$DOMAIN\"/,+3d" "$ZONES_CONF"
    rm -f "$ZONE_DIR/db.$DOMAIN" "$SERIAL_DIR/$DOMAIN.serial"
    systemctl restart named
    echo "Zona eliminada"
}

consultar_zona() {
    read -p "Dominio: " DOMAIN
    cat "$ZONE_DIR/db.$DOMAIN"
}

borrar_dns() {
    systemctl stop named
    rm -f "$ZONE_DIR"/db.*
    rm -f "$SERIAL_DIR"/*
    > "$ZONES_CONF"
    systemctl start named
    echo "Configuración DNS eliminada"
}

while true; do
    clear
    echo "=============================="
    echo " DNS openSUSE Leap - BIND9"
    echo "=============================="
    echo "1) Instalar DNS"
    echo "2) Crear zona DNS"
    echo "3) Alta de registro DNS"
    echo "4) Baja de registro DNS"
    echo "5) Consultar zona"
    echo "6) Eliminar zona DNS"
    echo "7) Borrar configuración DNS"
    echo "0) Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) alta_registro ;;
        4) baja_registro ;;
        5) consultar_zona ;;
        6) baja_zona ;;
        7) borrar_dns ;;
        0) exit ;;
        *) echo "Opción inválida" ;;
    esac

    pause
done
