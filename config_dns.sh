#!/bin/bash

# ===============================
# VALIDAR ROOT
# ===============================
[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

# ===============================
# VARIABLES
# ===============================
DNS_SERVICE="named"
INTERFACE="enp0s8"
ZONES_DIR="/var/lib/named"
ZONES_CONF="/etc/named.d/zonas.conf"

# ===============================
# UTILIDADES
# ===============================
pause() { read -p "ENTER para continuar..."; }

get_ip() {
    ip addr show "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

next_serial() {
    local serial_file="$1"
    [[ ! -f "$serial_file" ]] && date +%Y%m%d01 > "$serial_file"
    echo $(( $(cat "$serial_file") + 1 )) | tee "$serial_file"
}

# ===============================
# INSTALAR DNS (IDEMPOTENTE)
# ===============================
instalar_dns() {
    read -p "¿Instalar BIND9? (s/n): " r
    [[ "$r" != "s" ]] && return

    rpm -q bind &>/dev/null || zypper install -y bind bind-utils

    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null

    cat <<EOF > /etc/resolv.conf
nameserver 127.0.0.1
nameserver 8.8.8.8
EOF

    systemctl enable "$DNS_SERVICE"
    systemctl start "$DNS_SERVICE"

    echo "DNS instalado y activo"
}

# ===============================
# CREAR ZONA DNS
# ===============================
crear_zona() {
    read -p "Dominio/zona a crear (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    IP=$(get_ip)
    [[ -z "$IP" ]] && echo "La interfaz $INTERFACE no tiene IP" && return

    grep -q "zone \"$DOMAIN\"" "$ZONES_CONF" 2>/dev/null && {
        echo "La zona ya existe"
        return
    }

    cat <<EOF >> "$ZONES_CONF"
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    SERIAL=$(next_serial "$SERIAL_FILE")

    cat <<EOF > "$ZONE_FILE"
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

    named-checkconf && named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart "$DNS_SERVICE"

    echo "Zona $DOMAIN creada correctamente"
}

# ===============================
# ALTA DE REGISTRO
# ===============================
alta_registro() {
    read -p "Zona (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    [[ ! -f "$ZONE_FILE" ]] && echo "La zona no existe" && return

    read -p "Nombre (host o www): " NAME
    read -p "IP destino: " IP

    grep -q "^$NAME " "$ZONE_FILE" && {
        echo "El registro ya existe"
        return
    }

    echo "$NAME IN A $IP" >> "$ZONE_FILE"

    next_serial "$SERIAL_FILE" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart "$DNS_SERVICE"

    echo "Registro agregado"
}

# ===============================
# BAJA DE REGISTRO
# ===============================
baja_registro() {
    read -p "Zona: " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    [[ ! -f "$ZONE_FILE" ]] && echo "Zona no existe" && return

    read -p "Registro a eliminar: " NAME
    sed -i "/^$NAME /d" "$ZONE_FILE"

    next_serial "$SERIAL_FILE" > /dev/null
    named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart "$DNS_SERVICE"

    echo "Registro eliminado"
}

# ===============================
# CONSULTAR ZONA
# ===============================
consultar_zona() {
    read -p "Zona a consultar: " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"

    [[ ! -f "$ZONE_FILE" ]] && echo "Zona no existe" && return
    cat "$ZONE_FILE"
}

# ===============================
# BORRAR CONFIGURACIÓN DNS
# ===============================
borrar_dns() {
    read -p "¿BORRAR TODA la configuración DNS? (s/n): " r
    [[ "$r" != "s" ]] && return

    systemctl stop named
    systemctl disable named

    rm -f /etc/named.d/*.conf
    rm -f "$ZONES_DIR"/db.*
    rm -f "$ZONES_DIR"/serial.*

    echo "Configuración DNS eliminada completamente"
}

# ===============================
# MENÚ
# ===============================
while true; do
    clear
    echo "======================================"
    echo "  ADMINISTRADOR DNS - openSUSE Leap"
    echo "  Interfaz: $INTERFACE"
    echo "======================================"
    echo "1) Instalar DNS (BIND9)"
    echo "2) Crear zona DNS"
    echo "3) Alta de registro DNS"
    echo "4) Baja de registro DNS"
    echo "5) Consultar zona DNS"
    echo "6) Borrar configuración DNS"
    echo "0) Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) alta_registro ;;
        4) baja_registro ;;
        5) consultar_zona ;;
        6) borrar_dns ;;
        0) exit ;;
        *) echo "Opción inválida" ;;
    esac

    pause
done
