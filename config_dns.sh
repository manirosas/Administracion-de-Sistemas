#!/bin/bash

# ===============================
# VALIDAR ROOT
# ===============================
[[ $EUID -ne 0 ]] && echo "Ejecuta este script como root" && exit 1

# ===============================
# VARIABLES
# ===============================
INTERFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
ZONES_CONF="/etc/named.d/zonas.conf"
ZONE_DIR="/var/lib/named"

pause() { read -p "ENTER para continuar..."; }

# ===============================
# OBTENER IP
# ===============================
get_ip() {
    ip addr show $INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1
}

# ===============================
# VALIDAR IP ESTÁTICA
# ===============================
validar_ip() {
    IP=$(get_ip)
    if [[ -z $IP ]]; then
        echo "La interfaz no tiene IP configurada."
        read -p "IP estática: " IP
        read -p "Máscara (ej. 24): " MASK
        ip addr add $IP/$MASK dev $INTERFACE
        ip link set $INTERFACE up
    fi
}

# ===============================
# INSTALAR DNS
# ===============================
instalar_dns() {
    rpm -q bind &>/dev/null && echo "BIND ya instalado" && return

    zypper install -y bind bind-utils
    systemctl enable named
    systemctl start named

    cat <<EOF > /etc/resolv.conf
nameserver 127.0.0.1
EOF

    echo "DNS instalado"
}

# ===============================
# CREAR ZONA
# ===============================
crear_zona() {
    validar_ip

    read -p "Dominio (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"

    grep -q "$DOMAIN" $ZONES_CONF 2>/dev/null && echo "Zona ya existe" && return

    cat <<EOF >> $ZONES_CONF
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    SERIAL=$(date +%Y%m%d01)

    cat <<EOF > $ZONE_FILE
\$TTL 86400
@ IN SOA ns1.$DOMAIN. admin.$DOMAIN. (
$SERIAL
3600
1800
604800
86400 )

@   IN NS ns1.$DOMAIN.
ns1 IN A  $(get_ip)
@   IN A  $(get_ip)
www IN CNAME @
EOF

    chown named:named $ZONE_FILE
    named-checkconf && named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named

    echo "Zona creada"
}

# ===============================
# ALTA REGISTRO
# ===============================
alta_registro() {
    read -p "Dominio: " DOMAIN
    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"
    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return

    read -p "Nombre (ej. host o www): " NAME
    read -p "IP: " IP

    [[ $NAME != "www" && $NAME != *@* ]] && NAME="$NAME"

    echo "$NAME IN A $IP" >> $ZONE_FILE
    named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named

    echo "Registro agregado"
}

# ===============================
# BAJA REGISTRO
# ===============================
baja_registro() {
    read -p "Dominio: " DOMAIN
    read -p "Registro: " NAME

    ZONE_FILE="$ZONE_DIR/db.$DOMAIN"
    sed -i "/^$NAME /d" $ZONE_FILE

    named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named
    echo "Registro eliminado"
}

# ===============================
# CONSULTAR ZONA
# ===============================
consultar_zona() {
    read -p "Dominio: " DOMAIN
    cat "$ZONE_DIR/db.$DOMAIN"
}

# ===============================
# BORRAR DNS
# ===============================
borrar_dns() {
    systemctl stop named
    rm -f $ZONE_DIR/db.*
    > $ZONES_CONF
    systemctl start named
    echo "Configuración DNS eliminada"
}

# ===============================
# MENÚ
# ===============================
while true; do
    clear
    echo "=============================="
    echo " ADMINISTRADOR DNS - openSUSE"
    echo " Interfaz: $INTERFACE"
    echo "=============================="
    echo "1) Instalar DNS"
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
