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
DOMAIN="reprobados.com"
ZONE_FILE="/var/lib/named/db.$DOMAIN"
ZONES_CONF="/etc/named.d/zonas.conf"
SERIAL_FILE="/var/lib/named/serial.$DOMAIN"

# ===============================
# PAUSA
# ===============================
pause() { read -p "ENTER para continuar..."; }

# ===============================
# IP DE enp0s8
# ===============================
get_ip() {
    ip addr show $INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1
}

# ===============================
# SERIAL
# ===============================
next_serial() {
    [[ ! -f $SERIAL_FILE ]] && date +%Y%m%d01 > $SERIAL_FILE
    echo $(( $(cat $SERIAL_FILE) + 1 )) | tee $SERIAL_FILE
}

# ===============================
# INSTALAR DNS (IDEMPOTENTE)
# ===============================
instalar_dns() {
    read -p "¿Instalar BIND9? (s/n): " r
    [[ $r != "s" ]] && return

    rpm -q bind &>/dev/null || zypper install -y bind bind-utils

    systemctl stop systemd-resolved 2>/dev/null
    systemctl disable systemd-resolved 2>/dev/null

    cat <<EOF > /etc/resolv.conf
nameserver 127.0.0.1
nameserver 8.8.8.8
EOF

    systemctl enable named
    systemctl start named

    echo "DNS instalado y activo"
}

# ===============================
# CREAR ZONA
# ===============================
crear_zona() {
    IP=$(get_ip)
    [[ -z $IP ]] && echo "enp0s8 sin IP" && return

    grep -q "$DOMAIN" $ZONES_CONF 2>/dev/null && echo "Zona ya existe" && return

    cat <<EOF >> $ZONES_CONF
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    SERIAL=$(next_serial)

    cat <<EOF > $ZONE_FILE
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

    chown named:named $ZONE_FILE
    named-checkconf && named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named

    echo "Zona $DOMAIN creada"
}

# ===============================
# ALTA REGISTRO
# ===============================
alta_registro() {
    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return

    read -p "Nombre (ej. host): " NAME
    read -p "IP destino: " IP

    grep -q "^$NAME" $ZONE_FILE && echo "Registro existe" && return

    echo "$NAME IN A $IP" >> $ZONE_FILE
    next_serial > /dev/null

    named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named
    echo "Registro agregado"
}

# ===============================
# BAJA REGISTRO
# ===============================
baja_registro() {
    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return

    read -p "Registro a eliminar: " NAME
    sed -i "/^$NAME /d" $ZONE_FILE

    next_serial > /dev/null
    named-checkzone $DOMAIN $ZONE_FILE && systemctl restart named
    echo "Registro eliminado"
}

# ===============================
# CONSULTAR ZONA
# ===============================
consultar() {
    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return
    cat $ZONE_FILE
}

# ===============================
# MENÚ
# ===============================
while true; do
    clear
    echo "==============================="
    echo " DNS openSUSE - BIND9"
    echo " Dominio: $DOMAIN"
    echo "==============================="
    echo "1) Instalar DNS"
    echo "2) Crear zona"
    echo "3) Alta registro"
    echo "4) Baja registro"
    echo "5) Consultar zona"
    echo "0) Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) alta_registro ;;
        4) baja_registro ;;
        5) consultar ;;
        0) exit ;;
        *) echo "Opción inválida" ;;
    esac

    pause
done
