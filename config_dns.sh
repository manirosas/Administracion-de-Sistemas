#!/bin/bash

# ===============================
# VALIDAR ROOT
# ===============================
[[ $EUID -ne 0 ]] && echo "Ejecuta como root" && exit 1

# ===============================
# VARIABLES
# ===============================
IFACE="enp0s8"
NAMED_CONF="/etc/named.conf"
ZONES_CONF="/etc/named.d/zonas.conf"
ZONES_DIR="/var/lib/named"

pause() { read -p "ENTER para continuar..."; }

# ===============================
# OBTENER IP DEL SERVIDOR
# ===============================
get_ip() {
    ip addr show "$IFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

# ===============================
# INSTALAR DNS (IDEMPOTENTE)
# ===============================
instalar_dns() {
    if rpm -q bind &>/dev/null; then
        echo "BIND ya está instalado"
    else
        zypper install -y bind bind-utils
    fi

    mkdir -p /etc/named.d "$ZONES_DIR"
    touch "$ZONES_CONF"

    grep -q zonas.conf "$NAMED_CONF" || \
        echo 'include "/etc/named.d/zonas.conf";' >> "$NAMED_CONF"

    systemctl enable named
    systemctl start named
    echo "DNS listo"
}

# ===============================
# CREAR ZONA
# ===============================
crear_zona() {
    IP_SERVER=$(get_ip)
    [[ -z $IP_SERVER ]] && echo "enp0s8 sin IP" && return

    read -p "Dominio (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"

    grep -q "$DOMAIN" "$ZONES_CONF" && echo "Zona ya existe" && return

    SERIAL=$(date +%Y%m%d01)

    cat <<EOF > "$ZONE_FILE"
\$TTL 86400
@ IN SOA ns1.$DOMAIN. admin.$DOMAIN. (
$SERIAL
3600
1800
604800
86400 )

@   IN NS ns1.$DOMAIN.
ns1 IN A  $IP_SERVER
@   IN A  $IP_SERVER
www IN CNAME @
EOF

    cat <<EOF >> "$ZONES_CONF"
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    chown named:named "$ZONE_FILE"
    named-checkconf && named-checkzone "$DOMAIN" "$ZONE_FILE" && systemctl restart named
    echo "Zona creada"
}

# ===============================
# BORRAR ZONA
# ===============================
borrar_zona() {
    read -p "Dominio a borrar: " DOMAIN
    rm -f "$ZONES_DIR/db.$DOMAIN"
    sed -i "/$DOMAIN/d" "$ZONES_CONF"
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
# PROBAR DNS
# ===============================
probar_dns() {
    read -p "Dominio a probar: " DOMAIN
    nslookup "$DOMAIN" 127.0.0.1
    nslookup "www.$DOMAIN" 127.0.0.1
}

# ===============================
# MENÚ
# ===============================
while true; do
    clear
    echo "DNS BIND9 - openSUSE"
    echo "IP servidor: $(get_ip)"
    echo "1) Instalar DNS"
    echo "2) Crear zona"
    echo "3) Borrar zona"
    echo "4) Consultar zonas"
    echo "5) Probar DNS"
    echo "0) Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) borrar_zona ;;
        4) consultar_zonas ;;
        5) probar_dns ;;
        0) exit ;;
    esac

    pause
done
