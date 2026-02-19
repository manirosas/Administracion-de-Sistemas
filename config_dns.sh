#!/bin/bash

# VALIDAR ROOT
if [[ $EUID -ne 0 ]]; then
    echo "Ejecuta este script como root"
    exit 1
fi

# VARIABLES GLOBALES
DNS_SERVICE="named"
NAMED_LOCAL="/etc/named.conf.local"
ZONES_DIR="/var/lib/named"
DNS_INTERFACE="enp0s8"

# UTILIDADES

pause() {
    read -p "Presiona ENTER para continuar..."
}

validar_ip() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

get_dns_ip_enp0s8() {
    ip addr show "$DNS_INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

increment_serial() {
    local serial_file="$1"
    if [[ ! -f $serial_file ]]; then
        date +%Y%m%d01 > "$serial_file"
    else
        echo $(( $(cat "$serial_file") + 1 )) > "$serial_file"
    fi
    cat "$serial_file"
}

# VERIFICAR IP ENP0S8 (DHCP)
verificar_ip_dns() {
    DNS_IP=$(get_dns_ip_enp0s8)

    if [[ -z "$DNS_IP" ]]; then
        echo "ERROR: La interfaz $DNS_INTERFACE no tiene IP asignada"
        echo "Verifica que el DHCP de la práctica anterior esté activo"
        return 1
    fi

    echo "IP del servidor DNS (desde $DNS_INTERFACE): $DNS_IP"
    return 0
}

# INSTALAR DNS (IDEMPOTENTE)

instalar_dns() {
    if rpm -q bind &>/dev/null; then
        echo "BIND ya está instalado"
    else
        zypper install -y bind bind-utils bind-doc
    fi

    systemctl enable $DNS_SERVICE
    systemctl start $DNS_SERVICE
    echo "Servicio DNS activo"
}

# CREAR ZONA DNS

crear_zona() {
    verificar_ip_dns || return
    DNS_IP=$(get_dns_ip_enp0s8)

    read -p "Dominio a crear (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    if grep -q "$DOMAIN" "$NAMED_LOCAL" 2>/dev/null; then
        echo "La zona ya existe"
        return
    fi

    cat <<EOF >> "$NAMED_LOCAL"
zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};
EOF

    SERIAL=$(increment_serial "$SERIAL_FILE")

    cat <<EOF > "$ZONE_FILE"
\$TTL 86400
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
        $SERIAL
        3600
        1800
        604800
        86400 )

    IN  NS  ns1.$DOMAIN.
ns1 IN  A   $DNS_IP
EOF

    chown named:named "$ZONE_FILE"
    systemctl restart $DNS_SERVICE

    echo "Zona $DOMAIN creada usando IP $DNS_IP (enp0s8)"
}

# ALTA DE REGISTRO DNS

alta_registro() {
    read -p "Dominio base (zona) (ej. ejemplo.com): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    [[ ! -f $ZONE_FILE ]] && echo "La zona no existe" && return

    read -p "Nombre a registrar (ej. ejemplo.com o www.ejemplo.com): " NAME
    read -p "IP destino (cliente/VM): " IP

    validar_ip "$IP" || { echo "IP inválida"; return; }

    BASE=$(echo "$NAME" | sed 's/^www\.//')

    grep -q "^$BASE" "$ZONE_FILE" && { echo "El registro ya existe"; return; }

    echo "$BASE IN A $IP" >> "$ZONE_FILE"

    if [[ "$NAME" != www.* ]]; then
        echo "www IN CNAME $BASE." >> "$ZONE_FILE"
    fi

    increment_serial "$SERIAL_FILE" > /dev/null
    systemctl restart $DNS_SERVICE

    echo "Registro DNS agregado correctamente"
}


# BAJA DE REGISTRO DNS

baja_registro() {
    read -p "Dominio base (zona): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"
    SERIAL_FILE="$ZONES_DIR/serial.$DOMAIN"

    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return

    read -p "Registro a eliminar: " NAME
    sed -i "/$NAME/d" "$ZONE_FILE"

    increment_serial "$SERIAL_FILE" > /dev/null
    systemctl restart $DNS_SERVICE

    echo "Registro eliminado"
}

# CONSULTAR REGISTROS

consultar_registros() {
    read -p "Dominio (zona): " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"

    [[ ! -f $ZONE_FILE ]] && echo "Zona no existe" && return
    cat "$ZONE_FILE"
}


# VALIDACIONES

validar_dns() {
    named-checkconf || return
    read -p "Dominio a validar: " DOMAIN
    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"

    named-checkzone "$DOMAIN" "$ZONE_FILE"

    nslookup "$DOMAIN"
    nslookup "www.$DOMAIN"
}

# MENÚ PRINCIPAL

while true; do
    clear
    echo " ADMINISTRADOR DNS openSUSE (BIND9)"
    echo " Interfaz DNS fija: enp0s8 (DHCP)"
    echo "1. Instalar servicio DNS"
    echo "2. Crear zona DNS"
    echo "3. Alta de registro DNS"
    echo "4. Baja de registro DNS"
    echo "5. Consultar registros DNS"
    echo "6. Validar DNS"
    echo "0. Salir"
    read -p "Opción: " op

    case $op in
        1) instalar_dns ;;
        2) crear_zona ;;
        3) alta_registro ;;
        4) baja_registro ;;
        5) consultar_registros ;;
        6) validar_dns ;;
        0) exit ;;
        *) echo "Opción inválida" ;;
    esac

    pause
done
