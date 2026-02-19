##!/bin/bash

# ===============================
# VARIABLES GLOBALES
# ===============================
DNS_SERVICE="named"
INTERFACE="enp0s8"
ZONES_DIR="/var/lib/named"
NAMED_CONF="/etc/named.conf"

# ===============================
# VALIDAR ROOT
# ===============================
if [[ $EUID -ne 0 ]]; then
    echo "Ejecuta este script como root"
    exit 1
fi

# ===============================
# OBTENER IP DE enp0s8
# ===============================
get_ip_enp0s8() {
    ip addr show "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1
}

# ===============================
# CONFIGURAR IP FIJA SI NO EXISTE
# ===============================
verificar_ip_fija() {
    IP=$(get_ip_enp0s8)

    if [[ -z "$IP" ]]; then
        echo "No hay IP configurada en $INTERFACE"
        read -p "IP estática: " IP
        read -p "Máscara (ej. 24): " MASK
        read -p "Gateway: " GW

        nmcli con mod "$INTERFACE" ipv4.method manual ipv4.addresses "$IP/$MASK" ipv4.gateway "$GW"
        nmcli con up "$INTERFACE"
        echo "IP configurada correctamente"
    else
        echo "IP detectada en $INTERFACE: $IP"
    fi
}

# ===============================
# INSTALACIÓN IDempotente
# ===============================
instalar_dns() {
    if rpm -q bind &>/dev/null; then
        echo "BIND ya está instalado"
        return
    fi

    read -p "¿Deseas instalar BIND DNS? (s/n): " opt
    if [[ "$opt" == "s" ]]; then
        zypper install -y bind bind-utils bind-doc
        systemctl enable $DNS_SERVICE
        systemctl start $DNS_SERVICE
        echo "BIND instalado y activo"
    else
        echo "Instalación cancelada"
    fi
}

# ===============================
# CREAR ZONA
# ===============================
crear_zona() {
    read -p "Dominio (ej. reprobados.com): " DOMAIN
    read -p "IP destino del dominio: " TARGET_IP

    ZONE_FILE="$ZONES_DIR/db.$DOMAIN"

    if grep -q "zone \"$DOMAIN\"" "$NAMED_CONF"; then
        echo "La zona ya existe"
        return
    fi

    cat <<EOF >> "$NAMED_CONF"

zone "$DOMAIN" IN {
    type master;
    file "db.$DOMAIN";
};
EOF

    SERIAL=$(date +%Y%m%d01)

    cat <<EOF > "$ZONE_FILE"
\$TTL 86400
@   IN  SOA ns1.$DOMAIN. admin.$DOMAIN. (
        $SERIAL
        3600
        1800
        604800
        86400 )

@       IN  NS      ns1.$DOMAIN.
ns1     IN  A       $TARGET_IP
@       IN  A       $TARGET_IP
www     IN  A       $TARGET_IP
EOF

    validar_dns
}

# ===============================
# ELIMINAR ZONA
# ===============================
eliminar_zona() {
    read -p "Dominio a eliminar: " DOMAIN

    sed -i "/zone \"$DOMAIN\"/,/};/d" "$NAMED_CONF"
    rm -f "$ZONES_DIR/db.$DOMAIN"

    validar_dns
}

# ===============================
# CONSULTAR DOMINIO
# ===============================
consultar_dominio() {
    read -p "Dominio a consultar: " DOMAIN
    nslookup "$DOMAIN" $(get_ip_enp0s8)
}

# ===============================
# VALIDAR Y REINICIAR DNS
# ===============================
validar_dns() {
    if named-checkconf; then
        systemctl restart $DNS_SERVICE
        echo "DNS configurado correctamente"
    else
        echo "Error en configuración DNS"
    fi
}

# ===============================
# MENÚ PRINCIPAL
# ===============================
while true; do
    echo "==============================="
    echo "  SERVIDOR DNS - openSUSE"
    echo "==============================="
    echo "1) Verificar / configurar IP fija"
    echo "2) Instalar DNS (idempotente)"
    echo "3) Dar de alta dominio"
    echo "4) Dar de baja dominio"
    echo "5) Consultar dominio"
    echo "6) Salir"
    read -p "Opción: " OPC

    case $OPC in
        1) verificar_ip_fija ;;
        2) instalar_dns ;;
        3) crear_zona ;;
        4) eliminar_zona ;;
        5) consultar_dominio ;;
        6) exit 0 ;;
        *) echo "Opción inválida" ;;
    esac
done
