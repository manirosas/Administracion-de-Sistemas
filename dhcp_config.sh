#!/bin/bash

CONFIG_FILE="/etc/dhcpd.conf"
INTERFACE="enp0s8"
LEASE_FILE="/var/lib/dhcp/db/dhcpd.leases"

# ===============================
# VALIDAR ROOT
# ===============================
if [[ $EUID -ne 0 ]]; then
    echo "❌ Ejecuta este script como root"
    exit 1
fi

# ===============================
# FUNCIONES
# ===============================

ip_valida() {
    local ip=$1

    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS=. read -r a b c d <<< "$ip"

    for i in $a $b $c $d; do
        (( i >= 0 && i <= 255 )) || return 1
    done

    case "$ip" in
        127.0.0.1|0.0.0.0|255.255.255.255) return 1 ;;
    esac

    return 0
}

ip_to_int() {
    IFS=. read -r a b c d <<< "$1"
    echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

misma_red_24() {
    IFS=. read -r a b c _ <<< "$1"
    IFS=. read -r x y z _ <<< "$2"
    [[ "$a.$b.$c" == "$x.$y.$z" ]]
}

verificar_dhcp() {
    if ! rpm -q dhcp-server &>/dev/null; then
        echo "⚠️  dhcp-server NO está instalado"
        read -p "¿Deseas instalarlo? (s/n): " op
        if [[ "$op" == "s" ]]; then
            zypper install -y dhcp-server || exit 1
        else
            return
        fi
    else
        echo "✅ dhcp-server ya está instalado"
    fi
}

configurar_dhcp() {

    read -p "Nombre del ámbito (scope): " SCOPE_NAME

    while true; do
        read -p "IP inicial: " IP_START
        ip_valida "$IP_START" && break
        echo "❌ IP inválida"
    done

    while true; do
        read -p "IP final: " IP_END
        ip_valida "$IP_END" && break
        echo "❌ IP inválida"
    done

    if ! misma_red_24 "$IP_START" "$IP_END"; then
        echo "❌ Las IP no están en el mismo segmento /24"
        return
    fi

    if (( $(ip_to_int "$IP_START") >= $(ip_to_int "$IP_END") )); then
        echo "❌ IP inicial debe ser menor a IP final"
        return
    fi

    read -p "Máscara de subred (Enter para automática): " NETMASK
    read -p "Gateway (Enter para automático): " GATEWAY
    read -p "Tiempo de concesión (ej. 600): " LEASE_TIME
    read -p "DNS (opcional): " DNS_SERVER

    IFS=. read -r o1 o2 o3 o4 <<< "$IP_START"

    NETWORK="$o1.$o2.$o3.0"
    NETMASK=${NETMASK:-"255.255.255.0"}
    GATEWAY=${GATEWAY:-"$o1.$o2.$o3.1"}
    CLIENT_START="$o1.$o2.$o3.$((o4 + 1))"

    if (( o4 + 1 > ${IP_END##*.} )); then
        echo "❌ El rango no deja IPs para clientes"
        return
    fi

    echo "🛠 Generando configuración DHCP..."

    cat > "$CONFIG_FILE" <<EOF
# DHCP Server - $SCOPE_NAME

default-lease-time $LEASE_TIME;
max-lease-time $LEASE_TIME;
authoritative;

subnet $NETWORK netmask $NETMASK {
    range $CLIENT_START $IP_END;
    option routers $GATEWAY;
EOF

    if [[ -n "$DNS_SERVER" ]]; then
        echo "    option domain-name-servers $DNS_SERVER;" >> "$CONFIG_FILE"
    fi

    echo "}" >> "$CONFIG_FILE"

    dhcpd -t || return

    echo "DHCPD_INTERFACE=\"$INTERFACE\"" > /etc/sysconfig/dhcpd

    systemctl enable dhcpd
    systemctl restart dhcpd

    echo "✅ DHCP configurado correctamente"
}

monitorear_concesiones() {
    if [[ ! -f "$LEASE_FILE" ]]; then
        echo "❌ No hay archivo de concesiones"
        return
    fi

    echo "📊 Concesiones activas:"
    awk '
    /lease/ {ip=$2}
    /binding state active/ {print ip}
    ' "$LEASE_FILE"
}

# ===============================
# MENÚ PRINCIPAL
# ===============================

while true; do
    clear
    echo "==============================="
    echo "   MENÚ DHCP - openSUSE"
    echo "==============================="
    echo "1) Verificar / instalar DHCP"
    echo "2) Configurar DHCP"
    echo "3) Monitorear concesiones"
    echo "4) Salir"
    echo "==============================="
    read -p "Selecciona una opción: " op

    case $op in
        1) verificar_dhcp ; read -p "Enter para continuar..." ;;
        2) configurar_dhcp ; read -p "Enter para continuar..." ;;
        3) monitorear_concesiones ; read -p "Enter para continuar..." ;;
        4) exit 0 ;;
        *) echo "❌ Opción inválida" ; sleep 1 ;;
    esac
done
