#!/bin/bash

CONFIG_FILE="/etc/dhcpd.conf"
INTERFACE="enp0s8"
LEASE_FILE="/var/lib/dhcp/db/dhcpd.leases"

# =========================
# VALIDAR ROOT
# =========================
if [[ $EUID -ne 0 ]]; then
    echo "Error: Este script debe ejecutarse como root."
    exit 1
fi

# =========================
# FUNCIONES DE UTILIDAD
# =========================

ip_valida() {
    local ip=$1
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$ip"
    for i in $a $b $c $d; do
        (( i >= 0 && i <= 255 )) || return 1
    done
    case "$ip" in
        0.0.0.0|127.0.0.1|255.255.255.255) return 1 ;;
    esac
    return 0
}

ip_to_int() {
    IFS=. read -r a b c d <<< "$1"
    echo $(( (a<<24) + (b<<16) + (c<<8) + d ))
}

obtener_prefijo_automatico() {
    local ip=$1
    IFS=. read -r a _ <<< "$ip"
    if (( a >= 1 && a <= 126 )); then echo 8
    elif (( a >= 128 && a <= 191 )); then echo 16
    else echo 24
    fi
}

prefijo_a_mask() {
    local prefix=$1
    local mask=""
    local full=$((prefix / 8))
    local part=$((prefix % 8))

    for ((i=0; i<4; i++)); do
        if (( i < full )); then
            mask+="255"
        elif (( i == full )); then
            mask+=$((256 - 2**(8-part)))
        else
            mask+="0"
        fi
        [[ $i -lt 3 ]] && mask+="."
    done
    echo "$mask"
}

calcular_red() {
    local ip="$1"
    local prefix="$2"

    local ip_int
    ip_int=$(ip_to_int "$ip")

    local mask_int=$(( 0xFFFFFFFF << (32-prefix) & 0xFFFFFFFF ))
    local net_int=$(( ip_int & mask_int ))

    echo "$((net_int>>24&255)).$((net_int>>16&255)).$((net_int>>8&255)).$((net_int&255))"
}

# =========================
# DHCP / RED
# =========================

verificar_dhcp() {
    if ! rpm -q dhcp-server &>/dev/null; then
        read -p "dhcp-server no está instalado. ¿Instalar? (s/n): " r
        [[ "$r" == "s" ]] && zypper install -y dhcp-server
    else
        echo "dhcp-server ya está instalado."
    fi
}

asignar_ip_servidor() {
    local ip="$1"
    local prefix="$2"
    local conn="dhcp-static-$INTERFACE"

    nmcli device set "$INTERFACE" managed yes
    nmcli connection delete "$conn" 2>/dev/null

    nmcli connection add \
        type ethernet \
        ifname "$INTERFACE" \
        con-name "$conn" \
        ipv4.method manual \
        ipv4.addresses "$ip/$prefix" \
        ipv6.method ignore

    nmcli connection up "$conn"
}

resetear_clientes() {
    systemctl stop dhcpd
    [[ -f "$LEASE_FILE" ]] && cp "$LEASE_FILE" "${LEASE_FILE}.bak" && echo "" > "$LEASE_FILE"
    systemctl start dhcpd
    echo "Concesiones reiniciadas."
}

configurar_dhcp() {
    read -p "Nombre del ámbito (scope): " SCOPE_NAME

    while true; do
        read -p "IP inicial del rango (servidor): " IP_START
        ip_valida "$IP_START" && break
        echo "IP inválida."
    done

    while true; do
        read -p "IP final del rango: " IP_END
        ip_valida "$IP_END" && break
        echo "IP inválida."
    done

    if (( $(ip_to_int "$IP_START") >= $(ip_to_int "$IP_END") )); then
        echo "ERROR: IP inicial debe ser menor."
        return
    fi

    read -p "Máscara (/24 o 255.255.255.0) [ENTER automática]: " INPUT
    if [[ -z "$INPUT" ]]; then
        PREFIX=$(obtener_prefijo_automatico "$IP_START")
    elif [[ "$INPUT" =~ ^[0-9]{1,2}$ ]]; then
        PREFIX=$INPUT
    else
        case "$INPUT" in
            255.0.0.0) PREFIX=8 ;;
            255.255.0.0) PREFIX=16 ;;
            *) PREFIX=24 ;;
        esac
    fi

    NETMASK=$(prefijo_a_mask "$PREFIX")
    NETWORK=$(calcular_red "$IP_START" "$PREFIX")

    read -p "Gateway (ENTER automático): " GATEWAY
    IFS=. read -r a b c _ <<< "$IP_START"
    GATEWAY=${GATEWAY:-"$a.$b.$c.1"}

    while true; do
        read -p "DNS primario (ENTER 8.8.8.8): " DNS1
        DNS1=${DNS1:-8.8.8.8}
        ip_valida "$DNS1" && break
    done

    while true; do
        read -p "DNS secundario (ENTER 4.4.4.4): " DNS2
        DNS2=${DNS2:-4.4.4.4}
        ip_valida "$DNS2" && break
    done

    LEASE_TIME=600

    asignar_ip_servidor "$IP_START" "$PREFIX"

    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    cat > "$CONFIG_FILE" <<EOF
# DHCP Server Config - $SCOPE_NAME
default-lease-time $LEASE_TIME;
max-lease-time $LEASE_TIME;
authoritative;

subnet $NETWORK netmask $NETMASK {
    range $IP_START $IP_END;
    option routers $GATEWAY;
    option domain-name-servers $DNS1, $DNS2;
}
EOF

    dhcpd -t -cf "$CONFIG_FILE" && {
        echo "DHCPD_INTERFACE=\"$INTERFACE\"" > /etc/sysconfig/dhcpd
        systemctl enable dhcpd
        systemctl restart dhcpd
        echo "DHCP configurado correctamente."
    } || echo "Error en la configuración."
}

monitorear_concesiones() {
    systemctl is-active dhcpd
    [[ -f "$LEASE_FILE" ]] || return
    awk '/lease/ {ip=$2} /binding state active/ {print "IP: " ip}' "$LEASE_FILE"
}

# =========================
# MENÚ
# =========================

while true; do
    echo -e "\n ADMINISTRACIÓN DHCP "
    echo "1) Verificar / instalar DHCP"
    echo "2) Configurar DHCP"
    echo "3) Reiniciar concesiones"
    echo "4) Ver leases"
    echo "5) Salir"
    read -p "Opción: " op

    case $op in
        1) verificar_dhcp ;;
        2) configurar_dhcp ;;
        3) resetear_clientes ;;
        4) monitorear_concesiones ;;
        5) exit 0 ;;
        *) echo "Opción inválida" ;;
    esac
done
