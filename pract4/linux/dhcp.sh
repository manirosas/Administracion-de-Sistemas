#!/bin/bash
# dhcp.sh - Módulo de administración del servidor DHCP

[[ -z "$_COMMON_SH_SOURCED" ]] && source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

DHCP_CONFIG_FILE="/etc/dhcpd.conf"
DHCP_INTERFACE="enp0s8"
DHCP_LEASE_FILE="/var/lib/dhcp/db/dhcpd.leases"
DHCP_SERVICE="dhcpd"

# Verificar/instalar dhcp-server
dhcp_install() {
    ensure_package dhcp-server || return 1
}

# Asignar IP estática al servidor usando nmcli
dhcp_assign_server_ip() {
    local ip=$1
    local prefix=$2
    local conn_name="dhcp-static-$DHCP_INTERFACE"

    nmcli device set "$DHCP_INTERFACE" managed yes
    nmcli connection delete "$conn_name" 2>/dev/null
    nmcli connection add type ethernet ifname "$DHCP_INTERFACE" con-name "$conn_name" \
        ipv4.method manual ipv4.addresses "$ip/$prefix" ipv6.method ignore
    nmcli connection up "$conn_name"
    echo "IP $ip/$prefix asignada a $DHCP_INTERFACE."
}

# Reiniciar concesiones (leases)
dhcp_reset_leases() {
    systemctl stop "$DHCP_SERVICE"
    if [[ -f "$DHCP_LEASE_FILE" ]]; then
        cp "$DHCP_LEASE_FILE" "${DHCP_LEASE_FILE}.bak"
        > "$DHCP_LEASE_FILE"
    fi
    systemctl start "$DHCP_SERVICE"
    echo "Concesiones reiniciadas."
}

# Configurar DHCP con los datos proporcionados
dhcp_configure() {
    read -p "Nombre del ámbito (scope): " scope_name

    local ip_start ip_end
    while true; do
        read -p "IP inicial del rango (servidor): " ip_start
        validate_ip "$ip_start" && break
        echo "IP inválida."
    done

    while true; do
        read -p "IP final del rango: " ip_end
        validate_ip "$ip_end" && break
        echo "IP inválida."
    done

    if (( $(ip_to_int "$ip_start") >= $(ip_to_int "$ip_end") )); then
        echo "ERROR: IP inicial debe ser menor que la final." >&2
        return 1
    fi

    read -p "Máscara (/24 o 255.255.255.0) [ENTER automática]: " input_mask
    local prefix
    if [[ -z "$input_mask" ]]; then
        prefix=$(auto_prefix "$ip_start")
    elif [[ "$input_mask" =~ ^[0-9]{1,2}$ ]]; then
        prefix=$input_mask
    else
        case "$input_mask" in
            255.0.0.0)      prefix=8 ;;
            255.255.0.0)    prefix=16 ;;
            *)              prefix=24 ;;
        esac
    fi

    local netmask
    netmask=$(prefix_to_mask "$prefix")
    local network
    network=$(calculate_network "$ip_start" "$prefix")

    local gateway
    read -p "Gateway [ENTER automático]: " gateway
    IFS=. read -r a b c _ <<< "$ip_start"
    gateway=${gateway:-"$a.$b.$c.1"}

    local dns1 dns2
    while true; do
        read -p "DNS primario [ENTER 8.8.8.8]: " dns1
        dns1=${dns1:-8.8.8.8}
        validate_ip "$dns1" && break
    done

    while true; do
        read -p "DNS secundario [ENTER 4.4.4.4]: " dns2
        dns2=${dns2:-4.4.4.4}
        validate_ip "$dns2" && break
    done

    local lease_time=600

    # Asignar IP estática al servidor
    dhcp_assign_server_ip "$ip_start" "$prefix"

    # Backup y escritura de configuración
    [[ -f "$DHCP_CONFIG_FILE" ]] && cp "$DHCP_CONFIG_FILE" "${DHCP_CONFIG_FILE}.bak"
    cat > "$DHCP_CONFIG_FILE" <<EOF
# DHCP Server Config - $scope_name
default-lease-time $lease_time;
max-lease-time $lease_time;
authoritative;

subnet $network netmask $netmask {
    range $ip_start $ip_end;
    option routers $gateway;
    option domain-name-servers $dns1, $dns2;
}
EOF

    if dhcpd -t -cf "$DHCP_CONFIG_FILE"; then
        echo "DHCPD_INTERFACE=\"$DHCP_INTERFACE\"" > /etc/sysconfig/dhcpd
        systemctl enable "$DHCP_SERVICE"
        systemctl restart "$DHCP_SERVICE"
        echo "DHCP configurado correctamente."
    else
        echo "Error en la configuración." >&2
        return 1
    fi
}

# Mostrar concesiones activas
dhcp_monitor_leases() {
    if ! systemctl is-active "$DHCP_SERVICE" &>/dev/null; then
        echo "El servicio DHCP no está activo."
        return
    fi
    if [[ ! -f "$DHCP_LEASE_FILE" ]]; then
        echo "Archivo de concesiones no encontrado."
        return
    fi
    awk '/lease/ {ip=$2} /binding state active/ {print "IP: " ip}' "$DHCP_LEASE_FILE"
}