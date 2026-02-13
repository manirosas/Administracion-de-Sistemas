#!/bin/bash

CONFIG_FILE="/etc/dhcpd.conf"
INTERFACE="enp0s8"
LEASE_FILE="/var/lib/dhcp/db/dhcpd.leases"

# VALIDAR ROOT
if [[ $EUID -ne 0 ]]; then
    echo "Error: Este script debe ejecutarse con privilegios de root."
    exit 1
fi

# FUNCIONES DE UTILIDAD

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

# Determina el prefijo según la IP (Clases A, B, C) si no se especifica máscara
obtener_prefijo_automatico() {
    local ip=$1
    IFS=. read -r a b c d <<< "$ip"
    if (( a >= 1 && a <= 126 )); then echo 8;    # Clase A
    elif (( a >= 128 && a <= 191 )); then echo 16; # Clase B
    elif (( a >= 192 && a <= 223 )); then echo 24; # Clase C
    else echo 24; fi
}

prefijo_a_mask() {
    local prefix=$1
    local mask=""
    local full_octets=$((prefix / 8))
    local partial_octet=$((prefix % 8))
    
    for ((i=0; i<4; i++)); do
        if ((i < full_octets)); then
            mask+="255"
        elif ((i == full_octets)); then
            mask+=$((256 - 2**(8 - partial_octet)))
        else
            mask+="0"
        fi
        [[ $i -lt 3 ]] && mask+="."
    done
    echo "$mask"
}

resetear_cliente(){
	systemctl stop dhcpd
	
	if [[ -f "$LEASE_FILE" ]]; then
		#crear backup y limpiar leases para que el servidor reinicie las IPs asignadas
		echo "" > "$LEASE_FILE" "${LEASE_FILE}.bak"
		echo "" > "$LEASE_FILE"
		echo "Base de datos de las concesiones limpiada"
	fi

	systemctl start dhcpd
	echo "Servidor reiniciado.El cliente debe pedir su IP"
}

verificar_dhcp() {
    if ! rpm -q dhcp-server &>/dev/null; then
        echo "dhcp-server no está instalado."
        read -p "¿Deseas instalarlo con zypper? (s/n): " op
        if [[ "$op" == "s" ]]; then
            zypper install -y dhcp-server || exit 1
        else
            return
        fi
    else
        echo "dhcp-server ya está instalado."
    fi
}

asignar_ip_servidor() {
    local ip="$1"
    local prefix="$2"
    local conn_name="dhcp-static-$INTERFACE"

    echo "Configurando IP estática $ip/$prefix en $INTERFACE..."
    
    # Configuración mediante nmcli (NetworkManager)
    nmcli device set "$INTERFACE" managed yes
    nmcli connection delete "$conn_name" 2>/dev/null
    
    nmcli connection add \
        type ethernet \
        ifname "$INTERFACE" \
        con-name "$conn_name" \
        ipv4.method manual \
        ipv4.addresses "$ip/$prefix" \
        ipv6.method ignore

    nmcli connection up "$conn_name"
}

configurar_dhcp() {
    read -p "Nombre del ámbito (scope): " SCOPE_NAME

    while true; do
        read -p "IP inicial del rango: " IP_START
        ip_valida "$IP_START" && break
        echo "  IP inválida, intenta de nuevo."
    done

    while true; do
        read -p "IP final del rango: " IP_END
        ip_valida "$IP_END" && break
        echo "  IP inválida, intenta de nuevo."
    done

    if (( $(ip_to_int "$IP_START") >= $(ip_to_int "$IP_END") )); then
        echo "Error: La IP inicial debe ser menor a la final."
        return
    fi

    # Lógica de Máscara
    read -p "Máscara (ej. 24 o 255.255.255.0) [Enter para calcular automaticamente]: " INPUT_MASK
    if [[ -z "$INPUT_MASK" ]]; then
        PREFIX=$(obtener_prefijo_automatico "$IP_START")
        NETMASK=$(prefijo_a_mask "$PREFIX")
    elif [[ "$INPUT_MASK" =~ ^[0-9]{1,2}$ ]]; then
        PREFIX=$INPUT_MASK
        NETMASK=$(prefijo_a_mask "$PREFIX")
    else
        NETMASK=$INPUT_MASK
        # Conversión simple de máscara a prefijo (comunes)
        case $NETMASK in
            255.0.0.0) PREFIX=8 ;;
            255.255.0.0) PREFIX=16 ;;
            *) PREFIX=24 ;;
        esac
    fi

    read -p "Gateway (Enter para .1 de la red): " GATEWAY
    read -p "DNS (ej. 8.8.8.8, opcional): " DNS_SERVER
    LEASE_TIME=${LEASE_TIME:-600}

    # Calcular Red
    IFS=. read -r o1 o2 o3 o4 <<< "$IP_START"
    NETWORK="$o1.$o2.$o3.0" # Simplificado para /24, ajustable si es necesario
    GATEWAY=${GATEWAY:-"$o1.$o2.$o3.1"}

    # 1. Aplicar IP al servidor
    asignar_ip_servidor "$IP_START" "$PREFIX"

    # 2. Respaldar config anterior
    [[ -f "$CONFIG_FILE" ]] && cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    # 3. Generar nuevo dhcpd.conf
    echo "Generando archivo de configuración..."
    cat > "$CONFIG_FILE" <<EOF
# DHCP Server Config - $SCOPE_NAME
default-lease-time $LEASE_TIME;
max-lease-time $LEASE_TIME;
authoritative;

subnet $NETWORK netmask $NETMASK {
    range $IP_START $IP_END;
    option routers $GATEWAY;
    $( [[ -n "$DNS_SERVER" ]] && echo "option domain-name-servers $DNS_SERVER;" )
}
EOF

    # Validar sintaxis y reiniciar
    dhcpd -t -cf "$CONFIG_FILE" && {
        echo "DHCPD_INTERFACE=\"$INTERFACE\"" > /etc/sysconfig/dhcpd
        systemctl enable dhcpd
        systemctl restart dhcpd
        echo "Servicio DHCP iniciado correctamente."
    } || echo "Error en la sintaxis del archivo generado."
}

monitorear_concesiones() {
    echo "--- Estado del Servicio ---"
    systemctl is-active dhcpd
    if [[ ! -f "$LEASE_FILE" ]]; then
        echo "No se encuentra el archivo de concesiones ($LEASE_FILE)."
        return
    fi
    echo "--- Clientes Activos ---"
    awk '/lease/ {ip=$2} /binding state active/ {print "IP: " ip}' "$LEASE_FILE"
}

# MENÚ PRINCIPAL
while true; do
    echo -e "\n ADMINISTRACIÓN DHCP "
    echo "1) Verificar / instalar DHCP"
    echo "2) Configurar nuevo ámbito"
    echo "3) Reiniciar Clientes"
    echo "4) Monitorear concesiones"
    echo "5) Salir"
    read -p "Opción: " op

    case $op in
        1) verificar_dhcp ;;
        2) configurar_dhcp ;;
        3) resetear_cliente ;;
        4) monitorear_concesiones ;;
        5) exit 0 ;;
        *) echo "Opción no válida." ;;
    esac
done
