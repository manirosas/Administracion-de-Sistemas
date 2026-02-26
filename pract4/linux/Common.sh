#!/bin/bash
#Funciones reutilizables para administración de red

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verificar que el script se ejecute como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Este script debe ejecutarse como root.${NC}" >&2
        exit 1
    fi
}

# Validar formato y rango de una dirección IPv4
validate_ip() {
    local ip=$1
    local IFS=.
    local -a octetos
    read -ra octetos <<< "$ip"
    if [[ ${#octetos[@]} -ne 4 ]]; then
        return 1
    fi
    for oct in "${octetos[@]}"; do
        if ! [[ $oct =~ ^[0-9]+$ ]] || (( oct < 0 || oct > 255 )); then
            return 1
        fi
    done
    # Excluir direcciones reservadas
    case "$ip" in
        0.0.0.0|127.0.0.1|255.255.255.255) return 1 ;;
    esac
    return 0
}

# Convertir IP a entero de 32 bits
ip_to_int() {
    local ip=$1
    IFS=. read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Obtener prefijo CIDR automático basado en la primera clase de IP
auto_prefix() {
    local ip=$1
    IFS=. read -r a _ <<< "$ip"
    if (( a >= 1 && a <= 126 )); then
        echo 8
    elif (( a >= 128 && a <= 191 )); then
        echo 16
    else
        echo 24
    fi
}

# Convertir prefijo CIDR a máscara de red en formato decimal
prefix_to_mask() {
    local prefix=$1
    local mask=""
    local full=$((prefix / 8))
    local part=$((prefix % 8))
    for ((i=0; i<4; i++)); do
        if (( i < full )); then
            mask+="255"
        elif (( i == full )); then
            mask+=$((256 - (1 << (8 - part))))
        else
            mask+="0"
        fi
        [[ $i -lt 3 ]] && mask+="."
    done
    echo "$mask"
}

# Calcular la dirección de red a partir de IP y prefijo
calculate_network() {
    local ip=$1
    local prefix=$2
    local ip_int
    ip_int=$(ip_to_int "$ip")
    local mask_int=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
    local net_int=$(( ip_int & mask_int ))
    echo "$(( (net_int >> 24) & 255 )).$(( (net_int >> 16) & 255 )).$(( (net_int >> 8) & 255 )).$(( net_int & 255 ))"
}

# Obtener la IP actual de una interfaz
get_current_ip() {
    local iface=$1
    ip -4 addr show "$iface" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | head -1
}

# Obtener el prefijo actual de una interfaz
get_current_prefix() {
    local iface=$1
    ip -4 addr show "$iface" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f2 | head -1
}

# Obtener el gateway por defecto (para una interfaz específica o el primero)
get_default_gateway() {
    local iface=$1
    if [[ -n "$iface" ]]; then
        ip route show default dev "$iface" 2>/dev/null | awk '{print $3}'
    else
        ip route show default 2>/dev/null | awk '{print $3}' | head -1
    fi
}

# Instalar paquete con zypper si no está presente
ensure_package() {
    local pkg=$1
    if ! rpm -q "$pkg" &>/dev/null; then
        echo "Instalando $pkg..."
        zypper --non-interactive install -y "$pkg" &>/dev/null
        if [[ $? -eq 0 ]]; then
            echo "OK: $pkg instalado."
        else
            echo "ERROR: No se pudo instalar $pkg." >&2
            return 1
        fi
    else
        echo "OK: $pkg ya está instalado."
    fi
    return 0
}

# Pausa hasta que el usuario presione Enter
pause() {
    read -rp "Presione Enter para continuar..." _
}
