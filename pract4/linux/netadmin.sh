#!/bin/bash
# netadmin.sh - Administrador unificado de red (DHCP y DNS)
# Punto de entrada principal

# Cargar librerías
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
source "$SCRIPT_DIR/dhcp.sh"
source "$SCRIPT_DIR/dns.sh"

# Variables globales (pueden sobreescribirse en cada módulo)
INTERFACE_DHCP="enp0s8"
INTERFACE_DNS="enp0s8"

# Marcar que common ya fue cargado
_COMMON_SH_SOURCED=1

# Verificar root al inicio
check_root

# Inicializar módulos
dns_init

# Función para mostrar el menú principal
mostrar_menu() {
    clear
    echo "   ADMINISTRADOR DE RED - DHCP y DNS    "
    echo "1)  DHCP - Verificar/instalar servidor"
    echo "2)  DHCP - Configurar servidor"
    echo "3)  DHCP - Reiniciar concesiones"
    echo "4)  DHCP - Ver concesiones activas"
    echo "-----------------------------------------"
    echo "5)  DNS  - Instalar BIND9"
    echo "6)  DNS  - Configurar IP estática"
    echo "7)  DNS  - Alta de zona (dominio)"
    echo "8)  DNS  - Baja de zona"
    echo "9)  DNS  - Consultar zonas"
    echo "10) DNS  - Probar resolución"
    echo "11) DNS  - Servicio named (recargar, reiniciar, logs)"
    echo "12) DNS  - Borrar configuración completa"
    echo "-----------------------------------------"
    echo "0)  Salir"
    echo "========================================="
    read -rp "Opción: " opcion
}

# Bucle principal
while true; do
    mostrar_menu
    case "$opcion" in
        1) dhcp_install ; pause ;;
        2) dhcp_configure ; pause ;;
        3) dhcp_reset_leases ; pause ;;
        4) dhcp_monitor_leases ; pause ;;
        5) dns_install ; pause ;;
        6) dns_set_static_ip ; pause ;;
        7) dns_create_zone ; pause ;;
        8) dns_delete_zone ; pause ;;
        9) dns_list_zones ; pause ;;
        10) dns_test_zone ; pause ;;
        11) dns_service_menu ;;  # este menú ya tiene su propio bucle y pausas internas
        12) dns_clean_config ; pause ;;
        0) echo "Saliendo." ; exit 0 ;;
        *) echo "Opción no válida." ; sleep 1 ;;
    esac
done