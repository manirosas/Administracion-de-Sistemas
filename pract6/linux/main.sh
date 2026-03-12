#!/bin/bash
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/http_functions.sh"
 
requiere_root
 
while true; do
    menu_principal
    read -rp "Opcion: " OPCION
    case "$OPCION" in
        1) menu_versiones      ;;
        2) menu_instalar       ;;
        3) menu_cambiar_puerto ;;
        4) menu_borrar         ;;
        0) salir               ;;
        *) mensaje_invalido    ;;
    esac
done
 
