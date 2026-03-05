#!/bin/bash

# =================================================================
# SCRIPT DE GESTIÓN VSFTPD - OpenSUSE LEAP
# =================================================================

# Función para verificar privilegios de root
if [ "$EUID" -ne 0 ]; then 
  echo "Por favor, ejecute como root"
  exit
fi

# --- FUNCIONES DE CONFIGURACIÓN ---

function instalar_configurar_ftp() {
    echo "--- Iniciando Instalación Idempotente ---"
    
    # Instalación de paquete
    if ! rpm -q vsftpd &>/dev/null; then
        zypper install -y vsftpd
    else
        echo "vsftpd ya está instalado."
    fi

    # Crear directorios base si no existen
    mkdir -p /srv/ftp/general
    chmod 755 /srv/ftp/general
    
    # Crear grupos requeridos
    groupadd -f reprobados
    groupadd -f recursadores

    # Configuración de vsftpd.conf (Sobrescribe para asegurar consistencia)
    cat <<EOF > /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_root=/srv/ftp/general
no_anon_password=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
allow_writeable_chroot=YES
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pam_service_name=vsftpd
EOF

    systemctl enable vsftpd
    systemctl restart vsftpd
    echo "Servicio FTP configurado y activo."
}

function gestionar_usuarios() {
    read -p "Indique el número de usuarios a crear (n): " n
    
    for (( i=1; i<=$n; i++ )); do
        echo -e "\nDatos del Usuario $i:"
        read -p "Nombre de usuario: " username
        read -s -p "Contraseña: " password
        echo ""
        echo "Seleccione Grupo: 1) reprobados | 2) recursadores"
        read -p "Opción: " g_opt

        case $g_opt in
            1) grupo="reprobados" ;;
            2) grupo="recursadores" ;;
            *) echo "Opción no válida. Saltando usuario."; continue ;;
        esac

        # Crear usuario si no existe, o modificar si existe
        user_home="/home/ftp_users/$username"
        if id "$username" &>/dev/null; then
            usermod -g "$grupo" -d "$user_home" -s /sbin/nologin "$username"
        else
            useradd -m -d "$user_home" -g "$grupo" -s /sbin/nologin "$username"
        fi
        echo "$username:$password" | chpasswd

        # Lógica de carpetas requerida
        # Estructura: /general, /grupo, /nombre_usuario
        mkdir -p "$user_home/general"
        mkdir -p "$user_home/$grupo"
        mkdir -p "$user_home/$username"

        # Aplicar permisos (ACLs básicas y Chmod)
        # El usuario es dueño de su home para permitir escritura
        chown -R "$username:$grupo" "$user_home"
        
        # Permisos: Lectura/Escritura para el dueño en sus carpetas
        chmod 755 "$user_home"
        chmod 770 "$user_home/$username"
        chmod 770 "$user_home/$grupo"
        chmod 777 "$user_home/general" # Acceso de escritura según requerimiento

        echo "Usuario $username configurado correctamente en el grupo $grupo."
    done
}

function listar_usuarios() {
    echo -e "\n--- LISTA DE USUARIOS FTP ---"
    # Filtrar usuarios que pertenecen a los grupos creados
    local gid_reprobados=$(getent group reprobados | cut -d: -f3)
    local gid_recursadores=$(getent group recursadores | cut -d: -f3)

    printf "%-15s %-15s %-20s\n" "USUARIO" "GRUPO" "HOME"
    awk -F: -v g1="$gid_reprobados" -v g2="$gid_recursadores" \
    '{ if ($4 == g1 || $4 == g2) print $1 }' /etc/passwd | while read user; do
        grupo_actual=$(id -gn "$user")
        home_dir=$(getent passwd "$user" | cut -d: -f6)
        printf "%-15s %-15s %-20s\n" "$user" "$grupo_actual" "$home_dir"
    done
}

function borrar_configuracion() {
    echo "--- ELIMINANDO CONFIGURACIÓN Y USUARIOS ---"
    
    # Detener servicio
    systemctl stop vsftpd 2>/dev/null
    
    # Eliminar usuarios detectados en el sistema de los grupos específicos
    local gid_reprobados=$(getent group reprobados | cut -d: -f3)
    local gid_recursadores=$(getent group recursadores | cut -d: -f3)

    users_to_del=$(awk -F: -v g1="$gid_reprobados" -v g2="$gid_recursadores" \
    '{ if ($4 == g1 || $4 == g2) print $1 }' /etc/passwd)

    for u in $users_to_del; do
        userdel -r "$u" 2>/dev/null
        echo "Usuario $u eliminado."
    done

    # Limpiar directorios y grupos
    rm -rf /home/ftp_users
    rm -rf /srv/ftp
    groupdel reprobados 2>/dev/null
    groupdel recursadores 2>/dev/null
    
    # Desinstalar paquete
    zypper remove -y vsftpd
    echo "Limpieza completada."
}

# --- MENÚ PRINCIPAL ---

while true; do
    echo -e "\n=============================="
    echo "   MENÚ GESTIÓN FTP OpenSUSE"
    echo "=============================="
    echo "1. Instalar e Idempotencia (Configurar FTP)"
    echo "2. Gestión de Usuarios (Crear/Asignar)"
    echo "3. Listar Usuarios"
    echo "4. Borrar Configuración y Usuarios"
    echo "5. Salir"
    read -p "Seleccione una opción: " opcion

    case $opcion in
        1) instalar_configurar_ftp ;;
        2) gestionar_usuarios ;;
        3) listar_usuarios ;;
        4) borrar_configuracion ;;
        5) exit 0 ;;
        *) echo "Opción no válida." ;;
    esac
done
