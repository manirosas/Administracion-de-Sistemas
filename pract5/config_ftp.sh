#!/bin/bash

# Función para verificar privilegios de root
if [ "$EUID" -ne 0 ]; then 
  echo "Por favor, ejecute como root"
  exit
fi

# --- FUNCIONES ---

function instalar_configurar_ftp() {
    echo "--- Configurando vsftpd e Idempotencia ---"
    
    if ! rpm -q vsftpd &>/dev/null; then
        zypper install -y vsftpd
    fi

    mkdir -p /srv/ftp/general
    chmod 777 /srv/ftp/general
    
    groupadd -f reprobados
    groupadd -f recursadores

    # Configuración optimizada para evitar errores de conexión en FileZilla
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
seccomp_sandbox=NO
EOF

    # Abrir Firewall (Crítico para FileZilla)
    echo "Configurando Firewall..."
    firewall-cmd --permanent --add-service=ftp 2>/dev/null
    firewall-cmd --permanent --add-port=40000-40100/tcp 2>/dev/null
    firewall-cmd --reload 2>/dev/null

    systemctl enable vsftpd
    systemctl restart vsftpd
    echo "Servicio reiniciado y puertos abiertos."
}

function gestionar_usuarios() {
    read -p "Numero de usuarios a crear: " n
    for (( i=1; i<=$n; i++ )); do
        read -p "Usuario: " username
        read -s -p "Password: " password; echo ""
        echo "Grupo: 1) reprobados | 2) recursadores"
        read -p "Opcion: " g_opt
        grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

        user_home="/home/ftp_users/$username"
        if ! id "$username" &>/dev/null; then
            useradd -m -d "$user_home" -g "$grupo" -s /sbin/nologin "$username"
        fi
        echo "$username:$password" | chpasswd

        # Estructura de carpetas
        mkdir -p "$user_home/general" "$user_home/$grupo" "$user_home/$username"
        chown -R "$username:$grupo" "$user_home"
        chmod 755 "$user_home"
        chmod 770 "$user_home/$username" "$user_home/$grupo"
        chmod 777 "$user_home/general"
    done
}

function cambiar_grupo_usuario() {
    read -p "Nombre del usuario a modificar: " username
    if ! id "$username" &>/dev/null; then
        echo "El usuario no existe."
        return
    fi

    echo "Nuevo Grupo: 1) reprobados | 2) recursadores"
    read -p "Opcion: " g_opt
    nuevo_grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")
    viejo_grupo=$(id -gn "$username")

    if [ "$nuevo_grupo" == "$viejo_grupo" ]; then
        echo "El usuario ya pertenece a este grupo."
        return
    fi

    # 1. Cambiar grupo en el sistema
    usermod -g "$nuevo_grupo" "$username"
    
    # 2. Renombrar carpeta de grupo antigua por la nueva
    user_home="/home/ftp_users/$username"
    mv "$user_home/$viejo_grupo" "$user_home/$nuevo_grupo" 2>/dev/null || mkdir -p "$user_home/$nuevo_grupo"
    
    # 3. Reasignar permisos
    chown -R "$username:$nuevo_grupo" "$user_home"
    echo "Usuario $username movido exitosamente de $viejo_grupo a $nuevo_grupo."
}

function listar_usuarios() {
    echo -e "\nUSUARIO\t\tGRUPO\t\tHOME"
    getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user; do
        grp=$(id -gn "$user")
        if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]; then
            home=$(getent passwd "$user" | cut -d: -f6)
            echo -e "$user\t\t$grp\t$home"
        fi
    done
}

function borrar_todo() {
    systemctl stop vsftpd
    listar_usuarios | awk '{print $1}' | xargs -I {} userdel -r {} 2>/dev/null
    rm -rf /home/ftp_users /srv/ftp
    groupdel reprobados 2>/dev/null
    groupdel recursadores 2>/dev/null
    echo "Todo borrado."
}

# --- MENU ---
while true; do
    echo -e "\n1. Configurar FTP\n2. Crear Usuarios\n3. Cambiar Usuario de Grupo\n4. Listar\n5. Borrar Todo\n6. Salir"
    read -p "Opcion: " op
    case $op in
        1) instalar_configurar_ftp ;;
        2) gestionar_usuarios ;;
        3) cambiar_grupo_usuario ;;
        4) listar_usuarios ;;
        5) borrar_todo ;;
        6) exit 0 ;;
    esac
done
