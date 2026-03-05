#!/bin/bash

# Verificar privilegios de root
if [ "$EUID" -ne 0 ]; then 
  echo "Por favor, ejecute como root"
  exit
fi

function instalar_configurar_ftp() {
    echo "--- Configurando vsftpd e Idempotencia ---"
    
    if ! rpm -q vsftpd &>/dev/null; then
        zypper install -y vsftpd
    fi

    # 1. Crear origen central de carpetas compartidas
    mkdir -p /srv/ftp/general
    mkdir -p /srv/ftp/reprobados
    mkdir -p /srv/ftp/recursadores
    
    # Permisos para que los grupos puedan escribir en sus carpetas compartidas
    groupadd -f reprobados
    groupadd -f recursadores
    
    chown root:reprobados /srv/ftp/reprobados
    chown root:recursadores /srv/ftp/recursadores
    chmod 777 /srv/ftp/general
    chmod 770 /srv/ftp/reprobados /srv/ftp/recursadores

    # Configuración vsftpd
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

    # Firewall
    firewall-cmd --permanent --add-service=ftp 2>/dev/null
    firewall-cmd --permanent --add-port=40000-40100/tcp 2>/dev/null
    firewall-cmd --reload 2>/dev/null

    systemctl enable vsftpd
    systemctl restart vsftpd
    echo "Servicio listo y carpetas maestras creadas en /srv/ftp."
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

        # Crear puntos de montaje en el HOME del usuario
        mkdir -p "$user_home/general" "$user_home/$grupo" "$user_home/$username"
        
        # Realizar montajes BIND (Esto vincula la carpeta del usuario a la compartida)
        mount --bind /srv/ftp/general "$user_home/general"
        mount --bind "/srv/ftp/$grupo" "$user_home/$grupo"

        chown -R "$username:$grupo" "$user_home/$username"
        chmod 755 "$user_home"
        echo "Usuario $username creado y vinculado a carpetas compartidas."
    done
}

function cambiar_grupo_usuario() {
    read -p "Nombre del usuario a modificar: " username
    if ! id "$username" &>/dev/null; then echo "No existe"; return; fi

    viejo_grupo=$(id -gn "$username")
    echo "Nuevo Grupo: 1) reprobados | 2) recursadores"
    read -p "Opcion: " g_opt
    nuevo_grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

    [ "$nuevo_grupo" == "$viejo_grupo" ] && echo "Ya es de ese grupo" && return

    user_home="/home/ftp_users/$username"

    # 1. Desmontar carpeta del grupo viejo y borrar el directorio vacío
    umount "$user_home/$viejo_grupo" 2>/dev/null
    rmdir "$user_home/$viejo_grupo"

    # 2. Cambiar grupo en sistema
    usermod -g "$nuevo_grupo" "$username"

    # 3. Crear nuevo directorio y montar el nuevo grupo
    mkdir -p "$user_home/$nuevo_grupo"
    mount --bind "/srv/ftp/$nuevo_grupo" "$user_home/$nuevo_grupo"

    echo "Cambio aplicado: Ahora el usuario ve la carpeta de $nuevo_grupo."
}

function listar_usuarios() {
    echo -e "\nUSUARIO\t\tGRUPO"
    getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user; do
        grp=$(id -gn "$user")
        [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]] && echo -e "$user\t\t$grp"
    done
}

function borrar_todo() {
    systemctl stop vsftpd
    # Desmontar todo antes de borrar
    mount | grep /home/ftp_users | cut -d' ' -f3 | xargs umount 2>/dev/null
    
    getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user; do
        grp=$(id -gn "$user")
        [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]] && userdel -r "$user" 2>/dev/null
    done
    rm -rf /home/ftp_users /srv/ftp
    groupdel reprobados 2>/dev/null
    groupdel recursadores 2>/dev/null
    echo "Sistema limpio."
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
