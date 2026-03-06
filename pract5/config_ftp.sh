#!/bin/bash

# =================================================================
# SCRIPT FTP COLABORATIVO - OpenSUSE LEAP (BIND MOUNT + SGID)
# =================================================================

if [ "$EUID" -ne 0 ]; then 
  echo "Por favor, ejecute como root"
  exit
fi

function instalar_configurar_ftp() {
    echo "--- Configurando vsftpd, Firewall y Carpetas Maestras ---"
    
    # 1. Instalación idempotente
    rpm -q vsftpd &>/dev/null || zypper install -y vsftpd

    # 2. Crear Origen Central (El Almacén Real)
    mkdir -p /srv/ftp/general
    mkdir -p /srv/ftp/reprobados
    mkdir -p /srv/ftp/recursadores
    
    # Crear grupos si no existen
    groupadd -f reprobados
    groupadd -f recursadores
    groupadd -f ftp 2>/dev/null

    # ---------------------------------------------------------------
    # PERMISOS CRÍTICOS:
    # - SGID (2xxx): archivos nuevos heredan el grupo de la carpeta
    # - Sticky (1xxx): solo el dueño del archivo puede borrarlo
    # - 3xxx = SGID + Sticky combinados
    # Esto permite escribir archivos pero NO borrar carpetas del servidor
    # ---------------------------------------------------------------

    # Carpeta General: todos los usuarios autenticados pueden escribir
    # El grupo 'ftp' es el denominador común entre todos los usuarios
    chown root:ftp /srv/ftp/general
    chmod 3775 /srv/ftp/general   # SGID + Sticky + rwxrwxr-x

    # Carpeta Reprobados: solo root y el grupo reprobados
    chown root:reprobados /srv/ftp/reprobados
    chmod 3770 /srv/ftp/reprobados  # SGID + Sticky + rwxrwx---

    # Carpeta Recursadores: solo root y el grupo recursadores
    chown root:recursadores /srv/ftp/recursadores
    chmod 3770 /srv/ftp/recursadores  # SGID + Sticky + rwxrwx---

    # 3. Configuración vsftpd.conf
    cat <<EOF > /etc/vsftpd.conf
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_root=/srv/ftp/general
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
local_enable=YES
write_enable=YES
local_umask=002
file_open_mode=0664
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

    # 4. Firewall
    firewall-cmd --permanent --add-service=ftp 2>/dev/null
    firewall-cmd --permanent --add-port=40000-40100/tcp 2>/dev/null
    firewall-cmd --reload 2>/dev/null

    systemctl enable vsftpd && systemctl restart vsftpd
    echo "Servicio iniciado. Carpetas maestras listas en /srv/ftp."
}

function gestionar_usuarios() {
    read -p "Numero de usuarios a crear: " n
    for (( i=1; i<=$n; i++ )); do
        echo -e "\n--- Configurando Usuario $i ---"
        read -p "Nombre de usuario: " username
        read -s -p "Password: " password; echo ""
        echo "Grupo: 1) reprobados | 2) recursadores"
        read -p "Opcion: " g_opt
        grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

        user_home="/home/ftp_users/$username"
        
        # Crear usuario:
        # -g: grupo primario = su grupo (reprobados o recursadores)
        # -G: grupos secundarios = ftp (para acceso a /srv/ftp/general)
        if ! id "$username" &>/dev/null; then
            useradd -m -d "$user_home" -g "$grupo" -G ftp -s /sbin/nologin "$username"
        else
            # Si ya existe, asegurar que tenga el grupo ftp como secundario
            usermod -G ftp "$username"
        fi
        echo "$username:$password" | chpasswd

        # Crear subdirectorios en el HOME (Puntos de montaje)
        mkdir -p "$user_home/general" "$user_home/$grupo" "$user_home/$username"
        
        # Realizar montajes BIND
        mountpoint -q "$user_home/general" || mount --bind /srv/ftp/general "$user_home/general"
        mountpoint -q "$user_home/$grupo"  || mount --bind "/srv/ftp/$grupo" "$user_home/$grupo"

        # ---------------------------------------------------------------
        # FIX CRÍTICO: Tras el bind mount, aplicar permisos en el punto
        # de montaje para que el usuario pueda escribir vía su grupo.
        # Esto no afecta /srv/ftp/ sino solo la vista del usuario.
        # ---------------------------------------------------------------
        chown root:ftp "$user_home/general"
        chmod 3775 "$user_home/general"

        chown root:"$grupo" "$user_home/$grupo"
        chmod 3770 "$user_home/$grupo"

        # Persistencia en fstab
        grep -q "$user_home/general" /etc/fstab || \
            echo "/srv/ftp/general $user_home/general none bind 0 0" >> /etc/fstab
        grep -q "$user_home/$grupo" /etc/fstab || \
            echo "/srv/ftp/$grupo $user_home/$grupo none bind 0 0" >> /etc/fstab

        # Carpeta personal del usuario (solo él y su grupo pueden entrar)
        chown "$username:$grupo" "$user_home/$username"
        chmod 770 "$user_home/$username"
        
        # El HOME raíz debe ser de root y no escribible (requisito de chroot)
        chown root:root "$user_home"
        chmod 755 "$user_home"

        echo "Usuario $username creado exitosamente."
    done
}

function cambiar_grupo_usuario() {
    read -p "Nombre del usuario: " username
    if ! id "$username" &>/dev/null; then echo "Usuario no existe"; return; fi

    viejo_grupo=$(id -gn "$username")
    echo "Nuevo Grupo: 1) reprobados | 2) recursadores"
    read -p "Opcion: " g_opt
    nuevo_grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

    if [ "$nuevo_grupo" == "$viejo_grupo" ]; then echo "Ya es de ese grupo"; return; fi

    user_home="/home/ftp_users/$username"

    # 1. Desmontar grupo viejo
    echo "Desvinculando grupo $viejo_grupo..."
    umount -l "$user_home/$viejo_grupo" 2>/dev/null
    sed -i "\|$user_home/$viejo_grupo|d" /etc/fstab
    rm -rf "$user_home/$viejo_grupo"

    # 2. Cambiar grupo primario en el sistema
    usermod -g "$nuevo_grupo" "$username"
    # Mantener ftp como grupo secundario para acceso a general
    usermod -G ftp "$username"

    # 3. Vincular nuevo grupo y aplicar permisos en el punto de montaje
    mkdir -p "$user_home/$nuevo_grupo"
    mount --bind "/srv/ftp/$nuevo_grupo" "$user_home/$nuevo_grupo"
    chown root:"$nuevo_grupo" "$user_home/$nuevo_grupo"
    chmod 3770 "$user_home/$nuevo_grupo"
    echo "/srv/ftp/$nuevo_grupo $user_home/$nuevo_grupo none bind 0 0" >> /etc/fstab

    # 4. Actualizar dueño de la carpeta personal al nuevo grupo
    chown "$username:$nuevo_grupo" "$user_home/$username"

    echo "Cambio completado. El usuario $username ahora pertenece a $nuevo_grupo."
}

function listar_usuarios() {
    echo -e "\nUSUARIO\t\tGRUPO\t\tESTADO MONTAJE"
    echo "--------------------------------------------------------"
    getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user; do
        grp=$(id -gn "$user")
        if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]; then
            status=$(mountpoint -q "/home/ftp_users/$user/$grp" && echo "VINCULADO" || echo "DESCONECTADO")
            echo -e "$user\t\t$grp\t\t$status"
        fi
    done
}

function borrar_todo() {
    echo "Iniciando limpieza total..."
    systemctl stop vsftpd
    
    # Desmontar todos los binds activos
    mount | grep /home/ftp_users | awk '{print $3}' | xargs umount -l 2>/dev/null
    
    # Limpiar fstab
    sed -i '\|/home/ftp_users|d' /etc/fstab
    
    # Borrar usuarios de los grupos específicos
    getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user; do
        grp=$(id -gn "$user")
        if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]; then
            userdel -r "$user" 2>/dev/null
        fi
    done

    # Borrar directorios y grupos
    rm -rf /home/ftp_users /srv/ftp
    groupdel reprobados 2>/dev/null
    groupdel recursadores 2>/dev/null
    
    echo "Sistema limpio y configuración eliminada."
}

# --- MENU PRINCIPAL ---
while true; do
    echo ""
    echo "===== GESTIÓN FTP ====="
    echo "1. Configurar Servidor FTP e Idempotencia"
    echo "2. Crear Usuarios (n)"
    echo "3. Cambiar Usuario de Grupo"
    echo "4. Listar Usuarios"
    echo "5. Borrar Todo (Limpieza)"
    echo "6. Salir"
    read -p "Seleccione una opción: " op
    case $op in
        1) instalar_configurar_ftp ;;
        2) gestionar_usuarios ;;
        3) cambiar_grupo_usuario ;;
        4) listar_usuarios ;;
        5) borrar_todo ;;
        6) exit 0 ;;
        *) echo "Opción no válida." ;;
    esac
done
