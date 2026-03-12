#!/bin/bash
# =================================================================
# SCRIPT FTP - OpenSUSE LEAP - vsftpd
# Grupos: reprobados / recursadores
# Acceso anónimo: solo lectura en /general (chroot en /srv/ftp/anon)
# Acceso autenticado: escritura en /general, grupo y personal
# =================================================================

[ "$EUID" -ne 0 ] && echo "Ejecute como root." && exit 1

# --- RUTAS Y VARIABLES GLOBALES ---
FTP_ROOT="/srv/ftp"
ANON_ROOT="$FTP_ROOT/anon"
USERS_HOME="/home/ftp_users"
GRUPOS=("reprobados" "recursadores")

# =================================================================
# 1. INSTALAR Y CONFIGURAR VSFTPD
# =================================================================
function instalar_configurar() {
    echo ""
    echo "=== Instalando y configurando vsftpd ==="

    # Instalación idempotente
    rpm -q vsftpd &>/dev/null || zypper install -y vsftpd

    # Crear grupos si no existen
    for g in "${GRUPOS[@]}"; do
        getent group "$g" &>/dev/null || groupadd "$g"
        echo "Grupo '$g' listo."
    done

    # -------------------------------------------------------
    # CARPETAS MAESTRAS (almacén real de datos)
    # -------------------------------------------------------
    mkdir -p "$FTP_ROOT/general"
    mkdir -p "$FTP_ROOT/reprobados"
    mkdir -p "$FTP_ROOT/recursadores"

    # /general → grupo 'ftp', todos los usuarios autenticados escriben
    # chmod 2775: SGID (hereda grupo) rwxrwxr-x
    chown root:ftp "$FTP_ROOT/general"
    chmod 2775 "$FTP_ROOT/general"

    # Marcar /srv/ftp/general como shared para que los rename
    # dentro de bind mounts funcionen correctamente
    mount --make-shared "$FTP_ROOT/general" 2>/dev/null || true

    # /reprobados y /recursadores → solo su grupo escribe
    # chmod 2770: SGID rwxrwx---
    chown root:reprobados "$FTP_ROOT/reprobados"
    chmod 2770 "$FTP_ROOT/reprobados"

    chown root:recursadores "$FTP_ROOT/recursadores"
    chmod 2770 "$FTP_ROOT/recursadores"

    # -------------------------------------------------------
    # ESTRUCTURA PARA ACCESO ANÓNIMO
    # /srv/ftp/anon/         ← raíz chroot (no escribible, solo root)
    # /srv/ftp/anon/general/ ← bind mount de /srv/ftp/general
    # -------------------------------------------------------
    mkdir -p "$ANON_ROOT"
    chown root:root "$ANON_ROOT"
    chmod 755 "$ANON_ROOT"

    mkdir -p "$ANON_ROOT/general"
    if ! mountpoint -q "$ANON_ROOT/general"; then
        mount --bind "$FTP_ROOT/general" "$ANON_ROOT/general"
        mount --make-slave "$ANON_ROOT/general"
    fi

    # Persistencia en fstab
    grep -q "$ANON_ROOT/general" /etc/fstab || \
        echo "$FTP_ROOT/general $ANON_ROOT/general none bind 0 0" >> /etc/fstab

    # El anónimo corre como usuario 'ftp' (otros) → necesita r-x en el directorio
    # y r-- en los archivos. 2755 = SGID + rwxr-xr-x
    chown root:ftp "$ANON_ROOT/general"
    chmod 2755 "$ANON_ROOT/general"

    # Asegurar que archivos ya existentes en /general sean legibles por otros
    find "$FTP_ROOT/general" -type f  -exec chmod o+r  {} \;
    find "$FTP_ROOT/general" -type d  -exec chmod o+rx {} \;

    # -------------------------------------------------------
    # VIGILANTE DE PERMISOS EN TIEMPO REAL
    # Corrige permisos automáticamente cuando un usuario sube
    # archivos o crea carpetas dentro de /srv/ftp/general
    # -------------------------------------------------------
    rpm -q inotify-tools &>/dev/null || zypper install -y inotify-tools

    cat > /usr/local/bin/ftp_fix_perms.sh <<'WATCHER'
#!/bin/bash
# Vigila /srv/ftp/general y aplica o+rX a todo lo nuevo
TARGET="/srv/ftp/general"
inotifywait -m -r -e create -e moved_to --format '%w%f' "$TARGET" | \
while read path; do
    if [ -d "$path" ]; then
        chmod o+rx "$path"
    elif [ -f "$path" ]; then
        chmod o+r "$path"
    fi
done
WATCHER
    chmod +x /usr/local/bin/ftp_fix_perms.sh

    # Servicio systemd para el vigilante
    cat > /etc/systemd/system/ftp-fix-perms.service <<'SVC'
[Unit]
Description=FTP general folder permission watcher
After=vsftpd.service

[Service]
ExecStart=/usr/local/bin/ftp_fix_perms.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC

    systemctl daemon-reload
    systemctl enable --now ftp-fix-perms.service

    # Cronjob de respaldo: cada minuto corrige todo /general por si acaso
    echo "* * * * * root find $FTP_ROOT/general -type f -exec chmod o+r {} \\; && find $FTP_ROOT/general -type d -exec chmod o+rx {} \\;" \
        > /etc/cron.d/ftp_perms

    # -------------------------------------------------------
    # CONFIGURACIÓN VSFTPD.CONF
    # -------------------------------------------------------
    cat > /etc/vsftpd.conf <<EOF
# --- Modo de escucha ---
listen=YES
listen_ipv6=NO

# --- Acceso anónimo (solo lectura, chroot en $ANON_ROOT) ---
anonymous_enable=YES
anon_root=$ANON_ROOT
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO

# --- Usuarios locales autenticados ---
local_enable=YES
write_enable=YES
local_umask=022
file_open_mode=0644

# --- Chroot: cada usuario ve solo su HOME ---
chroot_local_user=YES
allow_writeable_chroot=YES

# --- Permitir renombrar/mover archivos y carpetas ---
# Necesario para que FileZilla pueda mover subcarpetas a la raíz
rename_enable=YES

# --- Seguridad y logs ---
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
pam_service_name=vsftpd
seccomp_sandbox=NO

# --- Modo pasivo (para FileZilla) ---
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
EOF

    # Firewall
    firewall-cmd --permanent --add-service=ftp          &>/dev/null
    firewall-cmd --permanent --add-port=40000-40100/tcp &>/dev/null
    firewall-cmd --reload                                &>/dev/null

    systemctl enable vsftpd
    systemctl restart vsftpd

    echo ""
    echo "vsftpd configurado y activo."
    echo "Carpetas maestras listas en $FTP_ROOT"
    echo "Raíz anónima: $ANON_ROOT (bind mount de $FTP_ROOT/general en $ANON_ROOT/general)"
}

# =================================================================
# 2. CREAR USUARIOS
# Estructura visible por FTP al hacer login:
#   /general
#   /reprobados  o  /recursadores
#   /nombre_usuario
# =================================================================
function crear_usuarios() {
    read -p "Número de usuarios a crear: " n

    for (( i=1; i<=n; i++ )); do
        echo ""
        echo "--- Usuario $i de $n ---"
        read -p "Nombre de usuario: " username
        read -s -p "Contraseña: " password; echo ""

        echo "Grupo: 1) reprobados  2) recursadores"
        read -p "Opción: " g_opt
        grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

        user_home="$USERS_HOME/$username"

        # --- Crear usuario del sistema ---
        if ! id "$username" &>/dev/null; then
            useradd -m -d "$user_home" \
                    -g "$grupo"        \
                    -G ftp             \
                    -s /sbin/nologin   \
                    "$username"
        else
            # Si ya existe, asegurar grupos correctos
            usermod -g "$grupo" -G ftp "$username"
        fi
        echo "$username:$password" | chpasswd

        # --- Crear estructura de carpetas (puntos de montaje) ---
        mkdir -p "$user_home/general"
        mkdir -p "$user_home/$grupo"
        mkdir -p "$user_home/$username"

        # --- BIND MOUNTS: conectar vistas del usuario con el almacén real ---
        # Se usa --make-slave para que los rename dentro del mount funcionen
        # correctamente sin propagar cambios de vuelta al master
        if ! mountpoint -q "$user_home/general"; then
            mount --bind "$FTP_ROOT/general" "$user_home/general"
            mount --make-slave "$user_home/general"
        fi

        if ! mountpoint -q "$user_home/$grupo"; then
            mount --bind "$FTP_ROOT/$grupo" "$user_home/$grupo"
            mount --make-slave "$user_home/$grupo"
        fi

        # Persistencia en fstab (sobrevive reinicios)
        grep -q "$user_home/general" /etc/fstab || \
            echo "$FTP_ROOT/general $user_home/general none bind 0 0" >> /etc/fstab

        grep -q "$user_home/$grupo" /etc/fstab || \
            echo "$FTP_ROOT/$grupo $user_home/$grupo none bind 0 0" >> /etc/fstab

        # --- Permisos de las carpetas montadas ---
        # /general: el usuario pertenece al grupo ftp → puede escribir
        chown root:ftp "$user_home/general"
        chmod 2775 "$user_home/general"

        # /grupo: el usuario pertenece a su grupo → puede escribir
        chown root:"$grupo" "$user_home/$grupo"
        chmod 2770 "$user_home/$grupo"

        # /personal: solo el usuario y su grupo
        chown "$username:$grupo" "$user_home/$username"
        chmod 770 "$user_home/$username"

        # HOME raíz: debe ser de root y no escribible (requisito chroot vsftpd)
        chown root:root "$user_home"
        chmod 755 "$user_home"

        echo "✓ Usuario '$username' creado en grupo '$grupo'."
    done
}

# =================================================================
# 3. CAMBIAR GRUPO DE USUARIO
# =================================================================
function cambiar_grupo() {
    read -p "Nombre del usuario: " username
    id "$username" &>/dev/null || { echo "Usuario no existe."; return; }

    viejo_grupo=$(id -gn "$username")
    if [[ "$viejo_grupo" != "reprobados" && "$viejo_grupo" != "recursadores" ]]; then
        echo "El usuario no pertenece a reprobados ni recursadores."
        return
    fi

    echo "Nuevo grupo: 1) reprobados  2) recursadores"
    read -p "Opción: " g_opt
    nuevo_grupo=$([ "$g_opt" == "1" ] && echo "reprobados" || echo "recursadores")

    [ "$nuevo_grupo" == "$viejo_grupo" ] && echo "Ya pertenece a ese grupo." && return

    user_home="$USERS_HOME/$username"

    # 1. Desmontar carpeta del grupo viejo
    echo "Desvinculando '$viejo_grupo'..."
    fuser -km "$user_home/$viejo_grupo" 2>/dev/null
    sleep 1
    umount "$user_home/$viejo_grupo" 2>/dev/null || umount -f "$user_home/$viejo_grupo" 2>/dev/null

    if mountpoint -q "$user_home/$viejo_grupo"; then
        echo "ERROR: No se pudo desmontar '$viejo_grupo'."
        echo "Cierra la sesion FTP activa e intenta de nuevo."
        return 1
    fi

    sed -i "\|$user_home/$viejo_grupo|d" /etc/fstab
    rm -rf "$user_home/$viejo_grupo"

    # 2. Cambiar grupo primario del usuario
    usermod -g "$nuevo_grupo" -G ftp "$username"

    # 3. Crear y montar carpeta del nuevo grupo
    mkdir -p "$user_home/$nuevo_grupo"
    mount --bind "$FTP_ROOT/$nuevo_grupo" "$user_home/$nuevo_grupo"
    mount --make-slave "$user_home/$nuevo_grupo"

    if ! mountpoint -q "$user_home/$nuevo_grupo"; then
        echo "ERROR: No se pudo montar '$nuevo_grupo'."
        return 1
    fi

    echo "$FTP_ROOT/$nuevo_grupo $user_home/$nuevo_grupo none bind 0 0" >> /etc/fstab

    # 4. Aplicar permisos en el nuevo punto de montaje
    chown root:"$nuevo_grupo" "$user_home/$nuevo_grupo"
    chmod 2770 "$user_home/$nuevo_grupo"

    # 5. Actualizar permisos de carpeta personal
    chown "$username:$nuevo_grupo" "$user_home/$username"

    echo "✓ '$username' ahora pertenece a '$nuevo_grupo'."
}

# =================================================================
# 4. LISTAR USUARIOS
# =================================================================
function listar_usuarios() {
    echo ""
    printf "%-15s %-15s %-12s\n" "USUARIO" "GRUPO" "MONTAJE"
    echo "-------------------------------------------"
    getent passwd | awk -F: '$3 >= 1000 && $6 ~ /ftp_users/ {print $1}' | \
    while read user; do
        grp=$(id -gn "$user" 2>/dev/null)
        if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]; then
            mnt=$(mountpoint -q "$USERS_HOME/$user/$grp" && echo "ACTIVO" || echo "INACTIVO")
            printf "%-15s %-15s %-12s\n" "$user" "$grp" "$mnt"
        fi
    done
}

# =================================================================
# 5. BORRAR TODO
# =================================================================
function borrar_todo() {
    read -p "¿Confirma borrado total? (s/N): " confirm
    [[ "$confirm" != "s" && "$confirm" != "S" ]] && echo "Cancelado." && return

    echo "Limpiando sistema..."

    systemctl stop vsftpd

    # --- Detener y eliminar servicio vigilante de permisos ---
    systemctl stop  ftp-fix-perms.service 2>/dev/null
    systemctl disable ftp-fix-perms.service 2>/dev/null
    rm -f /etc/systemd/system/ftp-fix-perms.service
    rm -f /usr/local/bin/ftp_fix_perms.sh
    rm -f /etc/cron.d/ftp_perms
    systemctl daemon-reload

    # --- Desmontar bind mount anónimo ---
    if mountpoint -q "$ANON_ROOT/general"; then
        fuser -km "$ANON_ROOT/general" 2>/dev/null
        sleep 1
        umount "$ANON_ROOT/general" 2>/dev/null || umount -l "$ANON_ROOT/general" 2>/dev/null
    fi
    sed -i "\|$ANON_ROOT/general|d" /etc/fstab

    # --- Desmontar todos los bind mounts de usuarios ---
    mount | grep "$USERS_HOME" | awk '{print $3}' | sort -r | \
        while read mnt; do
            fuser -km "$mnt" 2>/dev/null
            sleep 1
            umount "$mnt" 2>/dev/null || umount -l "$mnt" 2>/dev/null
        done

    # Limpiar entradas de usuarios en fstab
    sed -i "\|$USERS_HOME|d" /etc/fstab

    # --- Eliminar usuarios FTP ---
    getent passwd | awk -F: '$3 >= 1000 && $6 ~ /ftp_users/ {print $1}' | \
    while read user; do
        grp=$(id -gn "$user" 2>/dev/null)
        if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]; then
            userdel -r "$user" 2>/dev/null
            echo "Usuario '$user' eliminado."
        fi
    done

    # --- Eliminar directorios y grupos ---
    rm -rf "$USERS_HOME" "$FTP_ROOT"
    groupdel reprobados   2>/dev/null
    groupdel recursadores 2>/dev/null

    echo "✓ Limpieza completa."
}

# =================================================================
# MENÚ PRINCIPAL
# =================================================================
while true; do
    echo ""
    echo "╔══════════════════════════════╗"
    echo "║      GESTIÓN FTP - vsftpd    ║"
    echo "╠══════════════════════════════╣"
    echo "║ 1. Instalar y Configurar     ║"
    echo "║ 2. Crear Usuarios            ║"
    echo "║ 3. Cambiar Grupo de Usuario  ║"
    echo "║ 4. Listar Usuarios           ║"
    echo "║ 5. Borrar Todo               ║"
    echo "║ 6. Salir                     ║"
    echo "╚══════════════════════════════╝"
    read -p "Opción: " op
    case $op in
        1) instalar_configurar ;;
        2) crear_usuarios      ;;
        3) cambiar_grupo       ;;
        4) listar_usuarios     ;;
        5) borrar_todo         ;;
        6) exit 0              ;;
        *) echo "Opción no válida." ;;
    esac
done
