#!/bin/bash
# Script FTP 
# Servidor: vsftpd
# Requiere ejecucion como root

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Debe ejecutar este script como root."
    exit 1
fi

# Variables globales 
FTP_ROOT="/srv/ftp"
CONF="/etc/vsftpd.conf"
CONF_BAK="/etc/vsftpd.conf.bak"
GRUPOS=("reprobados" "recursadores")

# FUNCION: Instalar vsftpd (idempotente)
instalar_vsftpd() {
    echo ""
    echo "--- Instalacion de vsftpd ---"

    if rpm -q vsftpd &>/dev/null; then
        echo "vsftpd ya se encuentra instalado. No se realizara ninguna accion."
    else
        echo "Instalando vsftpd..."
        zypper install -y vsftpd
        if [ $? -ne 0 ]; then
            echo "ERROR: Fallo la instalacion de vsftpd."
            return 1
        fi
        echo "vsftpd instalado correctamente."
    fi

    systemctl enable vsftpd &>/dev/null
    systemctl start vsftpd

    if systemctl is-active --quiet vsftpd; then
        echo "Servicio vsftpd activo y habilitado."
    else
        echo "ERROR: El servicio vsftpd no pudo iniciarse."
        return 1
    fi
}

# FUNCION: Configurar vsftpd
configurar_vsftpd() {
    echo ""
    echo "--- Configuracion de vsftpd ---"

    if [ ! -f "$CONF_BAK" ]; then
        cp "$CONF" "$CONF_BAK"
        echo "Backup guardado en $CONF_BAK"
    fi

    # Requerido por PAM+vsftpd para usuarios con shell nologin
    if ! grep -qx "/sbin/nologin" /etc/shells; then
        echo "/sbin/nologin" >> /etc/shells
        echo "Se agrego /sbin/nologin a /etc/shells"
    fi

    cat <<EOF > "$CONF"
# vsftpd.conf - openSUSE Leap
listen=YES
listen_ipv6=NO

# Acceso anonimo (solo lectura a /general)
anonymous_enable=YES
anon_root=$FTP_ROOT/general
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO

# Acceso usuarios locales autenticados
local_enable=YES
write_enable=YES
local_umask=022

# Chroot: confina al usuario dentro de su directorio home
# La raiz del chroot debe ser de root y no escribible por el usuario
chroot_local_user=YES
allow_writeable_chroot=NO

# PAM
pam_service_name=vsftpd
userlist_enable=NO
tcp_wrappers=NO

# Modo pasivo
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30100

# Logs
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log

ftpd_banner=Servidor FTP - Acceso restringido
EOF

    systemctl restart vsftpd
    if systemctl is-active --quiet vsftpd; then
        echo "Configuracion aplicada y servicio reiniciado correctamente."
    else
        echo "ERROR: vsftpd no pudo reiniciarse. Revise /var/log/vsftpd.log"
    fi
}

# FUNCION: Crear estructura de directorios y grupos
crear_estructura() {
    echo ""
    echo "--- Creacion de estructura FTP ---"

    for g in "${GRUPOS[@]}"; do
        if getent group "$g" &>/dev/null; then
            echo "Grupo '$g' ya existe."
        else
            groupadd "$g"
            echo "Grupo '$g' creado."
        fi
    done

    # Raiz FTP: root la posee, sin escritura para otros
    mkdir -p "$FTP_ROOT"
    chown root:root "$FTP_ROOT"
    chmod 755 "$FTP_ROOT"

    # general: anonimos leen, usuarios autenticados (grupo ftp) escriben
    mkdir -p "$FTP_ROOT/general"
    chown root:ftp "$FTP_ROOT/general"
    chmod 775 "$FTP_ROOT/general"

    # Carpetas de grupo: solo miembros del grupo acceden
    mkdir -p "$FTP_ROOT/reprobados"
    chown root:reprobados "$FTP_ROOT/reprobados"
    chmod 770 "$FTP_ROOT/reprobados"

    mkdir -p "$FTP_ROOT/recursadores"
    chown root:recursadores "$FTP_ROOT/recursadores"
    chmod 770 "$FTP_ROOT/recursadores"

    echo "Estructura creada:"
    echo "  $FTP_ROOT/general       (lectura anonima, escritura autenticados)"
    echo "  $FTP_ROOT/reprobados    (acceso exclusivo grupo reprobados)"
    echo "  $FTP_ROOT/recursadores  (acceso exclusivo grupo recursadores)"
}

# FUNCION: Montar carpetas compartidas en home de usuario
# Se usa bind mount en lugar de symlinks porque vsftpd con
# chroot_local_user=YES bloquea escritura a traves de symlinks.
# El bind mount hace que el kernel presente las carpetas como
# directorios fisicos reales dentro del chroot del usuario.
montar_carpetas_usuario() {
    local usuario="$1"
    local grupo="$2"
    local HOME_USUARIO="$FTP_ROOT/$usuario"

    # Crear puntos de montaje como directorios reales
    mkdir -p "$HOME_USUARIO/general"
    mkdir -p "$HOME_USUARIO/$grupo"

    # Bind mount de /general
    if ! mountpoint -q "$HOME_USUARIO/general"; then
        mount --bind "$FTP_ROOT/general" "$HOME_USUARIO/general"
        if [ $? -eq 0 ]; then
            echo "  Bind mount aplicado: $HOME_USUARIO/general -> $FTP_ROOT/general"
        else
            echo "  ERROR: No se pudo montar general en $HOME_USUARIO/general"
        fi
    else
        echo "  Ya montado: $HOME_USUARIO/general"
    fi

    # Bind mount de la carpeta de grupo
    if ! mountpoint -q "$HOME_USUARIO/$grupo"; then
        mount --bind "$FTP_ROOT/$grupo" "$HOME_USUARIO/$grupo"
        if [ $? -eq 0 ]; then
            echo "  Bind mount aplicado: $HOME_USUARIO/$grupo -> $FTP_ROOT/$grupo"
        else
            echo "  ERROR: No se pudo montar $grupo en $HOME_USUARIO/$grupo"
        fi
    else
        echo "  Ya montado: $HOME_USUARIO/$grupo"
    fi

    # Persistir en /etc/fstab para sobrevivir reinicios (evitar duplicados)
    local fstab_general="$FTP_ROOT/general $HOME_USUARIO/general none bind 0 0"
    local fstab_grupo="$FTP_ROOT/$grupo $HOME_USUARIO/$grupo none bind 0 0"

    if ! grep -qF "$HOME_USUARIO/general" /etc/fstab; then
        echo "$fstab_general" >> /etc/fstab
        echo "  Entrada agregada a /etc/fstab: general"
    fi

    if ! grep -qF "$HOME_USUARIO/$grupo" /etc/fstab; then
        echo "$fstab_grupo" >> /etc/fstab
        echo "  Entrada agregada a /etc/fstab: $grupo"
    fi
}

# FUNCION: Crear usuarios masivamente
# Estructura visible al conectar via FTP 
crear_usuarios() {
    echo ""
    echo "--- Creacion de usuarios FTP ---"

    read -p "Numero de usuarios a crear: " n

    if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -lt 1 ]; then
        echo "ERROR: Numero invalido."
        return 1
    fi

    for ((i=1; i<=n; i++)); do
        echo ""
        echo "Usuario $i de $n:"
        read -p "  Nombre de usuario : " usuario
        read -s -p "  Contrasena        : " pass
        echo ""
        read -p "  Grupo (reprobados/recursadores): " grupo

        if [[ -z "$usuario" ]]; then
            echo "  ERROR: El nombre de usuario no puede estar vacio. Saltando."
            continue
        fi

        if [[ "$grupo" != "reprobados" && "$grupo" != "recursadores" ]]; then
            echo "  ERROR: Grupo '$grupo' no valido. Debe ser 'reprobados' o 'recursadores'. Saltando."
            continue
        fi

        if id "$usuario" &>/dev/null; then
            echo "  AVISO: El usuario '$usuario' ya existe. Saltando."
            continue
        fi

        HOME_USUARIO="$FTP_ROOT/$usuario"

        # Crear usuario: home personalizado, sin shell interactiva
        useradd -M -d "$HOME_USUARIO" -s /sbin/nologin "$usuario"
        echo "$usuario:$pass" | chpasswd

        # Grupo principal: su categoria | Grupo secundario: ftp (escritura en /general)
        usermod -g "$grupo" -G "ftp" "$usuario"

        # Raiz del chroot: propiedad root, sin escritura del usuario
        # vsftpd requiere que la raiz del chroot NO sea escribible por el usuario logeado
        mkdir -p "$HOME_USUARIO"
        chown root:"$grupo" "$HOME_USUARIO"
        chmod 550 "$HOME_USUARIO"

        # Carpeta personal: el usuario puede leer y escribir aqui
        mkdir -p "$HOME_USUARIO/$usuario"
        chown "$usuario":"$grupo" "$HOME_USUARIO/$usuario"
        chmod 770 "$HOME_USUARIO/$usuario"

        # Montar general y grupo via bind mount (no symlinks)
        montar_carpetas_usuario "$usuario" "$grupo"

        echo "  Usuario '$usuario' creado correctamente."
        echo "  Estructura al conectar via FTP:"
        echo "    /general/    (lectura y escritura)"
        echo "    /$grupo/     (lectura y escritura)"
        echo "    /$usuario/   (carpeta personal)"
    done
}

# FUNCION: Cambiar usuario de grupo
cambiar_grupo() {
    echo ""
    echo "--- Cambio de grupo de usuario ---"

    read -p "Nombre de usuario a cambiar: " usuario

    if ! id "$usuario" &>/dev/null; then
        echo "ERROR: El usuario '$usuario' no existe."
        return 1
    fi

    grupo_actual=$(id -gn "$usuario")
    echo "Grupo actual: $grupo_actual"

    read -p "Nuevo grupo (reprobados/recursadores): " nuevo_grupo

    if [[ "$nuevo_grupo" != "reprobados" && "$nuevo_grupo" != "recursadores" ]]; then
        echo "ERROR: Grupo '$nuevo_grupo' no valido."
        return 1
    fi

    if [[ "$grupo_actual" == "$nuevo_grupo" ]]; then
        echo "AVISO: El usuario ya pertenece al grupo '$nuevo_grupo'. No se realizaron cambios."
        return 0
    fi

    HOME_USUARIO="$FTP_ROOT/$usuario"

    # Desmontar bind mount del grupo anterior
    if mountpoint -q "$HOME_USUARIO/$grupo_actual"; then
        umount "$HOME_USUARIO/$grupo_actual"
        echo "Desmontado: $HOME_USUARIO/$grupo_actual"
    fi

    # Eliminar directorio del grupo anterior y su entrada en fstab
    rm -rf "${HOME_USUARIO:?}/$grupo_actual"
    sed -i "\|$HOME_USUARIO/$grupo_actual|d" /etc/fstab
    echo "Entrada de /etc/fstab eliminada para $grupo_actual"

    # Cambiar grupo principal, conservar ftp como secundario
    usermod -g "$nuevo_grupo" -G "ftp" "$usuario"

    # Actualizar permisos del home y carpeta personal
    chown root:"$nuevo_grupo" "$HOME_USUARIO"
    chown "$usuario":"$nuevo_grupo" "$HOME_USUARIO/$usuario"

    # Crear y montar el nuevo grupo
    montar_carpetas_usuario "$usuario" "$nuevo_grupo"

    echo "Usuario '$usuario' cambiado de '$grupo_actual' a '$nuevo_grupo' correctamente."
}

# FUNCION: Listar usuarios FTP
listar_usuarios() {
    echo ""
    echo "--- Usuarios FTP registrados ---"
    echo ""
    printf "%-20s %-15s %-35s\n" "USUARIO" "GRUPO" "HOME"
    printf "%-20s %-15s %-35s\n" "-------" "-----" "----"

    encontrados=0
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ "$home" == "$FTP_ROOT/"* && "$shell" == "/sbin/nologin" ]]; then
            grupo=$(id -gn "$user" 2>/dev/null || echo "N/A")
            printf "%-20s %-15s %-35s\n" "$user" "$grupo" "$home"
            encontrados=$((encontrados + 1))
        fi
    done < /etc/passwd

    if [ "$encontrados" -eq 0 ]; then
        echo "(No hay usuarios FTP registrados)"
    fi
}

# FUNCION: Remontar todos los bind mounts
remontar_todo() {
    echo ""
    echo "--- Remontando bind mounts FTP ---"

    while IFS=: read -r user _ _ _ _ home shell; do
        if [[ "$home" == "$FTP_ROOT/"* && "$shell" == "/sbin/nologin" ]]; then
            grupo=$(id -gn "$user" 2>/dev/null)
            if [[ "$grupo" == "reprobados" || "$grupo" == "recursadores" ]]; then
                echo "Remontando para usuario: $user (grupo: $grupo)"
                montar_carpetas_usuario "$user" "$grupo"
            fi
        fi
    done < /etc/passwd

    echo "Remontaje completado."
}

# FUNCION: Borrar configuracion FTP
borrar_todo() {
    echo ""
    echo "--- Borrado de configuracion FTP ---"
    echo "ADVERTENCIA: Se eliminaran todos los usuarios FTP, sus carpetas y la configuracion."
    read -p "Confirmar borrado (escriba 'CONFIRMAR'): " confirm

    if [[ "$confirm" != "CONFIRMAR" ]]; then
        echo "Operacion cancelada."
        return
    fi

    systemctl stop vsftpd

    # Desmontar y eliminar cada usuario FTP
    while IFS=: read -r user _ _ _ _ home shell; do
        if [[ "$home" == "$FTP_ROOT/"* && "$shell" == "/sbin/nologin" ]]; then
            grupo=$(id -gn "$user" 2>/dev/null)

            for punto in "$home/general" "$home/$grupo"; do
                if mountpoint -q "$punto" 2>/dev/null; then
                    umount "$punto"
                fi
            done

            userdel "$user" 2>/dev/null
            echo "  Usuario '$user' eliminado."
        fi
    done < /etc/passwd

    # Limpiar entradas de fstab relacionadas con FTP_ROOT
    sed -i "\|$FTP_ROOT|d" /etc/fstab
    echo "Entradas de /etc/fstab eliminadas."

    # Limpiar directorios
    rm -rf "${FTP_ROOT:?}"/*

    # Restaurar configuracion original
    if [ -f "$CONF_BAK" ]; then
        cp "$CONF_BAK" "$CONF"
        echo "Configuracion original restaurada desde backup."
    fi

    systemctl start vsftpd
    echo "Sistema FTP reiniciado a estado inicial."
}

# ============================================
# MENU PRINCIPAL
# ============================================
clear
while true; do
    echo ""
    echo "   MENU FTP - openSUSE Leap"
    echo " 1) Instalar vsftpd"
    echo " 2) Configurar vsftpd"
    echo " 3) Crear estructura de directorios"
    echo " 4) Crear usuarios"
    echo " 5) Cambiar usuario de grupo"
    echo " 6) Listar usuarios FTP"
    echo " 7) Remontar bind mounts (post-reinicio)"
    echo " 8) Borrar configuracion FTP"
    echo " 9) Salir"
    read -p "Seleccione una opcion: " opcion

    case "$opcion" in
        1) instalar_vsftpd ;;
        2) configurar_vsftpd ;;
        3) crear_estructura ;;
        4) crear_usuarios ;;
        5) cambiar_grupo ;;
        6) listar_usuarios ;;
        7) remontar_todo ;;
        8) borrar_todo ;;
        9) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida. Intente nuevamente." ;;
    esac

    echo ""
    read -p "Presione ENTER para continuar..."
    clear
done
