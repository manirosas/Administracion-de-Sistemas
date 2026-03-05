#!/bin/bash
# ============================================
# Script FTP - openSUSE Leap
# Servidor: vsftpd
# Requiere ejecucion como root
# ============================================

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Debe ejecutar este script como root."
    exit 1
fi

# -------- Variables globales --------
FTP_ROOT="/srv/ftp"
CONF="/etc/vsftpd.conf"
CONF_BAK="/etc/vsftpd.conf.bak"
GRUPOS=("reprobados" "recursadores")

# ============================================
# FUNCION: Instalar vsftpd (idempotente)
# ============================================
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

# ============================================
# FUNCION: Configurar vsftpd
# ============================================
configurar_vsftpd() {
    echo ""
    echo "--- Configuracion de vsftpd ---"

    # Backup de configuracion original
    if [ ! -f "$CONF_BAK" ]; then
        cp "$CONF" "$CONF_BAK"
        echo "Backup guardado en $CONF_BAK"
    fi

    # Asegurar que /sbin/nologin este en /etc/shells (requerido por PAM+vsftpd)
    if ! grep -qx "/sbin/nologin" /etc/shells; then
        echo "/sbin/nologin" >> /etc/shells
        echo "Se agrego /sbin/nologin a /etc/shells"
    fi

    cat <<EOF > "$CONF"
# vsftpd.conf - openSUSE Leap
listen=YES
listen_ipv6=NO

# Acceso anonimo (solo lectura)
anonymous_enable=YES
anon_root=$FTP_ROOT/general
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_other_write_enable=NO

# Acceso usuarios locales
local_enable=YES
write_enable=YES
local_umask=022

# Chroot: confina a cada usuario dentro de su directorio raiz
chroot_local_user=YES
allow_writeable_chroot=NO
passwd_chroot_enable=NO

# PAM y seguridad
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
log_ftp_protocol=NO

# Mensaje de bienvenida
ftpd_banner=Servidor FTP - Acceso restringido
EOF

    systemctl restart vsftpd
    if systemctl is-active --quiet vsftpd; then
        echo "Configuracion aplicada y servicio reiniciado correctamente."
    else
        echo "ERROR: vsftpd no pudo reiniciarse. Revise /var/log/vsftpd.log"
    fi
}

# ============================================
# FUNCION: Crear estructura de directorios y grupos
# ============================================
crear_estructura() {
    echo ""
    echo "--- Creacion de estructura FTP ---"

    # Crear grupos si no existen
    for g in "${GRUPOS[@]}"; do
        if getent group "$g" &>/dev/null; then
            echo "Grupo '$g' ya existe."
        else
            groupadd "$g"
            echo "Grupo '$g' creado."
        fi
    done

    # Crear directorios base
    mkdir -p "$FTP_ROOT/general"
    mkdir -p "$FTP_ROOT/reprobados"
    mkdir -p "$FTP_ROOT/recursadores"

    # /srv/ftp: root:root, sin escritura para nadie mas (base del chroot)
    chown root:root "$FTP_ROOT"
    chmod 755 "$FTP_ROOT"

    # general: acceso anonimo (lectura) y escritura para usuarios autenticados
    # Se gestiona via permisos de grupo ftp (usuarios autenticados se agregan a ftp)
    chown root:ftp "$FTP_ROOT/general"
    chmod 775 "$FTP_ROOT/general"

    # Carpetas de grupo: solo miembros del grupo pueden leer/escribir
    chown root:reprobados "$FTP_ROOT/reprobados"
    chmod 770 "$FTP_ROOT/reprobados"

    chown root:recursadores "$FTP_ROOT/recursadores"
    chmod 770 "$FTP_ROOT/recursadores"

    echo "Estructura creada:"
    echo "  $FTP_ROOT/general       (lectura anonima, escritura autenticados)"
    echo "  $FTP_ROOT/reprobados    (acceso exclusivo grupo reprobados)"
    echo "  $FTP_ROOT/recursadores  (acceso exclusivo grupo recursadores)"
}

# ============================================
# FUNCION: Crear usuarios masivamente
#
# Estructura visible al hacer login FTP:
#   /general
#   /reprobados  o  /recursadores  (segun grupo)
#   /nombre_usuario
#
# Esto se logra con symlinks dentro del home del usuario,
# ya que chroot_local_user confina al usuario en su carpeta.
# ============================================
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

        # Validaciones
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

        # Directorio home del usuario dentro de FTP_ROOT
        HOME_USUARIO="$FTP_ROOT/$usuario"

        # Crear usuario: home en /srv/ftp/<usuario>, sin shell interactiva
        useradd -M -d "$HOME_USUARIO" -s /sbin/nologin "$usuario"
        echo "$usuario:$pass" | chpasswd

        # Agregar usuario al grupo principal y al grupo ftp (para escritura en /general)
        usermod -g "$grupo" -G "ftp" "$usuario"

        # Crear el directorio home del usuario
        # chroot_local_user=YES: este directorio es la RAIZ del usuario al conectarse
        # NO debe ser escribible por el usuario (requisito vsftpd con chroot)
        mkdir -p "$HOME_USUARIO"
        chown root:"$grupo" "$HOME_USUARIO"
        chmod 550 "$HOME_USUARIO"

        # Crear subcarpeta personal (aqui puede escribir)
        mkdir -p "$HOME_USUARIO/$usuario"
        chown "$usuario":"$grupo" "$HOME_USUARIO/$usuario"
        chmod 770 "$HOME_USUARIO/$usuario"

        # Crear symlinks para que el usuario vea la estructura completa desde su raiz:
        #   ~/general       -> /srv/ftp/general
        #   ~/reprobados    -> /srv/ftp/reprobados  (o recursadores)
        ln -sf "$FTP_ROOT/general"  "$HOME_USUARIO/general"
        ln -sf "$FTP_ROOT/$grupo"   "$HOME_USUARIO/$grupo"

        echo "  Usuario '$usuario' creado en grupo '$grupo'."
        echo "  Estructura visible al conectar:"
        echo "    /$usuario/     (escritura personal)"
        echo "    /general/      -> $FTP_ROOT/general"
        echo "    /$grupo/       -> $FTP_ROOT/$grupo"
    done
}

# ============================================
# FUNCION: Cambiar usuario de grupo
# ============================================
cambiar_grupo() {
    echo ""
    echo "--- Cambio de grupo de usuario ---"

    read -p "Nombre de usuario a cambiar: " usuario

    if ! id "$usuario" &>/dev/null; then
        echo "ERROR: El usuario '$usuario' no existe."
        return 1
    fi

    # Mostrar grupo actual
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

    # Cambiar grupo principal, conservar ftp como grupo secundario
    usermod -g "$nuevo_grupo" -G "ftp" "$usuario"

    # Actualizar propietario del home y subcarpeta personal
    chown root:"$nuevo_grupo" "$HOME_USUARIO"
    chown "$usuario":"$nuevo_grupo" "$HOME_USUARIO/$usuario"

    # Actualizar symlink del grupo (eliminar el anterior, crear el nuevo)
    rm -f "$HOME_USUARIO/$grupo_actual"
    ln -sf "$FTP_ROOT/$nuevo_grupo" "$HOME_USUARIO/$nuevo_grupo"

    echo "Usuario '$usuario' cambiado de '$grupo_actual' a '$nuevo_grupo'."
    echo "Nuevo symlink: $HOME_USUARIO/$nuevo_grupo -> $FTP_ROOT/$nuevo_grupo"
}

# ============================================
# FUNCION: Listar usuarios FTP
# ============================================
listar_usuarios() {
    echo ""
    echo "--- Usuarios FTP registrados ---"
    echo ""
    printf "%-20s %-15s %-30s\n" "USUARIO" "GRUPO" "HOME"
    printf "%-20s %-15s %-30s\n" "-------" "-----" "----"

    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ "$home" == "$FTP_ROOT/"* && "$shell" == "/sbin/nologin" ]]; then
            grupo=$(id -gn "$user" 2>/dev/null || echo "N/A")
            printf "%-20s %-15s %-30s\n" "$user" "$grupo" "$home"
        fi
    done < /etc/passwd
}

# ============================================
# FUNCION: Borrar configuracion FTP
# ============================================
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

    # Eliminar usuarios cuyo home este dentro de FTP_ROOT
    while IFS=: read -r user _ _ _ _ home shell; do
        if [[ "$home" == "$FTP_ROOT/"* && "$shell" == "/sbin/nologin" ]]; then
            userdel -r "$user" 2>/dev/null
            echo "  Usuario '$user' eliminado."
        fi
    done < /etc/passwd

    # Limpiar directorios (excepto el punto de montaje base)
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
while true; do
    echo ""
    echo "===================================="
    echo "   MENU FTP - openSUSE Leap"
    echo "===================================="
    echo " 1) Instalar vsftpd"
    echo " 2) Configurar vsftpd"
    echo " 3) Crear estructura de directorios"
    echo " 4) Crear usuarios"
    echo " 5) Cambiar usuario de grupo"
    echo " 6) Listar usuarios FTP"
    echo " 7) Borrar configuracion FTP"
    echo " 8) Salir"
    echo "===================================="
    read -p "Seleccione una opcion: " opcion

    case "$opcion" in
        1) instalar_vsftpd ;;
        2) configurar_vsftpd ;;
        3) crear_estructura ;;
        4) crear_usuarios ;;
        5) cambiar_grupo ;;
        6) listar_usuarios ;;
        7) borrar_todo ;;
        8) echo "Saliendo..."; exit 0 ;;
        *) echo "Opcion invalida. Intente nuevamente." ;;
    esac

    echo ""
    read -p "Presione ENTER para continuar..."
    clear
done
