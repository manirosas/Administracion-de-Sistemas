#!/bin/bash
# =================================================================
# SCRIPT FTP - OpenSUSE LEAP - vsftpd
# Grupos: reprobados / recursadores
# =================================================================

[ "$EUID" -ne 0 ] && echo "Ejecute como root." && exit 1

FTP_ROOT="/srv/ftp"
USERS_HOME="/home/ftp_users"
GRUPOS=("reprobados" "recursadores")

# ================================================================
# 1. INSTALAR Y CONFIGURAR VSFTPD
# ================================================================
function instalar_configurar() {

echo "Instalando y configurando vsftpd..."

rpm -q vsftpd &>/dev/null || zypper install -y vsftpd

for g in "${GRUPOS[@]}"; do
    getent group "$g" &>/dev/null || groupadd "$g"
done

mkdir -p "$FTP_ROOT/general"
mkdir -p "$FTP_ROOT/reprobados"
mkdir -p "$FTP_ROOT/recursadores"

chown root:ftp "$FTP_ROOT/general"
chmod 3775 "$FTP_ROOT/general"

chown root:reprobados "$FTP_ROOT/reprobados"
chmod 3770 "$FTP_ROOT/reprobados"

chown root:recursadores "$FTP_ROOT/recursadores"
chmod 3770 "$FTP_ROOT/recursadores"

cat > /etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO

anonymous_enable=YES
anon_root=$FTP_ROOT/general
no_anon_password=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO

local_enable=YES
write_enable=YES
local_umask=002
file_open_mode=0664

chroot_local_user=YES
allow_writeable_chroot=YES

dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
pam_service_name=vsftpd

pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
EOF

firewall-cmd --permanent --add-service=ftp &>/dev/null
firewall-cmd --permanent --add-port=40000-40100/tcp &>/dev/null
firewall-cmd --reload &>/dev/null

systemctl enable vsftpd
systemctl restart vsftpd

# SELinux (si está activo)
setsebool -P ftp_home_dir on 2>/dev/null
setsebool -P allow_ftpd_full_access on 2>/dev/null

echo "Servidor FTP configurado."

}

# ================================================================
# 2. CREAR USUARIOS
# ================================================================
function crear_usuarios() {

read -p "Número de usuarios a crear: " n

for (( i=1; i<=n; i++ ))
do

echo ""
read -p "Nombre de usuario: " username
read -s -p "Contraseña: " password
echo ""

echo "Grupo: 1) reprobados  2) recursadores"
read -p "Opción: " g
grupo=$([ "$g" == "1" ] && echo "reprobados" || echo "recursadores")

user_home="$USERS_HOME/$username"

if ! id "$username" &>/dev/null
then
useradd -m -d "$user_home" -g "$grupo" -G ftp -s /sbin/nologin "$username"
fi

echo "$username:$password" | chpasswd

mkdir -p "$user_home/general"
mkdir -p "$user_home/$grupo"
mkdir -p "$user_home/$username"

mount --bind "$FTP_ROOT/general" "$user_home/general"
mount --bind "$FTP_ROOT/$grupo" "$user_home/$grupo"

grep -q "$user_home/general" /etc/fstab || \
echo "$FTP_ROOT/general $user_home/general none bind 0 0" >> /etc/fstab

grep -q "$user_home/$grupo" /etc/fstab || \
echo "$FTP_ROOT/$grupo $user_home/$grupo none bind 0 0" >> /etc/fstab

chown root:ftp "$user_home/general"
chmod 3775 "$user_home/general"

chown root:$grupo "$user_home/$grupo"
chmod 3770 "$user_home/$grupo"

chown "$username:$grupo" "$user_home/$username"
chmod 770 "$user_home/$username"

chown root:root "$user_home"
chmod 755 "$user_home"

echo "Usuario $username creado."

done

}

# ================================================================
# 3. CAMBIAR GRUPO DE USUARIO (CORREGIDO)
# ================================================================
function cambiar_grupo() {

read -p "Nombre del usuario: " username

id "$username" &>/dev/null || { echo "Usuario no existe"; return; }

viejo_grupo=$(id -gn "$username")

echo "Nuevo grupo: 1) reprobados 2) recursadores"
read -p "Opción: " g
nuevo_grupo=$([ "$g" == "1" ] && echo "reprobados" || echo "recursadores")

[ "$viejo_grupo" == "$nuevo_grupo" ] && echo "Ya pertenece a ese grupo." && return

user_home="$USERS_HOME/$username"

# desmontar grupo viejo
if mountpoint -q "$user_home/$viejo_grupo"
then
umount "$user_home/$viejo_grupo"
fi

sed -i "\|$user_home/$viejo_grupo|d" /etc/fstab
rm -rf "$user_home/$viejo_grupo"

# cambiar grupo
usermod -g "$nuevo_grupo" "$username"

# crear nueva carpeta
mkdir -p "$user_home/$nuevo_grupo"

mount --bind "$FTP_ROOT/$nuevo_grupo" "$user_home/$nuevo_grupo"

echo "$FTP_ROOT/$nuevo_grupo $user_home/$nuevo_grupo none bind 0 0" >> /etc/fstab

chown root:$nuevo_grupo "$user_home/$nuevo_grupo"
chmod 3770 "$user_home/$nuevo_grupo"

chown "$username:$nuevo_grupo" "$user_home/$username"

systemctl restart vsftpd

echo "Grupo cambiado correctamente."

}

# ================================================================
# 4. LISTAR USUARIOS
# ================================================================
function listar_usuarios() {

printf "%-15s %-15s\n" "USUARIO" "GRUPO"
echo "-----------------------------"

getent passwd | awk -F: '$3 >= 1000 && $6 ~ /ftp_users/ {print $1}' |
while read user
do
grp=$(id -gn "$user")
echo "$user        $grp"
done

}

# ================================================================
# 5. BORRAR TODO
# ================================================================
function borrar_todo() {

read -p "¿Seguro que desea borrar todo? (s/N): " c
[[ "$c" != "s" ]] && return

systemctl stop vsftpd

mount | grep "$USERS_HOME" | awk '{print $3}' | xargs -I{} umount {}

sed -i "\|$USERS_HOME|d" /etc/fstab

getent passwd | awk -F: '$3 >= 1000 && $6 ~ /ftp_users/ {print $1}' |
while read user
do
userdel -r "$user"
done

rm -rf "$USERS_HOME"
rm -rf "$FTP_ROOT"

groupdel reprobados 2>/dev/null
groupdel recursadores 2>/dev/null

echo "Sistema limpiado."

}

# ================================================================
# MENU
# ================================================================
while true
do

echo ""
echo "===== GESTIÓN FTP ====="
echo "1. Instalar y configurar"
echo "2. Crear usuarios"
echo "3. Cambiar grupo"
echo "4. Listar usuarios"
echo "5. Borrar todo"
echo "6. Salir"

read -p "Opción: " op

case $op in
1) instalar_configurar ;;
2) crear_usuarios ;;
3) cambiar_grupo ;;
4) listar_usuarios ;;
5) borrar_todo ;;
6) exit ;;
*) echo "Opción inválida" ;;
esac

done
