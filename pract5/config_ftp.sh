#!/bin/bash

# ============================================================
# SERVIDOR FTP COLABORATIVO - VERSION ROBUSTA
# Compatible con OpenSUSE Leap
# ============================================================

LOG="/var/log/ftp_manager.log"

if [ "$EUID" -ne 0 ]; then
    echo "Ejecutar como root"
    exit
fi

log(){
    echo "$(date) : $1" >> $LOG
}

instalar_configurar_ftp(){

echo "Instalando y configurando servidor FTP..."

rpm -q vsftpd &>/dev/null || zypper install -y vsftpd

mkdir -p /srv/ftp/general
mkdir -p /srv/ftp/reprobados
mkdir -p /srv/ftp/recursadores

mkdir -p /home/ftp_users

groupadd -f ftp
groupadd -f reprobados
groupadd -f recursadores

# Permisos correctos (SGID)
chown root:ftp /srv/ftp/general
chmod 2775 /srv/ftp/general

chown root:reprobados /srv/ftp/reprobados
chmod 2770 /srv/ftp/reprobados

chown root:recursadores /srv/ftp/recursadores
chmod 2770 /srv/ftp/recursadores

# limpiar ACL si existen
setfacl -b /srv/ftp/general 2>/dev/null
setfacl -b /srv/ftp/reprobados 2>/dev/null
setfacl -b /srv/ftp/recursadores 2>/dev/null

cat <<EOF > /etc/vsftpd.conf

listen=YES
listen_ipv6=NO

anonymous_enable=YES
anon_root=/srv/ftp/general
no_anon_password=YES

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

user_sub_token=\$USER
local_root=/home/ftp_users/\$USER

pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100

seccomp_sandbox=NO

EOF

firewall-cmd --permanent --add-service=ftp 2>/dev/null
firewall-cmd --permanent --add-port=40000-40100/tcp 2>/dev/null
firewall-cmd --reload 2>/dev/null

systemctl enable vsftpd
systemctl restart vsftpd

echo "Servidor FTP configurado correctamente"
log "Servidor FTP instalado"

}

crear_usuario(){

read -p "Numero de usuarios: " n

for ((i=1;i<=n;i++))
do

echo ""
echo "Usuario $i"

read -p "Nombre: " username
read -s -p "Password: " password
echo ""

echo "Grupo:"
echo "1) reprobados"
echo "2) recursadores"

read -p "Opcion: " op

if [ "$op" == "1" ]; then
grupo="reprobados"
else
grupo="recursadores"
fi

home="/home/ftp_users/$username"

if ! id "$username" &>/dev/null
then

useradd -m -d "$home" -g "$grupo" -aG ftp -s /sbin/nologin "$username"

echo "$username:$password" | chpasswd

else

usermod -aG ftp "$username"

fi

mkdir -p "$home/general"
mkdir -p "$home/$grupo"
mkdir -p "$home/$username"

mountpoint -q "$home/general" || mount --bind /srv/ftp/general "$home/general"
mountpoint -q "$home/$grupo" || mount --bind /srv/ftp/$grupo "$home/$grupo"

grep -q "$home/general" /etc/fstab || echo "/srv/ftp/general $home/general none bind 0 0" >> /etc/fstab
grep -q "$home/$grupo" /etc/fstab || echo "/srv/ftp/$grupo $home/$grupo none bind 0 0" >> /etc/fstab

chown $username:$grupo "$home/$username"
chmod 770 "$home/$username"

chown root:root "$home"
chmod 755 "$home"

echo "Usuario creado correctamente"

log "Usuario creado: $username"

done

}

listar_usuarios(){

echo ""
echo "USUARIO     GRUPO"

echo "---------------------"

getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user
do

grp=$(id -gn $user)

if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]
then

echo "$user      $grp"

fi

done

}

diagnostico(){

echo ""
echo "Diagnostico del sistema FTP"

echo ""

echo "Permisos /srv/ftp"
ls -ld /srv/ftp/*

echo ""

echo "Usuarios y grupos"
getent passwd | awk -F: '$3 >= 1000 {print $1}' | while read user
do

id $user

done

echo ""

echo "Montajes activos"
mount | grep ftp

echo ""

echo "Verificando escritura"

for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}')
do

grp=$(id -gn $user)

if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]
then

su -s /bin/bash $user -c "touch /home/ftp_users/$user/general/test 2>/dev/null"

if [ $? -eq 0 ]
then
echo "$user puede escribir"
rm -f /home/ftp_users/$user/general/test
else
echo "$user NO puede escribir"
fi

fi

done

}

limpiar_todo(){

echo "Limpiando sistema FTP"

systemctl stop vsftpd

mount | grep /home/ftp_users | awk '{print $3}' | xargs umount -l 2>/dev/null

sed -i '\|/home/ftp_users|d' /etc/fstab

for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}')
do

grp=$(id -gn $user)

if [[ "$grp" == "reprobados" || "$grp" == "recursadores" ]]
then
userdel -r $user
fi

done

rm -rf /home/ftp_users
rm -rf /srv/ftp

groupdel reprobados 2>/dev/null
groupdel recursadores 2>/dev/null

echo "Sistema limpiado"

}

while true
do

echo ""
echo "====== GESTION FTP ======"

echo "1. Instalar y configurar FTP"
echo "2. Crear usuarios"
echo "3. Listar usuarios"
echo "4. Diagnostico del sistema"
echo "5. Borrar todo"
echo "6. Salir"

read -p "Opcion: " op

case $op in

1) instalar_configurar_ftp ;;
2) crear_usuario ;;
3) listar_usuarios ;;
4) diagnostico ;;
5) limpiar_todo ;;
6) exit ;;

*) echo "Opcion invalida"

esac

done
