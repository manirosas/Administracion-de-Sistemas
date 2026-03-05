#!/bin/bash

FTP_ROOT="/srv/ftp"
CONF="/etc/vsftpd.conf"
CONF_BAK="/etc/vsftpd.conf.bak"
GRUPOS=("reprobados" "recursadores")

verificar_root(){
if [ "$EUID" -ne 0 ]; then
 echo "Ejecute como root"
 exit
fi
}

instalar_vsftpd(){

echo "Instalando vsftpd (idempotente)..."

if ! rpm -q vsftpd &>/dev/null; then
 zypper install -y vsftpd
fi

systemctl enable vsftpd

mkdir -p $FTP_ROOT/general
mkdir -p $FTP_ROOT/reprobados
mkdir -p $FTP_ROOT/recursadores

for g in "${GRUPOS[@]}"; do
 getent group $g >/dev/null || groupadd $g
done

echo "Estructura creada"
}

configurar_vsftpd(){

echo "Configurando vsftpd..."

[ ! -f "$CONF_BAK" ] && cp $CONF $CONF_BAK

cat <<EOF > $CONF
listen=YES
listen_ipv6=NO

anonymous_enable=YES
anon_root=$FTP_ROOT
anon_upload_enable=NO
anon_mkdir_write_enable=NO

local_enable=YES
write_enable=YES
local_umask=002

chroot_local_user=YES
allow_writeable_chroot=YES

pam_service_name=vsftpd
user_sub_token=\$USER
local_root=$FTP_ROOT

pasv_enable=YES
EOF

systemctl restart vsftpd

echo "vsftpd configurado"
}

configurar_permisos(){

echo "Configurando permisos..."

chmod 755 $FTP_ROOT
chmod 777 $FTP_ROOT/general

chown root:reprobados $FTP_ROOT/reprobados
chmod 2770 $FTP_ROOT/reprobados

chown root:recursadores $FTP_ROOT/recursadores
chmod 2770 $FTP_ROOT/recursadores

echo "Permisos aplicados"
}

crear_usuarios(){

read -p "Cuantos usuarios desea crear: " n

for ((i=1;i<=n;i++))
do

read -p "Usuario: " u
read -s -p "Contraseña: " p
echo
read -p "Grupo (reprobados/recursadores): " g

if id "$u" &>/dev/null; then
 echo "Usuario ya existe"
 continue
fi

useradd -d $FTP_ROOT/$u -s /sbin/nologin -g $g $u

echo "$u:$p" | chpasswd

mkdir -p $FTP_ROOT/$u

chown $u:$g $FTP_ROOT/$u
chmod 770 $FTP_ROOT/$u

echo "Usuario creado"

done
}

listar_usuarios(){

echo "Usuarios FTP creados:"
awk -F: '$6 ~ "/srv/ftp"' /etc/passwd | cut -d: -f1
}

cambiar_grupo(){

read -p "Usuario: " u
read -p "Nuevo grupo (reprobados/recursadores): " g

if ! id "$u" &>/dev/null; then
 echo "Usuario no existe"
 return
fi

usermod -g $g $u

chown $u:$g $FTP_ROOT/$u

echo "Grupo actualizado"
}

borrar_usuarios(){

echo "Borrando usuarios FTP..."

for u in $(awk -F: '$6 ~ "/srv/ftp"' /etc/passwd | cut -d: -f1)
do
 userdel -r $u
done

echo "Usuarios eliminados"
}

borrar_configuracion(){

echo "Borrando configuracion FTP..."

systemctl stop vsftpd

rm -rf $FTP_ROOT

if [ -f "$CONF_BAK" ]; then
 cp $CONF_BAK $CONF
fi

echo "Configuracion eliminada"
}

menu(){

while true
do

echo
echo "===== ADMIN FTP ====="
echo "1 Instalar servicio FTP"
echo "2 Configurar vsftpd"
echo "3 Configurar permisos"
echo "4 Crear usuarios"
echo "5 Listar usuarios FTP"
echo "6 Cambiar usuario de grupo"
echo "7 Borrar usuarios"
echo "8 Borrar configuracion FTP"
echo "9 Salir"
echo

read -p "Seleccione opcion: " op

case $op in

1) instalar_vsftpd ;;
2) configurar_vsftpd ;;
3) configurar_permisos ;;
4) crear_usuarios ;;
5) listar_usuarios ;;
6) cambiar_grupo ;;
7) borrar_usuarios ;;
8) borrar_configuracion ;;
9) exit ;;

*) echo "Opcion invalida"

esac

done
}

verificar_root
menu
