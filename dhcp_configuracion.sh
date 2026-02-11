CONFIG_FILE="/etc/dhcpd.conf"
INTERFACE="enp0s8"
#Validar ejecucion como root

if [[ $EUID -ne 0 ]]; then
	echo "Ejecuta este script como root"
	exit 1
fi

read -p "Nombre del ambito(scope): "
read -p "IP inicial (ej.192.168.100.10): " IP_START
read -p "IP final (ej.192.168.100.20) " IP_END
read -p "Ingresa el tiempo de concesion( ej. 600): " LEASE_TIME
read -p "DNS (opcional, enter para omitir): " DNS_Server

#Separar octetos

IFS=. read o1 o2 o3 o4 <<< "$IP_START"
IFS=. read f1 f2 f3 f4 <<< "$IP_END"

# Validar misma red /24

if [[ "$o1.$o2.$o3" != "$f1.$f2.$f3" ]]; then
	echo "Error: las IP no pertenecen a la misma red"
	exit 1
fi

#Calcular red,gateway y mascara

NETWORK="$o1.$o2.$o3.0"
GATEWAY="$o1.o2.o3.1"
NETMASK="255.255.255.0"

# CALCULAR primer IP para clientes, ya que el servidor se asigna la primera

SERVER_IP="$IP_START"
CLIENT_START="$o1.$o2.$o3.$((o4 + 1))"

if (( o4 + 1 > f4 )); then
	echo "Error: el rango no deja IPs disponibles para clientes "
	exit 1
fi

#Crear configuración DHCP

echo " Generando configuración DHCP  "
cat > $CONFIG_FILE <<EOF
#DHCP Server - $SCOPE_NAME

default-lease-time $LEASE_TIME;
max-lease-time $LEASE_TIME;
authoritative;

subnet $NETWORK netmask $NETMASK{
	range $CLIENT_START $IP_END;
	option routers $GATEWAY;
EOF

if [[ -n "$DNS_SERVER" ]]; then
	echo "	option domain-name-servers $DNS_SERVER;" >> $CONFIG_FILE
fi

cat >> $CONFIG_FILE <<EOF
}
EOF

# Validar configuracion

echo " Validando configuracion "
dhcpd -t || exit 1

#Configurar interfaz

echo "DHCPD_INTERFACE=\"$INTERFACE\"" > /etc/sysconfig/dhcpd
echo " Iniciando servicio DHCP "
systemctl enable dhcpd
systemctl restart dhcpd

systemctl status dhcp --no-pager


