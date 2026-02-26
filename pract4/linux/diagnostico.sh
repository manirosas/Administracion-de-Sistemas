echo "DIAGNÓSTICO DEL SISTEMA"
echo "Hostname:"
hostname
echo
echo "Direcciones IP:"
ip -4 addr show | grep inet | grep -v 127.0.0.1
echo
echo "Espacio en disco:"
df -h /
echo