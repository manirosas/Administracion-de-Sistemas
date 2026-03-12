#!/bin/bash
 
# --- Rutas de estado persistente ---------------------------------------------
ESTADO_DIR="/etc/pract6"
ESTADO_APACHE="${ESTADO_DIR}/apache.conf"
ESTADO_NGINX="${ESTADO_DIR}/nginx.conf"
ESTADO_TOMCAT="${ESTADO_DIR}/tomcat.conf"
 
# --- Puertos reservados (no permitidos) --------------------------------------
PUERTOS_RESERVADOS=(20 21 22 23 25 53 110 143 389 443 445 3306 5432 6379 8443 27017)
 
# =============================================================================
# FUNCIONES DE UTILIDAD
# =============================================================================
 
linea()   { echo "------------------------------------------------------------"; }
titulo()  { echo ""; linea; echo "  $1"; linea; }
 
salir() {
    echo ""
    echo "  Saliendo del sistema de aprovisionamiento."
    echo ""
    exit 0
}
 
mensaje_invalido() {
    echo "  Opcion invalida. Intente de nuevo."
}
 
requiere_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "  ERROR: Este script debe ejecutarse como root."
        echo "  Uso: sudo bash main.sh"
        exit 1
    fi
}
 
inicializar_estado() {
    mkdir -p "$ESTADO_DIR"
    [[ -f "$ESTADO_APACHE" ]] || echo "PUERTO=80"   > "$ESTADO_APACHE"
    [[ -f "$ESTADO_NGINX"  ]] || echo "PUERTO=80"   > "$ESTADO_NGINX"
    [[ -f "$ESTADO_TOMCAT" ]] || echo "PUERTO=8080" > "$ESTADO_TOMCAT"
}
 
leer_puerto() {
    local archivo=$1 defecto=$2
    if [[ -f "$archivo" ]]; then
        grep -oP '(?<=PUERTO=)\d+' "$archivo" 2>/dev/null || echo "$defecto"
    else
        echo "$defecto"
    fi
}
 
guardar_puerto() {
    echo "PUERTO=$2" > "$1"
}
 
servicio_instalado() {
    rpm -q "$1" &>/dev/null
}
 
estado_systemd() {
    systemctl is-active "$1" 2>/dev/null || echo "inactivo"
}
 
pausar() {
    echo ""
    read -rp "  Presione Enter para continuar..." _
}
 
# =============================================================================
# VALIDACION DE ENTRADA
# =============================================================================
 
validar_numero() {
    local valor="$1"
    [[ "$valor" =~ ^[0-9]+$ ]]
}
 
puerto_reservado() {
    local puerto=$1
    for p in "${PUERTOS_RESERVADOS[@]}"; do
        [[ "$puerto" -eq "$p" ]] && return 0
    done
    return 1
}
 
puerto_en_uso() {
    ss -tlnp 2>/dev/null | grep -q ":${1}[[:space:]]"
}
 
validar_puerto() {
    local puerto=$1
    local puerto_actual=${2:-""}
 
    if ! validar_numero "$puerto"; then
        echo "  ERROR: El puerto debe ser un numero entero."
        return 1
    fi
    if (( puerto < 1 || puerto > 65535 )); then
        echo "  ERROR: Puerto fuera de rango. Use un valor entre 1 y 65535."
        return 1
    fi
    if puerto_reservado "$puerto"; then
        echo "  ERROR: Puerto $puerto reservado para otro servicio del sistema."
        echo "  Puertos no permitidos: ${PUERTOS_RESERVADOS[*]}"
        return 1
    fi
    if [[ -n "$puerto_actual" && "$puerto" == "$puerto_actual" ]]; then
        echo "  AVISO: El puerto $puerto ya esta configurado para este servicio."
        return 1
    fi
    if puerto_en_uso "$puerto"; then
        echo "  ERROR: El puerto $puerto ya esta en uso por otro proceso."
        echo "  Use: ss -tlnp | grep :$puerto  para ver que proceso lo ocupa."
        return 1
    fi
    return 0
}
 
pedir_puerto() {
    local defecto=$1
    local puerto_actual=${2:-""}
    local puerto
 
    while true; do
        read -rp "  Puerto [$defecto]: " puerto
        puerto="${puerto:-$defecto}"
 
        # Validar que no este vacio ni tenga caracteres especiales
        if [[ -z "$puerto" ]]; then
            echo "  ERROR: El puerto no puede estar vacio."
            continue
        fi
        if [[ "$puerto" =~ [^0-9] ]]; then
            echo "  ERROR: El puerto solo debe contener numeros."
            continue
        fi
 
        if validar_puerto "$puerto" "$puerto_actual"; then
            echo "$puerto"
            return 0
        fi
    done
}
 
# =============================================================================
# CONSULTA DINAMICA DE VERSIONES (sin versiones quemadas)
# =============================================================================
 
obtener_versiones_zypper() {
    local paquete=$1
    # Consulta dinamica al repositorio - equivalente a apt-cache madison en openSUSE
    zypper search -s "$paquete" 2>/dev/null \
        | awk -F'|' 'NR>2 {gsub(/ /,"",$4); if($4 != "" && $4 != "Version") print $4}' \
        | sort -Vr \
        | uniq \
        | head -10
}
 
obtener_version_instalada() {
    local paquete=$1
    rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$paquete" 2>/dev/null || echo "No instalado"
}
 
# =============================================================================
# MENUS DE PANTALLA
# =============================================================================
 
menu_principal() {
    inicializar_estado
    clear
    linea
    echo "  SISTEMA DE APROVISIONAMIENTO WEB - openSUSE Leap"
    linea
    echo ""
    echo "  Estado de servicios:"
    printf "    %-10s estado: %-12s puerto: %s\n" \
        "Apache"  "$(estado_systemd apache2)" "$(leer_puerto "$ESTADO_APACHE" 80)"
    printf "    %-10s estado: %-12s puerto: %s\n" \
        "Nginx"   "$(estado_systemd nginx)"   "$(leer_puerto "$ESTADO_NGINX"  80)"
    printf "    %-10s estado: %-12s puerto: %s\n" \
        "Tomcat"  "$(estado_systemd tomcat)"  "$(leer_puerto "$ESTADO_TOMCAT" 8080)"
    echo ""
    linea
    echo "  1) Consultar versiones disponibles"
    echo "  2) Instalar y configurar servidor"
    echo "  3) Cambiar puerto"
    echo "  4) Borrar configuracion / Desinstalar"
    echo "  0) Salir"
    linea
    echo ""
}
 
mostrar_menu_servidor() {
    local accion=$1
    echo ""
    linea
    echo "  $accion - Seleccione servidor HTTP"
    linea
    echo "  1) Apache2"
    echo "  2) Nginx"
    echo "  3) Tomcat"
    echo "  0) Volver"
    linea
    echo ""
}
 
# =============================================================================
# CONSULTA DE VERSIONES
# =============================================================================
 
consultar_versiones_apache() {
    titulo "Versiones disponibles de Apache2 en repositorios"
    echo "  Consultando repositorios de zypper..."
    echo ""
 
    local versiones
    versiones=$(obtener_versiones_zypper "apache2")
 
    if [[ -z "$versiones" ]]; then
        echo "  No se encontraron versiones en los repositorios configurados."
        echo "  Verifique la conexion de red y los repositorios con: zypper repos"
    else
        echo "  Versiones encontradas:"
        local i=1
        while IFS= read -r v; do
            printf "    %2d) %s\n" "$i" "$v"
            (( i++ ))
        done <<< "$versiones"
    fi
 
    echo ""
    echo "  Version instalada actualmente: $(obtener_version_instalada apache2)"
    echo "  Puerto configurado:            $(leer_puerto "$ESTADO_APACHE" 80)"
    pausar
}
 
consultar_versiones_nginx() {
    titulo "Versiones disponibles de Nginx en repositorios"
    echo "  Consultando repositorios de zypper..."
    echo ""
 
    local versiones
    versiones=$(obtener_versiones_zypper "nginx")
 
    if [[ -z "$versiones" ]]; then
        echo "  No se encontraron versiones en los repositorios configurados."
    else
        echo "  Versiones encontradas:"
        local i=1
        while IFS= read -r v; do
            printf "    %2d) %s\n" "$i" "$v"
            (( i++ ))
        done <<< "$versiones"
    fi
 
    echo ""
    echo "  Version instalada actualmente: $(obtener_version_instalada nginx)"
    echo "  Puerto configurado:            $(leer_puerto "$ESTADO_NGINX" 80)"
    pausar
}
 
consultar_versiones_tomcat() {
    titulo "Versiones disponibles de Tomcat en repositorios"
    echo "  Consultando repositorios de zypper..."
    echo ""
 
    local versiones
    versiones=$(obtener_versiones_zypper "tomcat")
 
    if [[ -z "$versiones" ]]; then
        echo "  No se encontraron versiones en los repositorios configurados."
    else
        echo "  Versiones encontradas:"
        local i=1
        while IFS= read -r v; do
            printf "    %2d) %s\n" "$i" "$v"
            (( i++ ))
        done <<< "$versiones"
    fi
 
    echo ""
    echo "  Version instalada actualmente: $(obtener_version_instalada tomcat)"
    echo "  Puerto configurado:            $(leer_puerto "$ESTADO_TOMCAT" 8080)"
    pausar
}
 
menu_versiones() {
    while true; do
        mostrar_menu_servidor "Consultar versiones"
        read -rp "  Opcion: " opc
        case "$opc" in
            1) consultar_versiones_apache  ;;
            2) consultar_versiones_nginx   ;;
            3) consultar_versiones_tomcat  ;;
            0) return                      ;;
            *) mensaje_invalido            ;;
        esac
    done
}
 
# =============================================================================
# SELECCION DE VERSION (dinamica desde zypper)
# =============================================================================
 
seleccionar_version() {
    local paquete=$1
    local version_elegida=""
 
    echo ""
    echo "  Consultando versiones disponibles para $paquete..."
    echo ""
 
    local versiones
    versiones=$(obtener_versiones_zypper "$paquete")
 
    if [[ -z "$versiones" ]]; then
        echo "  AVISO: No se encontraron versiones en los repositorios."
        echo "  Se instalara la version por defecto disponible."
        VERSION_SELECCIONADA="default"
        return 0
    fi
 
    local lista=()
    while IFS= read -r v; do
        lista+=("$v")
    done <<< "$versiones"
 
    linea
    echo "  Versiones disponibles:"
    local i=1
    for v in "${lista[@]}"; do
        printf "    %2d) %s\n" "$i" "$v"
        (( i++ ))
    done
    printf "    %2d) %s\n" "$i" "Instalar version por defecto del repositorio"
    linea
 
    local total=$(( ${#lista[@]} + 1 ))
 
    while true; do
        read -rp "  Seleccione una version [1-${total}]: " opc
 
        if [[ -z "$opc" ]]; then
            echo "  ERROR: Debe seleccionar una opcion."
            continue
        fi
        if ! validar_numero "$opc"; then
            echo "  ERROR: Ingrese solo numeros."
            continue
        fi
        if (( opc < 1 || opc > total )); then
            echo "  ERROR: Opcion fuera de rango."
            continue
        fi
 
        if (( opc == total )); then
            VERSION_SELECCIONADA="default"
        else
            VERSION_SELECCIONADA="${lista[$((opc-1))]}"
        fi
        echo "  Version seleccionada: $VERSION_SELECCIONADA"
        return 0
    done
}
 
# =============================================================================
# FIREWALL
# =============================================================================
 
firewall_abrir_puerto() {
    local puerto=$1
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-port="${puerto}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo "  Firewalld: puerto $puerto/tcp abierto."
    elif command -v iptables &>/dev/null; then
        iptables -C INPUT -p tcp --dport "$puerto" -j ACCEPT &>/dev/null || \
            iptables -I INPUT -p tcp --dport "$puerto" -j ACCEPT
        echo "  iptables: puerto $puerto/tcp abierto."
    else
        echo "  AVISO: No se detecto firewall activo. Abra el puerto $puerto manualmente."
    fi
}
 
firewall_cerrar_puerto() {
    local puerto=$1
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --remove-port="${puerto}/tcp" &>/dev/null || true
        firewall-cmd --reload &>/dev/null
        echo "  Firewalld: puerto $puerto/tcp cerrado."
    elif command -v iptables &>/dev/null; then
        iptables -D INPUT -p tcp --dport "$puerto" -j ACCEPT &>/dev/null || true
        echo "  iptables: regla del puerto $puerto eliminada."
    fi
}
 
# =============================================================================
# INDEX.HTML PERSONALIZADO
# =============================================================================
 
crear_index_html() {
    local directorio=$1
    local servicio=$2
    local version=$3
    local puerto=$4
 
    mkdir -p "$directorio"
    cat > "${directorio}/index.html" <<HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>${servicio}</title>
</head>
<body>
    <h1>${servicio}</h1>
    <p>Servidor: ${servicio}</p>
    <p>Version: ${version}</p>
    <p>Puerto: ${puerto}</p>
    <p>Sistema: openSUSE Leap</p>
</body>
</html>
HTMLEOF
    echo "  index.html creado en: ${directorio}"
}
 
# =============================================================================
# USUARIO DEDICADO Y PERMISOS
# =============================================================================
 
crear_usuario_servicio() {
    local usuario=$1
    local directorio=$2
 
    if ! id "$usuario" &>/dev/null; then
        useradd --system \
                --no-create-home \
                --shell /sbin/nologin \
                --home-dir "$directorio" \
                "$usuario" 2>/dev/null
        echo "  Usuario de sistema '$usuario' creado (sin acceso interactivo)."
    else
        echo "  Usuario '$usuario' ya existe."
    fi
 
    mkdir -p "$directorio"
    chown -R "${usuario}:${usuario}" "$directorio"
    chmod 750 "$directorio"
    echo "  Permisos aplicados: $directorio -> propietario $usuario (chmod 750)"
}
 
# =============================================================================
# INSTALACION DE PAQUETE
# =============================================================================
 
instalar_paquete() {
    local paquete=$1
    local version=$2
 
    if [[ "$version" == "default" ]]; then
        echo "  Instalando $paquete (version por defecto del repositorio)..."
        zypper install -y "$paquete" 2>&1 | tail -5
    else
        echo "  Instalando ${paquete} version ${version}..."
        if ! zypper install -y "${paquete}=${version}" 2>/dev/null; then
            echo "  AVISO: No se pudo instalar la version exacta $version."
            echo "  Intentando instalar la version disponible por defecto..."
            zypper install -y "$paquete" 2>&1 | tail -5
        fi
    fi
}
 
# =============================================================================
# APACHE2 - INSTALAR Y CONFIGURAR
# =============================================================================
 
instalar_apache() {
    titulo "Instalar y Configurar Apache2"
 
    if servicio_instalado "apache2"; then
        echo "  Apache2 ya esta instalado."
        echo "  Version: $(obtener_version_instalada apache2)"
        echo ""
        read -rp "  Desea reconfigurar? [s/N]: " resp
        [[ ! "$resp" =~ ^[sS]$ ]] && return 0
    fi
 
    # Seleccion de version
    VERSION_SELECCIONADA=""
    seleccionar_version "apache2" || return 1
 
    # Seleccion de puerto
    echo ""
    echo "  Defina el puerto de escucha para Apache2:"
    local puerto
    puerto=$(pedir_puerto 80 "")
    [[ -z "$puerto" ]] && return 1
 
    # Instalacion silenciosa
    instalar_paquete "apache2" "$VERSION_SELECCIONADA"
    zypper install -y apache2-utils &>/dev/null || true
 
    # Version real instalada
    local ver_real
    ver_real=$(obtener_version_instalada apache2)
 
    # --- Seguridad: ocultar informacion del servidor ---
    # En openSUSE el archivo es /etc/apache2/conf.d/security.conf
    cat > /etc/apache2/conf.d/security.conf <<'EOF'
ServerTokens Prod
ServerSignature Off
EOF
    echo "  security.conf: ServerTokens Prod + ServerSignature Off configurados."
 
    # --- Habilitar modulos en openSUSE ---
    # openSUSE no tiene a2enmod; los modulos se declaran en /etc/sysconfig/apache2
    local sysconf="/etc/sysconfig/apache2"
    if [[ -f "$sysconf" ]]; then
        for mod in headers rewrite; do
            if ! grep -qP "(?<![a-zA-Z])${mod}(?![a-zA-Z])" "$sysconf" 2>/dev/null; then
                sed -i "s/^APACHE_MODULES=\"/APACHE_MODULES=\"${mod} /" "$sysconf"
                echo "  Modulo '$mod' habilitado en /etc/sysconfig/apache2."
            fi
        done
    fi
 
    # --- Encabezados de seguridad y bloqueo de metodos peligrosos ---
    cat > /etc/apache2/conf.d/security_headers.conf <<'EOF'
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK|DELETE|PUT|PATCH) [NC]
    RewriteRule .* - [F,L]
</IfModule>
EOF
    echo "  Encabezados de seguridad configurados."
 
    # --- Puerto de escucha ---
    # En openSUSE el archivo correcto es /etc/apache2/listen.conf
    if [[ -f /etc/apache2/listen.conf ]]; then
        sed -i "s/^Listen .*/Listen ${puerto}/" /etc/apache2/listen.conf
        echo "  listen.conf: puerto actualizado a $puerto."
    fi
 
    # --- VirtualHost ---
    cat > /etc/apache2/vhosts.d/pract6.conf <<VHEOF
<VirtualHost *:${puerto}>
    DocumentRoot /var/www/html/apache
    ServerName localhost
 
    <Directory /var/www/html/apache>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
 
        <LimitExcept GET POST HEAD>
            Require all denied
        </LimitExcept>
    </Directory>
</VirtualHost>
VHEOF
    echo "  VirtualHost configurado en /etc/apache2/vhosts.d/pract6.conf."
 
    # --- Usuario dedicado y permisos ---
    crear_usuario_servicio "wwwrun" "/var/www/html/apache"
 
    # --- Index personalizado ---
    crear_index_html "/var/www/html/apache" "Apache2" "$ver_real" "$puerto"
 
    # --- Firewall ---
    firewall_abrir_puerto "$puerto"
 
    # --- Guardar estado ---
    guardar_puerto "$ESTADO_APACHE" "$puerto"
 
    # --- Iniciar servicio ---
    systemctl enable apache2 &>/dev/null
    if systemctl restart apache2 2>/dev/null; then
        echo "  Apache2 iniciado correctamente."
    else
        echo "  ERROR: No se pudo iniciar Apache2."
        echo "  Revise los logs: journalctl -u apache2 -n 20"
    fi
 
    echo ""
    echo "  Instalacion completada."
    echo "  Servicio : Apache2"
    echo "  Version  : $ver_real"
    echo "  Puerto   : $puerto"
    echo "  Web root : /var/www/html/apache"
    pausar
}
 
# =============================================================================
# NGINX - INSTALAR Y CONFIGURAR
# =============================================================================
 
instalar_nginx() {
    titulo "Instalar y Configurar Nginx"
 
    if servicio_instalado "nginx"; then
        echo "  Nginx ya esta instalado."
        echo "  Version: $(obtener_version_instalada nginx)"
        echo ""
        read -rp "  Desea reconfigurar? [s/N]: " resp
        [[ ! "$resp" =~ ^[sS]$ ]] && return 0
    fi
 
    VERSION_SELECCIONADA=""
    seleccionar_version "nginx" || return 1
 
    echo ""
    echo "  Defina el puerto de escucha para Nginx:"
    local puerto
    puerto=$(pedir_puerto 80 "")
    [[ -z "$puerto" ]] && return 1
 
    instalar_paquete "nginx" "$VERSION_SELECCIONADA"
 
    local ver_real
    ver_real=$(obtener_version_instalada nginx)
 
    # --- Usuario dedicado ---
    crear_usuario_servicio "nginx" "/var/www/html/nginx"
 
    # --- Index personalizado ---
    crear_index_html "/var/www/html/nginx" "Nginx" "$ver_real" "$puerto"
 
    # --- Configuracion principal ---
    cat > /etc/nginx/nginx.conf <<NGEOF
user nginx;
worker_processes auto;
pid /run/nginx.pid;
 
events {
    worker_connections 1024;
}
 
http {
    server_tokens off;
 
    include      /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile     on;
    keepalive_timeout 65;
 
    add_header X-Frame-Options        "SAMEORIGIN"                      always;
    add_header X-Content-Type-Options "nosniff"                         always;
    add_header X-XSS-Protection       "1; mode=block"                   always;
    add_header Referrer-Policy        "strict-origin-when-cross-origin" always;
 
    server {
        listen      ${puerto};
        server_name localhost;
        root        /var/www/html/nginx;
        index       index.html;
 
        if (\$request_method !~ ^(GET|HEAD|POST)\$) {
            return 405;
        }
 
        location / {
            try_files \$uri \$uri/ =404;
        }
 
        location ~ /\. {
            deny all;
        }
    }
}
NGEOF
    echo "  nginx.conf configurado con seguridad aplicada."
 
    chown -R nginx:nginx /var/www/html/nginx
    chmod 750 /var/www/html/nginx
 
    firewall_abrir_puerto "$puerto"
    guardar_puerto "$ESTADO_NGINX" "$puerto"
 
    systemctl enable nginx &>/dev/null
    if systemctl restart nginx 2>/dev/null; then
        echo "  Nginx iniciado correctamente."
    else
        echo "  ERROR: No se pudo iniciar Nginx."
        echo "  Revise los logs: journalctl -u nginx -n 20"
    fi
 
    echo ""
    echo "  Instalacion completada."
    echo "  Servicio : Nginx"
    echo "  Version  : $ver_real"
    echo "  Puerto   : $puerto"
    echo "  Web root : /var/www/html/nginx"
    pausar
}
 
# =============================================================================
# TOMCAT - INSTALAR Y CONFIGURAR
# =============================================================================
 
instalar_tomcat() {
    titulo "Instalar y Configurar Tomcat"
 
    if servicio_instalado "tomcat"; then
        echo "  Tomcat ya esta instalado."
        echo "  Version: $(obtener_version_instalada tomcat)"
        echo ""
        read -rp "  Desea reconfigurar? [s/N]: " resp
        [[ ! "$resp" =~ ^[sS]$ ]] && return 0
    fi
 
    VERSION_SELECCIONADA=""
    seleccionar_version "tomcat" || return 1
 
    echo ""
    echo "  Defina el puerto de escucha para Tomcat:"
    local puerto
    puerto=$(pedir_puerto 8080 "")
    [[ -z "$puerto" ]] && return 1
 
    instalar_paquete "tomcat" "$VERSION_SELECCIONADA"
 
    local ver_real
    ver_real=$(obtener_version_instalada tomcat)
 
    # --- Usuario dedicado ---
    crear_usuario_servicio "tomcat" "/srv/tomcat/webapps/ROOT"
    mkdir -p /srv/tomcat/webapps/ROOT
 
    # --- Index personalizado ---
    crear_index_html "/srv/tomcat/webapps/ROOT" "Tomcat" "$ver_real" "$puerto"
 
    # --- server.xml: cambiar puerto y ocultar version ---
    local sxml="/etc/tomcat/server.xml"
    if [[ -f "$sxml" ]]; then
        sed -i "s/port=\"8080\"/port=\"${puerto}\"/" "$sxml"
        if ! grep -q 'server=""' "$sxml"; then
            sed -i "s/Connector port=\"${puerto}\"/Connector port=\"${puerto}\" server=\"\" xpoweredBy=\"false\"/" "$sxml"
        fi
        echo "  server.xml: puerto $puerto configurado, version ocultada."
    else
        echo "  AVISO: No se encontro /etc/tomcat/server.xml."
    fi
 
    # --- web.xml: deshabilitar listado de directorios ---
    local wxml="/etc/tomcat/web.xml"
    if [[ -f "$wxml" ]]; then
        sed -i 's|<param-value>true</param-value>|<param-value>false</param-value>|g' "$wxml"
        echo "  web.xml: listado de directorios deshabilitado."
    fi
 
    # --- context.xml: encabezados de seguridad ---
    local cxml="/etc/tomcat/context.xml"
    if [[ -f "$cxml" ]] && ! grep -q "HttpHeaderSecurityFilter" "$cxml"; then
        sed -i 's|</Context>|<filter>\
<filter-name>httpHeaderSecurity</filter-name>\
<filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>\
<init-param><param-name>antiClickJackingEnabled</param-name><param-value>true</param-value></init-param>\
<init-param><param-name>antiClickJackingOption</param-name><param-value>SAMEORIGIN</param-value></init-param>\
<init-param><param-name>blockContentTypeSniffingEnabled</param-name><param-value>true</param-value></init-param>\
</filter>\
</Context>|' "$cxml"
        echo "  context.xml: filtro de encabezados de seguridad configurado."
    fi
 
    chown -R tomcat:tomcat /srv/tomcat/webapps/ROOT
    chmod 750 /srv/tomcat/webapps/ROOT
    chown -R tomcat:tomcat /etc/tomcat/ 2>/dev/null || true
    chmod 700 /etc/tomcat/ 2>/dev/null || true
    echo "  Permisos de /etc/tomcat restringidos al usuario tomcat."
 
    firewall_abrir_puerto "$puerto"
    guardar_puerto "$ESTADO_TOMCAT" "$puerto"
 
    systemctl enable tomcat &>/dev/null
    if systemctl restart tomcat 2>/dev/null; then
        echo "  Tomcat iniciado correctamente."
    else
        echo "  ERROR: No se pudo iniciar Tomcat."
        echo "  Revise los logs: journalctl -u tomcat -n 20"
    fi
 
    echo ""
    echo "  Instalacion completada."
    echo "  Servicio : Tomcat"
    echo "  Version  : $ver_real"
    echo "  Puerto   : $puerto"
    echo "  Web root : /srv/tomcat/webapps/ROOT"
    pausar
}
 
menu_instalar() {
    while true; do
        mostrar_menu_servidor "Instalar y configurar"
        read -rp "  Opcion: " opc
        case "$opc" in
            1) instalar_apache  ;;
            2) instalar_nginx   ;;
            3) instalar_tomcat  ;;
            0) return           ;;
            *) mensaje_invalido ;;
        esac
    done
}
 
# =============================================================================
# CAMBIAR PUERTO
# =============================================================================
 
cambiar_puerto_apache() {
    titulo "Cambiar Puerto - Apache2"
 
    if ! servicio_instalado "apache2"; then
        echo "  ERROR: Apache2 no esta instalado."
        pausar; return 1
    fi
 
    local pa; pa=$(leer_puerto "$ESTADO_APACHE" 80)
    echo "  Puerto actual: $pa"
    echo ""
    echo "  Defina el nuevo puerto:"
    local np
    np=$(pedir_puerto "$pa" "$pa")
    [[ -z "$np" ]] && return 1
 
    if [[ -f /etc/apache2/listen.conf ]]; then
        sed -i "s/^Listen .*/Listen ${np}/" /etc/apache2/listen.conf
        echo "  listen.conf: puerto actualizado a $np."
    fi
 
    if [[ -f /etc/apache2/vhosts.d/pract6.conf ]]; then
        sed -i "s/<VirtualHost \*:[0-9]*>/<VirtualHost *:${np}>/" \
            /etc/apache2/vhosts.d/pract6.conf
        echo "  VirtualHost actualizado."
    fi
 
    local ver; ver=$(obtener_version_instalada apache2)
    crear_index_html "/var/www/html/apache" "Apache2" "$ver" "$np"
 
    firewall_cerrar_puerto "$pa"
    firewall_abrir_puerto  "$np"
    guardar_puerto "$ESTADO_APACHE" "$np"
 
    if systemctl restart apache2 2>/dev/null; then
        echo "  Apache2 reiniciado en puerto $np."
    else
        echo "  ERROR al reiniciar. Revise: journalctl -u apache2 -n 20"
    fi
    pausar
}
 
cambiar_puerto_nginx() {
    titulo "Cambiar Puerto - Nginx"
 
    if ! servicio_instalado "nginx"; then
        echo "  ERROR: Nginx no esta instalado."
        pausar; return 1
    fi
 
    local pa; pa=$(leer_puerto "$ESTADO_NGINX" 80)
    echo "  Puerto actual: $pa"
    echo ""
    echo "  Defina el nuevo puerto:"
    local np
    np=$(pedir_puerto "$pa" "$pa")
    [[ -z "$np" ]] && return 1
 
    if [[ -f /etc/nginx/nginx.conf ]]; then
        sed -i "s/listen[[:space:]]*${pa};/listen ${np};/" /etc/nginx/nginx.conf
        echo "  nginx.conf: puerto actualizado a $np."
    fi
 
    local ver; ver=$(obtener_version_instalada nginx)
    crear_index_html "/var/www/html/nginx" "Nginx" "$ver" "$np"
 
    firewall_cerrar_puerto "$pa"
    firewall_abrir_puerto  "$np"
    guardar_puerto "$ESTADO_NGINX" "$np"
 
    if systemctl restart nginx 2>/dev/null; then
        echo "  Nginx reiniciado en puerto $np."
    else
        echo "  ERROR al reiniciar. Revise: journalctl -u nginx -n 20"
    fi
    pausar
}
 
cambiar_puerto_tomcat() {
    titulo "Cambiar Puerto - Tomcat"
 
    if ! servicio_instalado "tomcat"; then
        echo "  ERROR: Tomcat no esta instalado."
        pausar; return 1
    fi
 
    local pa; pa=$(leer_puerto "$ESTADO_TOMCAT" 8080)
    echo "  Puerto actual: $pa"
    echo ""
    echo "  Defina el nuevo puerto:"
    local np
    np=$(pedir_puerto "$pa" "$pa")
    [[ -z "$np" ]] && return 1
 
    local sxml="/etc/tomcat/server.xml"
    if [[ -f "$sxml" ]]; then
        sed -i "s/port=\"${pa}\"/port=\"${np}\"/" "$sxml"
        echo "  server.xml: puerto actualizado a $np."
    fi
 
    local ver; ver=$(obtener_version_instalada tomcat)
    crear_index_html "/srv/tomcat/webapps/ROOT" "Tomcat" "$ver" "$np"
 
    firewall_cerrar_puerto "$pa"
    firewall_abrir_puerto  "$np"
    guardar_puerto "$ESTADO_TOMCAT" "$np"
 
    if systemctl restart tomcat 2>/dev/null; then
        echo "  Tomcat reiniciado en puerto $np."
    else
        echo "  ERROR al reiniciar. Revise: journalctl -u tomcat -n 20"
    fi
    pausar
}
 
menu_cambiar_puerto() {
    while true; do
        mostrar_menu_servidor "Cambiar puerto"
        read -rp "  Opcion: " opc
        case "$opc" in
            1) cambiar_puerto_apache  ;;
            2) cambiar_puerto_nginx   ;;
            3) cambiar_puerto_tomcat  ;;
            0) return                 ;;
            *) mensaje_invalido       ;;
        esac
    done
}
 
# =============================================================================
# BORRAR CONFIGURACION / DESINSTALAR
# =============================================================================
 
borrar_apache() {
    titulo "Borrar configuracion / Desinstalar Apache2"
 
    if ! servicio_instalado "apache2"; then
        echo "  Apache2 no esta instalado."
        pausar; return 0
    fi
 
    echo "  Se eliminara Apache2 y sus archivos de configuracion."
    read -rp "  Confirmar? [s/N]: " conf
    [[ ! "$conf" =~ ^[sS]$ ]] && return 0
 
    local p; p=$(leer_puerto "$ESTADO_APACHE" 80)
 
    systemctl stop    apache2 &>/dev/null || true
    systemctl disable apache2 &>/dev/null || true
    zypper remove -y apache2 apache2-utils &>/dev/null || true
 
    rm -f /etc/apache2/conf.d/security.conf
    rm -f /etc/apache2/conf.d/security_headers.conf
    rm -f /etc/apache2/vhosts.d/pract6.conf
    rm -rf /var/www/html/apache
    rm -f "$ESTADO_APACHE"
 
    firewall_cerrar_puerto "$p"
 
    echo "  Apache2 desinstalado. Puerto $p cerrado."
    pausar
}
 
borrar_nginx() {
    titulo "Borrar configuracion / Desinstalar Nginx"
 
    if ! servicio_instalado "nginx"; then
        echo "  Nginx no esta instalado."
        pausar; return 0
    fi
 
    echo "  Se eliminara Nginx y sus archivos de configuracion."
    read -rp "  Confirmar? [s/N]: " conf
    [[ ! "$conf" =~ ^[sS]$ ]] && return 0
 
    local p; p=$(leer_puerto "$ESTADO_NGINX" 80)
 
    systemctl stop    nginx &>/dev/null || true
    systemctl disable nginx &>/dev/null || true
    zypper remove -y nginx &>/dev/null || true
 
    rm -rf /var/www/html/nginx
    rm -f "$ESTADO_NGINX"
 
    firewall_cerrar_puerto "$p"
 
    echo "  Nginx desinstalado. Puerto $p cerrado."
    pausar
}
 
borrar_tomcat() {
    titulo "Borrar configuracion / Desinstalar Tomcat"
 
    if ! servicio_instalado "tomcat"; then
        echo "  Tomcat no esta instalado."
        pausar; return 0
    fi
 
    echo "  Se eliminara Tomcat y sus archivos de configuracion."
    read -rp "  Confirmar? [s/N]: " conf
    [[ ! "$conf" =~ ^[sS]$ ]] && return 0
 
    local p; p=$(leer_puerto "$ESTADO_TOMCAT" 8080)
 
    systemctl stop    tomcat &>/dev/null || true
    systemctl disable tomcat &>/dev/null || true
    zypper remove -y tomcat &>/dev/null || true
 
    rm -rf /srv/tomcat/webapps/ROOT
    rm -f "$ESTADO_TOMCAT"
 
    firewall_cerrar_puerto "$p"
 
    echo "  Tomcat desinstalado. Puerto $p cerrado."
    pausar
}
 
menu_borrar() {
    while true; do
        mostrar_menu_servidor "Borrar configuracion / Desinstalar"
        read -rp "  Opcion: " opc
        case "$opc" in
            1) borrar_apache    ;;
            2) borrar_nginx     ;;
            3) borrar_tomcat    ;;
            0) return           ;;
            *) mensaje_invalido ;;
        esac
    done
}
