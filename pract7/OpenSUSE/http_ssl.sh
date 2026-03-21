#!/bin/bash
# =================================================================
# HTTP_SSL.SH — SSL/TLS para Apache2, Nginx y Tomcat
# REQUIERE: source ssl_utils.sh ANTES de este archivo
# Puertos SSL configurables — no hardcodeados
# =================================================================

ESTADO_DIR="/etc/pract6"
ESTADO_APACHE="${ESTADO_DIR}/apache.conf"
ESTADO_NGINX="${ESTADO_DIR}/nginx.conf"
ESTADO_TOMCAT="${ESTADO_DIR}/tomcat.conf"

ESTADO_SSL_APACHE="/etc/pract7/apache_ssl.conf"
ESTADO_SSL_NGINX="/etc/pract7/nginx_ssl.conf"
ESTADO_SSL_TOMCAT="/etc/pract7/tomcat_ssl.conf"

_leer_puerto_http() {
    local archivo=$1 defecto=$2
    grep -oP '(?<=PUERTO=)\d+' "$archivo" 2>/dev/null || echo "$defecto"
}

_leer_puerto_ssl() {
    local archivo=$1 defecto=$2
    grep -oP '(?<=PUERTO_SSL=)\d+' "$archivo" 2>/dev/null || echo "$defecto"
}

_pedir_puerto_ssl() {
    local defecto="$1"
    local puerto_http="$2"
    local puerto_ssl

    while true; do
        read -rp "  Puerto SSL [$defecto]: " puerto_ssl
        puerto_ssl="${puerto_ssl:-$defecto}"

        if ! [[ "$puerto_ssl" =~ ^[0-9]+$ ]]; then
            echo "  ERROR: Solo números."
            continue
        fi
        if (( puerto_ssl < 1 || puerto_ssl > 65535 )); then
            echo "  ERROR: Rango 1-65535."
            continue
        fi
        if [[ "$puerto_ssl" == "$puerto_http" ]]; then
            echo "  ERROR: El puerto SSL no puede ser igual al HTTP ($puerto_http)."
            continue
        fi
        echo "$puerto_ssl"
        return 0
    done
}

# SSL APACHE2
configurar_ssl_apache() {
    titulo "SSL/TLS — Apache2"

    if ! rpm -q apache2 &>/dev/null; then
        echo "  ERROR: Apache2 no está instalado."
        return 1
    fi

    local puerto_http
    puerto_http=$(_leer_puerto_http "$ESTADO_APACHE" 80)
    local puerto_ssl_previo
    puerto_ssl_previo=$(_leer_puerto_ssl "$ESTADO_SSL_APACHE" 443)

    echo "  Puerto HTTP actual : $puerto_http"
    echo "  Puerto SSL previo  : $puerto_ssl_previo"
    echo ""
    echo "  Defina el puerto HTTPS para Apache2:"
    local puerto_ssl
    puerto_ssl=$(_pedir_puerto_ssl "$puerto_ssl_previo" "$puerto_http")

    generar_certificado "apache" "www.$DOMINIO" || return 1

    local sysconf="/etc/sysconfig/apache2"
    if [[ -f "$sysconf" ]]; then
        for mod in ssl socache_shmcb rewrite headers; do
            if ! grep -E "(^| )${mod}( |$)" "$sysconf" &>/dev/null; then
                sed -i "s/^APACHE_MODULES=\"/APACHE_MODULES=\"${mod} /" "$sysconf"
                echo "  Módulo '$mod' habilitado."
            fi
        done
    fi

    local listen_conf="/etc/apache2/listen.conf"
    if [[ -f "$listen_conf" ]]; then
        sed -i '/# SSL Practica7/d' "$listen_conf"
        sed -i "/^Listen ${puerto_ssl_previo}$/d" "$listen_conf"
        if ! grep -q "^Listen ${puerto_ssl}$" "$listen_conf"; then
            echo ""                       >> "$listen_conf"
            echo "# SSL Practica7"       >> "$listen_conf"
            echo "Listen ${puerto_ssl}"  >> "$listen_conf"
            echo "  listen.conf: Listen $puerto_ssl agregado."
        fi
    fi

    rm -f /etc/apache2/vhosts.d/pract7_http.conf
    rm -f /etc/apache2/vhosts.d/pract7_https.conf

    cat > /etc/apache2/vhosts.d/pract7_http.conf <<VHHTTP
<VirtualHost *:${puerto_http}>
    ServerName www.${DOMINIO}
    DocumentRoot /var/www/html/apache

    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}:${puerto_ssl}%{REQUEST_URI} [R=301,L]
</VirtualHost>
VHHTTP

    cat > /etc/apache2/vhosts.d/pract7_https.conf <<VHHTTPS
<VirtualHost *:${puerto_ssl}>
    ServerName www.${DOMINIO}
    DocumentRoot /var/www/html/apache

    SSLEngine on
    SSLCertificateFile    ${SSL_CERT}
    SSLCertificateKeyFile ${SSL_KEY}

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES

    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set X-Content-Type-Options "nosniff"
    </IfModule>

    <Directory /var/www/html/apache>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    ErrorLog  /var/log/apache2/ssl_error.log
    CustomLog /var/log/apache2/ssl_access.log combined
</VirtualHost>
VHHTTPS

    echo "  HTTP $puerto_http → redirige a HTTPS $puerto_ssl"

    ssl_firewall_abrir "$puerto_ssl"
    mkdir -p /etc/pract7
    { echo "SSL=ACTIVO"; echo "PUERTO_SSL=${puerto_ssl}"; echo "CERT=${SSL_CERT}"; echo "KEY=${SSL_KEY}"; } > "$ESTADO_SSL_APACHE"

    if systemctl restart apache2 2>/dev/null; then
        echo "  ✓ Apache2 reiniciado en puerto SSL $puerto_ssl."
    else
        echo "  ✗ Error al reiniciar Apache2."
        journalctl -u apache2 -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
        return 1
    fi

    sleep 2
    verificar_ssl_puerto "localhost" "$puerto_ssl" "https"
}

# SSL NGINX
configurar_ssl_nginx() {
    titulo "SSL/TLS — Nginx"

    if ! rpm -q nginx &>/dev/null; then
        echo "  ERROR: Nginx no está instalado."
        return 1
    fi

    local puerto_http
    puerto_http=$(_leer_puerto_http "$ESTADO_NGINX" 80)
    local puerto_ssl_previo
    puerto_ssl_previo=$(_leer_puerto_ssl "$ESTADO_SSL_NGINX" 443)

    echo "  Puerto HTTP actual : $puerto_http"
    echo "  Puerto SSL previo  : $puerto_ssl_previo"
    echo ""
    echo "  Defina el puerto HTTPS para Nginx:"
    local puerto_ssl
    puerto_ssl=$(_pedir_puerto_ssl "$puerto_ssl_previo" "$puerto_http")

    generar_certificado "nginx" "www.$DOMINIO" || return 1

    cat > /etc/nginx/nginx.conf <<NGSSL
user nginx;
worker_processes auto;
pid /run/nginx.pid;

events { worker_connections 1024; }

http {
    server_tokens off;
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    keepalive_timeout 65;

    server {
        listen      ${puerto_http};
        server_name www.${DOMINIO} localhost;
        return 301 https://\$host:${puerto_ssl}\$request_uri;
    }

    server {
        listen      ${puerto_ssl} ssl;
        server_name www.${DOMINIO} localhost;
        root        /var/www/html/nginx;
        index       index.html;

        ssl_certificate     ${SSL_CERT};
        ssl_certificate_key ${SSL_KEY};
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5:!3DES;
        ssl_prefer_server_ciphers on;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Frame-Options        "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff"    always;

        location / { try_files \$uri \$uri/ =404; }
    }
}
NGSSL

    echo "  HTTP $puerto_http → redirige a HTTPS $puerto_ssl"

    ssl_firewall_abrir "$puerto_ssl"
    mkdir -p /etc/pract7
    { echo "SSL=ACTIVO"; echo "PUERTO_SSL=${puerto_ssl}"; echo "CERT=${SSL_CERT}"; echo "KEY=${SSL_KEY}"; } > "$ESTADO_SSL_NGINX"

    if systemctl restart nginx 2>/dev/null; then
        echo " Nginx reiniciado en puerto SSL $puerto_ssl."
    else
        echo " Error al reiniciar Nginx."
        journalctl -u nginx -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
        return 1
    fi

    sleep 2
    verificar_ssl_puerto "localhost" "$puerto_ssl" "https"
}

# SSL TOMCAT
configurar_ssl_tomcat() {
    titulo "SSL/TLS — Tomcat"

    if ! rpm -q tomcat &>/dev/null; then
        echo "  ERROR: Tomcat no está instalado."
        return 1
    fi

    local puerto_http
    puerto_http=$(_leer_puerto_http "$ESTADO_TOMCAT" 8080)
    local puerto_ssl_previo
    puerto_ssl_previo=$(_leer_puerto_ssl "$ESTADO_SSL_TOMCAT" 8443)

    echo "  Puerto HTTP actual : $puerto_http"
    echo "  Puerto SSL previo  : $puerto_ssl_previo"
    echo ""
    echo "  Defina el puerto HTTPS para Tomcat:"
    local puerto_ssl
    puerto_ssl=$(_pedir_puerto_ssl "$puerto_ssl_previo" "$puerto_http")

    generar_certificado "tomcat" "www.$DOMINIO" || return 1

    local cert_dir="$SSL_BASE_DIR/tomcat"
    local p12_file="$cert_dir/keystore.p12"
    local p12_pass="reprobados2024"

    echo "  Convirtiendo a PKCS12..."
    openssl pkcs12 -export \
        -in "$SSL_CERT" -inkey "$SSL_KEY" \
        -out "$p12_file" -name "tomcat" \
        -passout "pass:${p12_pass}" 2>/dev/null

    if [[ $? -ne 0 ]]; then
        openssl pkcs12 -export -legacy \
            -in "$SSL_CERT" -inkey "$SSL_KEY" \
            -out "$p12_file" -name "tomcat" \
            -passout "pass:${p12_pass}" 2>/dev/null
    fi

    if [[ ! -s "$p12_file" ]]; then
        echo "  ✗ No se pudo generar keystore PKCS12."
        return 1
    fi
    echo " Keystore: $p12_file"

    local sxml="/etc/tomcat/server.xml"
    [[ ! -f "$sxml" ]] && echo "  ERROR: server.xml no existe." && return 1

    cp "$sxml" "${sxml}.bak7"
    sed -i '/<!-- SSL_P7_START -->/,/<!-- SSL_P7_END -->/d' "$sxml"

    sed -i "s|</Service>|    <!-- SSL_P7_START -->\n\
    <Connector port=\"${puerto_ssl}\"\n\
               protocol=\"org.apache.coyote.http11.Http11NioProtocol\"\n\
               SSLEnabled=\"true\" maxThreads=\"150\"\n\
               scheme=\"https\" secure=\"true\"\n\
               keystoreFile=\"${p12_file}\"\n\
               keystorePass=\"${p12_pass}\" keystoreType=\"PKCS12\"\n\
               clientAuth=\"false\" sslProtocol=\"TLS\"\n\
               sslEnabledProtocols=\"TLSv1.2,TLSv1.3\" />\n\
    <!-- SSL_P7_END -->\n\
</Service>|" "$sxml"

    sed -i "s/redirectPort=\"[0-9]*\"/redirectPort=\"${puerto_ssl}\"/g" "$sxml"
    echo "  server.xml: conector HTTPS en puerto $puerto_ssl."

    ssl_firewall_abrir "$puerto_ssl"
    mkdir -p /etc/pract7
    { echo "SSL=ACTIVO"; echo "PUERTO_SSL=${puerto_ssl}"; echo "CERT=${SSL_CERT}"; echo "KEY=${SSL_KEY}"; echo "P12=${p12_file}"; } > "$ESTADO_SSL_TOMCAT"

    if systemctl restart tomcat 2>/dev/null; then
        echo " Tomcat reiniciado."
    else
        echo " Error al reiniciar Tomcat."
        journalctl -u tomcat -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
        return 1
    fi

    echo "  Esperando que Tomcat arranque (15s)..."
    sleep 15
    verificar_ssl_puerto "localhost" "$puerto_ssl" "https"
}

# MENÚ SSL HTTP
menu_ssl_http() {
    titulo "Activar SSL/TLS — Servidores HTTP"

    for srv_info in "apache2:Apache" "nginx:Nginx" "tomcat:Tomcat"; do
        local pkg;    pkg=$(echo    "$srv_info" | cut -d: -f1)
        local nombre; nombre=$(echo "$srv_info" | cut -d: -f2)

        if rpm -q "$pkg" &>/dev/null; then
            echo ""
            printf "  Servicio instalado: %-10s" "$nombre"
            read -rp "  ¿Activar SSL? [S/N]: " resp
            if [[ "$resp" =~ ^[sS]$ ]]; then
                case "$pkg" in
                    apache2) configurar_ssl_apache ;;
                    nginx)   configurar_ssl_nginx  ;;
                    tomcat)  configurar_ssl_tomcat ;;
                esac
            else
                echo "  SSL omitido para $nombre."
            fi
        fi
    done
}