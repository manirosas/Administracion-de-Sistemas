#!/bin/bash
# MAIN.SH — Orquestador Práctica 7
# Uso: sudo bash main.sh

[ "$EUID" -ne 0 ] && echo "Ejecute como root: sudo bash main.sh" && exit 1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PASO 0: Importar módulos EN ORDEN CORRECTO
# ssl_utils.sh PRIMERO porque define titulo(), linea(), pausar()
# y las variables SSL_BASE_DIR, DOMINIO que todos usan
_importar_modulos() {
    # Orden estricto: utils → cliente ftp → http ssl → ftp ssl
    local orden=("ssl_utils.sh" "ftp_client.sh" "http_ssl.sh" "ftp_ssl.sh")

    for mod in "${orden[@]}"; do
        local ruta="$SCRIPT_DIR/$mod"
        if [[ ! -f "$ruta" ]]; then
            echo ""
            echo "  ERROR: Módulo faltante: $ruta"
            echo ""
            echo "  Asegúrese de que estos archivos estén juntos en $SCRIPT_DIR:"
            for m in "${orden[@]}"; do
                echo "    - $m"
            done
            echo ""
            exit 1
        fi
        # shellcheck source=/dev/null
        source "$ruta"
    done
}

_importar_modulos

_verificar_entorno_base() {
    local faltantes=()

    # Herramientas mínimas necesarias
    command -v openssl   &>/dev/null || faltantes+=("openssl")
    command -v curl      &>/dev/null || faltantes+=("curl")
    command -v sha256sum &>/dev/null || faltantes+=("coreutils")
    command -v ss        &>/dev/null || faltantes+=("iproute2")
    command -v rpm       &>/dev/null || true   # siempre disponible en OpenSUSE

    if [[ ${#faltantes[@]} -gt 0 ]]; then
        echo ""
        echo "  Instalando herramientas base: ${faltantes[*]}"
        zypper refresh &>/dev/null
        zypper install -y "${faltantes[@]}" 2>&1 | tail -3
    fi
}

_verificar_entorno_base

# práctica 6 — reutilizado
ESTADO_DIR="/etc/pract6"
mkdir -p "$ESTADO_DIR"
ESTADO_APACHE="${ESTADO_DIR}/apache.conf"
ESTADO_NGINX="${ESTADO_DIR}/nginx.conf"
ESTADO_TOMCAT="${ESTADO_DIR}/tomcat.conf"
[[ -f "$ESTADO_APACHE" ]] || echo "PUERTO=80"   > "$ESTADO_APACHE"
[[ -f "$ESTADO_NGINX"  ]] || echo "PUERTO=80"   > "$ESTADO_NGINX"
[[ -f "$ESTADO_TOMCAT" ]] || echo "PUERTO=8080" > "$ESTADO_TOMCAT"

# UTILIDADES LOCALES
# (titulo/linea/pausar ya definidos en ssl_utils.sh)
_estado_systemd() {
    systemctl is-active "$1" 2>/dev/null || echo "inactivo"
}

_leer_puerto() {
    local archivo=$1 defecto=$2
    grep -oP '(?<=PUERTO=)\d+' "$archivo" 2>/dev/null || echo "$defecto"
}

_puerto_en_uso() {
    ss -tlnp 2>/dev/null | grep -q ":${1}[[:space:]]"
}

_validar_puerto_simple() {
    local p="$1"
    # Solo verifica rango y que sea número; 443 es PERMITIDO en práctica 7
    [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

# CONFIGURACIONES POST-INSTALACIÓN
# Se llaman después de instalar por cualquier origen (WEB o FTP)
_post_apache() {
    local puerto="$1"
    local ver; ver=$(rpm -q --queryformat '%{VERSION}' apache2 2>/dev/null || echo "?")

    # security.conf
    mkdir -p /etc/apache2/conf.d
    cat > /etc/apache2/conf.d/security.conf <<'EOF'
ServerTokens Prod
ServerSignature Off
EOF

    # Módulos (ssl incluido para que SSL funcione después)
    local sysconf="/etc/sysconfig/apache2"
    if [[ -f "$sysconf" ]]; then
        for mod in ssl socache_shmcb rewrite headers; do
            if ! grep -E "(^| )${mod}( |$)" "$sysconf" &>/dev/null; then
                sed -i "s/^APACHE_MODULES=\"/APACHE_MODULES=\"${mod} /" "$sysconf"
            fi
        done
    fi

    # Puerto de escucha
    if [[ -f /etc/apache2/listen.conf ]]; then
        sed -i "s/^Listen .*/Listen ${puerto}/" /etc/apache2/listen.conf
    fi

    # DocumentRoot
    mkdir -p /var/www/html/apache
    cat > /etc/apache2/vhosts.d/pract7.conf <<VHEOF
<VirtualHost *:${puerto}>
    DocumentRoot /var/www/html/apache
    ServerName
    <Directory /var/www/html/apache>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
VHEOF

    cat > /var/www/html/apache/index.html <<HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Apache2 - Práctica 7</title></head>
<body>
  <h1>Apache2</h1>
  <p>Versión: ${ver} | Puerto: ${puerto} | Sistema: OpenSUSE Leap</p>
</body>
</html>
HTMLEOF

    echo "PUERTO=$puerto" > "$ESTADO_APACHE"
    systemctl enable apache2 &>/dev/null
    if systemctl restart apache2 2>/dev/null; then
        echo " Apache2 activo en puerto $puerto."
    else
        echo " Apache2 no inició. Revise: journalctl -u apache2 -n 20"
    fi
}

_post_nginx() {
    local puerto="$1"
    local ver; ver=$(rpm -q --queryformat '%{VERSION}' nginx 2>/dev/null || echo "?")

    mkdir -p /var/www/html/nginx
    cat > /etc/nginx/nginx.conf <<NGEOF
user nginx;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 1024; }
http {
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server {
        listen ${puerto};
        server_name localhost;
        root /var/www/html/nginx;
        index index.html;
        location / { try_files \$uri \$uri/ =404; }
        location ~ /\. { deny all; }
    }
}
NGEOF

    cat > /var/www/html/nginx/index.html <<HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Nginx - Práctica 7</title></head>
<body>
  <h1>Nginx</h1>
  <p>Versión: ${ver} | Puerto: ${puerto} | Sistema: OpenSUSE Leap</p>
</body>
</html>
HTMLEOF

    chown -R nginx:nginx /var/www/html/nginx 2>/dev/null
    echo "PUERTO=$puerto" > "$ESTADO_NGINX"
    systemctl enable nginx &>/dev/null
    if systemctl restart nginx 2>/dev/null; then
        echo " Nginx activo en puerto $puerto."
    else
        echo " Nginx no inició. Revise: journalctl -u nginx -n 20"
    fi
}

_post_tomcat() {
    local puerto="$1"
    local ver; ver=$(rpm -q --queryformat '%{VERSION}' tomcat 2>/dev/null || echo "?")

    mkdir -p /srv/tomcat/webapps/ROOT
    cat > /srv/tomcat/webapps/ROOT/index.html <<HTMLEOF
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Tomcat - Práctica 7</title></head>
<body>
  <h1>Tomcat</h1>
  <p>Versión: ${ver} | Puerto: ${puerto} | Sistema: OpenSUSE Leap</p>
</body>
</html>
HTMLEOF

    local sxml="/etc/tomcat/server.xml"
    if [[ -f "$sxml" ]]; then
        sed -i "s/port=\"8080\"/port=\"${puerto}\"/" "$sxml"
    fi

    chown -R tomcat:tomcat /srv/tomcat/webapps/ROOT 2>/dev/null
    echo "PUERTO=$puerto" > "$ESTADO_TOMCAT"
    systemctl enable tomcat &>/dev/null
    if systemctl restart tomcat 2>/dev/null; then
        echo " Tomcat activo en puerto $puerto."
    else
        echo " Tomcat no inició. Revise: journalctl -u tomcat -n 20"
    fi
}

_abrir_puerto_firewall() {
    local p="$1"
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-port="${p}/tcp" &>/dev/null
        firewall-cmd --reload &>/dev/null
        echo "  Firewall: puerto $p/tcp abierto."
    fi
}

# INSTALACIÓN HÍBRIDA
instalar_servicio_hibrido() {
    local servicio="$1"    # Apache | Nginx | Tomcat
    local paquete="$2"     # apache2 | nginx | tomcat
    local puerto_def="$3"  # 80 | 8080
    local estado_f="$4"    # archivo de estado

    titulo "Instalación — $servicio"

    # instalado?
    if rpm -q "$paquete" &>/dev/null; then
        local ver_actual; ver_actual=$(rpm -q --queryformat '%{VERSION}' "$paquete")
        echo "  $servicio ya instalado (versión $ver_actual)."
        read -rp "  ¿Reconfigurar? [s/N]: " resp
        [[ ! "$resp" =~ ^[sS]$ ]] && return 0
    fi

    # Elegir origen de instalación 
    echo ""
    echo "  Origen de instalación:"
    echo "  1) WEB  — repositorio oficial de zypper"
    echo "  2) FTP  — repositorio privado (Práctica 5)"
    read -rp "  Opción [1/2]: " origen

    case "$origen" in
        1)
            # WEB 
            echo ""
            echo "  Consultando versiones en zypper..."
            local versiones
            versiones=$(zypper search -s "$paquete" 2>/dev/null \
                | awk -F'|' 'NR>2 {gsub(/ /,"",$4);
                    if($4!="" && $4!="Version") print $4}' \
                | sort -Vr | uniq | head -10)

            local lista_v=()
            local i=1
            while IFS= read -r v; do
                [[ -z "$v" ]] && continue
                lista_v+=("$v")
                printf "    %2d) %s\n" "$i" "$v"
                (( i++ ))
            done <<< "$versiones"
            printf "    %2d) Versión por defecto\n" "$i"
            local total_v=$i

            read -rp "  Versión [1-$total_v]: " sel_v
            sel_v="${sel_v:-$total_v}"

            local version_elegida="default"
            if [[ "$sel_v" =~ ^[0-9]+$ ]] && \
               (( sel_v >= 1 && sel_v < total_v )); then
                version_elegida="${lista_v[$((sel_v-1))]}"
            fi

            echo "  Instalando $paquete ($version_elegida)..."
            if [[ "$version_elegida" == "default" ]]; then
                zypper install -y "$paquete" 2>&1 | tail -5
            else
                zypper install -y "${paquete}=${version_elegida}" 2>/dev/null \
                    || zypper install -y "$paquete" 2>&1 | tail -5
            fi
            ;;

        2)
            # FTP
            echo ""
            if [[ -z "${FTP_HOST:-}" ]]; then
                configurar_ftp_origen || return 1
            else
                echo "  FTP configurado: $FTP_HOST"
                read -rp "  ¿Cambiar servidor? [s/N]: " cambiar
                [[ "$cambiar" =~ ^[sS]$ ]] && { configurar_ftp_origen || return 1; }
            fi

            ftp_seleccionar_e_instalar "$servicio" || return 1
            instalar_rpm_ftp "$ARCHIVO_DESCARGADO"  || return 1
            ;;

        *)
            echo "  Opción inválida."
            return 1
            ;;
    esac

    # ── Puerto post-instalación ────────────────────────────────────
    echo ""
    local puerto_actual; puerto_actual=$(_leer_puerto "$estado_f" "$puerto_def")
    read -rp "  Puerto de escucha [$puerto_actual]: " nuevo_p
    nuevo_p="${nuevo_p:-$puerto_actual}"

    if ! _validar_puerto_simple "$nuevo_p"; then
        echo "  Puerto inválido. Usando $puerto_actual."
        nuevo_p="$puerto_actual"
    fi

    if _puerto_en_uso "$nuevo_p" && [[ "$nuevo_p" != "$puerto_actual" ]]; then
        echo "  AVISO: el puerto $nuevo_p está en uso. Continuando de todas formas."
    fi

    # Configuración post-instalación
    case "$paquete" in
        apache2) _post_apache "$nuevo_p" ;;
        nginx)   _post_nginx  "$nuevo_p" ;;
        tomcat)  _post_tomcat "$nuevo_p" ;;
    esac

    _abrir_puerto_firewall "$nuevo_p"

    # ── SSL opcional ───────────────────────────────────────────────
    echo ""
    read -rp "  ¿Activar SSL en $servicio? [S/N]: " ssl_resp
    if [[ "$ssl_resp" =~ ^[sS]$ ]]; then
        case "$paquete" in
            apache2) configurar_ssl_apache ;;
            nginx)   configurar_ssl_nginx  ;;
            tomcat)  configurar_ssl_tomcat ;;
        esac
    fi

    echo ""
    echo "  $servicio listo."
    pausar
}

# =================================================================
# VERIFICACIÓN COMPLETA
# =================================================================
verificacion_completa() {
    titulo "Verificación Completa — Práctica 7"

    # ── Tabla de servicios ─────────────────────────────────────────
    echo ""
    printf "  %-14s %-12s %-8s %-15s\n" "SERVICIO" "ESTADO" "PUERTO" "VERSION"
    linea
    for info in \
        "Apache:apache2:$(_leer_puerto "$ESTADO_APACHE" 80)" \
        "Nginx:nginx:$(_leer_puerto "$ESTADO_NGINX" 80)"     \
        "Tomcat:tomcat:$(_leer_puerto "$ESTADO_TOMCAT" 8080)"\
        "vsftpd:vsftpd:21"; do

        local nom; nom=$(echo "$info" | cut -d: -f1)
        local pkg; pkg=$(echo "$info" | cut -d: -f2)
        local prt; prt=$(echo "$info" | cut -d: -f3)
        local est; est=$(_estado_systemd "$pkg")
        local ver; ver=$(rpm -q --queryformat '%{VERSION}' "$pkg" 2>/dev/null || echo "N/I")
        printf "  %-14s %-12s %-8s %-15s\n" "$nom" "$est" "$prt" "$ver"
    done

    # ── Tabla SSL ─────────────────────────────────────────────────
    echo ""
    linea
    echo "  VERIFICACIÓN SSL/TLS"
    linea
    printf "  %-16s %-8s %-14s %-14s\n" \
        "SERVICIO" "PUERTO" "CERTIFICADO" "SSL ACTIVO"
    echo "  ──────────────────────────────────────────────────────"

    # Leer puertos SSL desde archivos de estado (configurables por usuario)
    local pssl_apache; pssl_apache=$(grep -oP "(?<=PUERTO_SSL=)\d+" /etc/pract7/apache_ssl.conf 2>/dev/null || echo "443")
    local pssl_nginx;  pssl_nginx=$(grep  -oP "(?<=PUERTO_SSL=)\d+" /etc/pract7/nginx_ssl.conf  2>/dev/null || echo "443")
    local pssl_tomcat; pssl_tomcat=$(grep -oP "(?<=PUERTO_SSL=)\d+" /etc/pract7/tomcat_ssl.conf 2>/dev/null || echo "8443")

    for info in "Apache:${pssl_apache}:https:apache" \
                "Nginx:${pssl_nginx}:https:nginx"     \
                "Tomcat:${pssl_tomcat}:https:tomcat"  \
                "vsftpd FTPS:21:ftp:vsftpd"; do
        local nom; nom=$(echo  "$info" | cut -d: -f1)
        local prt; prt=$(echo  "$info" | cut -d: -f2)
        local proto; proto=$(echo "$info" | cut -d: -f3)
        local srv; srv=$(echo  "$info" | cut -d: -f4)

        local cert_ok="NO"
        [[ -f "$SSL_BASE_DIR/$srv/cert.pem" ]] && cert_ok="SÍ ✓"

        local ssl_ok="INACTIVO"
        if [[ "$proto" == "ftp" ]]; then
            timeout 8 openssl s_client -connect "localhost:${prt}" \
                -starttls ftp </dev/null 2>/dev/null \
                | grep -q "CONNECTED" && ssl_ok="ACTIVO ✓"
        else
            timeout 6 openssl s_client -connect "localhost:${prt}" \
                </dev/null 2>/dev/null \
                | grep -q "CONNECTED" && ssl_ok="ACTIVO ✓"
        fi

        printf "  %-16s %-8s %-14s %-14s\n" "$nom" "$prt" "$cert_ok" "$ssl_ok"
    done

    # ── Verificar redirecciones HTTP→HTTPS ───────────────────────
    echo ""
    linea
    echo "  REDIRECCIÓN HTTP → HTTPS"
    linea
    for info in \
        "Apache:$(_leer_puerto "$ESTADO_APACHE" 80)" \
        "Nginx:$(_leer_puerto "$ESTADO_NGINX" 80)"; do
        local nom; nom=$(echo "$info" | cut -d: -f1)
        local prt; prt=$(echo "$info" | cut -d: -f2)

        local resultado
        resultado=$(curl --silent \
            --max-time 5 \
            --write-out "%{http_code}" \
            --output /dev/null \
            "http://localhost:${prt}/" 2>/dev/null)

        if [[ "$resultado" =~ ^30[12]$ ]]; then
            echo "  ✓ $nom: código $resultado (redirige a HTTPS)"
        else
            echo "  ✗ $nom: código $resultado (sin redirección en puerto $prt)"
        fi
    done

    # ── Certificados ─────────────────────────────────────────────
    echo ""
    linea
    echo "  CERTIFICADOS SSL GENERADOS"
    linea
    for srv in apache nginx tomcat vsftpd; do
        local cert="$SSL_BASE_DIR/$srv/cert.pem"
        if [[ -f "$cert" ]]; then
            local cn;    cn=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null \
                | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1)
            local expiry; expiry=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null \
                | cut -d= -f2)
            printf "  %-10s CN=%-30s Exp: %s\n" "$srv" "$cn" "$expiry"
        else
            printf "  %-10s Sin certificado.\n" "$srv"
        fi
    done

    echo ""
    echo "  Verificación completada."
    pausar
}

# =================================================================
# MENÚ PRINCIPAL
# =================================================================
menu_principal() {
    while true; do
        clear
        echo ""
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║        PRÁCTICA 7 — Infraestructura SSL/TLS              ║"
        echo "║        OpenSUSE Leap — reprobados.com                    ║"
        echo "╠══════════════════════════════════════════════════════════╣"
        printf "║  Apache %-10s Puerto:%-6s Nginx %-10s Puerto:%-4s║\n" \
            "$(_estado_systemd apache2)" \
            "$(_leer_puerto "$ESTADO_APACHE" 80)" \
            "$(_estado_systemd nginx)" \
            "$(_leer_puerto "$ESTADO_NGINX" 80)"
        printf "║  Tomcat %-10s Puerto:%-6s vsftpd %-9s Puerto:%-4s║\n" \
            "$(_estado_systemd tomcat)" \
            "$(_leer_puerto "$ESTADO_TOMCAT" 8080)" \
            "$(_estado_systemd vsftpd)" "21"
        echo "╠══════════════════════════════════════════════════════════╣"
        echo "║  1) Instalar servicio HTTP (WEB o FTP)                   ║"
        echo "║  2) Activar SSL/TLS (servicios ya instalados)            ║"
        echo "║  3) Verificación completa del entorno                    ║"
        echo "║  4) Preparar repositorio FTP (setup_repo.sh)             ║"
        echo "║  5) Ver certificados SSL                                 ║"
        echo "║  0) Salir                                                ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo ""
        read -rp "  Opción: " op

        case "$op" in
            1)
                echo ""
                echo "  Servicio a instalar:"
                echo "  1) Apache2   2) Nginx   3) Tomcat"
                read -rp "  Opción: " srv_op
                case "$srv_op" in
                    1) instalar_servicio_hibrido "Apache" "apache2" "80"   "$ESTADO_APACHE" ;;
                    2) instalar_servicio_hibrido "Nginx"  "nginx"   "80"   "$ESTADO_NGINX"  ;;
                    3) instalar_servicio_hibrido "Tomcat" "tomcat"  "8080" "$ESTADO_TOMCAT" ;;
                    *) echo "  Opción inválida." ;;
                esac
                ;;
            2)
                echo ""
                echo "  SSL en qué servicio:"
                echo "  1) Apache2  2) Nginx  3) Tomcat  4) vsftpd  5) Todos"
                read -rp "  Opción: " ssl_op
                case "$ssl_op" in
                    1) configurar_ssl_apache  ;;
                    2) configurar_ssl_nginx   ;;
                    3) configurar_ssl_tomcat  ;;
                    4) configurar_ssl_vsftpd  ;;
                    5)
                        menu_ssl_http
                        echo ""
                        read -rp "  ¿Activar FTPS en vsftpd? [S/N]: " r
                        [[ "$r" =~ ^[sS]$ ]] && configurar_ssl_vsftpd
                        ;;
                    *) echo "  Opción inválida." ;;
                esac
                pausar
                ;;
            3) verificacion_completa ;;
            4) bash "$SCRIPT_DIR/setup_repo.sh" ;;
            5)
                titulo "Certificados SSL"
                for srv in apache nginx tomcat vsftpd; do
                    info_certificado "$srv"
                done
                pausar
                ;;
            0) echo ""; echo "  Saliendo."; echo ""; exit 0 ;;
            *) echo "  Opción inválida." ;;
        esac
    done
}

menu_principal