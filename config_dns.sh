#!/bin/bash


# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';      DIM='\033[2m';       NC='\033[0m'

# ── Variables de entorno ──────────────────────────────────────────────────────
IFACE="enp0s8"                                    # Interfaz de red fija
BIND_CONF="/etc/named.conf"                       # Config principal BIND9
NAMED_D="/etc/named.d"                            # Directorio includes
ZONES_FILE="${NAMED_D}/zonas_locales.conf"        # Archivo de zonas personalizadas
ZONES_DIR="/var/lib/named/master"                 # Archivos de zona
LOG_FILE="/var/log/dns_manager.log"               # Log del script
DNS_SERVICE="named"                               # Nombre del servicio
DNS_SERVER_IP=""                                  # Se detecta dinámicamente

# ── Helpers de mensaje ────────────────────────────────────────────────────────
msg_ok()   { echo -e "${GREEN}  ✔  $*${NC}";   log "OK: $*"; }
msg_err()  { echo -e "${RED}  ✘  $*${NC}";    log "ERR: $*"; }
msg_warn() { echo -e "${YELLOW}  ⚠  $*${NC}"; log "WARN: $*"; }
msg_info() { echo -e "${CYAN}  ➜  $*${NC}";   log "INFO: $*"; }

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null; }

titulo() {
    local linea="════════════════════════════════════════════════"
    echo -e "\n${BOLD}${BLUE}${linea}${NC}"
    echo -e "${BOLD}${BLUE}   $*${NC}"
    echo -e "${BOLD}${BLUE}${linea}${NC}\n"
}

subtitulo() { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }

pausar() { echo -e "\n${DIM}Presiona ENTER para continuar...${NC}"; read -r; }

separador() { echo -e "${DIM}────────────────────────────────────────────────${NC}"; }

# ── Verificar root ────────────────────────────────────────────────────────────
verificar_root() {
    [[ $EUID -ne 0 ]] && { msg_err "Ejecuta como root: sudo $0"; exit 1; }
}

# =============================================================================
#  MÓDULO 1 ── GESTIÓN DE IP ESTÁTICA
# =============================================================================

obtener_ip_actual() {
    ip addr show "$IFACE" 2>/dev/null \
        | grep 'inet ' \
        | awk '{print $2}' \
        | cut -d'/' -f1 \
        | head -1
}

obtener_prefijo_actual() {
    ip addr show "$IFACE" 2>/dev/null \
        | grep 'inet ' \
        | awk '{print $2}' \
        | cut -d'/' -f2 \
        | head -1
}

obtener_gateway() {
    ip route | grep "^default.*$IFACE" | awk '{print $3}' | head -1 \
    || ip route | grep '^default' | awk '{print $3}' | head -1
}

verificar_ip_estatica() {
    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"
    if [[ -f "$cfg" ]]; then
        grep -qi "BOOTPROTO=.static." "$cfg" && return 0
    fi
    # Verificar con NetworkManager
    if command -v nmcli &>/dev/null; then
        nmcli -g IP4.METHOD con show --active 2>/dev/null \
            | grep -qi "manual" && return 0
    fi
    return 1
}

modulo_ip_fija() {
    titulo "Verificación / Configuración de IP Estática"
    subtitulo "Interfaz de red: ${BOLD}$IFACE${NC}"

    # Verificar existencia de la interfaz
    if ! ip link show "$IFACE" &>/dev/null; then
        msg_err "La interfaz '$IFACE' no existe en este sistema."
        msg_info "Interfaces disponibles:"
        ip link show | grep '^[0-9]' | awk -F': ' '{print "  •  " $2}'
        pausar; return 1
    fi

    local ip_actual prefijo gw
    ip_actual=$(obtener_ip_actual)
    prefijo=$(obtener_prefijo_actual)
    gw=$(obtener_gateway)

    echo -e "  IP actual   : ${BOLD}${ip_actual:-'Sin IP asignada'}${NC}"
    echo -e "  Prefijo     : ${BOLD}${prefijo:-'?'}${NC}"
    echo -e "  Gateway     : ${BOLD}${gw:-'?'}${NC}"
    separador

    if verificar_ip_estatica; then
        msg_ok "La interfaz $IFACE ya tiene IP estática configurada."
        DNS_SERVER_IP="$ip_actual"
        echo -e "  IP del servidor DNS: ${GREEN}${BOLD}$DNS_SERVER_IP${NC}"
        pausar; return 0
    fi

    msg_warn "La interfaz $IFACE usa DHCP o no tiene IP estática."
    echo ""
    read -rp "  ¿Configurar IP estática ahora? (s/n): " resp
    [[ ! "$resp" =~ ^[Ss]$ ]] && {
        msg_warn "Se usará la IP dinámica actual: ${ip_actual:-'ninguna'}"
        DNS_SERVER_IP="${ip_actual:-'127.0.0.1'}"
        pausar; return 0
    }

    _solicitar_y_aplicar_ip "$ip_actual" "$prefijo" "$gw"
}

_solicitar_y_aplicar_ip() {
    local ip_sug="$1" pfx_sug="$2" gw_sug="$3"
    local nueva_ip nuevo_pfx nuevo_gw nuevo_dns_ext

    echo ""
    subtitulo "Ingresa los nuevos datos de red"

    # ── IP ──
    while true; do
        read -rp "  Nueva IP [${ip_sug:-192.168.1.10}]: " nueva_ip
        nueva_ip="${nueva_ip:-${ip_sug:-192.168.1.10}}"
        _validar_ip "$nueva_ip" && break
        msg_err "  IP inválida. Formato: xxx.xxx.xxx.xxx  Ej: 192.168.1.10"
    done

    # ── Prefijo ──
    while true; do
        read -rp "  Prefijo CIDR [${pfx_sug:-24}]: " nuevo_pfx
        nuevo_pfx="${nuevo_pfx:-${pfx_sug:-24}}"
        [[ "$nuevo_pfx" =~ ^[0-9]+$ ]] && (( nuevo_pfx >= 8 && nuevo_pfx <= 30 )) && break
        msg_err "  Prefijo inválido. Rango válido: 8-30  Ej: 24"
    done

    # ── Gateway ──
    while true; do
        read -rp "  Gateway [${gw_sug:-192.168.1.1}]: " nuevo_gw
        nuevo_gw="${nuevo_gw:-${gw_sug:-192.168.1.1}}"
        _validar_ip "$nuevo_gw" && break
        msg_err "  Gateway inválido."
    done

    # ── DNS externo ──
    while true; do
        read -rp "  DNS externo secundario [8.8.8.8]: " nuevo_dns_ext
        nuevo_dns_ext="${nuevo_dns_ext:-8.8.8.8}"
        _validar_ip "$nuevo_dns_ext" && break
        msg_err "  DNS externo inválido."
    done

    echo ""
    echo -e "  ${YELLOW}Resumen de configuración:${NC}"
    echo -e "  ┌─────────────────────────────────┐"
    echo -e "  │  IP       : ${BOLD}$nueva_ip/$nuevo_pfx${NC}"
    echo -e "  │  Gateway  : ${BOLD}$nuevo_gw${NC}"
    echo -e "  │  DNS ext  : ${BOLD}$nuevo_dns_ext${NC}"
    echo -e "  └─────────────────────────────────┘"
    read -rp "  ¿Aplicar? (s/n): " ok
    [[ ! "$ok" =~ ^[Ss]$ ]] && { msg_info "Cancelado."; return; }

    local cfg="/etc/sysconfig/network/ifcfg-${IFACE}"

    # Backup
    [[ -f "$cfg" ]] && cp "$cfg" "${cfg}.bak_$(date +%Y%m%d%H%M%S)"

    cat > "$cfg" <<EOF
# Configurado por dns_manager_opensuse.sh - $(date)
BOOTPROTO='static'
STARTMODE='auto'
IPADDR='${nueva_ip}'
PREFIXLEN='${nuevo_pfx}'
EOF

    # Gateway
    echo "default ${nuevo_gw} - -" > /etc/sysconfig/network/routes

    # resolv.conf
    cat > /etc/resolv.conf <<EOF
# Generado por dns_manager_opensuse.sh
nameserver 127.0.0.1
nameserver ${nuevo_dns_ext}
EOF
    # Proteger resolv.conf de sobreescritura por DHCP
    chattr +i /etc/resolv.conf 2>/dev/null || true

    msg_info "Aplicando configuración de red con wicked..."
    if systemctl is-active wicked &>/dev/null; then
        wicked ifdown "$IFACE" &>/dev/null
        sleep 1
        wicked ifup "$IFACE" &>/dev/null
        sleep 3
    elif command -v nmcli &>/dev/null; then
        nmcli connection reload
        nmcli connection up "$IFACE" &>/dev/null
        sleep 2
    else
        ip addr flush dev "$IFACE"
        ip addr add "${nueva_ip}/${nuevo_pfx}" dev "$IFACE"
        ip link set "$IFACE" up
        ip route add default via "$nuevo_gw"
    fi

    local ip_check
    ip_check=$(obtener_ip_actual)
    if [[ "$ip_check" == "$nueva_ip" ]]; then
        msg_ok "IP estática aplicada: ${nueva_ip}/${nuevo_pfx}"
    else
        msg_warn "La IP puede tardar en sincronizarse. IP vista: ${ip_check:-'ninguna'}"
        msg_info "Tip: ejecuta 'ip addr show $IFACE' para verificar."
    fi

    DNS_SERVER_IP="$nueva_ip"
    log "IP estática configurada: $nueva_ip/$nuevo_pfx gw=$nuevo_gw en $IFACE"
    pausar
}

_validar_ip() {
    local ip="$1"
    local regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    [[ "$ip" =~ $regex ]]
}

# =============================================================================
#  MÓDULO 2 ── INSTALACIÓN IDEMPOTENTE DE BIND9
# =============================================================================

modulo_instalar() {
    titulo "Instalación Idempotente de BIND9"

    subtitulo "Verificando paquetes"
    local paquetes_requeridos=("bind" "bind-utils")
    local instalar=()

    for pkg in "${paquetes_requeridos[@]}"; do
        if rpm -q "$pkg" &>/dev/null; then
            msg_ok "$pkg ya está instalado."
        else
            msg_warn "$pkg NO está instalado."
            instalar+=("$pkg")
        fi
    done

    if [[ ${#instalar[@]} -gt 0 ]]; then
        msg_info "Instalando: ${instalar[*]}"
        zypper --non-interactive refresh
        zypper --non-interactive install -y "${instalar[@]}"
        if [[ $? -eq 0 ]]; then
            msg_ok "Paquetes instalados correctamente."
        else
            msg_err "Error al instalar paquetes. Verifica repositorios con: zypper repos"
            pausar; return 1
        fi
    fi

    subtitulo "Configurando estructura de directorios"
    mkdir -p "$NAMED_D" "$ZONES_DIR"
    chown -R named:named "$ZONES_DIR" 2>/dev/null || true

    # Crear archivo de zonas locales si no existe
    [[ ! -f "$ZONES_FILE" ]] && touch "$ZONES_FILE" && msg_ok "Creado: $ZONES_FILE"

    # Asegurar que named.conf incluya nuestras zonas
    _configurar_named_conf

    subtitulo "Verificando servicio named"
    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        msg_ok "El servicio '$DNS_SERVICE' ya está activo."
    else
        msg_info "Habilitando e iniciando el servicio..."
        systemctl enable "$DNS_SERVICE" &>/dev/null
        systemctl start "$DNS_SERVICE"
        sleep 2
        if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
            msg_ok "Servicio '$DNS_SERVICE' iniciado."
        else
            msg_err "No se pudo iniciar el servicio."
            msg_info "Diagnóstico: journalctl -u named -n 30"
        fi
    fi

    subtitulo "Configurando Firewall"
    _configurar_firewall

    pausar
}

_configurar_named_conf() {
    local include_line='include "/etc/named.d/zonas_locales.conf";'

    if grep -q "zonas_locales.conf" "$BIND_CONF" 2>/dev/null; then
        msg_ok "named.conf ya referencia las zonas locales."
        return
    fi

    if [[ -f "$BIND_CONF" ]]; then
        cp "$BIND_CONF" "${BIND_CONF}.bak_$(date +%Y%m%d%H%M%S)"
        echo -e "\n// === Zonas personalizadas (dns_manager) ===\n${include_line}" >> "$BIND_CONF"
        msg_ok "Include agregado a $BIND_CONF"
    else
        msg_info "Generando $BIND_CONF desde plantilla..."
        cat > "$BIND_CONF" <<'NAMEDCONF'
# /etc/named.conf - Generado por dns_manager_opensuse.sh
options {
    directory           "/var/lib/named";
    dump-file           "/var/log/named_dump.db";
    statistics-file     "/var/log/named.stats";
    pid-file            "/run/named/named.pid";

    listen-on           { any; };
    listen-on-v6        { any; };

    allow-query         { any; };
    allow-recursion     { localhost; localnets; };
    recursion           yes;

    forwarders {
        8.8.8.8;
        8.8.4.4;
    };

    dnssec-validation   no;
};

logging {
    channel default_log {
        file "/var/log/named.log" versions 3 size 5m;
        severity dynamic;
        print-time yes;
        print-severity yes;
        print-category yes;
    };
    category default { default_log; };
    category queries  { default_log; };
};

zone "." IN {
    type hint;
    file "root.hint";
};

zone "localhost" IN {
    type master;
    file "localhost.zone";
    notify no;
};

zone "0.0.127.in-addr.arpa" IN {
    type master;
    file "127.0.0.zone";
    notify no;
};

// === Zonas personalizadas (dns_manager) ===
include "/etc/named.d/zonas_locales.conf";
NAMEDCONF
        msg_ok "named.conf generado."
    fi
}

_configurar_firewall() {
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall-cmd --permanent --add-service=dns &>/dev/null
        firewall-cmd --reload &>/dev/null
        msg_ok "Puerto 53/TCP y 53/UDP abiertos en firewalld."
    elif systemctl is-active SuSEfirewall2 &>/dev/null; then
        msg_warn "SuSEfirewall2 activo. Verifica manualmente que el puerto 53 esté abierto."
    else
        msg_info "No se detectó firewall activo. Puerto 53 accesible."
    fi
}

# =============================================================================
#  MÓDULO 3 ── NORMALIZACIÓN Y VALIDACIÓN DE DOMINIOS
# =============================================================================

# Quita "www." del inicio → devuelve solo el dominio raíz
_normalizar_dominio() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | xargs
}

# Nombre del archivo de zona para un dominio
_archivo_zona() { echo "${ZONES_DIR}/db.${1}"; }

# Validar formato de dominio
_validar_dominio() {
    local d="$1"
    [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]
}

# =============================================================================
#  MÓDULO 4 ── ALTA DE ZONA DNS
# =============================================================================

modulo_alta() {
    titulo "Alta de Zona DNS"

    # Asegurar que tenemos la IP del servidor
    if [[ -z "$DNS_SERVER_IP" ]]; then
        DNS_SERVER_IP=$(obtener_ip_actual)
        if [[ -z "$DNS_SERVER_IP" ]]; then
            msg_err "No se pudo determinar la IP del servidor."
            msg_info "Ejecuta primero la opción [2] para configurar la IP."
            pausar; return 1
        fi
    fi

    separador
    echo -e "  ${CYAN}Puedes ingresar el dominio en cualquiera de estos formatos:${NC}"
    echo -e "  • ${BOLD}reprobados.com${NC}     → se crea A + CNAME para www"
    echo -e "  • ${BOLD}www.reprobados.com${NC} → se normaliza automáticamente"
    separador

    # ── Pedir dominio ──
    local entrada dominio
    while true; do
        echo ""
        read -rp "  Dominio a registrar: " entrada
        entrada=$(echo "$entrada" | xargs)

        if [[ -z "$entrada" ]]; then
            msg_err "El dominio no puede estar vacío."; continue
        fi

        dominio=$(_normalizar_dominio "$entrada")

        if ! _validar_dominio "$dominio"; then
            msg_err "Dominio inválido: '$dominio'"
            msg_info "Formato válido: reprobados.com  |  mi-empresa.com.mx"
            continue
        fi
        break
    done

    msg_info "Dominio normalizado: ${BOLD}$dominio${NC}"
    echo -e "  Se crearán los registros:"
    echo -e "  • ${BOLD}$dominio${NC}      →  A      →  <IP destino>"
    echo -e "  • ${BOLD}www.$dominio${NC}  →  CNAME  →  $dominio"

    # ── Pedir IP destino ──
    local ip_destino
    echo ""
    while true; do
        read -rp "  IP de destino [${DNS_SERVER_IP}]: " ip_destino
        ip_destino="${ip_destino:-$DNS_SERVER_IP}"
        _validar_ip "$ip_destino" && break
        msg_err "IP inválida. Ej: 192.168.1.20"
    done

    # ── Verificar idempotencia ──
    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    if grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        msg_warn "La zona '${dominio}' ya existe en la configuración."
        echo ""
        read -rp "  ¿Sobreescribir? (s/n): " sobre
        [[ ! "$sobre" =~ ^[Ss]$ ]] && { msg_info "Operación cancelada."; pausar; return; }
        _eliminar_zona_conf "$dominio"
    fi

    # ── Generar archivo de zona ──
    local serial
    serial=$(date +%Y%m%d%02d)
    msg_info "Generando archivo de zona: $archivo_z"

    cat > "$archivo_z" <<EOF
; ══════════════════════════════════════════════════════════════
;  Zona: $dominio
;  Generado: $(date '+%Y-%m-%d %H:%M:%S')
;  Servidor DNS: $DNS_SERVER_IP
;  IP destino  : $ip_destino
; ══════════════════════════════════════════════════════════════

\$TTL 86400      ; TTL por defecto: 1 día

; ── SOA (Start of Authority) ──────────────────────────────────
@   IN  SOA  ns1.${dominio}. admin.${dominio}. (
                ${serial}   ; Serial  (YYYYMMDDNN)
                3600        ; Refresh (1 hora)
                1800        ; Retry   (30 min)
                604800      ; Expire  (1 semana)
                86400 )     ; Minimum TTL (1 día)

; ── Servidores de nombres ──────────────────────────────────────
@       IN  NS   ns1.${dominio}.

; ── Registro A: Servidor de nombres ──────────────────────────
ns1     IN  A    ${DNS_SERVER_IP}

; ── Registro A: Dominio raíz ──────────────────────────────────
;  reprobados.com → ${ip_destino}
@       IN  A    ${ip_destino}

; ── Registro CNAME: www apunta al dominio raíz ────────────────
;  www.reprobados.com → reprobados.com → ${ip_destino}
www     IN  CNAME  ${dominio}.

; ══════════════════════════════════════════════════════════════
EOF

    chown named:named "$archivo_z" 2>/dev/null || true
    chmod 644 "$archivo_z"

    # ── Registrar zona en zonas_locales.conf ──
    cat >> "$ZONES_FILE" <<EOF

// ── Zona: $dominio ─────────────────────────────────────────
// Alta: $(date '+%Y-%m-%d %H:%M:%S') | IP: $ip_destino
zone "$dominio" IN {
    type   master;
    file   "$archivo_z";
    allow-update { none; };
    allow-query  { any;  };
    notify no;
};
EOF

    msg_ok "Zona registrada en $ZONES_FILE"

    # ── Validaciones ──
    subtitulo "Validando configuración"

    if named-checkconf "$BIND_CONF" 2>&1; then
        msg_ok "named-checkconf: sin errores."
    else
        msg_err "Errores en named.conf. Revisa la configuración."
        pausar; return 1
    fi

    if named-checkzone "$dominio" "$archivo_z" 2>&1; then
        msg_ok "named-checkzone: zona válida."
    else
        msg_err "Errores en el archivo de zona."
        pausar; return 1
    fi

    # ── Recargar servicio ──
    _recargar_bind

    echo ""
    echo -e "${GREEN}${BOLD}  ✔ Zona '$dominio' creada exitosamente.${NC}"
    separador
    echo -e "  ${CYAN}Registros DNS configurados:${NC}"
    echo -e "  ┌────────────────────────────────────────────────┐"
    echo -e "  │  ${BOLD}$dominio${NC}     →  A      →  $ip_destino"
    echo -e "  │  ${BOLD}www.$dominio${NC} →  CNAME  →  $dominio"
    echo -e "  │  ${BOLD}ns1.$dominio${NC} →  A      →  $DNS_SERVER_IP"
    echo -e "  └────────────────────────────────────────────────┘"
    separador

    log "Zona creada: $dominio | destino=$ip_destino | dns=$DNS_SERVER_IP"
    pausar
}

# =============================================================================
#  MÓDULO 5 ── BAJA DE ZONA DNS
# =============================================================================

modulo_baja() {
    titulo "Baja de Zona DNS"

    _listar_zonas_corto
    if [[ $? -ne 0 ]]; then pausar; return; fi

    local entrada dominio
    read -rp "  Dominio a eliminar: " entrada
    dominio=$(_normalizar_dominio "$entrada")

    if [[ -z "$dominio" ]]; then
        msg_err "Dominio vacío."; pausar; return
    fi

    if ! grep -q "\"$dominio\"" "$ZONES_FILE" 2>/dev/null; then
        msg_err "La zona '$dominio' no existe en la configuración."
        pausar; return
    fi

    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    echo ""
    echo -e "  ${RED}${BOLD}⚠  Se eliminará la siguiente zona:${NC}"
    echo -e "  ┌───────────────────────────────────────┐"
    echo -e "  │  Dominio : ${BOLD}$dominio${NC}"
    echo -e "  │  Archivo : $archivo_z"
    echo -e "  └───────────────────────────────────────┘"
    read -rp "  ¿Confirmar eliminación? (s/n): " conf
    [[ ! "$conf" =~ ^[Ss]$ ]] && { msg_info "Cancelado."; pausar; return; }

    _eliminar_zona_conf "$dominio"

    # Verificar y recargar
    if named-checkconf "$BIND_CONF" &>/dev/null; then
        _recargar_bind
        msg_ok "Zona '$dominio' eliminada y servicio recargado."
    else
        msg_err "Error en la configuración tras la baja. Verifica manualmente."
    fi

    log "Zona eliminada: $dominio"
    pausar
}

_eliminar_zona_conf() {
    local dominio="$1"
    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")

    # Eliminar bloque del archivo de zonas con Python3
    python3 <<PYEOF
import re, sys

filepath = "$ZONES_FILE"
dominio  = "$dominio"

try:
    with open(filepath, 'r') as f:
        content = f.read()

    # Patrón: desde el comentario hasta el cierre del bloque }; inclusive
    pattern = r'// ── Zona: ' + re.escape(dominio) + r'.*?^};'
    new_content = re.sub(pattern, '', content, flags=re.MULTILINE | re.DOTALL)

    with open(filepath, 'w') as f:
        f.write(new_content)
    print("  Bloque de zona eliminado del archivo de configuración.")
except Exception as e:
    print(f"  Error: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

    # Eliminar archivo de zona
    if [[ -f "$archivo_z" ]]; then
        rm -f "$archivo_z"
        msg_ok "Archivo de zona eliminado: $archivo_z"
    fi
}

# =============================================================================
#  MÓDULO 6 ── CONSULTA DE ZONAS DNS
# =============================================================================

_listar_zonas_corto() {
    if [[ ! -f "$ZONES_FILE" ]] || ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        msg_warn "No hay zonas DNS configuradas actualmente."
        return 1
    fi
    echo -e "\n  ${CYAN}${BOLD}Zonas configuradas:${NC}"
    grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/  •  \1/'
    echo ""
    return 0
}

modulo_consultar() {
    titulo "Consulta de Zonas DNS"

    if [[ ! -f "$ZONES_FILE" ]] || ! grep -q 'zone "' "$ZONES_FILE" 2>/dev/null; then
        msg_warn "No hay zonas DNS configuradas."
        pausar; return
    fi

    # Extraer dominios del archivo de zonas
    mapfile -t dominios < <(grep 'zone "' "$ZONES_FILE" | sed 's/.*zone "\(.*\)" IN.*/\1/')

    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║          ZONAS DNS CONFIGURADAS                      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    local idx=1
    for dom in "${dominios[@]}"; do
        local archivo_z
        archivo_z=$(_archivo_zona "$dom")

        echo -e "  ${BOLD}[$idx] ${GREEN}$dom${NC}"

        if [[ -f "$archivo_z" ]]; then
            echo -e "       ${DIM}Archivo: $archivo_z${NC}"
            echo -e "       ${CYAN}Registros:${NC}"
            # Mostrar solo registros A y CNAME, excluyendo comentarios
            while IFS= read -r linea; do
                [[ "$linea" =~ ^\; ]] && continue
                [[ "$linea" =~ ^$ ]] && continue
                [[ "$linea" =~ ^\\$ ]] && continue
                if echo "$linea" | grep -qE '\s+(A|CNAME|NS)\s+'; then
                    echo -e "       ${DIM}→${NC} $linea"
                fi
            done < "$archivo_z"
        else
            echo -e "       ${RED}⚠ Archivo de zona no encontrado${NC}"
        fi

        echo ""
        ((idx++))
    done

    separador
    # Estado del servicio
    echo -n "  Estado del servicio named: "
    if systemctl is-active "$DNS_SERVICE" &>/dev/null; then
        echo -e "${GREEN}${BOLD}ACTIVO ✔${NC}"
    else
        echo -e "${RED}${BOLD}INACTIVO ✘${NC}"
    fi

    # IP del servidor
    local ip_srv
    ip_srv=$(obtener_ip_actual)
    echo -e "  IP del servidor DNS     : ${BOLD}${ip_srv:-'No detectada'}${NC}"
    echo -e "  Interfaz de red         : ${BOLD}$IFACE${NC}"
    separador

    pausar
}

# =============================================================================
#  MÓDULO 7 ── PRUEBAS DE RESOLUCIÓN
# =============================================================================

modulo_probar() {
    titulo "Pruebas de Resolución DNS"

    _listar_zonas_corto

    local entrada dominio
    read -rp "  Dominio a probar: " entrada
    dominio=$(_normalizar_dominio "$entrada")

    [[ -z "$dominio" ]] && { msg_err "Dominio vacío."; pausar; return; }

    echo -e "\n${BOLD}  Iniciando pruebas para: ${GREEN}$dominio${NC}\n"

    # ── 1. Verificación de sintaxis ──
    echo -e "${YELLOW}  [1/6] named-checkconf — Verificación de sintaxis${NC}"
    separador
    if named-checkconf "$BIND_CONF" 2>&1 | sed 's/^/  /'; then
        msg_ok "Sintaxis de named.conf correcta."
    else
        msg_err "Errores de sintaxis detectados."
    fi

    # ── 2. Verificación de zona ──
    local archivo_z
    archivo_z=$(_archivo_zona "$dominio")
    echo -e "\n${YELLOW}  [2/6] named-checkzone — Verificación de archivo de zona${NC}"
    separador
    if [[ -f "$archivo_z" ]]; then
        named-checkzone "$dominio" "$archivo_z" 2>&1 | sed 's/^/  /'
        [[ ${PIPESTATUS[0]} -eq 0 ]] && msg_ok "Zona válida." || msg_err "Errores en zona."
    else
        msg_err "Archivo de zona no encontrado: $archivo_z"
    fi

    # ── 3. nslookup dominio raíz ──
    echo -e "\n${YELLOW}  [3/6] nslookup $dominio @127.0.0.1${NC}"
    separador
    if command -v nslookup &>/dev/null; then
        nslookup "$dominio" 127.0.0.1 2>&1 | sed 's/^/  /'
    else
        msg_warn "nslookup no disponible. Instala bind-utils."
    fi

    # ── 4. nslookup www ──
    echo -e "\n${YELLOW}  [4/6] nslookup www.$dominio @127.0.0.1${NC}"
    separador
    command -v nslookup &>/dev/null && nslookup "www.$dominio" 127.0.0.1 2>&1 | sed 's/^/  /'

    # ── 5. dig resolución A ──
    echo -e "\n${YELLOW}  [5/6] dig $dominio A — Resolución directa${NC}"
    separador
    if command -v dig &>/dev/null; then
        dig @127.0.0.1 "$dominio" A 2>&1 | sed 's/^/  /'
    else
        msg_warn "dig no disponible."
    fi

    # ── 6. Ping al www ──
    echo -e "\n${YELLOW}  [6/6] ping -c3 www.$dominio — Prueba de conectividad${NC}"
    separador
    # Temporalmente usar nuestro DNS
    local dns_orig
    dns_orig=$(grep '^nameserver' /etc/resolv.conf | head -1 | awk '{print $2}')
    ping -c 3 -W 2 "www.$dominio" 2>&1 | sed 's/^/  /' || true

    echo ""
    separador
    echo -e "  ${DIM}Nota: Para pruebas desde cliente externo, configura el"
    echo -e "  DNS del cliente a ${BOLD}$(obtener_ip_actual)${NC}${DIM} e intenta:${NC}"
    echo -e "  ${BOLD}  nslookup $dominio $(obtener_ip_actual)${NC}"
    separador

    log "Pruebas ejecutadas para: $dominio"
    pausar
}

# =============================================================================
#  MÓDULO 8 ── GESTIÓN DEL SERVICIO
# =============================================================================

_recargar_bind() {
    if rndc reload &>/dev/null; then
        msg_ok "Zonas recargadas con rndc reload."
    elif systemctl reload "$DNS_SERVICE" &>/dev/null; then
        msg_ok "Servicio recargado (systemctl reload)."
    else
        systemctl restart "$DNS_SERVICE" &>/dev/null
        sleep 2
        systemctl is-active "$DNS_SERVICE" &>/dev/null \
            && msg_ok "Servicio reiniciado." \
            || msg_err "Error al reiniciar el servicio."
    fi
}

modulo_servicio() {
    titulo "Estado y Gestión del Servicio DNS"

    echo -e "${CYAN}${BOLD}  Estado actual:${NC}"
    systemctl status "$DNS_SERVICE" --no-pager -l | sed 's/^/  /'

    echo ""
    separador
    echo "  [1] Recargar zonas (rndc reload)     — sin downtime"
    echo "  [2] Reiniciar servicio completo"
    echo "  [3] Detener servicio"
    echo "  [4] Ver log de named"
    echo "  [5] Ver log del script"
    echo "  [0] Volver al menú"
    separador
    read -rp "  Opción: " opc

    case "$opc" in
        1) _recargar_bind ;;
        2) systemctl restart "$DNS_SERVICE"; sleep 2
           systemctl is-active "$DNS_SERVICE" &>/dev/null \
               && msg_ok "Reiniciado." || msg_err "Error al reiniciar."
           ;;
        3) systemctl stop "$DNS_SERVICE" && msg_ok "Servicio detenido." ;;
        4) echo -e "\n${CYAN}Últimas 30 líneas del log de named:${NC}"
           [[ -f /var/log/named.log ]] \
               && tail -30 /var/log/named.log | sed 's/^/  /' \
               || journalctl -u named -n 30 --no-pager | sed 's/^/  /'
           ;;
        5) echo -e "\n${CYAN}Últimas 30 líneas del log del script:${NC}"
           [[ -f "$LOG_FILE" ]] && tail -30 "$LOG_FILE" | sed 's/^/  /' || msg_warn "Sin log todavía."
           ;;
        0) return ;;
        *) msg_warn "Opción inválida." ;;
    esac
    pausar
}

# =============================================================================
#  INICIALIZACIÓN
# =============================================================================

_inicializar() {
    mkdir -p "$(dirname "$LOG_FILE")" "$NAMED_D" "$ZONES_DIR" 2>/dev/null
    touch "$LOG_FILE" 2>/dev/null || true
    [[ ! -f "$ZONES_FILE" ]] && touch "$ZONES_FILE" 2>/dev/null || true

    # Detectar IP del servidor silenciosamente
    DNS_SERVER_IP=$(obtener_ip_actual)
}

# =============================================================================
#  MENÚ PRINCIPAL
# =============================================================================

menu_principal() {
    while true; do
        clear
        local ip_display="${DNS_SERVER_IP:-'No detectada'}"
        local svc_estado
        systemctl is-active "$DNS_SERVICE" &>/dev/null \
            && svc_estado="${GREEN}●  Activo${NC}" \
            || svc_estado="${RED}●  Inactivo${NC}"

        echo -e "${BOLD}${BLUE}"
        echo "  ╔════════════════════════════════════════════════════╗"
        echo "  ║      GESTOR DNS · BIND9 · OpenSUSE Leap            ║"
        echo "  ╠════════════════════════════════════════════════════╣"
        printf "  ║  Interfaz : %-38s║\n" "$IFACE"
        printf "  ║  IP DNS   : %-38s║\n" "$ip_display"
        echo -e "  ║  Servicio : $(echo -e $svc_estado)$(printf '%42s' '')${BOLD}${BLUE}║"
        echo "  ╚════════════════════════════════════════════════════╝"
        echo -e "${NC}"

        echo -e "  ${BOLD}CONFIGURACIÓN INICIAL${NC}"
        echo    "  [1]  Instalar BIND9                (idempotente)"
        echo    "  [2]  Verificar / Configurar IP estática"
        echo ""
        echo -e "  ${BOLD}GESTIÓN DE ZONAS DNS${NC}"
        echo    "  [3]  Alta de dominio/zona"
        echo    "  [4]  Baja de dominio/zona"
        echo    "  [5]  Consultar zonas configuradas"
        echo ""
        echo -e "  ${BOLD}DIAGNÓSTICO Y SERVICIO${NC}"
        echo    "  [6]  Probar resolución DNS"
        echo    "  [7]  Estado y gestión del servicio"
        echo ""
        echo    "  [0]  Salir"
        echo ""
        read -rp "  Selecciona una opción: " opcion

        case "$opcion" in
            1) modulo_instalar ;;
            2) modulo_ip_fija ;;
            3) modulo_alta ;;
            4) modulo_baja ;;
            5) modulo_consultar ;;
            6) modulo_probar ;;
            7) modulo_servicio ;;
            0)
                echo -e "\n${CYAN}  Saliendo del Gestor DNS. ¡Hasta pronto!${NC}\n"
                exit 0
                ;;
            *)
                msg_warn "Opción inválida."
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
#  SOPORTE CLI — parámetros para reutilización futura
# =============================================================================

_uso() {
    echo ""
    echo "  Uso: $0 [--opcion] [argumentos]"
    echo ""
    echo "  Opciones:"
    echo "    (sin argumento)       Menú interactivo completo"
    echo "    --instalar            Instalar BIND9 de forma idempotente"
    echo "    --ip                  Verificar / configurar IP estática"
    echo "    --alta DOMINIO IP     Dar de alta una zona DNS"
    echo "    --baja DOMINIO        Dar de baja una zona DNS"
    echo "    --consultar           Listar zonas configuradas"
    echo "    --probar DOMINIO      Ejecutar pruebas de resolución"
    echo "    --estado              Ver estado del servicio named"
    echo "    --ayuda               Mostrar este mensaje"
    echo ""
}

# =============================================================================
#  PUNTO DE ENTRADA
# =============================================================================
verificar_root
_inicializar

case "${1:-}" in
    --instalar)  modulo_instalar ;;
    --ip)        modulo_ip_fija ;;
    --alta)
        [[ -z "${2:-}" || -z "${3:-}" ]] && { msg_err "Uso: $0 --alta dominio ip"; exit 1; }
        entrada="$2"; ip_param="$3"
        dominio=$(_normalizar_dominio "$entrada")
        _validar_dominio "$dominio" || { msg_err "Dominio inválido."; exit 1; }
        _validar_ip "$ip_param"     || { msg_err "IP inválida."; exit 1; }
        DNS_SERVER_IP=$(obtener_ip_actual)
        # Llamada directa sin interacción
        [[ ! -f "$ZONES_FILE" ]] && touch "$ZONES_FILE"
        archivo_z=$(_archivo_zona "$dominio")
        serial=$(date +%Y%m%d%02d)
        cat > "$archivo_z" <<EOF
\$TTL 86400
@ IN SOA ns1.${dominio}. admin.${dominio}. (${serial} 3600 1800 604800 86400)
@ IN NS  ns1.${dominio}.
ns1 IN A   ${DNS_SERVER_IP}
@   IN A   ${ip_param}
www IN CNAME ${dominio}.
EOF
        cat >> "$ZONES_FILE" <<EOF
zone "$dominio" IN { type master; file "$archivo_z"; allow-update { none; }; };
EOF
        named-checkconf && _recargar_bind && msg_ok "Zona '$dominio' creada."
        ;;
    --baja)
        [[ -z "${2:-}" ]] && { msg_err "Uso: $0 --baja dominio"; exit 1; }
        dominio=$(_normalizar_dominio "$2")
        _eliminar_zona_conf "$dominio"
        _recargar_bind && msg_ok "Zona '$dominio' eliminada."
        ;;
    --consultar) modulo_consultar ;;
    --probar)
        [[ -z "${2:-}" ]] && { msg_err "Uso: $0 --probar dominio"; exit 1; }
        entrada="$2"; dominio=$(_normalizar_dominio "$entrada")
        modulo_probar <<< "$dominio"
        ;;
    --estado)    modulo_servicio ;;
    --ayuda|-h)  _uso ;;
    "")          menu_principal ;;
    *)           msg_err "Opción desconocida: $1"; _uso; exit 1 ;;
esac
