#!/bin/bash

# ============================================================
# VARIABLES GLOBALES
# ============================================================
DC_IP="222.222.222.222"
DOMINIO="dominio.local"
REALM="DOMINIO.LOCAL"
ADMIN_PASS="Admin@12345!"

# ---------------------------------------- Funciones ----------------------------------------

VerificarRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "Este script debe ejecutarse como root"
        exit 1
    fi
}

# ------------------------------------------------------------
# 1. CONFIGURAR DNS
# ------------------------------------------------------------
configurar_dns() {
    echo "[+] Configurando DNS hacia el DC ($DC_IP)..."

    # Desactivar systemd-resolved si esta activo (Mint lo usa por defecto)
    if systemctl is-active --quiet systemd-resolved; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        rm -f /etc/resolv.conf
    fi

    cat > /etc/resolv.conf << EOF
nameserver $DC_IP
search $DOMINIO
domain $DOMINIO
EOF
    chattr +i /etc/resolv.conf

    if host "$DOMINIO" &>/dev/null; then
        echo "    DNS OK: $DOMINIO resuelto correctamente"
    else
        echo "    ERROR: No se puede resolver $DOMINIO"
        return 1
    fi
}

# ------------------------------------------------------------
# 2. INSTALAR PAQUETES
# ------------------------------------------------------------
instalar_paquetes() {
    echo "[+] Instalando paquetes necesarios..."
    export DEBIAN_FRONTEND=noninteractive

    # Forzar IPv4 para evitar "Network is unreachable" por IPv6
    echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

    apt-get update -qq
    apt-get install -y \
        realmd sssd sssd-tools adcli \
        samba-common samba-common-bin \
        krb5-user libpam-sss libnss-sss libsss-sudo \
        oddjob oddjob-mkhomedir packagekit \
        ntp ntpdate

    echo "[+] Sincronizando hora con el DC (requerido por Kerberos)..."
    ntpdate "$DC_IP" 2>/dev/null || true

    echo "    Paquetes instalados correctamente"
}

# ------------------------------------------------------------
# 3. CONFIGURAR KERBEROS
# ------------------------------------------------------------
configurar_kerberos() {
    echo "[+] Configurando Kerberos..."
    cat > /etc/krb5.conf << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $REALM = {
        kdc = $DC_IP
        admin_server = $DC_IP
        default_domain = $DOMINIO
    }

[domain_realm]
    .$DOMINIO = $REALM
    $DOMINIO  = $REALM
EOF
    echo "    Kerberos configurado (realm: $REALM)"
}

# ------------------------------------------------------------
# 4. UNIRSE AL DOMINIO
# ------------------------------------------------------------
unir_dominio() {
    echo "[+] Uniendo al dominio $DOMINIO..."

    # --client-software=sssd fuerza uso de SSSD en lugar de winbind
    echo "$ADMIN_PASS" | /usr/sbin/realm join \
        --user=Administrator \
        --client-software=sssd \
        "$DOMINIO" -v

    if /usr/sbin/realm list | grep -q "$DOMINIO"; then
        echo "    Union al dominio completada"
    else
        echo "    ERROR: No se pudo unir al dominio"
        return 1
    fi
}

# ------------------------------------------------------------
# 5. CONFIGURAR SSSD
#    fallback_homedir = /home/%u@%d  (requerido por la rubrica)
# ------------------------------------------------------------
configurar_sssd() {
    echo "[+] Configurando SSSD..."
    cat > /etc/sssd/sssd.conf << EOF
[sssd]
domains = $DOMINIO
config_file_version = 2
services = nss, pam, sudo

[domain/$DOMINIO]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = $DOMINIO
krb5_realm = $REALM

# Requerido por la rubrica de la Tarea 08
fallback_homedir = /home/%u@%d
default_shell = /bin/bash

cache_credentials = true
ldap_id_mapping = true
ldap_referrals = false
use_fully_qualified_names = false

# Opciones para Linux Mint / Ubuntu
ad_gpo_access_control = disabled
dyndns_update = false
EOF
    chmod 600 /etc/sssd/sssd.conf
    echo "    sssd.conf configurado (fallback_homedir=/home/%u@%d)"
}

# ------------------------------------------------------------
# 6. CONFIGURAR SUDOERS
#    Permite sudo a Domain Admins y opcionalmente a grupos de la tarea
# ------------------------------------------------------------
configurar_sudoers() {
    echo "[+] Configurando sudoers para usuarios AD..."
    cat > /etc/sudoers.d/ad-admins << EOF
## Tarea 08 - Usuarios AD con privilegios sudo
## Domain Admins tienen acceso total
%domain\ admins@$DOMINIO ALL=(ALL:ALL) ALL

## Grupos de la tarea (descomentar si se requiere sudo para ellos)
# %grupocuates@$DOMINIO    ALL=(ALL:ALL) ALL
# %gruponocuates@$DOMINIO  ALL=(ALL:ALL) ALL
EOF
    chmod 440 /etc/sudoers.d/ad-admins
    echo "    /etc/sudoers.d/ad-admins configurado"
}

# ------------------------------------------------------------
# 7. CONFIGURAR PAM MKHOMEDIR
#    Crea el home automaticamente al primer login del usuario AD
# ------------------------------------------------------------
configurar_pam_mkhomedir() {
    echo "[+] Configurando PAM mkhomedir (creacion automatica de home)..."

    # En Linux Mint se usa pam-auth-update de forma segura
    if command -v pam-auth-update &>/dev/null; then
        pam-auth-update --enable mkhomedir
        echo "    PAM mkhomedir habilitado via pam-auth-update"
    else
        if ! grep -q "pam_mkhomedir" /etc/pam.d/common-session; then
            echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" \
                >> /etc/pam.d/common-session
            echo "    PAM mkhomedir agregado manualmente"
        else
            echo "    PAM mkhomedir ya estaba configurado"
        fi
    fi
}

# ------------------------------------------------------------
# 8. REINICIAR SSSD
# ------------------------------------------------------------
reiniciar_sssd() {
    echo "[+] Habilitando y reiniciando sssd..."
    systemctl enable sssd
    systemctl restart sssd
    sleep 3
    if systemctl is-active --quiet sssd; then
        echo "    sssd: ACTIVO"
    else
        echo "    ERROR: sssd no esta activo"
        systemctl status sssd --no-pager
        return 1
    fi
}

# ------------------------------------------------------------
# EVIDENCIA - Rubrica Tarea 08
# ------------------------------------------------------------
mostrar_evidencia() {
    echo ""
    echo "========================================================"
    echo "  EVIDENCIA TAREA 08 - Cliente Linux Mint"
    echo "  Distro : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
    echo "  Fecha  : $(date)"
    echo "========================================================"

    echo ""
    echo "--- [1] UNION AL DOMINIO ---"
    /usr/sbin/realm list

    echo ""
    echo "--- [2] HOSTNAME COMPLETO ---"
    hostname -f

    echo ""
    echo "--- [3] USUARIOS AD RESUELTOS POR SSSD ---"
    echo "  cramirez:"
    id cramirez 2>/dev/null || echo "  (usuario no encontrado)"
    echo "  smendez:"
    id smendez  2>/dev/null || echo "  (usuario no encontrado)"

    echo ""
    echo "--- [4] GRUPOS AD ---"
    getent group grupocuates   2>/dev/null || echo "  grupocuates:   (no encontrado)"
    getent group gruponocuates 2>/dev/null || echo "  gruponocuates: (no encontrado)"

    echo ""
    echo "--- [5] ESTADO DE SSSD ---"
    systemctl is-active sssd
    systemctl status sssd --no-pager | head -10

    echo ""
    echo "--- [6] SUDOERS AD ---"
    cat /etc/sudoers.d/ad-admins

    echo ""
    echo "--- [7] fallback_homedir EN sssd.conf (requerido rubrica) ---"
    grep fallback_homedir /etc/sssd/sssd.conf

    echo ""
    echo "--- [8] PAM MKHOMEDIR ---"
    grep -r "pam_mkhomedir" /etc/pam.d/ 2>/dev/null || echo "  (no encontrado)"

    echo ""
    echo "--- [9] DNS ACTIVO ---"
    cat /etc/resolv.conf

    echo ""
    echo "--- [10] PROBAR LOGIN MANUAL ---"
    echo "  Ejecuta:  su - cramirez"
    echo "  O via SSH: ssh cramirez@$(hostname)"
    echo "========================================================"
}

# ------------------------------------------------------------
# FLUJO COMPLETO
# ------------------------------------------------------------
instalar_todo() {
    echo ""
    echo "========================================="
    echo "  INICIANDO FLUJO COMPLETO - TAREA 08"
    echo "========================================="

    configurar_dns          || { echo "[!] Fallo en configurar_dns";    exit 1; }
    instalar_paquetes       || { echo "[!] Fallo en instalar_paquetes"; exit 1; }
    configurar_kerberos
    unir_dominio            || { echo "[!] Fallo en unir_dominio";      exit 1; }
    configurar_sssd
    configurar_sudoers
    configurar_pam_mkhomedir
    reiniciar_sssd          || { echo "[!] Fallo en reiniciar_sssd";    exit 1; }
    mostrar_evidencia

    echo ""
    echo "  [OK] Configuracion completada exitosamente."
}
