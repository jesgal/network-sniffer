#!/bin/bash
# audit_test.sh - Script de pruebas integrales con colores

# Definición de colores
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # Sin color (No Color)
BOLD='\033[1m'

# Cargar configuración y variables comunes
BASE_DIR="/etc/network-sniffer"
# Intentamos cargar desde la ruta proporcionada en tu configuración
source "$BASE_DIR/src/lib/config.conf" 2>/dev/null || source "/etc/network-sniffer/lib/common.sh" 2>/dev/null

echo -e "${BOLD}=== Iniciando Auditoría de Pruebas Integrales ===${NC}"

# Función para verificar si hay logs nuevos con colores
check_log() {
    local log_file="$1"
    local pattern="$2"
    
    # Pausa breve para dar tiempo al sniffer a procesar el paquete
    sleep 2
    
    if [ -f "$log_file" ] && tail -n 10 "$log_file" | grep -Eq "$pattern"; then
        echo -e "${GREEN}[OK] Evento detectado en $(basename $log_file)${NC}"
    else
        echo -e "${RED}[ERROR] No se detectó actividad en $(basename $log_file)${NC}"
        echo -e "      (Patrón buscado: $pattern)"
    fi
}

# Prueba de Módulo PROCESS (Conexiones Locales)
echo -e "\nTesting: Módulo Process..."
nc -z 8.8.8.8 53 > /dev/null 2>&1
check_log "$LOG_DIR/proccess.log" "PROC=nc.+DST=8.8.8.8\s+DPORT=53"

# Prueba de Módulo DNS
echo -e "\nTesting: Módulo DNS..."
nslookup google.com > /dev/null 2>&1
check_log "$LOG_DIR/dns.log" "QNAME=google.com"

# Prueba de Módulo HTTP
echo -e "\nTesting: Módulo HTTP..."
curl -s http://www.google.com/test > /dev/null 2>&1
check_log "$LOG_DIR/http.log" "http://www.google.com/test"

# Prueba de Módulo TLS/HTTPS
echo -e "\nTesting: Módulo TLS..."
curl -s https://www.google.com > /dev/null 2>&1
check_log "$LOG_DIR/tls.log" "SNI=\"www.google.com\""

# Prueba de Módulo CERT
echo -e "\nTesting: Módulo CERT..."
curl -s --tls-max 1.2 --tlsv1.2 --no-sessionid --http1.1 -k https://www.example.com > /dev/null 2>&1
check_log "$LOG_DIR/cert.log" "DNS:example\.com"

# Prueba de Módulo ICMP
echo -e "\nTesting: Módulo ICMP..."
ping -c 1 8.8.8.8 > /dev/null 2>&1
check_log "$LOG_DIR/icmp.log" "INFO=PING_REQUEST"

# Prueba de Módulo SSH
echo -e "\nTesting: Módulo SSH..."
ssh -o BatchMode=yes -o ConnectTimeout=1 user@github.com exit > /dev/null 2>&1
check_log "$LOG_DIR/ssh.log" "PROTO=SSH"

# Prueba de Módulo SMTP (Simulación Silent)
echo -e "\nTesting: Módulo SMTP (Internet)..."
(echo "HELO $(hostname)"; sleep 2; echo "QUIT") | nc -w 5 gmail-smtp-in.l.google.com 25 > /dev/null 2>&1
check_log "$LOG_DIR/smtp.log" "PROTO=SMTP"

# Prueba de Módulo SMB (Conexión Silent)
echo -e "\nTesting: Módulo SMB (Internet)..."
smbclient -L //8.8.8.8 -N -p 445 --connect-timeout=2 > /dev/null 2>&1
check_log "$LOG_DIR/smb.log" "PROTO=SMB"

# Prueba de Módulo BBDD (MySQL/MariaDB Silent)
echo -e "\nTesting: Módulo BBDD (Internet)..."
nc -z -w 3 8.8.8.8 3306 > /dev/null 2>&1
check_log "$LOG_DIR/bbdd.log" "TECH=MySQL/MariaDB"

echo -e "\n${BOLD}=== Auditoría Finalizada ===${NC}"