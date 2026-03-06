#!/bin/bash
# network-sniffer/install/uninstall.sh

# Colores y variables de identidad
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 
echo -e "${RED}\n\n--------------------------------------------------${NC}"
echo -e "${RED}Iniciando desinstalación de Network Sniffer${NC}"
echo -e "${RED}--------------------------------------------------${NC}"

# Verificar privilegios de root
if [ "$EUID" -ne 0 ]; then
    echo -e "\n${RED}Error: Por favor, ejecuta como root (sudo).${NC}"
    exit 1
fi

# Asegurar que el script se ejecute desde su propia ubicación
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$SCRIPT_DIR" || exit 1

CONFIG_FILE="$SCRIPT_DIR/../src/lib/config.conf"

if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo -e "\t${RED}[-] No se pudo cargar config.conf. La limpieza manual será necesaria.${NC}"
    exit 1
fi

### Detener y eliminar servicio Systemd
echo -e "\nDeteniendo servicios..."
if systemctl is-active --quiet network-sniffer; then
    systemctl stop network-sniffer
    systemctl disable network-sniffer
    # Asegurar que los procesos hijos de la captura se cierren
    pkill -u "$APP_USER"
fi

if [ -f "$SERVICE_DEST" ]; then
    rm -f $SERVICE_DEST
    echo -e "\t${GREEN}[+] Servicio $SERVICE_DEST eliminado.${NC}"
fi

if [ -f "$SERVICE_WEB_DEST" ]; then
    rm -f $SERVICE_WEB_DEST
    echo -e "\t${GREEN}[+] Servicio $SERVICE_WEB_DEST eliminado.${NC}"
fi

### Limpiar logrotate
echo -e "\nRevocando configuraciones de sistema..."
if [ -f "$LOGROTATE_DEST" ]; then
    rm -f $LOGROTATE_DEST
    echo -e "\t${GREEN}[+] Eliminado $LOGROTATE_DEST.${NC}"
fi

### Eliminar archivos de la aplicación
echo -e "\nEliminando archivos de aplicación..."
# Borrar archivos instalados en STATE_DIR
if [[ -d "$STATE_DIR" && "$STATE_DIR" != "/" ]]; then
    rm -rf "$STATE_DIR"
    echo -e "\t${GREEN}[+] Directorio de estado $STATE_DIR eliminado.${NC}"
fi

# Limpieza de directorios temporales/runtime
if [[ -d "$BUS_DIR" && "$BUS_DIR" != "/" ]]; then
    rm -rf "$BUS_DIR"
    echo -e "\t${GREEN}[+] Directorio runtime $BUS_DIR eliminado.${NC}"
fi

### Gestión de Logs (Pregunta al usuario)
# Por seguridad y auditoría, los logs no suelen borrarse automáticamente
read -p "¿Deseas eliminar también todos los archivos de LOG en $LOG_DIR? (s/n): " confirm
if [[ "$confirm" == "s" || "$confirm" == "S" ]]; then
    if [[ -d "$LOG_DIR" && "$LOG_DIR" != "/" ]]; then
        rm -rf "$LOG_DIR"
        echo -e "\t${GREEN}[+] Logs eliminados.${NC}"
    fi
else
    echo -e "\t${GREEN}[!] Logs preservados en $LOG_DIR para auditoría.${NC}"
fi

### Limpieza de Identidad (Usuario y Grupo)
echo -e "\nEliminando usuario de sistema..."
if id "$APP_USER" &>/dev/null; then
    killall -u "$APP_USER" 2>/dev/null
    userdel "$APP_USER"
    echo -e "\t${GREEN}[+] Usuario $APP_USER eliminado.${NC}"
fi

systemctl daemon-reload

echo -e "\n${RED}--------------------------------------------------${NC}"
echo -e "${GREEN}¡Desinstalación completada con éxito!${NC}"
echo -e "${RED}--------------------------------------------------${NC}"