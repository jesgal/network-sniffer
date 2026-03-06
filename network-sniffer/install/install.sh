#!/bin/bash
# network-sniffer/install/install.sh

# Colores y variables de identidad
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' 
echo -e "${GREEN}\n\n--------------------------------------------------${NC}"
echo -e "${GREEN}Iniciando instalación segura de Network Sniffer${NC}"
echo -e "${GREEN}--------------------------------------------------${NC}"

# Verificar privilegios de root
if [ "$EUID" -ne 0 ]; then
    echo -e "\n${RED}Error: Por favor, ejecuta como root (sudo).${NC}"
    exit 1
fi

# Asegurar que el script se ejecute desde su propia ubicación
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$SCRIPT_DIR" || exit 1

## Carga fichero configuración
CONFIG_FILE="../src/lib/config.conf"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Verificación de seguridad: Asegurar que no son enlaces simbólicos maliciosos (opcional)
if [[ -L "$LOG_DIR" || -L "$STATE_DIR" ]]; then
    echo -e "\t${RED}[ALERTA] Se detectaron enlaces simbólicos en las rutas críticas. Abortando por seguridad.${NC}"
    exit 1
fi

# Crear la estructura de directorios
echo -e "\nCreando estructura de directorios..."
# Intentar crear el directorio
if mkdir -p "$BUS_DIR"; then
    chmod -R 770 "$BUS_DIR"
    chown -R "$APP_USER":"$APP_GROUP" "$BUS_DIR"
    # Verificar si es un directorio real y si tenemos permisos de escritura (como root)
    if [[ -d "$BUS_DIR" && -w "$BUS_DIR" ]]; then
        echo -e "\t${GREEN}[+] Directorio creado y accesible: $BUS_DIR${NC}"
    fi
fi

# Verificar dependencias
echo -e "\nVerificando dependencias..."
for cmd in tshark ss awk comm setcap readlink; do 
    if ! command -v $cmd &> /dev/null; then
        echo -e "\t${RED}Error: La herramienta '$cmd' no está instalada.${NC}"
        exit 1
    fi
done

if [ -f "$LOGROTATE_SRC" ]; then
    cp "$LOGROTATE_SRC" "$LOGROTATE_DEST"
    
    # Logrotate es muy estricto con los permisos (debe ser root y 644)
    chown root:root "$LOGROTATE_DEST"
    chmod 644 "$LOGROTATE_DEST"
    
    echo -e "$\t{GREEN}[+] Configuración de logrotate instalada correctamente.${NC}"
else
    echo -e "$\t{RED}[-] Error: No se encontró el archivo de configuración en $LOGROTATE_SRC${NC}"
    exit 1
fi

## Identidad
# Crear usuario y grupo de sistema si no existen
if ! id "$APP_USER" &>/dev/null; then
    echo -e "\nCreando usuario de sistema: $APP_USER..."
    useradd --system --shell /usr/sbin/nologin --no-create-home "$APP_USER"
    
    # Verificación post-creación
    if id "$APP_USER" &>/dev/null; then
        echo -e "\t${GREEN}[+] Usuario $APP_USER creado con éxito.${NC}"
    else
        echo -e "\t${RED}[-] Falló la creación del usuario $APP_USER.${NC}"
        exit 1
    fi
else
    echo -e "\t${GREEN}[!] El usuario $APP_USER ya existe, omitiendo creación.${NC}"
fi

# Crear la estructura de directorios
echo -e "\nCreando estructura de directorios..."
# Lista de directorios a crear y verificar
DIRECTORIES=("$LOG_DIR" "$STATE_DIR")
for dir in "${DIRECTORIES[@]}"; do
    # Intentar crear el directorio
    if mkdir -p "$dir"; then
        chmod -R 770 "$dir"
        chown -R "$APP_USER":"$APP_GROUP" "$dir"
        # Verificar si es un directorio real y si tenemos permisos de escritura (como root)
        if [[ -d "$dir" && -w "$dir" ]]; then
            echo -e "\t${GREEN}[+] Directorio creado y accesible: $dir${NC}"
        else
            echo -e "\t${RED}[-] El directorio $dir no es accesible o no tiene permisos de escritura.${NC}"
            exit 1
        fi
    else
        echo -e "\t${RED}[-] No se pudo crear el directorio $dir. Revisa los permisos del sistema.${NC}"
        exit 1
    fi
done

# Instalar archivos y verificar la copia
echo -e "\nInstalando archivos en $STATE_DIR..."
if [ -d "../src/" ]; then
    cp -r ../src/* "$STATE_DIR/"
    chmod -R 770 "$STATE_DIR/"
    chown -R "$APP_USER":"$APP_GROUP" "$STATE_DIR/"

    # Verificación de integridad: ¿El directorio de destino tiene archivos?
    FILE_COUNT=$(ls -A "$STATE_DIR" | wc -l)
    if [ "$FILE_COUNT" -gt 0 ]; then
        echo -e "\t${GREEN}[+] Instalación completada en $STATE_DIR ($FILE_COUNT elementos).${NC}"
    else
        echo -e "\t${RED}[-] La carpeta de destino $STATE_DIR está vacía tras la copia.${NC}"
        exit 1
    fi
else
    echo -e "${RED}[-] No se encontró la carpeta fuente ../src. Verifica la ubicación del instalador.${NC}"
    exit 1
fi

# Asegurar existencia de archivos de log/contexto y verificar permisos
echo -e "\nInicializando archivos de registro..."
for f in "$SERVICE_LOG" "$ERROR_LOG"; do
    if [ -z "$f" ]; then
        echo -e "\t${RED}[-] Una de las variables de archivo está vacía en config.conf.${NC}"
        exit 1
    fi
    
    touch "$f"

    if [ $? -eq 0 ]; then
        # Forzamos permisos iniciales para que el usuario de la app pueda escribir
        chmod 770 "$f"
        chown "$APP_USER":"$APP_GROUP" "$f"
        echo -e "\t${GREEN}[+] Archivo preparado: $f${NC}"
    else
        echo -e "\t${RED}[-] No se pudo crear el archivo: $f${NC}"
        exit 1
    fi
done

# Verificar permisos de ejecución en scripts
echo -e "\nOtorgando permisos de ejecución a los scripts..."
find "$STATE_DIR" -type f -name "*.sh" -exec chmod 770 {} +
if [ $(find "$STATE_DIR" -type f -name "*.sh" ! -executable | wc -l) -eq 0 ]; then
    echo -e "\t${GREEN}[+] Todos los scripts .sh son ejecutables.${NC}"
else
    echo -e "\t${RED}[-] Algunos scripts no recibieron permisos de ejecución.${NC}"
    exit 1
fi

# Verificar pertenencia al grupo wireshark
echo -e "\nConfigurando privilegios de red para captura..."
groupadd -f wireshark
usermod -aG wireshark "$APP_USER"
if id -nG "$APP_USER" | grep -qw "wireshark"; then
    echo -e "\t${GREEN}[+] Usuario $APP_USER añadido al grupo wireshark.${NC}"
else
    echo -e "\t${RED}[-] No se pudo añadir al usuario al grupo.${NC}"
    exit 1
fi

### Arrancar servicios
# Configurar y arrancar el servicio de captura
if [ -f "$SERVICE_FILE" ]; then
    echo -e "\nConfigurando el servicio network-sniffer..."
    cp "$SERVICE_FILE" "$SERVICE_DEST"
    systemctl daemon-reload
    systemctl enable network-sniffer.service
    
    echo -e "\tIniciando el servicio network-sniffer..."
    systemctl restart network-sniffer

    # --- Verificación de estado ---
    # Esperamos 2 segundos para que el proceso asiente
    sleep 2

    if systemctl is-active --quiet network-sniffer; then
        echo -e "\t${GREEN}[+] El servicio network-sniffer se está ejecutando correctamente.${NC}"
    else
        echo -e "\t${RED}[-] El servicio network-sniffer no pudo arrancar. Revisar logs...${NC}"
        journalctl -u network-sniffer -n 20 --no-pager
        exit 1
    fi
else
    echo -e "\t${RED}Error: No se encontró el archivo de servicio en $SERVICE_FILE${NC}"
fi

sleep 2

# Configurar y arrancar el servicio de visualización de datos
if [ -f "$SERVICE_WEB_FILE" ]; then
    echo -e "\nConfigurando el servicio network-sniffer-web..."
    cp "$SERVICE_WEB_FILE" "$SERVICE_WEB_DEST"
    systemctl daemon-reload
    systemctl enable network-sniffer-web.service
    
    echo -e "\tIniciando el servicio network-sniffer-web..."
    systemctl start network-sniffer-web

    # --- Verificación de estado ---
    # Esperamos 2 segundos para que el proceso asiente
    sleep 2

    if systemctl is-active --quiet network-sniffer-web; then
        echo -e "\t${GREEN}[+] El servicio network-sniffer-web se está ejecutando correctamente.${NC}"
    else
        echo -e "\t${RED}[-] El servicio network-sniffer-web no pudo arrancar. Revisar logs...${NC}"
        journalctl -u network-sniffer-web -n 20 --no-pager
        exit 1
    fi
else
    echo -e "\t${RED}Error: No se encontró el archivo de servicio en $SERVICE_FILE${NC}"
fi

echo -e "${GREEN}--------------------------------------------------${NC}"
echo -e "${GREEN}\n[+] Instalación completada con éxito!${NC}"
echo -e "\tLogs: $LOG_DIR"
echo -e "${GREEN}--------------------------------------------------${NC}"