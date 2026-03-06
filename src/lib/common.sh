#!/bin/bash
# network-sniffer/src/lib/common.sh

# Cargar configuración
readonly CONF_FILE="/etc/network-sniffer/lib/config.conf"
if [ -f "$CONF_FILE" ]; then
    source "$CONF_FILE";
else
    echo "[!] Error al cargar el fichero de configuración." >&2
    exit 1;
fi

# Exportar variables ANTES de las funciones para asegurar disponibilidad
export INTERFACE
export STATE_DIR LOG_DIR BUS_DIR LIB_DIR MODULES_DIR
export SERVICE_LOG ERROR_LOG LOGROTATE_SRC LOGROTATE_DEST TMP_PROC_CONTEXT
export SERVICE_FILE
export APP_USER APP_GROUP

get_timestamp() {
    date +"%d-%m-%Y %H:%M:%S.%3N%:z"
}

get_process_info() {
    local sport=$1
    
    # Limpieza robusta: extrae solo el primer bloque de números
    sport=$(echo "$sport" | grep -oE '[0-9]+' | head -n 1)
    [ -z "$sport" ] && { echo "Desconocido"; return; }

    local match=$(grep "|$sport|" "$TMP_PROC_CONTEXT" 2>/dev/null | tail -n 1)
    
    if [ -n "$match" ]; then
        local pid=$(echo "$match" | cut -d'|' -f1)
        local proc=$(echo "$match" | cut -d'|' -f2)
        echo "$proc PID=$pid"
    else
        local flag="-tnp"
        [[ "$proto" == "UDP" ]] && flag="-unp"
        # Usamos sudo aquí porque 'ss -p' requiere privilegios para ver el nombre del proceso
        local live=$(/usr/bin/ss $flag 2>/dev/null | \
             grep -E "(:|\])$sport " | \
             head -n 1 | \
             awk '{
                if (match($0, /users:\(\("([^"]+)",(pid|pgid)=([0-9]+)/, m)) {
                    printf "%s PID=%s", m[1], m[3]
                }
             }')
        
        echo "${live:-Desconocido}"
    fi
}

create_file() {
    local FILEPATH="$1"
    touch "$FILEPATH"
    chown "$APP_USER":"$APP_GROUP" "$FILEPATH"
    chmod 660 "$FILEPATH"
}

sanitize_input() {
    # Recibe la cadena
    # 'tr -cd' elimina todo lo que no sea un carácter imprimible (ASCII 32-126)
    # 'cut' limita la cadena a 255 caracteres para evitar logs excesivos
    echo "$1" | tr -cd '[:print:]' | cut -c 1-255
}

# Exportar funciones
export -f get_timestamp get_process_info create_file sanitize_input