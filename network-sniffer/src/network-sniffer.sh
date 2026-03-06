#!/bin/bash
# network-sniffer/src/network-sniffer.sh

BASE_DIR=$(dirname "$(readlink -f "$0")")
source "$BASE_DIR/lib/common.sh"

# Configuración del Watchdog
MAX_RETRIES=3        # Máximo de reintentos antes de desistir
declare -A RETRIES   # Diccionario para contar fallos por módulo
declare -A PIDS      # Diccionario para rastrear PIDs

# Limpieza al salir
cleanup() {
    echo "[$(get_timestamp)] [!] Señal de parada recibida. Terminando módulos..."  >> "$SERVICE_LOG"
    for name in "${!PIDS[@]}"; do
        kill "${PIDS[$name]}" >&2
    done
    exit 0
}
trap cleanup SIGINT SIGTERM

# Redirección y Errores
#exec >> "$SERVICE_LOG" 2>&1

# Borrar directorio temporal para recreación
rm -rf "$BUS_DIR/*"

# Crear la estructura de directorios
echo "Creando estructura de directorios..." >> "$SERVICE_LOG"
# Intentar crear el directorio
if mkdir -p "$BUS_DIR"; then
    chmod -R 770 "$BUS_DIR"
    chown -R "$APP_USER":"$APP_GROUP" "$BUS_DIR"
    # Verificar si es un directorio real y si tenemos permisos de escritura (como root)
    if [[ -d "$BUS_DIR" && -w "$BUS_DIR" ]]; then
        echo -e "${GREEN}[+] Directorio creado y accesible: $BUS_DIR${NC}" >> "$SERVICE_LOG"
    fi
fi

log_system_error() {
    local message="$1"
    [[ -n "$message" ]] && echo "[$(get_timestamp)] [ERROR] [system] $message" >> "$ERROR_LOG"
}
exec 2> >(while read -r line; do log_system_error "$line"; done)

# Gestión de Módulos
declare -A MODULES=(
    ["core"]="$BASE_DIR/modules/sniffer_core.sh"
    ["proc"]="$BASE_DIR/modules/proccess.sh"
    ["cert"]="$BASE_DIR/modules/cert.sh"
    ["tls"]="$BASE_DIR/modules/tls.sh"
    ["dns"]="$BASE_DIR/modules/dns.sh"
    ["http"]="$BASE_DIR/modules/http.sh"
    ["icmp"]="$BASE_DIR/modules/icmp.sh"
    ["ssh"]="$BASE_DIR/modules/ssh.sh"
    ["smtp"]="$BASE_DIR/modules/smtp.sh"
    ["bbdd"]="$BASE_DIR/modules/bbdd.sh"
    ["smb"]="$BASE_DIR/modules/smb.sh"
)

start_module() {
    local name=$1
    local script=$2

    # Si ya superó el límite de errores, no lo intentamos más
    if [[ ${RETRIES[$name]} -ge $MAX_RETRIES ]]; then
        return
    fi

    if [[ -f "$script" ]]; then
        # Obtener dueño y permisos numéricos (ej. 770)
        OWNER=$(stat -c '%U' "$script")
        PERMS=$(stat -c '%a' "$script")

        # Validación estricta: 
        # - No debe ser de root.
        # - NO debe tener permiso de escritura para 'otros' (el último dígito debe ser 0)
        if [[ "$OWNER" == "$APP_USER" ]] && [[ "$PERMS" =~ ^[0-7][0-7]0$ ]]; then
            
            bash "$script" &
            PIDS["$name"]=$!
            
            echo "[+][$(get_timestamp)] Módulo [$name] iniciado (PID: ${PIDS[$name]})" >> "$SERVICE_LOG"
        else
            echo -e "[!][$(get_timestamp)] ERROR DE SEGURIDAD: Permisos inseguros en $script" >&2
            # Bloqueamos por seguridad
            RETRIES["$name"]=$MAX_RETRIES 
        fi
    else
        echo "[$(get_timestamp)] [-] Error crítico: No se encuentra $script" >&2
        RETRIES["$name"]=$MAX_RETRIES
    fi


}

echo "[$(get_timestamp)] --- Iniciando Network Sniffer Suite ---"  >> "$SERVICE_LOG"

# Iniciar core primero
RETRIES["core"]=0
start_module "core" "${MODULES["core"]}"

# Esperar unos segundos para que cree los pipes y arranque dumpcap/tshark
sleep 3

# Iniciar el resto de módulos
for name in "${!MODULES[@]}"; do
    [[ "$name" == "core" ]] && continue
    RETRIES[$name]=0
    start_module "$name" "${MODULES[$name]}"
done

# Bucle de Supervisión
while true; do
    for name in "${!MODULES[@]}"; do
        # ¿El módulo está en estado error? Saltamos.
        [[ ${RETRIES[$name]} -ge $MAX_RETRIES ]] && continue

        # ¿Sigue vivo el proceso?
        if ! ps -p "${PIDS[$name]}" > /dev/null; then
            ((RETRIES[$name]++))
            echo "[$(get_timestamp)] [!] Módulo [$name] CAÍDO (Intento ${RETRIES[$name]}/$MAX_RETRIES)" >&2
            if [[ ${RETRIES[$name]} -ge $MAX_RETRIES ]]; then
                echo "[$(get_timestamp)] [-] Módulo [$name] ha fallado demasiadas veces. Deshabilitado." >&2
            else
                start_module "$name" "${MODULES[$name]}"
            fi
        fi
    done
    sleep 5
done