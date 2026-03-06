#!/bin/bash
# network-sniffer/src/modules/ssh.sh

# Cargar librería común (fundamental para sanitize_input, get_timestamp y get_process_info)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/ssh.pipe"
LOGFILE="$LOG_DIR/ssh.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Verificar si realmente es SSH
    IS_SSH=$(echo "$line" | jq -r '.layers.ssh? // empty')
    if [ -z "$IS_SSH" ]; then
        continue
    fi

    # Extraer y sanitizar red (ips y puertos)
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ] || [ -z "$SPORT" ] || [ -z "$DPORT" ]; then
        # SEGURIDAD: Nunca logueamos $line (JSON crudo) para evitar inyecciones
        echo "Error: Datos de red incompletos en paquete SSH" >&2
        continue
    fi

    # Extraer y sanitizar versión ssh
    # El banner de SSH (ej: "SSH-2.0-OpenSSH_8.9p1") es un vector de inyección de logs
    RAW_SSH_PROTO=$(echo "$line" | jq -r '.layers.ssh.ssh_ssh_protocol? // empty')
    SSH_PROTO=$(sanitize_input "$RAW_SSH_PROTO")

    TS=$(get_timestamp)

    # Determinar dirección y proceso (saneamos la salida de proc)
    if [ "$DPORT" = "22" ]; then
        # SSH saliente (el proceso local está en el puerto origen)
        PROC=$(sanitize_input "$(get_process_info "$SPORT")")
        TAG="SSH_OUT"
    else
        # SSH entrante (el proceso local está en el puerto destino)
        PROC=$(sanitize_input "$(get_process_info "$DPORT")")
        TAG="SSH_IN"
    fi

    # Registro final (todo limpio y garantizado)
    echo "[$TS] PROTO=$TAG PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT VER=\"${SSH_PROTO:-UNKNOWN}\"" >> "$LOGFILE"

done < "$PIPE"