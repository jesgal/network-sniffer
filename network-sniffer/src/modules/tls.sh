#!/bin/bash
# network-sniffer/src/modules/tls.sh

# Cargar librería común (fundamental para sanitize_input, get_timestamp y get_process_info)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/tls.pipe"
LOGFILE="$LOG_DIR/tls.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Extraer y sanitizar el sni
    # El SNI es texto plano y un vector claro de Log Injection
    RAW_SNI=$(echo "$line" | jq -r '.layers.tls?.tls_tls_handshake_extensions_server_name? // empty')
    SNI=$(sanitize_input "$RAW_SNI")

    # Verificamos si se extrajo el SNI
    if [ -z "$SNI" ]; then
        continue
    fi

    # Extraer y santizar ip y puertos
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport // empty')")

    # Verificamos validez de datos críticos
    if [ -z "$SRC" ] || [ -z "$DST" ] || [ -z "$SPORT" ] || [ -z "$DPORT" ]; then
        echo "Error: Datos de red incompletos en paquete TLS" >&2
        continue
    fi

    # Obtener marca de tiempo y proceso (saneando la salida de proc)
    TS=$(get_timestamp)
    PROC=$(sanitize_input "$(get_process_info "$DPORT")")

    # Registro final seguro
    echo "[$TS] PROTO=TLS PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT SNI=\"$SNI\"" >> "$LOGFILE"

done < "$PIPE"