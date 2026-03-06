#!/bin/bash
# network-sniffer/src/modules/smtp.sh

# Cargar librería común
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/smtp.pipe"
LOGFILE="$LOG_DIR/smtp.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Verificar si realmente es SMTP
    IS_SMTP=$(echo "$line" | jq -r '.layers.smtp? // empty')
    if [ -z "$IS_SMTP" ]; then
        continue
    fi

    # Sanitizar red (ips)
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ]; then
        # SEGURIDAD: Nunca logueamos $line (JSON crudo) si hay error para evitar inyección
        echo "Error: Dirección IP de origen o destino no encontrada en paquete SMTP" >&2
        continue
    fi

    # Comandos smtp (cliente → servidor)
    # Saneamos tanto el comando como el parámetro
    CMD=$(sanitize_input "$(echo "$line" | jq -r '.layers.smtp.smtp_smtp_req_command? // empty')")
    PARAM=$(sanitize_input "$(echo "$line" | jq -r '.layers.smtp."smtp.command_line.parameter" // empty')")

    # Si es comando SMTP (Petición)
    if [ -n "$CMD" ]; then
        TS=$(get_timestamp)
        echo "[$TS] PROTO=SMTP_OUT SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT CMD=$CMD PARAM=\"${PARAM:-NONE}\"" >> "$LOGFILE"
        continue
    fi

    # Respuestas smtp (servidor → cliente)
    RCODE=$(sanitize_input "$(echo "$line" | jq -r '.layers.smtp.smtp_smtp_response_code? // empty')")

    # Normalizar y sanitizar texto de respuesta
    RTEXT_RAW=$(echo "$line" | jq -r '
        .layers.smtp.smtp_smtp_rsp_parameter? 
        | if type=="array" then join(" | ") else . end
        // empty
    ')
    RTEXT=$(sanitize_input "$RTEXT_RAW")

    # Si es respuesta SMTP
    if [ -n "$RCODE" ]; then
        TS=$(get_timestamp)
        echo "[$TS] PROTO=SMTP_IN SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT CODE=$RCODE TEXT=\"${RTEXT:-NONE}\"" >> "$LOGFILE"
        continue
    fi

done < "$PIPE"