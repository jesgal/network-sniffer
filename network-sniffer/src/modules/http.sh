#!/bin/bash
# network-sniffer/src/modules/http.sh

# Cargar librería común (fundamental para sanitize_input, get_timestamp y get_process_info)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/http.pipe"
LOGFILE="$LOG_DIR/http.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Verificar si es HTTP
    IS_HTTP=$(echo "$line" | jq -r '.layers.http // empty')
    if [ -z "$IS_HTTP" ]; then
        continue
    fi

    # Extraer y sanitizar red (ips y puertos)
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ]; then
        continue
    fi

    # Extraer Method y Response Code
    METHOD_RAW=$(echo "$line" | jq -r '.layers.http.http_http_request_method // empty')
    RESP_CODE_RAW=$(echo "$line" | jq -r '.layers.http.http_http_response_code // empty')

    # Extraer y sanitizar Content-Length
    CONTENT_LEN=$(sanitize_input "$(echo "$line" | jq -r '.layers.http.http_http_content_length // empty')")
    [[ -z "$CONTENT_LEN" ]] && CONTENT_LEN="-"

    TS=$(get_timestamp)

    if [ -n "$METHOD_RAW" ]; then
        # Extraer campos de la petición
        HOST_RAW=$(echo "$line" | jq -r '.layers.http.http_http_host // empty')
        URI_RAW=$(echo "$line" | jq -r '.layers.http.http_http_request_uri // empty')

        # SANITIZACIÓN CRÍTICA
        METHOD=$(sanitize_input "$METHOD_RAW")
        HOST=$(sanitize_input "${HOST_RAW:-no-host}")
        URI=$(sanitize_input "${URI_RAW:-/}")

        # Construcción de URL segura (usamos variables ya saneadas)
        URL="http://$HOST$URI"

        # Obtener proceso del cliente (SPORT)
        PROC=$(sanitize_input "$(get_process_info "$SPORT")")

        echo "[$TS] PROTO=HTTP_IN PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT METHOD=$METHOD DOMAIN=$HOST URL=\"$URL\"" >> "$LOGFILE"

    elif [ -n "$RESP_CODE_RAW" ]; then
        # Sanitizar código de respuesta (evita inyección de espacios o texto)
        RESP_CODE=$(sanitize_input "$RESP_CODE_RAW")

        # Obtener proceso del cliente (DPORT en respuesta)
        PROC=$(sanitize_input "$(get_process_info "$DPORT")")

        echo "[$TS] PROTO=HTTP_OUT PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT CODE=$RESP_CODE CONTENT_LEN=$CONTENT_LEN" >> "$LOGFILE"

    else
        continue
    fi

done < "$PIPE"