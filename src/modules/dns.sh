#!/bin/bash
# network-sniffer/src/modules/dns.sh

# Cargar librería común (fundamental para sanitize_input, get_timestamp y get_process_info)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/dns.pipe"
LOGFILE="$LOG_DIR/dns.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Extraer y sanitizar QNAME (El dominio consultado)
    RAW_QNAME=$(echo "$line" | jq -r '.layers.dns?.dns_dns_qry_name? // empty')
    QNAME=$(sanitize_input "$RAW_QNAME")

    QTYPE_NUM=$(echo "$line" | jq -r '.layers.dns?.dns_dns_qry_type? // empty')

    if [ -z "$QNAME" ] || [ -z "$QTYPE_NUM" ]; then
        continue
    fi

    # Mapeo de tipos (Seguro, es interno)
    case "$QTYPE_NUM" in
        1)   QTYPE="A" ;;
        2)   QTYPE="NS" ;;
        5)   QTYPE="CNAME" ;;
        6)   QTYPE="SOA" ;;
        12)  QTYPE="PTR" ;;
        15)  QTYPE="MX" ;;
        16)  QTYPE="TXT" ;;
        28)  QTYPE="AAAA" ;;
        33)  QTYPE="SRV" ;;
        255) QTYPE="ANY" ;;
        *)   QTYPE="TYPE$(sanitize_input "$QTYPE_NUM")" ;;
    esac

    # Sanitizar red (ips y puertos)
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.udp.udp_udp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.udp.udp_udp_dstport // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ] || [ -z "$SPORT" ] || [ -z "$DPORT" ]; then
        continue
    fi

    # Construcción y sanitización de respuestas
    # Las respuestas (especialmente TXT) pueden contener cualquier carácter.
    RAW_RESP=$(echo "$line" | jq -r '
        [
            (.layers.dns?.dns_dns_a      // [] | (if type=="string" then [.] else . end) | map("A:" + .)     | .[]?),
            (.layers.dns?.dns_dns_aaaa   // [] | (if type=="string" then [.] else . end) | map("AAAA:" + .)   | .[]?),
            (.layers.dns?.dns_dns_cname  // [] | (if type=="string" then [.] else . end) | map("CNAME:" + .)  | .[]?),
            (.layers.dns?.dns_dns_ns     // [] | (if type=="string" then [.] else . end) | map("NS:" + .)     | .[]?),
            (.layers.dns?.dns_dns_mx     // [] | (if type=="string" then [.] else . end) | map("MX:" + .)     | .[]?),
            (.layers.dns?.dns_dns_ptr    // [] | (if type=="string" then [.] else . end) | map("PTR:" + .)    | .[]?),
            (.layers.dns?.dns_dns_txt    // [] | (if type=="string" then [.] else . end) | map("TXT:" + .)    | .[]?),
            (.layers.dns?.dns_dns_srv    // [] | (if type=="string" then [.] else . end) | map("SRV:" + .)    | .[]?)
        ]
        | join(",")
    ')
    RESP=$(sanitize_input "$RAW_RESP")

    TS=$(get_timestamp)

    # Identificación de proceso (Saneamos la salida por seguridad)
    if [ "$SPORT" = "53" ]; then
        PROC=$(sanitize_input "$(get_process_info "$DPORT")")
    else
        PROC=$(sanitize_input "$(get_process_info "$SPORT")")
    fi

    # Registro final
    echo "[$TS] PROTO=DNS PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT QTYPE=$QTYPE QNAME=$QNAME RESP=\"${RESP:-NONE}\"" >> "$LOGFILE"

done < "$PIPE"