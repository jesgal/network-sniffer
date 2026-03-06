#!/bin/bash
# network-sniffer/src/modules/icmp.sh

# Cargar librería común (fundamental para sanitize_input y get_timestamp)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/icmp.pipe"
LOGFILE="$LOG_DIR/icmp.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Verificar si es ICMPv4 o ICMPv6
    IS_ICMP=$(echo "$line" | jq -r '.layers.icmp? // empty')
    IS_ICMP6=$(echo "$line" | jq -r '.layers.icmpv6? // empty')

    if [ -z "$IS_ICMP" ] && [ -z "$IS_ICMP6" ]; then
        continue
    fi

    # Extraer y sanitizar ips
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_ipv6_dst // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ]; then
        # Eliminamos echo "$line" >> "$LOGFILE" por seguridad, el JSON crudo no debe ir al log
        echo "Error: Dirección IP de origen o destino no encontrada en paquete ICMP" >&2
        continue
    fi

    # Extraer tipo y código (saneamos para evitar inyecciones de texto)
    TYPE4=$(sanitize_input "$(echo "$line" | jq -r '.layers.icmp.icmp_icmp_type? // empty')")
    TYPE6=$(sanitize_input "$(echo "$line" | jq -r '.layers.icmpv6.icmpv6_icmpv6_type? // empty')")
    CODE=$(sanitize_input "$(echo "$line" | jq -r '.layers.icmp.icmp_icmp_code? // .layers.icmpv6.icmpv6_icmpv6_code? // empty')")

    if [ -z "$TYPE4" ] && [ -z "$TYPE6" ]; then
        continue
    fi

    TS=$(get_timestamp)
    INFO="UNKNOWN"

    # Lógica ICMPv4 (Mapeo interno seguro)
    if [ -n "$TYPE4" ]; then
        case $TYPE4 in
            8)  INFO="PING_REQUEST" ;;
            0)  INFO="PING_REPLY" ;;
            3)  INFO="DEST_UNREACHABLE" ;;
            5)  INFO="REDIRECT" ;;
            11) INFO="TIME_EXCEEDED" ;;
            *)  INFO="TYPE4_$TYPE4" ;;
        esac

    # Lógica ICMPv6 (Mapeo interno seguro)
    elif [ -n "$TYPE6" ]; then
        case $TYPE6 in
            128) INFO="V6_PING_REQUEST" ;;
            129) INFO="V6_PING_REPLY" ;;
            1)   INFO="V6_DEST_UNREACHABLE" ;;
            3)   INFO="V6_TIME_EXCEEDED" ;;
            133) INFO="V6_ROUTER_SOLICITATION" ;;
            134) INFO="V6_ROUTER_ADVERTISEMENT" ;;
            135) INFO="V6_NEIGHBOR_SOLICITATION" ;;
            136) INFO="V6_NEIGHBOR_ADVERTISEMENT" ;;
            *)   INFO="TYPE6_$TYPE6" ;;
        esac
    fi

    # Limpiar el código de espacios y asegurar valor por defecto
    CODE="${CODE:-0}"

    # Registro final
    echo "[$TS] PROTO=ICMP SRC=$SRC DST=$DST INFO=$INFO CODE=$CODE" >> "$LOGFILE"

done < "$PIPE"