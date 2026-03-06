#!/bin/bash
# network-sniffer/src/modules/bbdd.sh

# Cargar librería común (fundamental para usar sanitize_input y get_timestamp)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/bbdd.pipe"
LOGFILE="$LOG_DIR/bbdd.log"
create_file "$LOGFILE"

# Diccionario de tecnologías por puerto (Estático, es seguro)
declare -A DB_MAP=(
    ["1433"]="MS-SQL-Server"
    ["1521"]="Oracle-DB"
    ["3306"]="MySQL/MariaDB"
    ["4333"]="mSQL"
    ["5432"]="PostgreSQL"
    ["5433"]="PostgreSQL(Alt)"
    ["5984"]="CouchDB"
    ["6379"]="Redis"
    ["7474"]="Neo4j(HTTP)"
    ["7687"]="Neo4j(Bolt)"
    ["8086"]="InfluxDB"
    ["9042"]="Cassandra"
    ["9092"]="Kafka"
    ["9200"]="Elasticsearch"
    ["9300"]="Elasticsearch(Nodes)"
    ["11211"]="Memcached"
    ["27017"]="MongoDB"
    ["50000"]="IBM-DB2"
)

while IFS= read -r line; do

    # Verificar que es TCP
    IS_TCP=$(echo "$line" | jq -r '.layers.tcp? // empty')
    if [ -z "$IS_TCP" ]; then
        continue
    fi

    # Extraer y sanitizar puertos
    # Aunque esperamos números, sanitizamos para evitar inyección de caracteres en el log
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport? // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport? // empty')")

    # Validar que DPORT es estrictamente numérico (Seguridad adicional)
    if [[ -z "$DPORT" || ! "$DPORT" =~ ^[0-9]+$ ]]; then
        continue
    fi

    # Comprobar si el puerto destino está en el diccionario
    if [[ -z "${DB_MAP[$DPORT]}" ]]; then
        continue
    fi

    # Extraer flag SYN
    SYN=$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_flags_syn? // empty')

    # Normalizar SYN
    if [[ "$SYN" == "true" || "$SYN" == "1" || "$SYN" == 1 ]]; then
        SYN=1
    else
        SYN=0
    fi

    # Solo procesar si es SYN (intento de conexión)
    if [ "$SYN" -ne 1 ]; then
        continue
    fi

    # Extraer y sanitizar ips
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src? // .layers.ipv6.ipv6_ipv6_src? // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst? // .layers.ipv6.ipv6_ipv6_dst? // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ]; then
        # Evitamos hacer echo "$line" >> "$LOGFILE" directamente porque $line no está saneado
        echo "Error: Dirección IP de origen o destino no encontrada en paquete TCP" >&2
        continue
    fi

    # Identificar tecnología
    DB_TECH="${DB_MAP[$DPORT]}"

    TS=$(get_timestamp)

    # REGISTRO FINAL (Todos los componentes han sido saneados)
    echo "[$TS] DB_TECH=$DB_TECH SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT" >> "$LOGFILE"

done < "$PIPE"