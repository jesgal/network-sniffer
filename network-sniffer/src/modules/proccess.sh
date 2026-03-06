#!/bin/bash
# network-sniffer/src/modules/proccess.sh

LOGFILE="$LOG_DIR/proccess.log"
create_file "$LOGFILE"

TMP_PROC_CURRENT="$BUS_DIR/proc_current$$.txt"
TMP_PROC_CONTEXT="$BUS_DIR/proc_context.txt"
create_file "$TMP_PROC_CURRENT"
create_file "$TMP_PROC_CONTEXT"

# Limpieza al salir
trap "rm -f $TMP_PROC_CURRENT" EXIT

while true; do
    # -t (TCP) -u (UDP) -p (Process) -n (Numeric)
    timeout 5s bash -c "/usr/bin/ss -tupn | awk '
    NR>1 {
        match(\$0, /users:\(\(\"([^\"]+)\",pid=([0-9]+)/, m);
        proc = m[1]; pid = m[2];
        proto = (\$1 ~ /tcp/) ? \"TCP\" : \"UDP\";

        # Identificar puerto buscando el último \":\" (compatible con IPv6)
        n = split(\$5, addr_src, \":\");
        src_port = addr_src[n];
        src_ip = substr(\$5, 1, length(\$5) - length(src_port) - 1);
        gsub(/[\\[\\]]/, \"\", src_ip);

        m_dst = split(\$6, addr_dst, \":\");
        dst_port = addr_dst[m_dst];
        dst_ip = substr(\$6, 1, length(\$6) - length(dst_port) - 1);
        gsub(/[\\[\\]]/, \"\", dst_ip);

        if (pid != \"\" && dst_ip != \"*\" && dst_ip != \"0.0.0.0\" && dst_ip != \"::\" && dst_ip != \"::1\") {
            print pid \"|\" proc \"|\" proto \"|\" src_ip \"|\" src_port \"|\" dst_ip \"|\" dst_port
        }
    }' | sort -u" > "$TMP_PROC_CURRENT"

    # Comparar conexiones nuevas
    NEW_LINES=$(comm -13 "$TMP_PROC_CONTEXT" "$TMP_PROC_CURRENT")

    if [ -n "$NEW_LINES" ]; then
        while IFS="|" read -r PID PROC PROTO SRC SPORT DST DPORT; do
            TS=$(date +"%d-%m-%Y %H:%M:%S.%3N%:z")
            # Log formateado con el nuevo campo PROTO
            echo "[$TS] PROTO=$PROTO PROC=$PROC PID=$PID SRC=${SRC} SPORT=${SPORT} DST=${DST} DPORT=${DPORT}" >> "$LOGFILE"
        done <<< "$NEW_LINES"

        # Actualizar el estado de conexiones conocidas
        printf "%s\n" "$NEW_LINES" >> "$TMP_PROC_CONTEXT"
        sort -u "$TMP_PROC_CONTEXT" -o "$TMP_PROC_CONTEXT"
    fi
done