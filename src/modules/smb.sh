#!/bin/bash
# network-sniffer/src/modules/smb.sh

# Cargar librería común (para usar sanitize_input, get_timestamp y get_process_info)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/smb.pipe"
LOGFILE="$LOG_DIR/smb.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Verificar que es TCP
    IS_TCP=$(echo "$line" | jq -r '.layers.tcp? // empty')
    if [ -z "$IS_TCP" ]; then
        continue
    fi

    # Verificar que es SMB
    IS_SMB=$(echo "$line" | jq -r '.layers.smb? // .layers.smb2? // empty')
    if [ -z "$IS_SMB" ]; then
        continue
    fi

    # Extraer y sanitizar red (ips y puertos)
    SRC=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_src // .layers.ipv6.ipv6_ipv6_src // empty')")
    DST=$(sanitize_input "$(echo "$line" | jq -r '.layers.ip.ip_ip_dst // .layers.ipv6.ipv6_ipv6_dst // empty')")
    SPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_srcport // empty')")
    DPORT=$(sanitize_input "$(echo "$line" | jq -r '.layers.tcp.tcp_tcp_dstport // empty')")

    if [ -z "$SRC" ] || [ -z "$DST" ]; then
        # Eliminamos el log de la línea cruda por seguridad
        echo "Error: Dirección IP no encontrada en paquete SMB" >&2
        continue
    fi

    # Protocolo (Saneamos por si acaso tshark devuelve algo extraño)
    PROTO=$(sanitize_input "$(echo "$line" | jq -r '.layers["_ws.col.Protocol"]? // empty')")

    # Comandos (Son numéricos, pero los tratamos como texto seguro)
    CMD2=$(sanitize_input "$(echo "$line" | jq -r '.layers.smb2.smb2_smb2_cmd? // empty')")
    CMD1=$(sanitize_input "$(echo "$line" | jq -r '.layers.smb.smb_smb_cmd? // empty')")

    # Extracción y sanitización de campos smb (crítico)
    FILE=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_filename? // empty')")
    TREE=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_tree? // empty')")
    ACCT=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_acct? // empty')")
    DOMAIN=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_domain? // empty')")
    
    # GUIDs y Metadatos técnicos
    CLIENT_GUID=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_client_guid? // empty')")
    SERVER_GUID=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_server_guid? // empty')")
    DIALECT=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_dialect? // empty')")
    SIGN_REQ=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_sec_mode_sign_required? // empty')")
    ENCRYPT_CAP=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_capabilities_encryption? // empty')")
    ENCRYPT_SES=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_ses_flags_encrypt? // empty')")
    NTSTATUS=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_nt_status? // empty')")
    EOF_SIZE=$(sanitize_input "$(echo "$line" | jq -c -r '.layers.smb2.smb2_smb2_eof? // empty')")

    # Identificación de operación SMB
    INFO="UNKNOWN"
    if [ -n "$CMD2" ]; then
        case "$CMD2" in
            0)  INFO="SMB2_NEGOTIATE" ;;
            3)  INFO="SMB2_SESSION_SETUP" ;;
            5)  INFO="SMB2_OPEN_FILE" ;;
            11) INFO="SMB2_TREE_CONNECT" ;; # Quitamos $TREE de aquí, ya se loguea aparte
            *)  INFO="SMB2_CMD_$CMD2" ;;
        esac
    elif [ -n "$CMD1" ]; then
        INFO="SMBv1_CMD_$CMD1"
    else
        INFO="SMB_UNKNOWN"
    fi

    # Dirección y proceso local (Saneamos la salida de PROC)
    if [[ "$DPORT" == "445" || "$DPORT" == "139" ]]; then
        DIR="OUT"
        PROC=$(sanitize_input "$(get_process_info "$SPORT")")
    else
        DIR="IN"
        PROC=$(sanitize_input "$(get_process_info "$DPORT")")
    fi

    TS=$(get_timestamp)

    # Registro final (todo garantizado como texto imprimible)
    echo "[$TS] PROTO=$PROTO DIR=$DIR PROC=$PROC SRC=$SRC SPORT=$SPORT DST=$DST DPORT=$DPORT OP=$INFO FILE=[${FILE:-N/A}] ACCT=${ACCT:-N/A} DOMAIN=${DOMAIN:-N/A} DIALECT=${DIALECT:-N/A} SIGN_REQ=${SIGN_REQ:-N/A} ENC_CAP=${ENCRYPT_CAP:-N/A} ENC_SES=${ENCRYPT_SES:-N/A} NTSTATUS=${NTSTATUS:-N/A} EOF=${EOF_SIZE:-N/A} CLIENT_GUID=${CLIENT_GUID:-N/A} SERVER_GUID=${SERVER_GUID:-N/A}" >> "$LOGFILE"

done < "$PIPE"