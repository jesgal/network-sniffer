#!/bin/bash
# network-sniffer/src/modules/cert.sh

# Cargar librería común (para sanitize_input y get_timestamp)
LIB_PATH="$(dirname "$0")/../lib/common.sh"
if [ -f "$LIB_PATH" ]; then
    source "$LIB_PATH"
else
    echo "Error: No se pudo encontrar $LIB_PATH" >&2
    exit 1
fi

PIPE="$BUS_DIR/cert.pipe"
LOGFILE="$LOG_DIR/cert.log"
create_file "$LOGFILE"

while IFS= read -r line; do

    # Extraer certificado en HEX desde JSON
    CERT_HEX=$(echo "$line" | jq -r '.layers.tls[0]?["tls_tls_handshake_certificate"] | (if type=="array" then .[0] else . end) // empty')

    [ -z "$CERT_HEX" ] && continue

    # Archivos temporales seguros
    TMP_DER=$(mktemp)
    TMP_PEM=$(mktemp)

    # HEX → DER
    echo "$CERT_HEX" | xxd -r -p > "$TMP_DER"

    # DER → PEM (Redirigimos errores a /dev/null por seguridad)
    openssl x509 -inform DER -in "$TMP_DER" -out "$TMP_PEM" 2>/dev/null
    if [ $? -ne 0 ]; then
        rm -f "$TMP_DER" "$TMP_PEM"
        continue
    fi

    # Extracción y sanitización de campos
    # Saneamos CN e ISSUER (pueden contener cualquier texto)
    CN=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -subject | sed 's/.*CN=//')")
    ISSUER=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -issuer | sed 's/.*CN=//')")
    
    # Saneamos fechas (aunque tienen formato fijo, evitamos sorpresas)
    NOT_BEFORE=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -startdate | cut -d= -f2-)")
    NOT_AFTER=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -enddate | cut -d= -f2-)")
    
    # Fingerprint y Algoritmos
    FINGERPRINT=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -fingerprint -sha256 | cut -d= -f2)")
    
    # Saneamos datos técnicos extraídos con awk/grep
    KEY_ALGO=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -text | grep "Public Key Algorithm" | head -1 | awk -F: '{print $2}' | xargs)")
    KEY_SIZE=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -text | grep "Public-Key" | awk -F'[()]' '{print $2}' | xargs)")
    SIG_ALGO=$(sanitize_input "$(openssl x509 -in "$TMP_PEM" -noout -text | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)")
    
    # SAN (Subject Alternative Name) es MUY propenso a inyecciones
    SAN_RAW=$(openssl x509 -in "$TMP_PEM" -noout -text | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/ *//')
    SAN=$(sanitize_input "$SAN_RAW")

    # Timestamp
    TS=$(get_timestamp)

    # Registro final
    # Usamos comillas dobles en el echo para asegurar que los valores saneados se traten como strings
    echo "[$TS] PROTO=TLS CERT_CN=\"$CN\" ISSUER=\"$ISSUER\" NOT_BEFORE=\"$NOT_BEFORE\" NOT_AFTER=\"$NOT_AFTER\" KEY_ALGO=\"$KEY_ALGO\" KEY_SIZE=\"$KEY_SIZE\" SIG_ALGO=\"$SIG_ALGO\" SAN=\"$SAN\" SHA256=\"$FINGERPRINT\"" >> "$LOGFILE"

    # Limpieza de temporales
    rm -f "$TMP_DER" "$TMP_PEM"

done < "$PIPE"