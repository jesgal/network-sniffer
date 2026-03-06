#!/bin/bash
# network-sniffer/src/modules/sniffer_core.sh

# Creamos pipes para enviar datos del sniffer de red
mkfifo "$BUS_DIR/tls.pipe" >&2
mkfifo "$BUS_DIR/cert.pipe" >&2
mkfifo "$BUS_DIR/dns.pipe" >&2
mkfifo "$BUS_DIR/http.pipe" >&2
mkfifo "$BUS_DIR/icmp.pipe" >&2
mkfifo "$BUS_DIR/ssh.pipe" >&2
mkfifo "$BUS_DIR/smtp.pipe" >&2
mkfifo "$BUS_DIR/bbdd.pipe" >&2
mkfifo "$BUS_DIR/smb.pipe" >&2

dumpcap -i "$INTERFACE" -P -w - 2>> /dev/null \
  | tshark -r - -T ek 2>> /dev/null \
  | stdbuf -oL tee \
    "$BUS_DIR/tls.pipe" \
    "$BUS_DIR/cert.pipe" \
    "$BUS_DIR/dns.pipe" \
    "$BUS_DIR/http.pipe" \
    "$BUS_DIR/icmp.pipe" \
    "$BUS_DIR/ssh.pipe" \
    "$BUS_DIR/smtp.pipe" \
    "$BUS_DIR/bbdd.pipe" \
    "$BUS_DIR/smb.pipe" \
> /dev/null