import os
import re
from collections import Counter, defaultdict
from flask import Blueprint, render_template, request, abort

from logs import (
    LOG_DIR,
    get_main_logs,
    get_related_logs,
    read_file_reverse,
    read_gz_reverse
)

analysis_bp = Blueprint("analysis", __name__)

# ============================
# REGEX INDIVIDUALES
# ============================

TS_REGEX = re.compile(r'\[(?P<ts>[\d\-:.\+ ]+)\]')
PROTO_REGEX = re.compile(r'PROTO=(\w+)')
PROC_REGEX = re.compile(r'PROC=([\w\-.]+)')
SRC_IP_REGEX = re.compile(r'SRC=([\d\.]+)')
DST_IP_REGEX = re.compile(r'DST=([\d\.]+)')
SNI_REGEX = re.compile(r'SNI="([^"]+)"')

TS_MINUTE = re.compile(r'(\d{2}-\d{2}-\d{4} \d{2}:\d{2})')


@analysis_bp.route('/analysis/stats')
def analysis_stats():
    selected_log = request.args.get('log', '')

    if not selected_log:
        return abort(400, "No se especificó ningún log")

    logs = get_main_logs()
    if selected_log not in logs:
        return abort(403, "Acceso no autorizado")

    related_files = get_related_logs(selected_log)
    all_lines = []

    for filename in related_files:
        path = os.path.join(LOG_DIR, filename)

        try:
            if filename.endswith(".gz"):
                lines = read_gz_reverse(path)[::-1]
            else:
                lines = read_file_reverse(path)[::-1]

            all_lines.extend(lines)

        except Exception as e:
            print(f"Error leyendo {filename}: {e}")

    total_lines = len(all_lines)

    ip_src = Counter()
    ip_dst = Counter()
    sni_count = Counter()
    process_count = Counter()
    protocol_count = Counter()
    timeline = Counter()

    process_to_sni = defaultdict(set)

    for line in all_lines:

        ts = TS_REGEX.search(line)
        if ts:
            tm = TS_MINUTE.search(ts.group("ts"))
            if tm:
                timeline[tm.group(1)] += 1

        proto = PROTO_REGEX.search(line)
        if proto:
            protocol_count[proto.group(1)] += 1

        proc = PROC_REGEX.search(line)
        proc_name = proc.group(1) if proc else None
        if proc_name:
            process_count[proc_name] += 1

        src = SRC_IP_REGEX.search(line)
        if src:
            ip_src[src.group(1)] += 1

        dst = DST_IP_REGEX.search(line)
        if dst:
            ip_dst[dst.group(1)] += 1

        sni = SNI_REGEX.search(line)
        sni_value = sni.group(1) if sni else None
        if sni_value:
            sni_count[sni_value] += 1

        if proc_name and sni_value:
            process_to_sni[proc_name].add(sni_value)

    total_ip_src = len(ip_src)
    total_ip_dst = len(ip_dst)
    total_sni = len(sni_count)
    total_process = len(process_count)

    # Limitar SNI a 100 para la vista
    sni_limited = dict(list(sni_count.items())[:100])

    return render_template(
        "stats.html",
        selected_log=selected_log,
        total_lines=total_lines,
        total_ip_src=total_ip_src,
        total_ip_dst=total_ip_dst,
        total_sni=total_sni,
        total_process=total_process,
        sni_count = dict(sni_count.most_common(100)),
        process_count=process_count,
        process_to_sni=process_to_sni,
        top_protocols=protocol_count.most_common(),
        timeline=timeline
    )
