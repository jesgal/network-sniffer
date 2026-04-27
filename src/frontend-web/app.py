import os
import glob
import re
import subprocess
from markupsafe import escape
from flask import Flask, render_template, request, abort

# Importar funciones comunes
from logs import (
    LOG_DIR,
    MAX_LINES,
    get_main_logs,
    get_related_logs,
    read_file_reverse,
    read_gz_reverse,
    parse_timestamp
)

# Importar blueprint de análisis
from analysis.stats import analysis_bp

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')

app = Flask(__name__, template_folder=template_dir)

# Registrar blueprint
app.register_blueprint(analysis_bp)


# ---------------------------------------------------------
# RUTA PRINCIPAL
# ---------------------------------------------------------
@app.route('/')
def index():
    logs = get_main_logs()

    service_logs = [l for l in logs if l in ("error.log", "service.log")]
    protocol_logs = [l for l in logs if l not in ("error.log", "service.log")]
    protocol_logs.sort()

    return render_template(
        'index.html',
        service_logs=service_logs,
        protocol_logs=protocol_logs
    )


# ---------------------------------------------------------
# NUEVA RUTA: PROCESAR BÚSQUEDA GLOBAL
# ---------------------------------------------------------
@app.route('/search')
def global_search_query():
    term = request.args.get("q", "").strip()

    # Respuesta vacía si no hay término
    if not term:
        return {"results": [], "term": ""}

    # Validación de caracteres
    if not re.match(r'^[a-zA-Z0-9\.\:\-\ ]*$', term):
        return abort(400, "Término de búsqueda contiene caracteres no permitidos")

    search_files = glob.glob(os.path.join(LOG_DIR, "*"))
    search_files.sort(key=os.path.getmtime)

    results   = []
    all_lines = []
    count     = 0
    
    try:
        for filename in search_files:
            # Comando según tipo de archivo
            if filename.endswith(".gz"):
                cmd = f"zgrep -h -i -- '{term}' '{filename}'"
            else:
                cmd = f"grep -h -i -- '{term}' '{filename}'"

            # Ejecutar búsqueda
            result = subprocess.run(
                ["sh", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            for line in result.stdout.splitlines():
                all_lines.append(line)
                count += 1
                if count >= MAX_LINES: break


        all_lines.sort(key=parse_timestamp, reverse=True)

        return render_template(
            "log_view.html",
            content=all_lines,
            selected_log="",
            search_term=""
        )

    except Exception as e:
        return {"results": [], "term": term, "error": str(e)}



# ---------------------------------------------------------
# RUTA PARA VER LOGS INDIVIDUALES
# ---------------------------------------------------------
@app.route('/view_log')
def view_log():
    selected_log = request.args.get('log', '')

    logs = get_main_logs()

    if not selected_log or selected_log not in logs:
        return render_template("log_view.html", content=[], selected_log="", search_term="")

    try:
        related_files = get_related_logs(selected_log)
        display_name = selected_log

        all_lines = []
        count = 0

        for filename in related_files:
            path = os.path.join(LOG_DIR, filename)
            if filename.endswith(".gz"):
                lines = read_gz_reverse(path)
            else:
                lines = read_file_reverse(path)

            for line in lines:
                all_lines.append(line)
                count += 1
                if count >= MAX_LINES: break

            if count >= MAX_LINES: break

        all_lines.sort(key=parse_timestamp, reverse=True)

        return render_template(
            "log_view.html",
            content=all_lines,
            selected_log=display_name,
            search_term=""
        )

    except Exception as e:
        return f"Error interno: {str(e)}", 500


# ---------------------------------------------------------
# EJECUCIÓN
# ---------------------------------------------------------
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)