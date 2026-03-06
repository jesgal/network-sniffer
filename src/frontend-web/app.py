import os
import subprocess
import glob
import re
from markupsafe import escape
from flask import Flask, render_template, request, abort

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')

app = Flask(__name__, template_folder=template_dir)

LOG_DIR = "/var/log/network-sniffer"

def get_log_files():
    """Obtiene la lista de archivos .log de forma segura."""
    try:
        if not os.path.exists(LOG_DIR): 
            return []
        # Filtramos solo archivos con extensión .log
        files = [f for f in os.listdir(LOG_DIR) if f.endswith('.log')]
        files.sort()
        return files
    except Exception as e:
        # Registro básico de errores en lugar de except vacío
        print(f"Error accediendo a LOG_DIR: {e}")
        return []

@app.route('/')
def index():
    logs = get_log_files()
    return render_template('index.html', logs=logs, content=[], selected_log="", search_term="")

@app.route('/view_log')
def view_log():
    selected_log = request.args.get('log', '')
    search_term = request.args.get('search', '').strip()

    if not re.match(r'^[a-zA-Z0-9\.\:\-\ ]*$', search_term):
        return abort(400, "Término de búsqueda contiene caracteres no permitidos")
    
    logs = get_log_files()
    raw_content = ""

    try:
        # VALIDACIÓN DE SEGURIDAD: Evitar Path Traversal
        if selected_log and selected_log != "Búsqueda Global":
            valid_logs = get_log_files()
            if selected_log not in valid_logs:
                return abort(403, "Acceso no autorizado")
            
            log_path = os.path.join(LOG_DIR, selected_log)
            if not os.path.exists(log_path):
                return abort(404, "Archivo no encontrado")

        # LÓGICA DE BÚSQUEDA
        if search_term:
            # Definir archivos donde buscar
            if not selected_log or selected_log == "Búsqueda Global":
                search_files = glob.glob(os.path.join(LOG_DIR, "*.log"))
                display_name = "Búsqueda Global"
            else:
                search_files = [os.path.join(LOG_DIR, selected_log)]
                display_name = selected_log

            if search_files:
                cmd = ["grep", "-i", "--", search_term] + search_files
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
                raw_content = result.stdout
        
        elif selected_log and selected_log != "Búsqueda Global":
            # Si no hay búsqueda, mostrar las últimas 500 líneas del archivo seleccionado
            log_path = os.path.join(LOG_DIR, selected_log)
            result = subprocess.run(["tail", "-n", "500", log_path], capture_output=True, text=True, check=True)
            raw_content = result.stdout
            display_name = selected_log
        else:
            return index()

        # Procesar salida para la plantilla
        if raw_content.strip():
            # Dividimos por líneas, limitamos a las primeras 50000 por rendimiento
            # y escapamos cada línea para seguridad XSS
            content_list = [escape(line) for line in raw_content.strip().split('\n')[:50000]]
        else:
            content_list = ["No se encontraron resultados."]

        return render_template(
            'index.html', 
            logs=logs, 
            content=content_list, 
            selected_log=display_name,
            search_term=search_term
        )

    except Exception as e:
        return f"Error interno: {str(e)}", 500

if __name__ == '__main__':
    # Importante: debug=False en producción
    app.run(host='127.0.0.1', port=5000, debug=False)