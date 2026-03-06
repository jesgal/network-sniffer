# Network Sniffer Suite 🛡️

**Network Sniffer Suite** es una herramienta modular de análisis de tráfico de red basada en **Bash**, diseñada para la monitorización en tiempo real y la generación de logs enriquecidos por protocolo.

Esta diseñada para ser una herramienta segura y de bajo consumo🌱.

El sistema utiliza una arquitectura de tuberías (**pipes FIFO**) para distribuir el tráfico capturado por `dumpcap` hacia múltiples módulos especializados que procesan la información de forma independiente.

## 🔍 Correlación de Procesos
Cada entrada en los logs incluye, siempre que sea posible, el **PID** y el **Nombre del Proceso** local que ha generado o recibido el tráfico, permitiendo una trazabilidad total desde la red hasta el binario en ejecución.

## 🚀 Características Principales
* **Captura Multitarea:** Uso de `dumpcap` y `tshark` para la captura y transformación de paquetes a JSON.
* **Identificación de Procesos:** Vinculación automática de conexiones de red con el proceso local (PID y nombre) que las originó mediante la utilidad `ss`.
* **Arquitectura Modular:** Módulos específicos para DNS, HTTP, TLS, Certificados, SSH, SMB, SMTP, Bases de Datos e ICMP.
* **Gestión de Logs:** Integración nativa con **logrotate**.
* **Sistema de Watchdog:** Supervisión automática que reinicia módulos en caso de caída (hasta un máximo de 3 reintentos).
* **Soporte Dual:** Compatibilidad completa con protocolos **IPv4 e IPv6**.
* **Interfaz Web:** Panel de visor de registros de actividad, garantizando una experiencia responsiva y visualmente clara.

## 🏗️ Arquitectura

```
        dumpcap
           │
           ▼
        tshark
           │
           ▼
        JSON (EK)
           │
           ▼
         tee
   ┌───────┼───────────────────────────────┐
   ▼       ▼       ▼       ▼       ▼       ▼
 tls     http     dns     ssh     smb     ...
pipe     pipe     pipe    pipe    pipe
   │       │       │       │       │
   ▼       ▼       ▼       ▼       ▼
 módulos independientes de análisis
```

Cada módulo consume eventos desde su FIFO correspondiente y genera logs especializados.

## 🧩 Dependencias

Para que la suite funcione correctamente, asegúrate de tener instaladas las siguientes herramientas:

* **Wireshark (dumpcap/tshark):** Para la captura y disección de paquetes.
* **jq:** Imprescindible para procesar los datos en formato JSON.
* **openssl:** Utilizado por los módulos de seguridad para analizar certificados.
* **libcap2-bin:** (Recomendado) Proporciona el comando `setcap`, necesario para que el usuario `network-sniffer` pueda capturar tráfico sin ser root.
* **iproute2:** Proporciona el comando `ss` (normalmente ya instalado).
* **python3:** Con las librerías os, subprocess, glob, re, markupsafe, flask


```bash
sudo apt update
sudo apt install -y wireshark tshark jq openssl libcap2-bin iproute2
sudo apt install -y python3 python3-flask python3-markupsafe
```

El proyecto ha sido validado con las siguientes versiones:

* **Wireshark (dumpcap/tshark):** v4.2.2+.
* **jq:** v1.7+ (para el procesamiento de JSON).
* **OpenSSL:** v3.0+ (para el análisis de certificados).
* **Bash:** v4.0+ (requerido para el uso de diccionarios/arrays asociativos).

## 📁 Estructura del Proyecto
```text
network-sniffer/
├── LICENSE                 # Términos legales y condiciones de uso del software.
├── README.md               # Manual principal.
├── install/                # --- GESTIÓN DEL CICLO DE VIDA ---
│   ├── audit_test.sh       # Script para verificar que la captura y los permisos funcionan.
│   ├── install.sh          # Instala la aplicación como servicio
│   └── uninstall.sh        # Desinstala la aplicación
└── src/                    # --- CÓDIGO FUENTE (CORE) ---
    ├── network-sniffer.sh  # Ejecutable principal que orquesta la captura de datos.
    ├── frontend-web/       # --- INTERFAZ DE USUARIO (FLASK/PYTHON) ---
    │   ├── app.py          # Servidor web (backend) que sirve los datos capturados.
    │   ├── static/         # Recursos estáticos para el navegador.
    │   │   └── css/        # Estilos visuales (Bootstrap 5).
    │   │       ├── bootstrap-icons.css # Iconografía para identificar protocolos.
    │   │       ├── bootstrap.min.css   # Framework CSS para diseño responsivo.
    │   │       └── fonts/              # Archivos de fuentes para los iconos.
    │   │           ├── bootstrap-icons.woff
    │   │           └── bootstrap-icons.woff2
    │   └── templates/      # Plantillas HTML.
    │       └── index.html  # Página principal donde se visualiza el tráfico.
    ├── lib/                # --- LIBRERÍAS Y CONFIGURACIÓN ---
    │   ├── common.sh       # Variables globales (rutas, colores, funciones comunes).
    │   ├── config.conf     # Parámetros ajustables.
    │   ├── logrotate/      # Configuración de rotado de logs.
    │   │   └── network-sniffer
    │   └── systemd/        # Configuración para ejecutar la aplicación en segundo plano.
    │       ├── network-sniffer-web.service # Servicio para la web.
    │       └── network-sniffer.service     # Servicio para el motor de captura.
    └── modules/            # --- MÓDULOS DE ANÁLISIS DE PROTOCOLOS ---
        ├── bbdd.sh         # Lógica de almacenamiento y persistencia de datos.
        ├── cert.sh         # Análisis de certificados SSL/TLS.
        ├── dns.sh          # Captura y resolución de consultas DNS.
        ├── http.sh         # Extracción de cabeceras y datos de tráfico web plano.
        ├── icmp.sh         # Monitoreo de pings y mensajes de control.
        ├── proccess.sh     # Vincula el tráfico de red con procesos locales del sistema.
        ├── smb.sh          # Análisis de protocolos de compartición de archivos.
        ├── smtp.sh         # Captura de tráfico de correo electrónico.
        ├── sniffer_core.sh # El motor base de captura de red.
        ├── ssh.sh          # Identificación de conexiones seguras por terminal.
        └── tls.sh          # Obtención de SNI de comunicación TLS.
```

## ⚠️ Seguridad

El sistema está diseñado para ejecutarse con privilegios limitados. El archivo de servicio de `systemd` utiliza `ProtectSystem=true` para proteger directorios críticos como `/usr` o `/boot`.

## ⚙️ Configuración e Instalación

* **Interfaz de Red:** Define tu interfaz en `src/lib/config.conf` (por defecto: `any`).
* **Directorios:** El sistema utiliza `/etc/network-sniffer` como directorio de la aplicación, `/var/log/network-sniffer` para los registros de actividad y `/tmp/network-sniffer` como directorio temporal.
* **Servicio Systemd:** Se incluye archivos de configuración de servicio para ejecutar la suite de forma persistente bajo el usuario `network-sniffer`.
* **Identidad:** En la instalación se crea y configura la identidad de aplicación `network-sniffer`.
* **Configuracion:** Fichero de configuración de directorios `/etc/network-sniffer/config.conf`

### Instalación sugerida (como root)
* **Instalación:** `network-sniffer/install/install.sh`
* **Desinstalación:** `network-sniffer/install/uninstall.sh`
* **Auditoría:** `network-sniffer/install/audit_test.sh`

## 📊 Protocolos Soportados

La suite analiza el tráfico y genera logs detallados en `/var/log/network-sniffer/` para los siguientes protocolos:

* **HTTP:** Captura métodos (GET, POST, etc.), Dominios (Host), URLs y códigos de respuesta.
* **DNS:** Registra consultas (QNAME), tipos de registro (A, AAAA, MX, CNAME, TXT) y respuestas.
* **TLS/SSL:** Extracción del SNI y análisis de Certificados X.509 (CN, Emisor, validez y SHA256).
* **Bases de Datos (Módulo DB):** Identificación avanzada para los siguientes motores:
    * **MySQL / MariaDB** (3306)
    * **PostgreSQL** (5432, 5433)
    * **Oracle DB** (1521)
    * **MS-SQL Server** (1433)
    * **MongoDB** (27017)
    * **Redis** (6379)
    * **Elasticsearch** (9200, 9300)
    * **Cassandra** (9042)
    * **Kafka** (9092)
    * **InfluxDB** (8086)
    * **Neo4j** (7474, 7687)
    * **CouchDB** (5984)
    * **Memcached** (11211)
    * **IBM DB2** (50000)
    * **mSQL** (4333)
* **SMB:** Monitorización de transferencias de archivos y enumeración de recursos.
* **SMTP:** Monitorización de flujo de correo,
* **SSH:** Monitorizacion de conexione SSH.
* **ICMP:** Monitorización de protocolo ICMP.

## 📜 Licencia / License

Este proyecto se distribuye bajo la licencia **[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/)**.

### 🎓 Uso Educativo y Personal (Gratuito)

Se autoriza el uso **completamente gratuito** para:

* **Estudiantes y Profesores:** Uso en clases, laboratorios y proyectos académicos.
* **Investigadores:** Análisis de tráfico para publicaciones científicas o seguridad.
* **Entusiastas (Home Lab):** Pruebas en redes domésticas con fines de aprendizaje personal.

### 💼 Uso Comercial y Profesional (Requiere autorización)

Esta versión está optimizada para ser utilizada en un entorno personal o educativo.

Por favor ponte en contacto conmigo para realizar la adaptación si quieres usar esta suite en los siguientes escenarios:

* **Entornos Corporativos:** Monitorización de redes de empresas o instituciones.
* **Consultoría de Seguridad:** Uso de la herramienta para prestar servicios a terceros (Auditorías, Pentesting, SOC).
* **Redistribución:** Integración de este código en productos o servicios comerciales.

Copyright (c) 2026

---

> **Nota sobre Dependencias:** Este software invoca herramientas externas (`tshark`, `jq`, `openssl`, `ss`) que se rigen por sus propias licencias de software libre (GPL, MIT, Apache). El uso de esta suite respeta dichas licencias al no modificar su código fuente original.