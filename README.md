# euneiz-redes1 - Sniffer de Red

Práctica de captura y análisis de tráfico de red en tiempo real para el Grado en Seguridad de EUNEIZ.

El programa captura paquetes de una interfaz de red, los procesa según el protocolo elegido, los guarda en JSON local y, opcionalmente, los envía a un stack ELK (Elasticsearch + Logstash + Kibana) para su visualización.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![uv](https://img.shields.io/badge/uv-package%20manager-DE5FE9?logo=astral&logoColor=white)
![Wireshark](https://img.shields.io/badge/tshark-Wireshark-1679A7?logo=wireshark&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-ELK%20Stack-005571?logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-visualización-E8488B?logo=kibana&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%2FDebian-FCC624?logo=linux&logoColor=black)

---

## Requisitos previos

### Sistema operativo

Linux (Ubuntu/Debian recomendado).

### Herramientas del sistema

| Herramienta | Versión mínima | Instalación |
|-------------|---------------|-------------|
| Python      | 3.8           | `sudo apt install python3` |
| tshark      | cualquiera    | `sudo apt install tshark` |
| uv          | cualquiera    | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

Durante la instalación de `tshark`, el sistema preguntará si los usuarios sin privilegios pueden capturar paquetes. Selecciona **Sí**.

Si no lo hiciste en ese momento, añade tu usuario al grupo `wireshark` manualmente:

```bash
sudo usermod -aG wireshark $USER
```

Luego **cierra sesión y vuelve a entrar** para que el cambio surta efecto. Verifica que funciona:

```bash
tshark -D
```

Deberías ver la lista de interfaces disponibles sin errores.

---

## Instalación

```bash
# 1. Clona el repositorio
git clone <url-del-repo>
cd euneiz-redes1

# 2. Copia el fichero de configuración de ejemplo
cp conf/conf_tmp.ini conf/conf.ini

# 3. Instala las dependencias Python con uv
uv sync
```

> `uv sync` crea automáticamente un entorno virtual en `.venv` e instala todas las dependencias declaradas en `pyproject.toml`.

---

## Configuración

Edita el fichero `conf/conf.ini` antes de lanzar el programa. Es la única fuente de configuración.

```ini
[GlobalConfig]
debug_mode: true          # true → muestra información detallada por consola

[App]
project_name: ikasle      # nombre del fichero JSON de salida (en captured_data/)
log_type: conn            # patrón de captura (ver tabla de patrones más abajo)
net_sniffer_interface: eth0   # interfaz de red a escuchar (ej: eth0, wlan0, lo)
net_summarize: true       # true → muestra resumen; false → muestra todos los campos
net_custome_filters:      # filtro BPF opcional (vacío = captura todo)

[MonitorSystem]
monitor_system_enable: false  # true → envía datos a Logstash
monitor_ip: localhost
monitor_port: 5000
```

### Cómo saber qué interfaz usar

```bash
tshark -D
```

Aparecerá una lista numerada. Usa el nombre de la interfaz que te interese (ej: `eth0`, `wlan0`, `ens33`).

### Filtros BPF

Los filtros BPF (Berkeley Packet Filter) permiten reducir la captura a tráfico específico. Ejemplos:

```
# Solo tráfico ICMP
net_custome_filters: icmp

# Excluir tráfico local y al puerto 5000
net_custome_filters: not ip host localhost and not tcp port 5000

# Solo tráfico hacia o desde una IP concreta
net_custome_filters: host 192.168.1.1
```

---

## Patrones de captura disponibles

El parámetro `log_type` en `conf.ini` selecciona qué protocolo analizar:

| Valor `log_type` | Protocolo | Campos que extrae |
|-----------------|-----------|-------------------|
| `conn`          | Ethernet (capa 2) | MACs origen/destino, OUI, tipo de trama |
| `pcap_live`     | Genérico  | Captura sin procesamiento específico |
| `icmp`          | ICMP      | Tipo, código, checksum, secuencia, datos |
| `imap`          | IMAP      | Comandos, usuario, contraseña (texto claro) |

> El patrón `imap` es especialmente útil para ver cómo IMAP transmite credenciales en texto claro si no usa TLS. Útil para entender la importancia del cifrado.

---

## Lanzar el programa

### Forma rápida (script interactivo)

```bash
./lanzar.sh
```

El script guía el proceso paso a paso: limpia el entorno si es necesario, sincroniza dependencias, verifica `tshark` y arranca la captura.

### Forma manual

```bash
uv run python src/MAIN.py
```

### Parar la captura

`Ctrl + C`

---

## Salida de datos

Los paquetes capturados se guardan en:

```
captured_data/<project_name>
```

Cada paquete se añade como una línea JSON al fichero. El nombre del fichero corresponde al valor de `project_name` en `conf.ini`.

Ejemplo de línea JSON capturada con el patrón `icmp`:

```json
{
  "layer_name": "icmp",
  "type": "8",
  "code": "0",
  "checksum": "0x00004f3a",
  "seq": "1",
  "db_name": "icmp.log"
}
```

---

## Monitorización con ELK (opcional)

El directorio `monitorizacion/` contiene un stack completo de Elasticsearch + Logstash + Kibana listo para usar con Docker Compose.

### Requisitos adicionales

- Docker
- Docker Compose

### Arrancar el stack

```bash
cd monitorizacion/
docker compose up -d
```

- **Kibana** estará disponible en: `http://localhost:5601`
- **Logstash** escucha en el puerto TCP `5000`

### Activar el envío de datos

En `conf/conf.ini`:

```ini
[MonitorSystem]
monitor_system_enable: true
monitor_ip: localhost
monitor_port: 5000
```

---

## Estructura del proyecto

```
euneiz-redes1/
├── conf/
│   ├── conf_tmp.ini          # Plantilla de configuración
│   └── conf.ini              # Tu configuración (no se sube a git)
├── src/
│   ├── MAIN.py               # Punto de entrada
│   ├── net/
│   │   └── NetSniffer.py     # Captura de paquetes con pyshark
│   ├── utils/
│   │   └── ConfigReader.py   # Lectura del fichero .ini
│   ├── enviodatos/
│   │   └── EnvioDatosLogstash.py  # Envío a Logstash
│   └── lectura_logs/
│       ├── PatronPadre.py    # Clase base de los patrones
│       └── patrones/
│           ├── connPatron.py
│           ├── pcapLivePatron.py
│           └── curso_2025/
│               ├── icmpPatron.py
│               └── imapPatron.py
├── monitorizacion/           # Stack ELK con Docker Compose
├── pyproject.toml            # Dependencias del proyecto
├── uv.lock                   # Versiones exactas resueltas
└── lanzar.sh                 # Script de arranque
```

---

## Añadir un nuevo patrón

1. Crea un fichero en `src/lectura_logs/patrones/` que herede de `PatronPadre`.
2. Define `dict_values` con los campos de la capa que quieres extraer.
3. Implementa `process_log_data()` filtrando la capa correspondiente.
4. Registra el nuevo patrón en el diccionario `logs_patterns_types` de `src/MAIN.py`.
5. Usa el nuevo nombre como valor de `log_type` en `conf.ini`.
