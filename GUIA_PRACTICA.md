# Guía de Práctica — Sniffer de Red byPGG
### Máster en Seguridad · EUNEIZ · Introducción a Redes

---

## 1. Requisitos previos

Antes de clonar el proyecto necesitas tener instalado:

| Herramienta | Para qué sirve | Cómo instalar |
|---|---|---|
| **Git** | Clonar el repositorio | `sudo apt install git` |
| **Python 3.8+** | Ejecutar el sniffer | `sudo apt install python3` |
| **uv** | Gestionar el entorno virtual y dependencias | Ver abajo |
| **tshark** | Captura real de paquetes de red (motor de pyshark) | `sudo apt install tshark` |

### Instalar `uv`

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verifica que funciona:

```bash
uv --version
```

> **¿Por qué `uv`?** Es el gestor de entornos que usa este proyecto. Lee `pyproject.toml` y resuelve las dependencias de forma reproducible sin necesidad de crear el `.venv` manualmente.

### Instalar `tshark`

```bash
sudo apt install tshark
```

Durante la instalación te preguntará si usuarios no-root pueden capturar paquetes — responde **Sí**. Si no lo hiciste así, añade tu usuario al grupo `wireshark`:

```bash
sudo usermod -aG wireshark $USER
# Cierra sesión y vuelve a entrar para que el grupo se aplique
```

---

## 2. Clonar el repositorio

```bash
git clone https://github.com/Chispasgg/euneiz-redes1.git
cd euneiz-redes1
```

Estructura principal del proyecto una vez clonado:

```
euneiz-redes1/
├── conf/
│   ├── conf.ini              ← Configuración principal (interfaz, patrón activo)
│   ├── patron_info.json      ← Descripciones educativas de cada patrón
│   ├── layer_info.json       ← Descripciones de capas OSI
│   └── icmp_types.json       ← Significado de los tipos ICMP
├── src/
│   ├── MAIN.py               ← Punto de entrada
│   ├── net/NetSniffer.py     ← Motor de captura (pyshark)
│   └── lectura_logs/
│       ├── PatronPadre.py    ← Clase base abstracta de todos los patrones
│       └── patrones/
│           ├── connPatron.py         ← Patrón Ethernet (Capa 2)
│           ├── pcapLivePatron.py     ← Captura genérica todas las capas
│           └── curso_2025/
│               ├── icmpPatron.py     ← Patrón ICMP (Capa 3)
│               └── imapPatron.py     ← Patrón IMAP (Capa 7)
├── lanzar.sh                 ← Script de arranque
└── pyproject.toml            ← Dependencias del proyecto
```

---

## 3. Configuración antes de lanzar

Edita el fichero `conf/conf.ini` y ajusta **dos parámetros**:

```ini
[App]
log_type: icmp                  # patrón a usar (ver tabla más abajo)
net_sniffer_interface: enp108s0 # nombre de tu interfaz de red
```

### Cómo saber el nombre de tu interfaz

```bash
ip link show
# o
ifconfig
```

Busca la interfaz conectada a la red (suele ser `eth0`, `enp3s0`, `wlan0`, etc.).

### Patrones disponibles

| Valor `log_type` | Protocolo | Capa OSI |
|---|---|---|
| `conn` | Ethernet — MACs y fabricantes | Capa 2 |
| `pcap_live` | Genérico — todas las capas | Capas 2–7 |
| `icmp` | ICMP — ping, traceroute | Capa 3 |
| `imap` | IMAP — correo sin cifrar | Capa 7 |

---

## 4. Abrir el proyecto en VSCode

```bash
# Desde el directorio del proyecto:
code .
```

O desde VSCode: `File → Open Folder` y selecciona la carpeta `euneiz-redes1`.

**Extensiones recomendadas** (VSCode las sugiere automáticamente):
- Python (Microsoft)
- Pylance

---

## 5. Lanzar el proyecto

### Opción A — Script de arranque (recomendada)

```bash
chmod +x lanzar.sh
./lanzar.sh
```

El script hace automáticamente:
1. Instala/sincroniza las dependencias con `uv`
2. Verifica que `tshark` está disponible
3. Lanza `src/MAIN.py`

### Opción B — Terminal directa

```bash
# Instalar dependencias (solo la primera vez)
uv sync

# Lanzar
uv run python src/MAIN.py
```

### Opción C — Desde VSCode (Run & Debug)

1. Abre `src/MAIN.py`
2. Pulsa `F5` o ve a `Run → Start Debugging`
3. Selecciona el intérprete del `.venv` que `uv` ha creado en la raíz del proyecto

> **Nota**: la captura de paquetes requiere permisos de red. Si VSCode lanza el proceso sin los permisos necesarios, usa la terminal con `./lanzar.sh`.

### Detener la captura

Pulsa `Ctrl+C` — el programa cierra limpiamente y muestra dónde se han guardado los paquetes capturados.

---

## 6. Crear un nuevo patrón de protocolo

Cada patrón es una clase Python que extiende `PatronPadre` y decide **qué campos extraer de cada paquete**.

### Paso 1 — Crear el fichero del patrón

Crea un nuevo fichero en `src/lectura_logs/patrones/curso_2025/`:

```python
# src/lectura_logs/patrones/curso_2025/dnsPatron.py

from lectura_logs.PatronPadre import PatronPadre

class dnsPatron(PatronPadre):

    # Campos que quieres capturar de la capa DNS
    dict_values = ["layer_name", "qry_name", "qry_type", "resp_name", "a"]

    def __init__(self, path_log):
        super().__init__('dns.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'dns' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['dns']:
                        resultado[x] = data_string['layers']['dns'][x] \
                            .replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
```

### Paso 2 — Registrar el patrón en MAIN.py

Abre `src/MAIN.py` y añade el import y la entrada en el diccionario:

```python
# Al inicio del fichero, junto a los otros imports de patrones:
from lectura_logs.patrones.curso_2025.dnsPatron import dnsPatron

# En el diccionario logs_patterns_types:
logs_patterns_types = {
    'conn': connPatron,
    'pcap_live': pcapLivePatron,
    'icmp': icmpPatron,
    'imap': imapPatron,
    'dns': dnsPatron,   # ← añadir aquí
}
```

### Paso 3 — Añadir la descripción educativa

Abre `conf/patron_info.json` y añade una entrada:

```json
"dns": {
    "protocolo": "DNS (Domain Name System)",
    "capa": "Capa 7 — Aplicación",
    "descripcion": "DNS traduce nombres de dominio a direcciones IP. Viaja en texto claro por UDP puerto 53.",
    "campos": "nombre consultado, tipo de registro, respuesta IP",
    "ejemplo": "Abre un navegador y verás las consultas DNS de cada página que visitas."
}
```

### Paso 4 — Activar el nuevo patrón

En `conf/conf.ini`:

```ini
log_type: dns
```

Lanza con `./lanzar.sh` y abre un navegador — verás las consultas DNS en tiempo real.

---

## 7. ¿Cómo saber qué campos tiene una capa?

Usa el patrón `pcap_live` para ver todos los campos en bruto:

```ini
log_type: pcap_live
```

Lanza el sniffer y observa la salida. Cada campo que aparece bajo una capa (ej. `dns`) puede incluirse en `dict_values` de tu patrón.

También puedes inspeccionar directamente con tshark:

```bash
# Ver los campos disponibles de la capa DNS
tshark -G fields | grep "^F\tdns"
```

---

## 8. Referencia rápida de comandos

```bash
# Clonar
git clone https://github.com/Chispasgg/euneiz-redes1.git && cd euneiz-redes1

# Ver tu interfaz de red
ip link show

# Instalar dependencias
uv sync

# Lanzar
./lanzar.sh

# Cambiar patrón (editar conf/conf.ini)
nano conf/conf.ini

# Ver paquetes capturados
cat captured_data/ikasle.json
```
