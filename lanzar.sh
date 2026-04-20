#!/bin/bash
# Script para lanzar el sniffer de red euneiz-redes1 con entorno virtual

# Limpiar variables de entorno que puedan causar conflictos
unset VIRTUAL_ENV
unset PYTHONPATH

cd "$(dirname "$0")"

# Verificar si uv está instalado, si no, avisar al usuario
if ! command -v uv &> /dev/null; then
    echo "❌ 'uv' no está instalado. Por favor, instálalo para gestionar el entorno (https://docs.astral.sh/uv/)"
    exit 1
fi

echo "🧹 --- Fase de Limpieza de Entorno ---"
if [ -d ".venv" ]; then
    read -p "⚠️ Se ha detectado un entorno virtual (.venv). ¿Deseas borrarlo para recrearlo? (s/n): " borrar_venv
    if [[ "$borrar_venv" == "s" || "$borrar_venv" == "S" ]]; then
        echo "🗑️ Borrando .venv..."
        rm -rf .venv
    fi
fi

echo -e "\n📦 --- Fase de Dependencias ---"
echo "⚙️ Sincronizando entorno virtual con uv..."
uv sync

echo -e "\n🔍 --- Fase de Verificación del Sistema ---"
if ! command -v tshark &> /dev/null; then
    echo "❌ 'tshark' no está instalado. Es necesario para la captura de paquetes."
    echo "   Instálalo con: sudo apt-get install tshark"
    exit 1
else
    echo "✅ tshark detectado: $(tshark --version | head -1)"
fi

echo -e "\n🌐 --- Fase de Ejecución ---"
echo "🚀 Iniciando sniffer de red..."
uv run python src/MAIN.py
