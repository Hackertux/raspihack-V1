#!/bin/bash

# Instalación de Scapy
echo "Instalando Scapy..."
pip install scapy

# Navegar al directorio del proyecto y ejecutar el script
echo "Ejecutando el script proyecto.py..."
cd raspihack-V1/proyecto || exit
python3 proyecto.py
