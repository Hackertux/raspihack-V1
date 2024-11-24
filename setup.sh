#!/bin/bash

# Instalación de Scapy
echo "Instalando Scapy..."
pip install scapy

# Clonar el repositorio desde GitHub
echo "Clonando el repositorio..."
git clone https://github.com/Hackertux/proyecto-raspberry-pi-3-hacking.git

# Navegar al directorio del proyecto y ejecutar el script
echo "Ejecutando el script proyecto.py..."
cd proyecto-raspberry-pi-3-hacking/proyecto || exit
python3 proyecto.py
