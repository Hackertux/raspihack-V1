import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, sniff
from datetime import datetime

# Lista para almacenar dispositivos detectados
devices = []

# Función para actualizar la tabla en tiempo real
def update_table(device_ip, device_mac):
    global devices
    # Si el dispositivo ya está en la lista, no lo agregues de nuevo
    for dev in devices:
        if dev[1] == device_mac:
            return
    # Agrega un nuevo dispositivo detectado
    devices.append((device_ip, device_mac))
    table.insert("", "end", values=(device_ip, device_mac, datetime.now().strftime("%H:%M:%S")))

# Función para detectar dispositivos con Scapy
def detect_devices(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # ARP request
        device_ip = pkt[ARP].psrc
        device_mac = pkt[ARP].hwsrc
        update_table(device_ip, device_mac)

# Configuración de la ventana principal de Tkinter
root = tk.Tk()
root.title("Monitor de Red")
root.geometry("600x400")

# Etiqueta del título
title_label = tk.Label(root, text="Monitor de Red en Tiempo Real", font=("Helvetica", 16))
title_label.pack(pady=10)

# Tabla para mostrar dispositivos
columns = ("IP", "MAC", "Hora Detectada")
table = ttk.Treeview(root, columns=columns, show="headings")
table.heading("IP", text="Dirección IP")
table.heading("MAC", text="Dirección MAC")
table.heading("Hora Detectada", text="Hora Detectada")
table.pack(fill="both", expand=True, padx=10, pady=10)

# Scrollbar para la tabla
scrollbar = ttk.Scrollbar(root, orient="vertical", command=table.yview)
table.configure(yscroll=scrollbar.set)
scrollbar.pack(side="right", fill="y")

# Inicia la captura de paquetes en un hilo separado
import threading

sniffer_thread = threading.Thread(target=lambda: sniff(prn=detect_devices, filter="arp", store=0))
sniffer_thread.daemon = True
sniffer_thread.start()

# Inicia la interfaz gráfica
root.mainloop()
