from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time
from colorama import Fore, Back, Style, init
import psutil
import subprocess
import re
import socket
from datetime import datetime

def info_interfacce_rete():
    def get_info_wifi():
        try:
            output_cmd=subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")
            ssid_rete=re.search(r"^\s*SSID\s*:\s(.+)", output_cmd, re.MULTILINE)
            segnale_rete=re.search(r"^\s*Segnale\s*:\s(\d+)%", output_cmd, re.MULTILINE)
            velocità_rete=re.search(r"^\s*Velocità ricezione\s*:\s(\d+)\sMbps", output_cmd, re.MULTILINE)
            tipo_infrastruttura_rete=re.search(r"^\s*Tipo di rete\s*:\s(.+)", output_cmd, re.MULTILINE)
            return{
                "SSID": ssid_rete.group(1).strip() if ssid_rete else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL,
                "Segnale": segnale_rete.group(1).strip()+"%" if segnale_rete else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL,
                "Velocità Wi-Fi (in Mbps)": velocità_rete.group(1).strip() if velocità_rete else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL, 
                "Tipo di infrastruttura di rete": tipo_infrastruttura_rete.group(1).strip() if tipo_infrastruttura_rete else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            }
        except Exception:
            return{
                "SSID": Fore.RED+"Errore"+Style.RESET_ALL,
                "Segnale": Fore.RED+"Errore"+Style.RESET_ALL,
                "Velocità Wi-Fi (in Mbps)": Fore.RED+"Errore"+Style.RESET_ALL,
                "Tipo di infrastruttura di rete": Fore.RED+"Errore"+Style.RESET_ALL
            }

    def get_dns_rete():
        try:
            output_cmd=subprocess.check_output(["nslookup", "www.google.it"], encoding="utf-8", stderr=subprocess.DEVNULL, timeout=10) # stderr=subprocess.DEVNULL serve per ignorare eventuali messaggi di errore (es.: il Wi-Fi non è attivo).
            server_rete_match=re.search(r"Server:\s*(.+)", output_cmd)
            ip_dns_rete_match=re.search(r"Address:\s*(.+)", output_cmd)
            return{
                "DNS": ip_dns_rete_match.group(1).strip() if ip_dns_rete_match else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL,
                "Nome DNS": server_rete_match.group(1).strip() if server_rete_match else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            }
        except:
            return{
                "DNS": Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL,
                "Nome DNS": Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            }

    def get_gateway_rete():
        try:
            output_cmd=subprocess.check_output(["ipconfig"], encoding="utf-8")
            gateway_rete_match=re.findall(r"Gateway predefinito[ .:]*([\d\.]+)", output_cmd)
            gateway_rete=gateway_rete_match[0][1] if gateway_rete_match else None
            return {
                "Gateway predefinito": gateway_rete if gateway_rete else Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            }
        except:
            return{
                "Gateway predefinito": Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            }

    def get_interfacce_rete():
        interfacce_rete={}
        for nome_rete, indirizzi_rete, in psutil.net_if_addrs().items():
            indirizzo_IP=Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            indirizzo_MAC=Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            maschera_rete=Fore.RED+"N/A (non disponibile/sconosciuto)"+Style.RESET_ALL
            for indirizzo_rete in indirizzi_rete:
                tipo_protocollo_rete=indirizzo_rete.family.name if hasattr(indirizzo_rete.family, "name") else str(indirizzo_rete.family)
                if tipo_protocollo_rete=="AF_INET" or indirizzo_rete.family==2:
                    indirizzo_IP=indirizzo_rete.address
                    maschera_rete=indirizzo_rete.netmask
                elif tipo_protocollo_rete=="AF_LINK" or indirizzo_rete.address==-1:
                    if indirizzo_rete.address and indirizzo_rete.address!="00-00-00-00-00-00":
                        indirizzo_MAC=indirizzo_rete.address
            stato_rete=psutil.net_if_stats().get(nome_rete)
            velocità_rete=stato_rete.speed if stato_rete else 0
            rete_attiva=stato_rete.isup if stato_rete else False
            interfacce_rete[nome_rete] = {
                "Indirizzo IP": indirizzo_IP,
                "Indirizzo MAC": indirizzo_MAC,
                "Maschera di sottorete": maschera_rete,
                "Velocità (in Mbps)": stato_rete.speed if stato_rete else 0,
                "Stato": Fore.GREEN+"Rete attiva"+Style.RESET_ALL if stato_rete and stato_rete.isup else Fore.RED+"Rete inattiva"+Style.RESET_ALL
            }
        return interfacce_rete
    
    print("Informazioni sulle interfacce di rete attualmente presenti nel dispositivo:")
    
    interfacce_rete=get_interfacce_rete()
    dns_rete=get_dns_rete()
    gateway_rete=get_gateway_rete()
    
    for i, (nome_interfaccia_rete, dati_rete) in enumerate(interfacce_rete.items(), start=1):
        print(f"{Fore.LIGHTMAGENTA_EX}\n{i}) Interfaccia: {nome_interfaccia_rete}{Style.RESET_ALL}")
        print(f"- Indirizzo IP: {dati_rete["Indirizzo IP"]}")
        print(f"- Indirizzo MAC: {dati_rete["Indirizzo MAC"]}")
        print(f"- Maschera di sottorete (subnet mask): {dati_rete["Maschera di sottorete"]}")
        velocità_interfaccia_rete=dati_rete["Velocità (in Mbps)"]
        if isinstance(velocità_interfaccia_rete, int) and velocità_interfaccia_rete>=0:
            print(f"- Velocità (in Mbps): {velocità_interfaccia_rete} Mbps")
        else:
            print(f"- Velocità (in Mbps): {velocità_interfaccia_rete}")
        print(f"- Stato: {dati_rete["Stato"]}")
        print(f"- Gateway predefinito: {gateway_rete["Gateway predefinito"]}")
        print(f"- Nome DNS: {dns_rete["DNS"]} ({dns_rete["Nome DNS"]})")
        
        if "WI-FI" in nome_interfaccia_rete.upper() or "WLAN" in nome_interfaccia_rete.upper() or "WIRELESS" in nome_interfaccia_rete.upper():
            info_WiFi=get_info_wifi()
            print(f"- Segnale: {info_WiFi['Segnale']}")
            velocità_WiFi=info_WiFi["Velocità Wi-Fi (in Mbps)"]
            if velocità_WiFi.isdigit():
                print(f"- Velocità del Wi-Fi (in Mbps): {velocità_WiFi} Mbps")
            elif "N/A (non disponibile/sconosciuto)" in velocità_WiFi or "Errore" in velocità_WiFi:
                print(f"- Velocità del Wi-Fi (in Mbps): {velocità_WiFi}")
            else:
                print(f"- Velocità del Wi-Fi (in Mbps): {velocità_WiFi} Mbps")
            print(f"- Tipo di infrastruttura di rete: {info_WiFi['Tipo di infrastruttura di rete']}")
    
    print()
    print(Fore.GREEN+"Scansione delle interfacce di rete completata con successo!"+Style.RESET_ALL)
    print()

spazio_necessario_extra = False

def esci_o_ricomincia():
    global spazio_necessario_extra
    pulsante_premuto=input("Premi Q o E per uscire, altrimenti premi qualsiasi altro pulsante per rieseguire il programma dall'inizio: ").upper()
    if pulsante_premuto=="E" or pulsante_premuto=="Q":
        print("Il programma verrà chiuso a momenti...")
        time.sleep(2)
        exit()
    else:
        print("Tra poco il programma verrà eseguito nuovamente...")
        time.sleep(2)
        spazio_necessario_extra=True
        introduzione_programma()
        
# Ottiene il fuso orario dinamico per il timestamp dei pacchetti di rete catturati
offset_fuso_orario=time.localtime().tm_gmtoff//3600
nome_fuso_orario=time.tzname[time.localtime().tm_isdst]

# Funzione per catturare e analizzare i pacchetti
def cattura_pacchetti_rete():
    print(f"Inizio della cattura dei pacchetti di rete... {Fore.RED}(Premere Ctrl+C per fermare l'operazione in qualsiasi momento){Style.RESET_ALL}")
    time.sleep(3)
    def analisi_pacchetto_rete(pacchetto_rete):
        print(f"{Fore.CYAN}\n--- Pacchetto di rete catturato ---{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Timestamp: {time.strftime('%d/%m/%Y')} {time.strftime('%H:%M:%S')} ({nome_fuso_orario}, GMT/UTC{offset_fuso_orario:+}){Style.RESET_ALL}")
        print()
        
        # Analisi layer Ethernet
        if pacchetto_rete.haslayer(Ether):
            livello_ethernet=pacchetto_rete[Ether]
            print(f"FRAME DEL LAYER ETHERNET:")
            print(f"- Indirizzo MAC di sorgente: {livello_ethernet.src}")
            print(f"- Indirizzo MAC di destinazione: {livello_ethernet.dst}")
            print(f"- Tipo: 0x{livello_ethernet.type:04x}")
            print()
        
        # Analisi layer IP
        if pacchetto_rete.haslayer(IP):
            livello_IP=pacchetto_rete[IP]
            print(f"FRAME DEL LAYER IP:")
            print(f"- Indirizzo IP di sorgente: {livello_IP.src}")
            print(f"- Indirizzo IP di destinazione: {livello_IP.dst}")
            print(f"- Protocollo usato: {livello_IP.proto}")
            print(f"- TTL: {livello_IP.ttl}")
            print(f"- Dimensione pacchetto: {livello_IP.len} bytes")
            print()
            
        # Analisi layer TCP
        if pacchetto_rete.haslayer(TCP):
            livello_tcp=pacchetto_rete[TCP]
            print(f"FRAME DEL SEGMENTO TCP:")
            print(f"- Porta sorgente: {livello_tcp.sport}")
            print(f"- Porta di destinazione: {livello_tcp.dport}")
            print(f"- Numero di sequenza: {livello_tcp.seq}")
            print(f"- Flag: {livello_tcp.flags}")
            print()
            
        # Analisi layer UDP
        elif pacchetto_rete.haslayer(UDP):
            livello_udp=pacchetto_rete[UDP]
            print(f"FRAME DEL DATAGRAMMA UDP:")
            print(f"- Porta sorgente: {livello_udp.sport}")
            print(f"- Porta di destinazione: {livello_udp.dport}")
            print(f"- Lunghezza: {livello_udp.len}")
            print()
            
        # Layer ICMP
        elif pacchetto_rete.haslayer(ICMP):
            livello_icmp=pacchetto_rete[ICMP]
            print(f"FRAME DEL MESSAGGIO ICMP:")
            print(f"- Tipo: {livello_icmp.type}")
            print(f"- Codice: {livello_icmp.code}")
            print()
        
        # Dimensione totale del pacchetto di rete    
        print(f"La dimensione totale del pacchetto di rete è {len(pacchetto_rete)} bytes")    
        print()
        
        # Separatori tra diversi pacchetti di rete
        print("-" * 40)
    try:
        # Avvia effettivamente la cattura dei pacchetti di rete
        sniff(prn=analisi_pacchetto_rete, store=True)
    except KeyboardInterrupt:
        interruzione_analisi_pacchetti_rete()
    
def interruzione_analisi_pacchetti_rete():
    print(Fore.RED+"\nLa cattura dei pacchetti di rete è stata interrotta!"+Style.RESET_ALL)
    print()

def introduzione_programma():
    global spazio_necessario_extra
    if spazio_necessario_extra==True:
        print()
        spazio_necessario_extra=False
    print(f"Benvenuto su {Fore.BLUE}Fake Wireshark{Style.RESET_ALL}: l'analizzatore di pacchetti reti definitivo!")
    print(f"Questo programma prende esempio da Wireshark ({Fore.CYAN}https://www.wireshark.org/{Style.RESET_ALL}), un analizzatore di pachetti open source.")
    print()
    print(Fore.RED+"ATTENZIONE: Questo programma è stato creato a solo scopo educazionale, è quindi vietato l'uso per scopi illeciti e non etici!"+Style.RESET_ALL)
    print()
    while True:
        inizio_scansione_interfacce_rete=input("Prima di avviare la cattura di pacchetti di rete, si desidera analizzare le interfacce di rete attualmente presenti nel dispositivo (rispondere solo con S/N)? ").upper()
        if inizio_scansione_interfacce_rete=="S":
            print()
            print(Fore.YELLOW+"Tra poco inizierà l'analisi delle interfacce di rete..."+Style.RESET_ALL)
            time.sleep(2)
            print()
            info_interfacce_rete()
            break
        elif inizio_scansione_interfacce_rete=="N":
            print()
            print(Fore.RED+"Non verrà effettuata l'analisi delle interfacce di rete!"+Style.RESET_ALL)
            print()
            break
        else:
            print("Risposta non riconosciuta. Verrà quindi riformulata la domanda, è possibile rispondere solo con S/N")
    while True:
        inizio_scansione_pacchetti_rete=input("Si desidera avviare la cattura di pacchetti di rete (rispondere solo con S/N)? ").upper()
        if inizio_scansione_pacchetti_rete=="S":
            print()
            print(Fore.YELLOW+"Tra poco inizierà la scansione di pacchetti di rete..."+Style.RESET_ALL)
            time.sleep(2)
            print()
            cattura_pacchetti_rete()
            interruzione_analisi_pacchetti_rete()
            time.sleep(1)
            esci_o_ricomincia()
        elif inizio_scansione_pacchetti_rete=="N":
            print()
            print(Fore.RED+"Non verrà avviata la cattura di pacchetti di rete!"+Style.RESET_ALL)
            print()
            time.sleep(1)
            esci_o_ricomincia()
        else:
            print("Risposta non riconosciuta. Verrà quindi riformulata la domanda, è possibile rispondere solo con S/N")
            
def main():
    introduzione_programma()

if __name__ == "__main__":
    main()