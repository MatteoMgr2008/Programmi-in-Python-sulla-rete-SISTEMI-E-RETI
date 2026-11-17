# Programmi in Python sulla rete – Sistemi e Reti

🇮🇹 [Italiano](#-italiano) | 🇬🇧 [English](#-english)

## 🇮🇹 Italiano

### 📌 Descrizione

Raccolta di programmi in **Python** dedicati alle reti, realizzati per la materia scolastica **Sistemi e Reti**.
Al momento il repository contiene il progetto **Fake Wireshark**, un semplice analizzatore di pacchetti da riga di comando ispirato a [Wireshark](https://www.wireshark.org/).

> ⚠️ Il programma è stato creato **solo a scopo educativo**: non va usato per scopi illeciti o non etici.

### 📂 Contenuto

| Percorso | Descrizione |
|---|---|
| `Progetto Fake Wireshark/Versione per Windows/Fake Wireshark for Windows.py` | Codice sorgente del programma |
| `Progetto Fake Wireshark/Versione per Windows/Fake Wireshark for Windows.exe` | Versione già compilata (eseguibile per Windows) |
| `Progetto Fake Wireshark/Versione per Windows/requirements.txt` | Librerie Python necessarie (`colorama`, `psutil`, `scapy`) |
| `Progetto Fake Wireshark/Versione per Linux - Unix/` | Cartella per la versione Linux/Unix, per ora vuota (contiene solo un file segnaposto `File 0`) |

### 🔍 Cosa fa Fake Wireshark

Il programma è interattivo e in italiano. All'avvio chiede:

1. **Analisi delle interfacce di rete** (S/N): per ogni interfaccia mostra indirizzo IP, indirizzo MAC, subnet mask, velocità e stato (attiva/inattiva), oltre al gateway predefinito e al server DNS. Per le interfacce Wi-Fi (riconosciute dal nome) mostra anche segnale, velocità di ricezione e tipo di rete. Queste informazioni sono ricavate con `psutil` e con i comandi di Windows `ipconfig`, `nslookup` e `netsh wlan show interfaces`.
2. **Cattura dei pacchetti** (S/N): usa `sniff()` di Scapy e, per ogni pacchetto, stampa timestamp con fuso orario e i dettagli dei livelli:
   - **Ethernet**: MAC sorgente/destinazione, tipo;
   - **IP**: IP sorgente/destinazione, protocollo, TTL, dimensione;
   - **TCP** (porte, numero di sequenza, flag), **UDP** (porte, lunghezza) oppure **ICMP** (tipo, codice);
   - dimensione totale del pacchetto.

La cattura si interrompe con **Ctrl+C**; alla fine si può premere **Q** o **E** per uscire, oppure un altro tasto per ricominciare.

### 🛠️ Tecnologie utilizzate

- **Python** (le f-string del codice richiedono **Python 3.12 o superiore**)
- **Scapy** – cattura e analisi dei pacchetti
- **psutil** – informazioni sulle interfacce di rete
- **colorama** – testo colorato nel terminale

### ▶️ Come eseguirlo

**Opzione 1 – Eseguibile:** avviare `Fake Wireshark for Windows.exe` (consigliato come amministratore, dato che la cattura dei pacchetti di solito richiede privilegi elevati).

**Opzione 2 – Da sorgente:**

```bash
cd "Progetto Fake Wireshark/Versione per Windows"
pip install -r requirements.txt
python "Fake Wireshark for Windows.py"
```

### 📋 Requisiti

- **Windows** (il programma usa comandi specifici di Windows)
- Per catturare i pacchetti su Windows, Scapy ha normalmente bisogno di un driver di cattura come [Npcap](https://npcap.com/)
- Alcune informazioni vengono lette dall'output dei comandi di sistema in **italiano** (es. "Gateway predefinito", "Segnale"): con Windows in un'altra lingua potrebbero comparire come "N/A"

### 👤 Autore

Realizzato da [MatteoMgr2008](https://github.com/MatteoMgr2008).

---

## 🇬🇧 English

### 📌 Description

A collection of **Python** networking programs, made for the school subject **Sistemi e Reti** (Systems and Networks).
At the moment the repository contains the **Fake Wireshark** project, a simple command-line packet analyzer inspired by [Wireshark](https://www.wireshark.org/).

> ⚠️ The program was created **for educational purposes only**: it must not be used for illegal or unethical purposes.

### 📂 Contents

| Path | Description |
|---|---|
| `Progetto Fake Wireshark/Versione per Windows/Fake Wireshark for Windows.py` | Program source code |
| `Progetto Fake Wireshark/Versione per Windows/Fake Wireshark for Windows.exe` | Prebuilt Windows executable |
| `Progetto Fake Wireshark/Versione per Windows/requirements.txt` | Required Python libraries (`colorama`, `psutil`, `scapy`) |
| `Progetto Fake Wireshark/Versione per Linux - Unix/` | Folder for the Linux/Unix version, currently empty (it only holds a placeholder file `File 0`) |

### 🔍 What Fake Wireshark does

The program is interactive and its interface is in Italian. On startup it asks:

1. **Network interface analysis** (yes/no, answered with S/N): for each interface it shows IP address, MAC address, subnet mask, speed and status (up/down), plus the default gateway and DNS server. For Wi-Fi interfaces (recognized by name) it also shows signal, receive speed and network type. This information comes from `psutil` and the Windows commands `ipconfig`, `nslookup` and `netsh wlan show interfaces`.
2. **Packet capture** (S/N): it uses Scapy's `sniff()` and, for each packet, prints a timestamp with time zone and the details of each layer:
   - **Ethernet**: source/destination MAC, type;
   - **IP**: source/destination IP, protocol, TTL, size;
   - **TCP** (ports, sequence number, flags), **UDP** (ports, length) or **ICMP** (type, code);
   - total packet size.

Capture stops with **Ctrl+C**; at the end you can press **Q** or **E** to quit, or any other key to start over.

### 🛠️ Technologies

- **Python** (the f-strings in the code require **Python 3.12 or later**)
- **Scapy** – packet capture and analysis
- **psutil** – network interface information
- **colorama** – colored terminal output

### ▶️ How to run

**Option 1 – Executable:** launch `Fake Wireshark for Windows.exe` (running it as administrator is recommended, since packet capture usually needs elevated privileges).

**Option 2 – From source:**

```bash
cd "Progetto Fake Wireshark/Versione per Windows"
pip install -r requirements.txt
python "Fake Wireshark for Windows.py"
```

### 📋 Requirements

- **Windows** (the program relies on Windows-specific commands)
- To capture packets on Windows, Scapy normally needs a capture driver such as [Npcap](https://npcap.com/)
- Some information is parsed from the **Italian** output of system commands (e.g. "Gateway predefinito", "Segnale"): on a Windows installation in another language these fields may show up as "N/A"

### 👤 Author

Made by [MatteoMgr2008](https://github.com/MatteoMgr2008).
