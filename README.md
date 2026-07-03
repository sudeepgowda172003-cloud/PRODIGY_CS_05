# 🌐 Network Packet Analyzer — PRODIGY_CS_05

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Socket](https://img.shields.io/badge/Raw_Socket-Networking-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![Internship](https://img.shields.io/badge/Prodigy-InfoTech-purple?style=for-the-badge)

> **Task 05** — Prodigy InfoTech Cyber Security Internship

---

## ⚠️ Ethical Disclaimer

> This tool is developed **strictly for educational purposes** as part of a cybersecurity internship.
>
> - ✅ Use ONLY on your **own network**
> - ✅ Use ONLY with **authorization**
> - ❌ **NEVER** sniff traffic on public/corporate networks without permission
> - ❌ Unauthorized packet sniffing is **ILLEGAL**
>
> The purpose is to understand **how network traffic works** so security professionals can better **monitor and protect** networks.

---

## 📌 Task Description

Develop a **packet sniffer tool** that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

---

## ✨ Features

- ✅ Captures **live network packets** in real-time
- ✅ Displays **Source & Destination IP** addresses
- ✅ Identifies **Protocol** — TCP / UDP / ICMP
- ✅ Shows **Port numbers** (source & destination)
- ✅ Displays **TCP Flags** (SYN, ACK, FIN, RST, PSH)
- ✅ Shows **Payload data** (hex + ASCII format)
- ✅ Saves complete log to `packet_log.txt`
- ✅ Set **packet capture limit** or run unlimited
- ✅ Works on **Linux & Windows**

---

## 🔍 What is a Packet Sniffer?

Every time you browse the internet, data travels in small chunks called **packets**. A packet sniffer captures these packets and lets you inspect them — this is the foundation of **network security analysis**.

```
Your Computer  →  [Packet]  →  Internet
                     ↑
               Sniffer captures this!
               Shows: IP, Protocol, Port, Data
```

---

## 🛠️ Requirements

- Python 3.x
- **Root/Admin privileges** required
- No external libraries needed (uses built-in `socket` module)

---

## ▶️ How to Run

```bash
# Clone the repository
git clone https://github.com/Prasadsarkate/PRODIGY_CS_05.git

# Navigate to folder
cd PRODIGY_CS_05

# Run with sudo (root required for raw sockets)
sudo python packet_sniffer.py
```

> ⚠️ On **Windows**: Run Command Prompt as Administrator

---

## 💻 Usage Example

```
============================================================
   🌐 Network Packet Analyzer — Task 05
   Prodigy Infotech Internship
============================================================

  Options:
  1. Start Sniffing
  2. View Log File
  3. Clear Log File
  4. Exit

  Enter choice: 1
  Capture how many packets? (0 = unlimited): 10
  Show payload data? (y/n): n

  🟢 Sniffing started... (Ctrl+C to stop)

  #     Time       Proto  Source                 Destination            Info
  ─────────────────────────────────────────────────────────────────────────────
  1     13:45:01   TCP    192.168.1.5            142.250.77.46          52341→443 [ACK]
  2     13:45:01   UDP    192.168.1.1            192.168.1.5            53→5353 len=68
  3     13:45:02   ICMP   192.168.1.5            8.8.8.8                Echo Request code=0
  4     13:45:02   TCP    142.250.77.46          192.168.1.5            443→52341 [ACK,PSH]
  5     13:45:03   TCP    192.168.1.5            142.250.77.46          52341→443 [ACK]

  ✅ Captured 10 packets. Done.
  📊 Total packets captured : 10
  📄 Log saved to           : /path/to/packet_log.txt
```

---

## 📦 Packet Structure Parsed

### IPv4 Header
| Field | Description |
|-------|-------------|
| Source IP | Where packet came from |
| Destination IP | Where packet is going |
| Protocol | TCP / UDP / ICMP |
| TTL | Time To Live |

### TCP Segment
| Field | Description |
|-------|-------------|
| Source Port | Sending port |
| Destination Port | Receiving port |
| Flags | SYN, ACK, FIN, RST, PSH, URG |
| Sequence & Ack | Connection tracking numbers |

### UDP Segment
| Field | Description |
|-------|-------------|
| Source/Dest Port | Port numbers |
| Length | Segment length |

### ICMP Packet
| Field | Description |
|-------|-------------|
| Type | Echo Request / Reply / etc. |
| Code | Sub-type code |

---

## 📂 Project Structure

```
PRODIGY_CS_05/
│
├── packet_sniffer.py   # Main program
├── packet_log.txt      # Generated log file (after running)
└── README.md           # Project documentation
```

---

## 📚 What I Learned

- How **network packets** are structured (Ethernet → IP → TCP/UDP)
- Working with **raw sockets** in Python
- Parsing **binary data** using `struct` module
- Understanding **TCP/IP protocol suite**
- Basics of **network traffic analysis**
- How tools like **Wireshark** work under the hood

---

## 👨‍💻 Author

**Prasad** — Cyber Security Intern @ Prodigy InfoTech

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/Prasadsarkate)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/Prasadsarkate)

---

## 🏢 Internship

This project was completed as part of the **Prodigy InfoTech Cyber Security Internship**.

`#ProdigyInfoTech` `#Internship` `#CyberSecurity` `#Python` `#NetworkSecurity` `#PacketSniffer`
