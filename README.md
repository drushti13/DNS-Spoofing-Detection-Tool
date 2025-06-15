# DNS Spoofing Detection Tool

A Python-based security utility that continuously monitors DNS traffic and detects spoofing attempts in real time. The application includes a graphical user interface, live traffic visualization, sound-based alerts, and desktop notifications to ensure an intuitive and responsive experience.

## Description

This tool is designed to identify DNS spoofing by actively inspecting incoming DNS responses and validating them against a trusted DNS server (Google DNS - 8.8.8.8). It provides network administrators, researchers, or students with a hands-on solution for understanding and observing DNS-related vulnerabilities. The application emphasizes usability through its interactive GUI and automated alert mechanisms.

## Key Features

- **Real-Time DNS Capture**: Continuously inspects DNS packets on the network using Scapy.
- **Spoof Detection Logic**: Validates DNS answers by cross-referencing responses with a reliable DNS resolver to detect inconsistencies.
- **Anomaly Alerts**: Highlights DNS replies lacking proper answer sections as potentially suspicious.
- **System Notifications**: Delivers instant desktop alerts when spoofing or abnormal behavior is identified.
- **Audio Alerts**: Triggers sound notifications for quick attention.
- **User Interface**: Built with Tkinter for an interactive environment to monitor events and logs.
- **Live Visualization**: Displays DNS query volume trends over time using Matplotlib-based dynamic graphing.
- **Filter Controls**: Allows users to refine log views—showing all entries, spoofed events, or only suspect packets.
- **Log Exporting**: Enables saving filtered logs into a `.txt` file for archival or external review.

## Technology Stack

- **Programming Language**: Python
- **Libraries**:
  - Scapy (network packet processing)
  - Tkinter (GUI framework)
  - Matplotlib (live graph plotting)
  - Plyer (desktop notifications)


## 📸 Screenshot

![image](https://github.com/user-attachments/assets/6a9c637d-dfe9-43f5-a80c-fd319ef2a716)


## 🛠️ Requirements

- Python 3.x
- [`scapy`](https://pypi.org/project/scapy/)
- [`dnspython`](https://pypi.org/project/dnspython/)
- [`matplotlib`](https://pypi.org/project/matplotlib/)
- [`plyer`](https://pypi.org/project/plyer/) *(optional, for desktop notifications)*
- `tkinter` (Usually included with Python installations)
- `npcap` - scapy needs either Npcap (recommended) or the old WinPcap to sniff network packets on Windows

### 📦 Install Dependencies

```bash
pip install scapy dnspython matplotlib plyer
