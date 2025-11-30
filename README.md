# 🛡️ DoS Attack Detector

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.4%2B-orange)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![License](https://img.shields.io/badge/License-MIT-green)

A Blue Team defense tool that monitors network traffic in real-time to detect Denial of Service (DoS) attacks. It specifically analyzes packet rates and TCP flags to identify **SYN Flood** signatures and alerts the user via a live dashboard.

## 🧐 The Problem

Denial of Service (DoS) attacks aim to overwhelm a server with traffic, making it unavailable to legitimate users. A common method is the **SYN Flood**, where an attacker sends thousands of connection requests (SYN packets) but never completes the handshake.

## 💡 The Solution

This tool acts as a lightweight Intrusion Detection System (IDS):
1.  **Sniffs** network traffic using Scapy.
2.  **Analyzes** packet headers for suspicious patterns (e.g., high volume of SYN flags).
3.  **Alerts** when traffic exceeds safety thresholds (e.g., >20 SYN packets/sec).

## 🚀 Features

- **Real-Time Monitoring**: Continuously scans network activity.
- **SYN Flood Detection**: Specialized logic to catch TCP handshake abuse.
- **Live Dashboard**: Web-based UI that flashes RED when an attack is detected.
- **Attack Simulator**: Includes a script (`attacker.py`) to safely simulate a DoS attack against localhost for testing.

## 🛠️ Installation

### Prerequisites
- **Python 3.8+**
- **Npcap** (Windows): Required for packet sniffing. Download from [npcap.com](https://npcap.com/).
- **Admin Privileges**: Required to capture network traffic.

### Steps

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/CyberShuriken/dos-detector.git
    cd dos-detector
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

**Note:** You must run the detector as **Administrator**.

1.  **Start the Detector**:
    ```bash
    python app.py
    ```

2.  **Open Dashboard**:
    Go to `http://localhost:5000`. You should see "SYSTEM SECURE".

3.  **Simulate an Attack** (Open a new terminal):
    ```bash
    python attacker.py
    ```

4.  **Watch the Dashboard**:
    It will detect the spike in SYN packets and switch to **"DoS ATTACK DETECTED"**.

## 🧠 Skills Demonstrated

- **Network Security**: Understanding TCP/IP handshakes and DoS attack vectors.
- **Traffic Analysis**: Using Scapy to dissect network packets programmatically.
- **Blue Team Operations**: Building tools for monitoring and alerting.
- **Multithreading**: Running packet sniffing and web serving concurrently in Python.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
