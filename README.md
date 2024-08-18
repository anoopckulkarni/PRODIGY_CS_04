# Packet Sniffer Tool

By Anoop C Kulkarni

This Python tool captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data. It is intended for educational purposes to help users understand network traffic.

## Features

- **Packet Capture**: Captures network packets on a specified network interface.
- **Information Display**: Displays source and destination IP addresses, protocol type, and payload data.
- **Protocol Identification**: Identifies and displays TCP and UDP packet details.

## Requirements

- Python 3.x
- `scapy` library

### Installation

1. **Install Python 3.x**: Ensure Python 3.x is installed on your system.

2. **Install scapy**:
   ```bash
   pip install scapy
   ```

## Usage

1. **Run the Program**:
   - Save the script as `packet_sniffer.py`.
   - Open a terminal or command prompt.
   - Navigate to the directory containing `packet_sniffer.py`.
   - Run the program using the command:
     ```bash
     sudo python packet_sniffer.py
     ```
   - On Windows, you may need to run the script with administrative privileges.

2. **Select Network Interface**:
   - The script will list available network interfaces.
   - For Windows, it displays interface indices; select the correct index.
   - For other platforms, enter the network interface name (e.g., `eth0`, `wlan0`).

3. **View Packet Information**:
   - The program will display details about each captured packet in real-time.

## Example

### Running the Program:

```bash
Packet Sniffer Tool
Available interfaces:
0: \Device\NPF_{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
1: \Device\NPF_{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
Enter the index of the network interface to sniff on: 0
Starting packet sniffing on \Device\NPF_{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}...
Source IP: 192.168.1.5
Destination IP: 192.168.1.1
Protocol: 6
Protocol: TCP
Source Port: 12345
Destination Port: 80
Payload: <Raw Data>
----------------------------------------
```

### Feedback Example for a Packet:

```bash
Packet Sniffer Tool
Available interfaces:
eth0
wlan0
Enter the network interface to sniff on (e.g., eth0, wlan0): wlan0
Starting packet sniffing on wlan0...
Source IP: 192.168.1.5
Destination IP: 192.168.1.1
Protocol: 17
Protocol: UDP
Source Port: 12345
Destination Port: 53
Payload: <Raw Data>
----------------------------------------
```

## Notes

- **Ethical Use**: This tool is intended for educational purposes and should only be used on networks you own or have explicit permission to monitor.
- **Permissions**: Administrative or root privileges may be required for capturing packets, especially on Windows.


## Contributing

Feel free to fork this project, submit issues, or contribute by creating pull requests.

## Acknowledgements

This tool utilizes the `scapy` library for packet capturing and analysis, providing a powerful framework for network exploration.
