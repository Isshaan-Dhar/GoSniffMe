# GoSniffMe: High-Performance Network Telemetry Utility
A concurrent network packet analyzer built in Go (Golang) designed for real-time traffic monitoring and protocol dissection. This project demonstrates the transition from high-level scripting to performance-oriented systems programming, essential for roles in Network Security and SOC Operations.

## Technical Features
Concurrent Packet Processing: Utilizes Go's lightweight threading (Goroutines) to handle live data streams with minimal CPU overhead.

Multi-Layer Decoding: Manually parses and extracts data from Ethernet, IPv4, and TCP layers using the gopacket library.

Interface Discovery: Automatically identifies and lists available network hardware (Wi-Fi/Ethernet) for targeted sniffing.

Hardware Interfacing: Direct integration with Npcap/Libpcap for raw socket access on Windows environments.

## Project Architecture
The sniffer follows a "Capture-to-Decode" pipeline:

Discovery: Identifying active network interfaces.

Streaming: Opening a live handle to the network card driver.

Dissection: Feeding raw bytes into a decoder to identify source/destination IPs and ports.

## Installation & Usage
### Prerequisites
Go Compiler: (v1.24+ recommended).

Npcap: Must be installed in "WinPcap API-compatible Mode".

### Building from Source
#### Initialize and Download Dependencies:
go mod init gosniffme    
go get github.com/google/gopacket

#### Compile the Executable:
go build

#### Running the Analyzer:
./gosniffme.exe


## [!IMPORTANT]
Network sniffing requires Administrator Privileges. Ensure your terminal or VS Code is running as an Administrator.
