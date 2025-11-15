# Network-Packet-sniffer-project

A network packet sniffer, also known as a packet analyzer or protocol analyzer, is a software or hardware tool that captures, inspects, and analyzes data packets transmitted over a computer network. Packets are the fundamental units of data in network communications, containing information like source/destination addresses, protocols, and payload data. Sniffers intercept these packets in real-time or from stored captures, allowing users to view and decode their contents for diagnostic, security, or forensic purposes.

How It Works
Packet sniffers operate by placing the network interface card (NIC) into "promiscuous mode," which enables it to capture all packets on the network segment, not just those addressed to the device. This is possible because Ethernet networks broadcast packets to all devices on a shared medium (like a hub), though modern switched networks (using switches) limit this to avoid eavesdropping.

Key components:

Capture Interface: Uses libraries like libpcap (on Unix/Linux) or WinPcap (on Windows) to interface with the NIC.
Filtering: Applies rules (e.g., via Berkeley Packet Filter syntax) to capture only specific packets, such as those using TCP on port 80.
Analysis: Parses packet headers and payloads, displaying details in a human-readable format. Tools often support decoding protocols like HTTP, DNS, or SSL/TLS.
Storage: Saves captures in formats like PCAP for later review.
Evidence of functionality: Packet sniffers rely on the OSI model's data link layer (Layer 2) to access raw packets, as standardized in protocols like IEEE 802.3. For instance, Wireshark, a popular open-source sniffer, has been used in network troubleshooting since its inception in 1998, with documentation confirming its promiscuous mode capabilities.

Common Uses
Network Troubleshooting: Diagnosing issues like latency, packet loss, or protocol errors by examining traffic flow.
Security Analysis: Detecting intrusions, malware, or unauthorized access by monitoring for suspicious patterns (e.g., unusual ports or encrypted anomalies).
Development and Education: Debugging applications or learning network protocols.
Forensics: Investigating cyber incidents by replaying captured traffic.
Legitimate use is widespread in IT fields, but misuse (e.g., unauthorized eavesdropping) can violate privacy laws like the U.S. Wiretap Act.

Examples of Tools
Wireshark: Free, cross-platform, with a GUI for deep packet inspection; supports over 3,000 protocols.
tcpdump: Command-line tool for Unix/Linux, lightweight and scriptable.
Snort: Primarily an intrusion detection system but includes sniffing capabilities.
Microsoft Network Monitor: Windows-based for enterprise environments.
