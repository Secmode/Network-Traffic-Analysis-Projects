# Project 2 — Network Analysis with Wireshark

## Overview
This project demonstrates practical network forensic analysis using Wireshark to investigate malicious traffic from two packet capture files. The objective is to detect suspicious activity, extract Indicators of Compromise (IOCs), and correlate them with known malware families and MITRE ATT&CK techniques.  
**Analyzed PCAPs:**  
`sample-2021-09-14.pcap`  `sample-2023-02-03.pcap`  

**Tools used:**  
`Wireshark` `CyberChef Git` `Bash (sha256sum)` `VirusTotal` `MalwareBazaar Malpedia` `Microsoft Security Intelligence`

## Step 1 — Initial Setup & Capture Properties
- Loaded the PCAP files into Wireshark → verified capture file properties (duration, packet count, and protocols), and performed baseline analysis using Statistics → Capture File Properties.
<img width="1899" height="774" alt="image" src="https://github.com/user-attachments/assets/f331b77e-ef65-4c4a-bf98-6d46526f3736" />

## Step 2 — Filtering & Stream Analysis  

**Applied key Wireshark filters to isolate suspicious activity:**  

- `http.request.method == "GET"`  - `http.request.method == "POST"`  - `http contains "service"`  - `http contains "audiodg.exe"`  - `tcp.port == 80`  - `http.request.uri contains "audiodg"`  - `arp` and `icmp` (to review host discovery and broadcast traffic)  - `arp and eth.dst eq ff:ff:ff:ff:ff:ff` - `tcp.stream eq 75` - `http.request.uri contains "audiodg"` - `http.request.uri contains "audiodg"` 

**Findings (2021-09-14.pcap):**  
- Detected an HTTP request attempting to download a suspicious file `audiodg.exe`.  
- Exported the object and confirmed it contained a malicious executable.  
- Extracted the SHA256 hash:  
- VirusTotal flagged by 57 vendors as malicious.
- Downloading the malicious executable → MITRE ATT&CK Ingress Tool Transfer (T1105).
<img width="1798" height="933" alt="Screenshot 2025-09-21 173606" src="https://github.com/user-attachments/assets/f6eda94f-ec85-43cf-86ba-ec4406811a4e" />
<img width="1790" height="825" alt="Screenshot 2025-09-21 210457" src="https://github.com/user-attachments/assets/6641e013-16b2-49a7-ace7-a550abdebb88" />
<img width="1833" height="851" alt="Screenshot 2025-09-21 210742" src="https://github.com/user-attachments/assets/55433a87-a47f-43a0-8669-357e897b99e8" />








===============================================================================================
## Step 3 — Host & Protocol Hierarchy Analysis
**Findings (2023-02-03.pcap):**
- Conversations analysis showed 10.0.0.149 communicating with 10.0.0.6 with over 12,000 packets.
- Protocol Hierarchy revealed multiple HTTP requests.
- Detected HTTP GET request for suspicious .dat file:
- File header (MZ) confirmed executable format.
- Extracted SHA256 hash of 86607.dat:
- VirusTotal detection: 56/72 vendors.
- MalwareBazaar signature: Qakbot (QBot) banking Trojan.
<img width="1916" height="297" alt="Screenshot 2025-09-21 212204" src="https://github.com/user-attachments/assets/46cbbebc-a40b-48db-b96e-f957481c2a68" />
<img width="1872" height="824" alt="Screenshot 2025-09-21 212733" src="https://github.com/user-attachments/assets/0198d487-a1b0-4dc7-99ac-6bdadec8fa03" />
<img width="1832" height="847" alt="Screenshot 2025-09-21 214355" src="https://github.com/user-attachments/assets/89ec2efe-5c5e-44f8-bb2a-8d8d6479471f" />
<img width="1645" height="887" alt="Screenshot 2025-09-21 220958" src="https://github.com/user-attachments/assets/ccd6d940-c5e8-48a7-92e7-5a8ecf7ec876" />
<img width="1323" height="785" alt="Screenshot 2025-09-21 222023" src="https://github.com/user-attachments/assets/642595c3-a84f-4c9e-8360-f6ea0641dba4" />


## Step 4 — Credentials & SMB Analysis
- Detected **SMTP Auth Login** traffic with Base64 encoding.
- Decoded with CyberChef:
- Exported SMB objects revealed 6 DLL files.
- Hashed with sha256sum for IOC documentation.
<img width="1919" height="929" alt="Screenshot 2025-09-21 230652" src="https://github.com/user-attachments/assets/91f63577-b8ce-4812-9c3b-d07da4993bda" />
<img width="1836" height="822" alt="Screenshot 2025-09-21 232737" src="https://github.com/user-attachments/assets/e5625618-2504-4819-bb6f-9beed2554522" />
<img width="1345" height="808" alt="Screenshot 2025-09-21 223238" src="https://github.com/user-attachments/assets/a584419a-e730-4e19-8e91-40da2691f3da" />

## Step 5 — MITRE ATT&CK Mapping

| Activity                                    | Technique                     | ID           |
|--------------------------------------------|-------------------------------|-------------|
| Malicious file download via HTTP (`audiodg.exe`, `86607.dat`) | Ingress Tool Transfer          | T1105       |
| Credential harvesting (SMTP AUTH LOGIN)    | Valid Accounts                | T1078       |
| Malware execution (Qakbot DLLs)            | Command and Scripting Interpreter | T1059  |
| ARP/ICMP traffic analysis                  | Discovery                     | T1087, T1016 |
<img width="1900" height="1026" alt="image" src="https://github.com/user-attachments/assets/951a51e2-5e6e-46ce-9cb4-fc3ed5de32af" />




## Step 6 — Key Findings
- Malicious executables (audiodg.exe, 86607.dat) downloaded over HTTP.
- Hash correlation confirmed Qakbot malware.
- Clear evidence of credential theft via SMTP traffic.
- Indicators of possible lateral movement (SMB DLL files, ARP/ICMP broadcast activity).


## Indicators of Compromise (IOCs)
**Hashes:**
- `f485d1a65ccf9f857baa49725d337c15e8aa34515b85c8ef59a72afad7b85249 (audiodg.exe)`
- `713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432 (86607.dat → Qakbot)`
**IPs:**
- 128.254.207.55 (Malicious C2 server)
- 10.0.0.149 (Infected host)
- 10.0.0.6 (Target communication)

**Credentials (captured in traffic):**
- Username: `arthit@macnels.co.th`
- Password: `Art123456`

## Conclusion  
This project demonstrates how Wireshark can be used for deep packet inspection to uncover:

- Malicious downloads
- Credential exposure
- C2 communication
- Malware family attribution (Qakbot)

By combining filtering, protocol analysis, object export, hash verification, and threat intelligence correlation, analysts can build a strong case for detection and response.

## Skills Highlighted
- Practical network forensics & malware traffic analysis
- Strong command of Wireshark filters and statistics
- Threat intelligence integration (VirusTotal, MalwareBazaar, Malpedia)
- IOC documentation and ATT&CK framework mapping
- Hands-on DFIR methodology
