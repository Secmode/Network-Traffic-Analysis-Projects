# Project 1 — Network Traffic Analysis with tcpdump

## Overview
This project demonstrates how to capture, save, and analyze network traffic using tcpdump. The sample dataset is a packet capture (PCAP) downloaded from an online source that contains traffic from a host infected with LockBit, a well-known information stealer and remote access Trojan.
**The infected host in the capture uses the IP address 10.0.0.168. By analyzing this traffic, the project highlights:**
- Fundamentals of packet capturing with tcpdump.
- Filtering techniques to isolate suspicious traffic (e.g., HTTP requests, DNS queries).
- Identifying network behavior associated with malware infections.
## Lab Setup
- **OS/Environment:** (Ubuntu 22.04 VM / Kali Linux / etc.)
- **Tool:** tcpdump
- **Infected Host IPe:** 10.0.0.168
- **Sample PCAP:** [2021-09-14.pcap  /2023-02-03.pcap]





## Initial Traffic Analysis using tcpdump
Step 1 — Count HTTP packets
`tcpdump -tt -r 2021-09-14.pcap  port 80 --count`
- Purpose: Quickly determine how many HTTP packets are in the capture.
- Observation: The capture contains 3,679 packets, indicating significant HTTP activity.
<img width="1870" height="574" alt="image" src="https://github.com/user-attachments/assets/b1bd7211-4070-41f3-87bb-a6b8bc82bb52" />

Step 2 — Inspect HTTP requests from infected host
  `tcpdump -tt -r 2021-09-14.pcap port 80 and host 10.0.0.168 | grep -E "GET|POST"`
- Purpose: Filter for HTTP GET and POST requests specifically from the infected host (10.0.0.168).
- Observation: Example of HTTP request captured:
<img width="1924" height="196" alt="image" src="https://github.com/user-attachments/assets/69d1f4bc-90ba-4d70-ad10-7a4bf3b01ae1" />
<img width="1905" height="207" alt="image" src="https://github.com/user-attachments/assets/48dedca9-3e28-48c7-ad27-1208b921981c" />

`1631630132.552578 IP 10.0.0.168.49724 > 103.232.55.148.http: Flags [P.], seq 1:282, ack 1, win 32768, length 281: HTTP: GET /service/.audiodg.exe HTTP/1.1`

## 
<img width="1906" height="405" alt="image" src="https://github.com/user-attachments/assets/9b77d9f2-cc4b-400c-a0c4-56b0a93dc5b3" />
<img width="795" height="246" alt="image" src="https://github.com/user-attachments/assets/6b594752-0238-4e90-804a-687a8f644daf" />


## Investigating audiodg.exe Using tcpdump
Step 3 — Search for the filename in the PCAP
`tcpdump -tt -r 2021-09-14.pcap | grep "audiodg.exe"`
- Purpose: Identify all packets containing the suspicious filename.
- Observation: Two HTTP GET requests were observed:
<img width="1912" height="154" alt="image" src="https://github.com/user-attachments/assets/8b702d92-3d71-4e2c-8629-a49d07092da4" />

Step 4 — View full ASCII payload for more context
  `tcpdump -tt -r 2021-09-14.pcap -A | grep "audiodg.exe" -A 500 | less`
Observation: Additional information shows Host: api.bing.com and destination IP 13.107.5.80.
<img width="1910" height="233" alt="image" src="https://github.com/user-attachments/assets/e6c6c65f-5cda-480a-94a4-140647f4efd2" />

Step 5 — Lookup remote IP (13.107.5.80)
- Method: DomainTools / whois lookup
- Observation: IP, Location and ASN
<img width="795" height="267" alt="image" src="https://github.com/user-attachments/assets/2ca8cdf1-18af-47ca-8273-267b1be4c84b" />


Step 6 — Decode and defang encoded URL
- Decoded using CyberChef
<img width="1915" height="635" alt="image" src="https://github.com/user-attachments/assets/aaa3853a-db0e-411a-b9c0-6ce908e3e1de" />

Step 7 — Check URL on VirusTotal
- Observation: The URL was flagged by 3 security vendors, confirming it as a potential IOC.
<img width="1915" height="643" alt="image" src="https://github.com/user-attachments/assets/ed0efcf1-6cee-483e-801a-787791da87ee" />


 ## Analysis & Interpretation

- The infected host `10.0.0.168` attempted to download `.audiodg.exe` from `103.232.55.148`.  
- URL decoding and VirusTotal analysis confirms the file is **potentially malicious**.  
- Destination IP `13.107.5.80` (Microsoft) appears in the packet due to URL query parameters — common in malware using legitimate infrastructure as a proxy.  
- Evidence collected (packet number, URL, decoded payload, VirusTotal results) represents a **clear IOC**.

 ###
  ## Framework Alignment

This project aligns with recognized cybersecurity frameworks:

### MITRE ATT&CK
- **T1071.001 – Application Layer Protocol: Web Protocols**  
- **T1105 – Ingress Tool Transfer**  

### NIST Cybersecurity Framework (CSF)
- **Identify (ID):** Understanding infected host behavior and network indicators.  
- **Detect (DE):** Capturing suspicious HTTP traffic and identifying malware downloads.  
- **Respond (RS):** Documenting IOCs and providing actionable recommendations.

### SOC / Threat Hunting
- IOC collection using PCAP and VirusTotal.  
- Malware behavior analysis based on HTTP traffic patterns and file signatures.


---

## Next Steps / i will be analyzing  the second PCAP captured 2023-02-03.pcap
count pcap. tcpdump -r 2023-02-03.pcap --count
<img width="922" height="170" alt="image" src="https://github.com/user-attachments/assets/a26ac1bd-391f-4367-81dd-35450438f8ad" />

tcpdump -tt -r 2023-02-03.pcap -n tcp and dst 10.0.18.169 and src 85.239.53.219 \
| cut -d " " -f 5 \
| cut -d "." -f 1-3 \
| sort \
| uniq -c \
| sort -nr





