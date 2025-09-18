# Project 1 — Capturing Traffic with tcpdump

## Overview
This project demonstrates how to capture, save, and analyze network traffic using **tcpdump.**  **The Sample Contain a capture of a host infected with Lockbit, A popular and know info stealer and remote access Trojan piece of malware.** The goal is to showcase packet capturing fundamentals, filtering techniques, and exporting traffic for deeper analysis in Wireshark. 
## Lab Setup
- **OS/Environment:** (Ubuntu 22.04 VM / Kali Linux / etc.)
- **Tool:** tcpdump
- **Network Interface:** (eth0 / wlan0 / ens33, etc.)
- **Sample PCAP:** [2021-09-14.pcap  /2023-02-03.pcap]
<img width="771" height="284" alt="image" src="https://github.com/user-attachments/assets/f5c82f0d-363a-42b8-b8c9-94942198b1f8" />





in Life trafic Cature filter tell the type of trafic we want to capture  and Display filter Capability 




======================================================================
## Objective
Learn how to capture network traffic safely with `tcpdump`, apply capture filters, and produce PCAPs for later analysis.

## Lab Setup
- Use an isolated VM or lab network.
- Tools: `tcpdump`, `tshark`, Wireshark for offline analysis.

## Capture examples
Capture all traffic on interface `eth0`:
```bash
sudo tcpdump -i eth0 -w captures/tcpdump_capture_1.pcap





# Project 1 — Capturing Traffic with tcpdump

## Overview
This project demonstrates how to capture and analyze raw network traffic using **tcpdump**.  
The goal is to collect packet data from a live network (or pre-captured PCAP file) and prepare it for further analysis in tools like Wireshark.  

## Tools Used
- **Ubuntu Machine**
- **tcpdump**
- Sample **PCAP file** (downloaded online)

---

## Objectives
- Learn how to capture network traffic using `tcpdump`.
- Understand capture filters (host, port, protocol).
- Save captured packets into a `.pcap` file for later analysis.
- Build a foundation for deeper inspection with Wireshark.

---

## Tools Used
- **Ubuntu Machine**
- **tcpdump**
- Sample **PCAP file** (downloaded online)

---

## Example tcpdump Commands
Capture all traffic on interface `eth0`:
```bash
sudo tcpdump -i eth0 -w capture.pcap
