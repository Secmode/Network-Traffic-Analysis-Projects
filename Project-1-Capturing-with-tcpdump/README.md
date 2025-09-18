# Project 1 — Capturing Traffic with tcpdump

## Objective
Learn how to capture network traffic safely with `tcpdump`, apply capture filters, and produce PCAPs for later analysis.

## Lab Setup
- Use an isolated VM or lab network.
- Tools: `tcpdump`, `tshark`, Wireshark for offline analysis.

## Capture examples
Capture all traffic on interface `eth0`:
```bash
sudo tcpdump -i eth0 -w captures/tcpdump_capture_1.pcap
