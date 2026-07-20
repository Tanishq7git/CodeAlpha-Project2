# Task 1: Basic Network Sniffer

A Python network sniffer built with **Scapy** that captures live traffic and displays source/destination IPs, protocol, ports, and payload data.

## Features
- Captures live packets on the network interface
- Identifies protocol (TCP / UDP / ICMP)
- Displays source & destination IP and port
- Shows payload data when present

## Tech Used
Python 3, Scapy

## How to Run
```bash
pip install scapy
sudo python3 network_sniffer.py
```
Root/admin privileges are required — raw packet capture needs elevated access.

## What I Learned
- How data flows through the network across layers (IP → TCP/UDP → payload)
- The basic structure of a network packet and its headers
- Why packet capture requires elevated privileges
