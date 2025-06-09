#!/bin/bash

echo "Rodando script"

# ICMP ipv4
echo "Teste icmp ipv4"
ping -c1 8.8.8.8 >/dev/null

# ICMPv6 ipv6
echo "Teste icmpv6 ipv6"
ping -6 -c1 ipv6.google.com >/dev/null

# ARP 
echo "Teste arp ipv4"
ping -c1 192.168.0.1 >/dev/null
