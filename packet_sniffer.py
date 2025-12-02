"""
Educational Packet Sniffer using Scapy (Color-Coded)
----------------------------------------------------
This script demonstrates how packet sniffing works on a local network interface.
It is intended for **educational and authorized security research only**.

⚠ LEGAL NOTICE:
Use only on networks you own or have explicit permission to analyze.

Author: Internalveil
License: MIT
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP

# =========================
# ANSI COLOR CODES
# =========================
RESET  = "\033[0m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
MAGENTA = "\033[95m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


def colorize(packet):
    """Return a color based on packet protocol."""

    if packet.haslayer(TCP):
        return BLUE          # TCP packets = blue

    if packet.haslayer(UDP):
        return GREEN         # UDP packets = green

    if packet.haslayer(DNS):
        return YELLOW        # DNS packets = yellow

    if packet.haslayer(ICMP):
        return MAGENTA       # ICMP echo/icmp = magenta

    if packet.haslayer(ARP):
        return CYAN          # ARP = cyan

    return WHITE             # Anything else = white


def packet_callback(packet):
    """
    Called automatically for each captured packet.
    Prints a readable, color-coded summary.
    """
    color = colorize(packet)

    try:
        print(color + packet.summary() + RESET)
    except Exception as e:
        print(RED + f"Error processing packet: {e}" + RESET)


def main():
    print(GREEN + "=== Educational Packet Sniffer Started ===" + RESET)
    print("Press CTRL+C to stop.\n")

    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    main()

