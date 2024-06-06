from scapy.all import rdpcap

class PcapProcessor:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def extract_features(self):
        packets = rdpcap(self.pcap_file)
        features = []
        for packet in packets:
            if packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp_layer = packet['TCP']
                ip_layer = packet['IP']
                # SYN flag kontrolü (SYN=1, ACK=0)
                if tcp_layer.flags == 0x02:
                    features.append({
                        'src_ip': ip_layer.src,
                        'dst_ip': ip_layer.dst,
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'flags': tcp_layer.flags,
                        'length': len(packet)
                    })
        return features
