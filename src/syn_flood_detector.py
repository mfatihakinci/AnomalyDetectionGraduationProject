from collections import Counter

class SynFloodDetector:
    def __init__(self, threshold):
        self.threshold = threshold

    def detect(self, features):
        # SYN bayraklı paketleri filtrele
        syn_packets = [f for f in features if f.get('flags') == 0x02]
        # SYN paketlerinin kaynak IP adreslerini al
        src_ips = [f.get('src_ip') for f in syn_packets]
        # IP adreslerini say
        ip_counts = Counter(src_ips)
        # Eşik değeri aşan IP adreslerini anomali olarak belirle
        anomalies = {ip: count for ip, count in ip_counts.items() if count > self.threshold}
        return anomalies
