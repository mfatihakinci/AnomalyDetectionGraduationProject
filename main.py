from src.pcap_processor import PcapProcessor
from src.syn_flood_detector import SynFloodDetector
from src.dos_amplification_detector import DosAmplificationDetector
from src.dns_malicious_detector import DnsMaliciousDetector
from src.utils import print_anomalies, setup_logger
import requests
import os
import pandas as pd

def fetch_malicious_domains():
    url = "https://urlhaus.abuse.ch/downloads/csv/"
    response = requests.get(url)
    lines = response.text.splitlines()
    malicious_domains = []
    for line in lines:
        if not line.startswith('#'):
            fields = line.split(',')
            if len(fields) > 2:
                domain = fields[2]
                malicious_domains.append(domain)
    return malicious_domains

def main():
    logger = setup_logger()
    
    # PCAP dosyalarının yolları
    syn_flood_pcap = 'C:/Users/z004pn2m/Downloads/syn-flood-attack-16-05-ddos-v2.pcap'
    dos_amplification_pcap = 'C:/Users/z004pn2m/Downloads/syn-flood-attack-16-05-ddos-v2.pcap'
    dns_malicious_pcap = 'C:/Users/z004pn2m/Downloads/dns-zone-transfer-axfr.pcap'

    # Eşik değerleri
    syn_flood_threshold = 10  # SYN paketleri eşiği
    dos_amplification_threshold = 55  # UDP paket uzunluğu eşiği
    malicious_domains = fetch_malicious_domains()  # Zararlı domainleri alın

    # Anomali verilerini depolamak için bir liste oluşturun
    anomalies = []

    # SYN Flood Anomali Tespiti
    processor = PcapProcessor(syn_flood_pcap)
    features = processor.extract_features()
    syn_flood_detector = SynFloodDetector(syn_flood_threshold)
    syn_flood_anomalies = syn_flood_detector.detect(features)
    anomalies.extend([{'anomaly_type': 'SYN Flood', 'details': anomaly} for anomaly in syn_flood_anomalies])
    print_anomalies(syn_flood_anomalies, 'SYN Flood', logger)

    # DoS Amplification Anomali Tespiti
    processor = PcapProcessor(dos_amplification_pcap)
    features = processor.extract_features()
    dos_amplification_detector = DosAmplificationDetector(dos_amplification_threshold)
    dos_amplification_anomalies = dos_amplification_detector.detect(features)
    anomalies.extend([{'anomaly_type': 'DoS Amplification', 'details': anomaly} for anomaly in dos_amplification_anomalies])
    print_anomalies(dos_amplification_anomalies, 'DoS Amplification', logger)

    # Zararlı DNS Sorguları Anomali Tespiti
    processor = PcapProcessor(dns_malicious_pcap)
    features = processor.extract_features()
    dns_malicious_detector = DnsMaliciousDetector(malicious_domains)
    dns_malicious_anomalies = dns_malicious_detector.detect(features)
    anomalies.extend([{'anomaly_type': 'Malicious DNS Queries', 'details': anomaly} for anomaly in dns_malicious_anomalies])
    print_anomalies(dns_malicious_anomalies, 'Malicious DNS Queries', logger)

    # Anomalileri bir DataFrame'e dönüştürün
    df = pd.DataFrame(anomalies)
    df.index = df.index + 1
    return df

if __name__ == "__main__":
    df = main()
    # Anomalileri CSV olarak kaydedin veya başka bir şekilde işleyin
    df.to_csv('anomalies.csv', index=False)
