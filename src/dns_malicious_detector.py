class DnsMaliciousDetector:
    def __init__(self, malicious_domains):
        self.malicious_domains = malicious_domains

    def detect(self, features):
        anomalies = []
        for f in features:
            query_name = f.get('query', '')
            if any(domain in query_name for domain in self.malicious_domains):
                anomalies.append(f)
        return anomalies
