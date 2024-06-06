class DosAmplificationDetector:
    def __init__(self, threshold):
        self.threshold = threshold

    def detect(self, features):
        # Paket uzunluğu eşik değerini aşan paketleri bul
        amplification_attacks = [f for f in features if f.get('length') > self.threshold]
        return amplification_attacks
