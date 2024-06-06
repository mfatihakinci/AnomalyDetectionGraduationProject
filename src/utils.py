import logging

def setup_logger():
    logging.basicConfig(level=logging.INFO, filename='anomalies.log', filemode='w',
                        format='%(name)s - %(levelname)s - %(message)s')
    return logging.getLogger('AnomalyDetection')

def print_anomalies(anomalies, anomaly_type, logger):
    logger.info(f"Detected {anomaly_type} anomalies:")
    for anomaly in anomalies:
        logger.info(anomaly)
        print(f"{anomaly_type} anomaly detected: {anomaly}")
