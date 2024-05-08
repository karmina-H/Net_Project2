import numpy as np
import pandas as pd
from scapy.all import *
from sklearn.ensemble import IsolationForest

# 패킷 캡처 및 데이터프레임 생성
def capture_packets(num_packets):
    packets = sniff(count=num_packets)
    data = []
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_len = len(pkt)
            data.append([src_ip, dst_ip, proto, pkt_len])
    df = pd.DataFrame(data, columns=['Source_IP', 'Destination_IP', 'Protocol', 'Packet_Length'])
    return df

# Isolation Forest 모델 학습
def train_isolation_forest(df):
    X = df[['Packet_Length']]
    clf = IsolationForest(contamination=0.05)
    clf.fit(X)
    return clf

# 디도스 공격 탐지
def detect_ddos_attack(clf, df):
    X = df[['Packet_Length']]
    y_pred = clf.predict(X)
    df['Anomaly'] = y_pred
    return df[df['Anomaly'] == -1]

if __name__ == "__main__":
    # 패킷 캡처 및 데이터프레임 생성
    num_packets = 1000
    df = capture_packets(num_packets)

    # Isolation Forest 모델 학습
    clf = train_isolation_forest(df)

    # 디도스 공격 탐지
    ddos_attacks = detect_ddos_attack(clf, df)

    print("Detected DDoS Attacks:")
    print(ddos_attacks)