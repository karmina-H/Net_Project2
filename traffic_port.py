from scapy.all import *
from collections import defaultdict
import subprocess
import threading
import time

# 트래픽 증가 감지에 사용될 변수
traffic_threshold = 500  # 트래픽 증가를 감지하기 위한 임계값
traffic_window_size = 1  # 트래픽을 모니터링할 시간 간격 (초)
traffic_window = defaultdict(int)  # 트래픽을 저장할 딕셔너리

# 포트 닫는데 사용될 변수
port_to_block = None

# 패킷 처리 함수 정의
def packet_callback(packet):
    global port_to_block
    if IP in packet:
        if TCP in packet:
            dst_port = packet[TCP].dport
            # 트래픽 증가 감지
            traffic_window[dst_port] += 1
            if sum(traffic_window.values()) > traffic_threshold:
                # 가장 많이 사용된 포트 식별
                max_port = max(traffic_window, key=traffic_window.get)
                port_to_block = max_port
                print(f"Traffic spike detected! Blocking port {port_to_block} for 3 minutes.")
                # 포트를 3분 동안 닫는 스레드 시작
                threading.Thread(target=block_port_for_3_minutes).start()

# 포트를 3분 동안 닫는 함수
def block_port_for_3_minutes():
    global port_to_block
    # PowerShell 스크립트 실행하여 포트 닫기
    subprocess.run(["powershell.exe", "-File", "block_port.ps1", str(port_to_block)], capture_output=True, text=True)
    print(f"Port {port_to_block} blocked for 3 minutes.")

# 패킷 수집 시작
sniff(prn=packet_callback, store=0)