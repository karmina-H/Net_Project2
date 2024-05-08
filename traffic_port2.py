from scapy.all import *
from collections import defaultdict
import threading
import time

# 트래픽 증가 감지에 사용될 변수
traffic_threshold = 1000  # 트래픽 증가를 감지하기 위한 임계값
traffic_window_size = 2  # 트래픽을 모니터링할 시간 간격 (초)
traffic_window = defaultdict(int)  # 트래픽을 저장할 딕셔너리

# 패킷 닫는데 사용될 변수
packet_to_block = None

# 패킷 처리 함수 정의
def packet_callback(packet):
    global packet_to_block
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto  # IP 프로토콜 번호

        if protocol == 6:  # TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif protocol == 1:  # ICMP
            src_port = None
            dst_port = None
        elif protocol == 17:  # ARP
            src_port = None
            dst_port = None
        elif protocol == 6 and packet[TCP].dport == 80:  # HTTP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and packet[UDP].dport == 53:  # DNS
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return  # 다른 프로토콜은 스킵

        # 트래픽 증가 감지
        traffic_window[(src_ip, dst_ip, protocol, src_port, dst_port)] += 1

# 패킷을 처리하는 함수
def process_packets():
    global packet_to_block, traffic_window
    while True:
        time.sleep(traffic_window_size)
        if sum(traffic_window.values()) > traffic_threshold:
            # 트래픽이 임계값을 초과하면 가장 많이 사용된 패킷 식별
            max_packet = max(traffic_window, key=traffic_window.get)
            packet_to_block = max_packet
            print(f"Traffic spike detected! Blocking {max_packet} for 3 minutes.")
            # 패킷을 3분 동안 닫는 스레드 시작
            threading.Thread(target=block_packet_for_3_minutes).start()
            # traffic_window 초기화
            traffic_window = defaultdict(int)

# 패킷을 3분 동안 닫는 함수
def block_packet_for_3_minutes():
    global packet_to_block
    # 패킷 닫기 작업 수행
    # 여기에 패킷을 닫는 코드를 추가하세요.
    print(f"Packet {packet_to_block} blocked for 3 minutes.")
    time.sleep(180)  # 3분 동안 대기
    print(f"Packet {packet_to_block} unblocked.")
    packet_to_block = None

# 패킷 처리 스레드 시작
threading.Thread(target=process_packets).start()

# 패킷 수집 시작 (모든 패킷을 수집함)
sniff(prn=packet_callback, store=0)

# 이후의 작업을 원하시면 해당 스레드를 메인 스레드로 바꾸거나 적절히 조정해야합니다.