from scapy.all import *
from collections import defaultdict
import time

# 각 프로토콜에 대한 카운터 초기화
packet_count = defaultdict(int)

# 공격 탐지 조건
THRESHOLD = 25000  # 패킷 임계치
TIME_WINDOW = 10  # 시간 윈도우 (초)
ATTACK_DURATION = 2  # 공격으로 판단할 지속 시간 (초)

def packet_callback(packet):
    global packet_count

    if IP in packet:
        if UDP in packet:
            packet_count['UDP'] += 1
        elif TCP in packet and packet[TCP].flags & 2:
            packet_count['SYN'] += 1
        elif ICMP in packet:
            packet_count['ICMP'] += 1
        elif packet.haslayer(Raw) and b'GET' in packet[Raw].load:
            packet_count['HTTP'] += 1

def detect_attack():
    global packet_count

    while True:
        time.sleep(TIME_WINDOW)
        total_packets = sum(packet_count.values())
        print("Total packets in last", TIME_WINDOW, "seconds:", total_packets)
        
        # 공격 탐지
        if total_packets > THRESHOLD:
            print("Possible attack detected!")
            for protocol, count in packet_count.items():
                print(protocol, "packets:", count)
            
            # 공격 지속 시간 체크
            time.sleep(ATTACK_DURATION)
            total_packets_after_delay = sum(packet_count.values())
            if total_packets_after_delay > THRESHOLD:
                print("Attack confirmed!")
                # 여기에 알림 또는 기타 조치를 추가할 수 있음

        # 카운터 초기화
        packet_count = defaultdict(int)

def main():
    # 스니핑 시작
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # 공격 탐지 쓰레드 시작
    import threading
    t = threading.Thread(target=detect_attack)
    t.daemon = True
    t.start()

    # 메인 프로그램 실행
    main()