from scapy.all import *
# 数据流类


class Stream:
    def __init__(self, pkt):
        self.pkts = [pkt]  # 数据包列表
        self.src_ip = pkt[IP].src  # 源IP地址
        self.dst_ip = pkt[IP].dst  # 目的IP地址
        self.sport = pkt.sport  # 源端口号
        self.dport = pkt.dport  # 目的端口号
        self.protocol = pkt[IP].proto  # 协议id
        self.content = [pkt.load.decode(errors='ignore')] if pkt.haslayer(
            'Raw') else []  # 数据流包内容列表
        self.prname = pkt[IP].payload.name #协议名

    def update(self, pkt):  # 更新流
        self.pkts.append(pkt)
        # 如果数据包有原始层，则将原始数据解码并添加到流内容中
        if pkt.haslayer('Raw'):
            self.content.append(pkt.load.decode(errors='ignore'))

            
def parse_pcap(file_name):
    streams = {}
    pkts = rdpcap(file_name)  # 读取pcap文件
    for pkt in pkts:
        if IP in pkt:  # 如果该包包含 IP 层信息
            proto = pkt[IP].proto  # 获取协议编号
            if proto in [6, 17, 132, 33, 46]: 
                five_tuple = None
                if proto == 6:
                    five_tuple = (pkt[IP].src, pkt[IP].dst,
                                  pkt[TCP].sport, pkt[TCP].dport, proto)
                elif proto == 17:
                    five_tuple = (pkt[IP].src, pkt[IP].dst,
                                  pkt[UDP].sport, pkt[UDP].dport, proto)
                if five_tuple in streams:  # 如果该五元组已经存在于streams字典中
                    streams[five_tuple].update(pkt)  # 更新流 
                else:
                    streams[five_tuple] = Stream(pkt)  # 创建新的流
    return streams
