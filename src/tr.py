#!/usr/bin/env python
# coding:utf-8

"""
    版本：v5.0
程序功能：修改IPv6的报文处理逻辑
    作者：Roger
    时间：2024年12月12日

    版本：v4.0
程序功能：新增-h --hide隐藏本地设备信息
    作者：Roger
    时间：2024年11月27日

    版本：v3.0
程序功能：新增IPv6的支持
    作者：Roger
    时间：2024年11月27日

    版本：v2.0
程序功能：新增-list ip 查询路由的功能(本地+纯真)
    作者：Roger
    时间：2024年11月17日

    版本：v1.0
程序功能：新增纯真数据库ip查询功能
    作者：Roger
    时间：2024年11月17日

    版本：v0.6
程序功能：新增-list ip 查询路由的功能(本地)
    作者：Roger
    时间：2024年11月14日

    版本：v0.5
程序功能：添加命令行参数支持
    作者：Roger
    时间：2024年11月14日

    版本：v0.4
程序功能：查询与删除后台数据
    作者：Roger
    时间：2024年11月13日

    版本：v0.3
程序功能：更新ip对应的设备名称
    作者：Roger
    时间：2024年11月13日

    版本：v0.2
程序功能：查询ip对应的设备名称
    作者：Roger
    时间：2024年11月13日

    版本：v0.1
程序功能：路由跟踪
    作者：Roger
    时间：2024年11月12日
"""

import struct
import socket
import select
import time
import os
import sys
import signal
import requests
import IPy
import json
import argparse

def signal_handler(Signal, Frame):
    print()
    sys.exit()

class IP_Packet:
    def __init__(self, source_ip, destination_ip, ttl, protocol=1, payload=b''):
        self.version = 4                                            # IP版本号,IPv4为4,IPv6为6
        self.header_length = 5                                      # IP报头长度(32位字的数量)
        self.type_of_service = 0                                    # 服务类型(通常为0)
        self.total_length = 20 + len(payload)                       # IP报文总长度(字节数)
        self.identification = 0                                     # 标识符
        self.flags = 0                                              # 标志(DF和MF)(通常为0)
        self.fragment_offset = 0                                    # 分片偏移(通常为0)
        self.time_to_live = ttl                                     # 生存时间(TTL)
        self.protocol = protocol                                    # 上层协议(TCP=6,UDP=17)
        self.checksum = 0                                           # 校验和(初始值为0)
        self.source_ip = socket.inet_aton(source_ip)                # 源IP地址
        self.destination_ip = socket.inet_aton(destination_ip)      # 目标IP地址
        self.payload = payload                                      # 上层协议数据

    def calculate_checksum(self, header):
        """
        计算IP报头的校验和
        """
        checksum = 0
        # 将每个16位字添加到校验和中
        for i in range(0, len(header), 2):
            checksum += (header[i] << 8) + header[i+1]
        # 将溢出位添加到校验和中
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        # 取反得到校验和的补码
        checksum = ~checksum & 0xFFFF
        return checksum

    def pack(self):
        """
        将IP报文打包成二进制数据
        """
        # 构造IP报头
        version_header_length = (self.version << 4) + self.header_length
        # print(f'version_header_length: {hex(version_header_length)}')
        flags_fragment_offset = (self.flags << 13) + self.fragment_offset
        # print(f'flags_fragment_offset: {hex(flags_fragment_offset)}')
        header = struct.pack('!BBHHHBBH4s4s', version_header_length, self.type_of_service, self.total_length,
                             self.identification, flags_fragment_offset, self.time_to_live, self.protocol,
                             self.checksum, self.source_ip, self.destination_ip)
        # 计算IP报头的校验和
        self.checksum = self.calculate_checksum(header)
        # 重新构造IP报头,更新校验和字段
        header = struct.pack('!BBHHHBBH4s4s', version_header_length, self.type_of_service, self.total_length,
                             self.identification, flags_fragment_offset, self.time_to_live, self.protocol,
                             self.checksum, self.source_ip, self.destination_ip)
        # 打包IP报文数据和上层协议数据
        packet = header + self.payload
        return packet

class ICMP_Packet:
    def __init__(self, icmp_sequence, icmp_identifier=os.getpid() % 0xffff,  icmp_type=8, icmp_code=0):
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_checksum = 0
        self.icmp_identifier = icmp_identifier
        self.icmp_sequence = icmp_sequence
        self.payload = 'https://www.roogeer.com   QQ:1681991'.encode()

    def calculate_checksum(self, header):
        """
        计算ICMP报头的校验和
        """
        checksum = 0
        # 将每个16位字添加到校验和中
        for i in range(0, len(header), 2):
            checksum += (header[i] << 8) + header[i+1]
        # 将溢出位添加到校验和中
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        # 取反得到校验和的补码
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def pack(self):
        """
        将ICMP报文打包成二进制数据
        """
        icmp_header = struct.pack('!BBHHH', self.icmp_type, self.icmp_code, self.icmp_checksum, self.icmp_identifier, self.icmp_sequence)  # 长度和校验和暂时设为0
        self.icmp_checksum = self.calculate_checksum(icmp_header + self.payload)
        # print(f'icmp header_checksum={hex(self.icmp_checksum)}')
        icmp_header = struct.pack('!BBHHH', self.icmp_type, self.icmp_code, self.icmp_checksum, self.icmp_identifier, self.icmp_sequence)  # 修正校验和
        # print(f'icmp_header = {len(icmp_header)}')
    
        # 打包ICMP报文数据
        packet = icmp_header + self.payload
        # print(f'packet = {len(packet)}')
        return packet

def reply_icmp(send_icmp_request_time, sock, icmp_sequence, timeout=2):
        # 接收数据
        while True:
            # 开始接收返回数据包的时间
            started_select_time = time.time()
            what_ready = select.select([sock], [], [], TIMEOUT)
            # 等待时间
            wait_for_time = time.time() - started_select_time
            if what_ready[0] == []:
                # print(f'sock中无数据，超时')    # Timeout
                return -1, "*"
        
            timeout = timeout - wait_for_time
            if timeout <= 0:
                return -1, "*"
            
            # socket中有数据,记录下接收数据的时间，此处时间会 < 2s
            time_received = time.time()
            # 查看ip头部是否指示上层协议为icmp
            received_packet, addr = sock.recvfrom(1024)

            protocol, = struct.unpack(">B", received_packet[9:10])
            # print(f'上层协议号是: {protocol}')
            if 1 != protocol:     # 上层协议不是ICMP
                print(f'不是ICMP数据包')
                return -1, "*"

            # 到这里，开始处理icmp数据包
            #roger print(f'{"接收到的数据：":>10}')
            # 先判断icmp的TYPE类型
            icmpheader = received_packet[20:22]
            type, code = struct.unpack(">BB", icmpheader)
            # 是差错报文
            if 11==type and 0==code:
                #roger print(f'{"type: ":>20}{type}  code: {code}')
                # 检查差错报文中的负载，判断是否为当前进程和等待的序列号回包
                identifier, seq = struct.unpack(">HH", received_packet[52:56])
                #roger print(f'{"identifier: ":>20}{hex(identifier)}')
                #roger print(f'{"seq: ":>20}{seq}')
                if (icmp_sequence!=seq) or (OS_ID!=identifier):
                    #roger print(f'接收到的数据包其中进程或序列号不是期待的值')
                    return -1, "*"

                ip_header = received_packet[12:16]
                sip, =struct.unpack(">4s", ip_header)
                return time_received - send_icmp_request_time, socket.inet_ntoa(sip)
                # print(f'第{ttl}跳的ip为：{socket.inet_ntoa(sip)}')
                # break
            # 是reply报文
            elif  0==type and 0==code:
                #roger print(f'{"type: ":>20}{type}  code: {code}')
                # 检查reply报文中的负载，判断是否为当前进程和等待的序列号回包
                identifier, seq = struct.unpack(">HH", received_packet[24:28])
                #roger print(f'{"identifier: ":>20}{hex(identifier)}')
                #roger print(f'{"seq: ":>20}{seq}')
                if (icmp_sequence!=seq) or (OS_ID!=identifier):
                    # print(f'接收到的数据包，进程或序列号不是期待的值')
                    return -1, "*"

                ip_header = received_packet[12:16]
                sip, =struct.unpack(">4s", ip_header)
                return time_received - send_icmp_request_time, socket.inet_ntoa(sip)
                # print(f'第{ttl}跳的ip为：{socket.inet_ntoa(sip)}')
            else:
                return -1, "*"

########################## IPv6部分 ############################
class IPv6_Packet:
    def __init__(self, source_ip, destination_ip, ttl, payload_length=44):
        self.version = 6                                            #   4bit, IPv6为6
        self.traffic_class = 0                                      #   8bit, 流类型
        self.flow_label = 0                                         #  20bit, 流标签
        self.payload_length = payload_length                        #  16bit, IPv6报文负载字节数: icmpv6(8) + 负载
        self.next_header = 58                                       #   8bit, ICMPv6协议号：58
        self.hop_limit = ttl                                        #   8bit, hop_limit：生存时间(TTL)
        self.source_ip = socket.inet_pton(socket.AF_INET6, source_ip)                # 128bit, 源IP地址：128
        self.destination_ip = socket.inet_pton(socket.AF_INET6, destination_ip)      # 128bit, 目标IP地址
        # self.payload = payload                                      # 上层协议数据

    def pack(self):
        """
        将IPv6报文打包成二进制数据
        """
        # 构造IPv6报头
        version_header_length = (self.version << 4)
        # print(f'version_header_length: {hex(version_header_length)}')

        header = struct.pack('!BBHHBB16s16s ', version_header_length, self.traffic_class, self.flow_label,
                             self.payload_length, self.next_header, self.hop_limit,
                             self.source_ip, self.destination_ip)
        packet = header
        return packet

class ICMPv6_Packet:
    def __init__(self, pseudoheader_sip, pseudoheader_dip, icmp_sequence, icmp_identifier=os.getpid() % 0xffff, icmp_type=128, icmp_code=0):
        self.pseudoheader_sip = socket.inet_pton(socket.AF_INET6, pseudoheader_sip)
        self.pseudoheader_dip = socket.inet_pton(socket.AF_INET6, pseudoheader_dip)
        self.pseudoheader_nexthop = 58
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.icmp_checksum = 0
        self.icmp_identifier = icmp_identifier
        self.icmp_sequence = icmp_sequence
        self.payload = ('https://www.roogeer.com   QQ:1681991').encode()
        self.pseudoheader_payload_length = len(self.payload) + 8

    def icmpv6_checksum(self):
        packet = struct.pack('!16s16sIIBBHHH36s', self.pseudoheader_sip, self.pseudoheader_dip,
                                self.pseudoheader_payload_length,
                                self.pseudoheader_nexthop,
                                self.icmp_type,
                                self.icmp_code,
                                self.icmp_checksum,
                                self.icmp_identifier,
                                self.icmp_sequence,
                                self.payload
                                )

        # 伪首部格式：128位（16字节）
        # 计算伪首部的校验和
        checksum = 0
        for i in range(0, len(packet), 2):
            word = packet[i] << 8 | packet[i+1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        checksum = ~checksum & 0xffff
        return checksum

    def pack(self):
        """
        将ICMPv6报文打包成二进制数据
        """
        # 计算校验和字段
        self.icmp_checksum = self.icmpv6_checksum()
        # print(f'icmp header_checksum={hex(self.icmp_checksum)}')

        # 填充正确的校验和字段
        icmp_header = struct.pack('!BBHHH', self.icmp_type, self.icmp_code, self.icmp_checksum, self.icmp_identifier, self.icmp_sequence)  
        # print(f'icmp_header = {len(icmp_header)}')
        # print(f'在ICMPv6_Packet类中的icmpv6数据包:')
        # for i in icmp_header:
        #     print(hex(i))

        # 打包ICMPv6报文数据
        packet = icmp_header + self.payload
        return packet

def ipv6_reply_icmp(send_icmp_request_time, sock, icmp_sequence, timeout=2):
        OS_ID = os.getpid() % 0xffff

        # 接收数据
        while True:
            # 开始接收返回数据包的时间
            started_select_time = time.time()
            what_ready = select.select([sock], [], [], timeout)
            # 等待时间
            wait_for_time = time.time() - started_select_time
            if what_ready[0] == []:
                # print(f'sock中无数据，超时')    # Timeout
                return -1, "*"

            timeout = timeout - wait_for_time
            if timeout <= 0:
                # print(f'timeout <= 0')    # Timeout
                return -1, "*"

            # socket中有数据,记录下接收数据的时间，此处时间会 < 2s
            time_received = time.time()
            # 查看ipv6头部是否为icmpv6，且数据是期待的
            # icmp(58)，
            # type(129/3), 
            # code(0/0), 
            # icmp_identifier(进程id), 
            # icmp_sequence(发送的探测包序列号)

            # 实际网卡是以下的情况：
            # ICMP为: type=129 code=0 时：44 = 8 + 36(icmp_payload)
            # ICMP为：type=3   code=0 时：92 = 8 + 40 + 8 + 36(icmp_payload)            

            received_packet, addr = sock.recvfrom(1024)
            # 显示收到的数据
            # if len(received_packet) in [92, 44]:
            #     for index, item in enumerate(received_packet):
            #         index = index + 1
            #         if index % 16 ==0:
            #             print(f'{hex(item)}  ')
            #         else:
            #             print(f'{hex(item)}  ', end='')
            #     print()
            #     print()

            ####### 实际网卡中的处理 ################
            # 如果收到的数据长度不是44、92，直接开始下一轮处理
            if len(received_packet) not in [44, 92]:
                continue

            rec_icmp_protocol_type, = struct.unpack(">B", received_packet[0:1])
            # 如果不是icmpv6协议 type=129 or type=3，直接开始下一轮处理
            if 129 != rec_icmp_protocol_type and 3 != rec_icmp_protocol_type:
                continue

            # 收到的数据是否为ICMPv6 TTL耗尽报文：type=3, code=0
            if 92 == len(received_packet):
                # print(f'这里处理type=3 code=0的icmpv6报文')
                rcv_icmp_type, rcv_icmp_code  = struct.unpack(">BB", received_packet[0:2])
                rcv_identifier, rcv_sequence  = struct.unpack(">HH", received_packet[8+40+4:8+40+4+4])
                _rcv_src_ipv6 = addr[0]

                # 如果是ICMPv6 TTL耗尽报文
                # 且identifier、sequence也是期待的值
                if 3 == rcv_icmp_type and 0 == rcv_icmp_code and OS_ID == rcv_identifier and icmp_sequence == rcv_sequence:
                    # 是ICMP差错报文，返回：耗时 + 源ipv6地址
                    # print(f'rcv_sequence = {rcv_sequence}, sip = {_rcv_src_ipv6}')
                    return time_received - send_icmp_request_time, _rcv_src_ipv6

            # 收到的数据是否为ICMPv6 TTL耗尽报文：type=129, code=0
            if 44 == len(received_packet):
                # print(f'这里处理type=129 code=0的icmpv6报文')
                rcv_icmp_type, rcv_icmp_code  = struct.unpack(">BB", received_packet[0:2])
                rcv_identifier, rcv_sequence  = struct.unpack(">HH", received_packet[4:4+4])
                _rcv_src_ipv6 = addr[0]

                # 如果是ICMPv6 Reply
                # 且identifier、sequence也是期待的值
                if 129 == rcv_icmp_type and 0 == rcv_icmp_code and OS_ID == rcv_identifier and icmp_sequence == rcv_sequence:
                    # 是ICMP Reply报文，返回：耗时 + 源ipv6地址
                    # print(f'rcv_sequence = {rcv_sequence}, sip = {_rcv_src_ipv6}')
                    return time_received - send_icmp_request_time, _rcv_src_ipv6

# 判断命令行中args.ip是ipv6、ipv、域名、其他
def getArgsIPInfo(info):
    # 默认返回数据
    version = 0
    ip = "error"

    # 先尝试转为IPy.IP对象
    try:
        ip = IPy.IP(info)
        # 如果能成功执行，判断是ip的版本信息
        version = ip.version()
        if 4==version:
            ip = ip.strNormal()
        elif 6==version:
            ip = ip.strCompressed()
        return version, ip
    except ValueError:
        # 进入到这里，表示不是直接给出的ipv4 或 ipv6地址，尝试解析域名
        try:
            ip = socket.gethostbyname(info)
            # 如果能成功解析，返回version + ipv4
            version = 4
            return version, ip
        except Exception as e:
            # 进入到这里，表示不是ip，也不是域名，程序无法处理，退出
            ip = "错误: ip地址格式不正确或域名无法解析"
    return version, ip

if __name__ == "__main__":
    # 处理CTRL + C键盘中断
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Roger's tracert v5.0")
    parser.add_argument('ip', default=None, nargs="?", help='需要跟踪的ip')
    parser.add_argument('-u', '--update', dest="_update", nargs=2, default=False, help='更新标记ip对应的元素', metavar=('ip', 'description'))
    parser.add_argument('-d', '--delete', dest="_delete", nargs="+", default=False, help='删除标记ip对应的元素', metavar="ip")
    parser.add_argument('-l', '--list', dest="_list", nargs="?", action="store", const=4, type=int, choices=[4,6], help='显示所有ip对应的信息')
    parser.add_argument('--hide', dest="_hide", default=False, action="store_true", help='隐藏本地设备信息')
    parser.add_argument('-v', '--version', dest="_version", default=False, action="store_true", help='显示版本信息')
    args = parser.parse_args()

    # 如果命令行参数是：-v, --version
    if args._version:
        url = f'http://192.168.108.102:8984/trserver/getversion/'
        ret = requests.get(url)
        ret = json.loads(ret.text)
        print()
        print("Roger's tracert v5.0")
        print(ret)
        sys.exit()

    # 如果命令行参数是: --list
    if 4==args._list and not args.ip:
        # 向后台请求全部数据: ipv4
        url = f'http://192.168.108.102:8984/trserver/getipdb/'
        ret = requests.get(url)
        ipdb = json.loads(ret.text)
        print()
        for key, value in ipdb.items():
            print(f'{key:>20}    {value}')
        
        print()
        sys.exit()

    if 6==args._list and not args.ip:
        # 向后台请求全部数据: ipv4
        url = f'http://192.168.108.102:8984/trserver/getipv6db/'
        ret = requests.get(url)
        ipdb = json.loads(ret.text)
        print()
        for key, value in ipdb.items():
            print(f'{key:>40}    {value}')
        
        print()
        sys.exit()

    # 如果命令行参数是: --list x.x.x.x
    if 4==args._list and args.ip:
        print()
        try:
            _ip = IPy.IP(args.ip)
            # 向后台请求全部数据
            url = f'http://192.168.108.102:8984/trserver/getipdb/?ip={args.ip}'
            ret = requests.get(url)
            result = json.loads(ret.text)
            if "ipdb" == result["db"]:
                # 数据来自ipdb本地数据库
                print(f"{'':>2} {_ip.strNormal():<20} 在本地数据中，匹配以下地址段：")
                print()                
                for item in result["ipinfo"][0:1]:
                    deviceip, devicename = item
                    print(f"{'>':>2} {deviceip:<20} {devicename}")
                for item in result["ipinfo"][1:]:
                    deviceip, devicename = item
                    print(f"{'':>2} {deviceip:<20} {devicename}")
            else:
                # 数据来自czdb纯真数据库
                print(f"{'':>2} {_ip.strNormal():<20} 在纯真数据中，匹配以下地址段：")
                print()
                for item in result["ipinfo"][0:1]:
                    deviceip, devicename = item
                    print(f"{'>':>2} {deviceip:<20} {devicename}")                

            print()
            sys.exit()
        except ValueError:
            print(f'{args.ip} 地址格式不对，请检查后再试')
            sys.exit()

    if 6==args._list and args.ip:
        print()
        try:
            _ip = IPy.IP(args.ip)
            # 向后台请求全部数据
            url = f'http://192.168.108.102:8984/trserver/getipv6db/?ip={args.ip}'
            ret = requests.get(url)
            result = json.loads(ret.text)
            if "ipdb" == result["db"]:
                # 数据来自ipdb本地数据库
                print(f"{'':>2} {_ip.strCompressed():<40} 在本地数据中，匹配以下地址段：")
                print()                
                for item in result["ipinfo"][0:1]:
                    deviceip, devicename = item
                    print(f"{'>':>2} {deviceip:<40} {devicename}")
                for item in result["ipinfo"][1:]:
                    deviceip, devicename = item
                    print(f"{'':>2} {deviceip:<40} {devicename}")
            else:
                # 数据来自czdb纯真数据库
                print(f"{'':>2} {_ip.strCompressed():<40} 在纯真数据中，匹配以下地址段：")
                print()
                for item in result["ipinfo"][0:1]:
                    deviceip, devicename = item
                    print(f"{'>':>2} {deviceip:<40} {devicename}")                

            print()
            sys.exit()
        except ValueError:
            print(f'{args.ip} 地址格式不对，请检查后再试')
            sys.exit()


    # 处理--delete参数
    if args._delete:
        for ip in args._delete:
            # print(f'{ip} 将被删除')
            version, _ip = getArgsIPInfo(ip)
            if 4==version:
                try:
                    # _ip = IPy.IP(ip)
                    # 向后台请求删除数据
                    data={"deviceip":_ip}
                    url = f'http://192.168.108.102:8984/trserver/deletenamebyip/'
                    ret = requests.post(url=url, data=json.dumps(data))
                    ret = json.loads(ret.text)
                    print(f'{ret["deviceip"]} {ret["devicename"]}')
                    # sys.exit()
                except ValueError:
                    print(f'{ip} 地址格式不对，请检查后再试')
                    # sys.exit()
                    continue
            elif 6==version:
                try:
                    # _ip = IPy.IP(ip)
                    # 向后台请求删除数据
                    data={"deviceip":_ip}
                    url = f'http://192.168.108.102:8984/trserver/deletenamebyipv6/'
                    ret = requests.post(url=url, data=json.dumps(data))
                    ret = json.loads(ret.text)
                    print(f'{ret["deviceip"]} {ret["devicename"]}')
                    # sys.exit()
                except ValueError:
                    print(f'{ip} 地址格式不对，请检查后再试')
                    # sys.exit()
                    continue
            else:
                pass

        sys.exit()

    # 处理--update参数
    if args._update:
        version, ip = getArgsIPInfo(args._update[0])
        deviceip = ip
        devicename = args._update[1]        
        if 4==version:
            try:
                # _ip = IPy.IP(deviceip)
                # 向后台请求更新/添加数据
                data={"deviceip":deviceip, "devicename":devicename}
                url = f'http://192.168.108.102:8984/trserver/updatenamebyip/'
                ret = requests.post(url=url, data=json.dumps(data))
                print(f'{deviceip} 信息更新为 {devicename}')
                # sys.exit()
            except ValueError:
                print(f'{deviceip} 地址格式不对，请检查后再试')
            sys.exit()
        elif 6==version:
            try:
                # _ip = IPy.IP(deviceip)
                # 向后台请求更新/添加数据
                data={"deviceip":deviceip, "devicename":devicename}
                url = f'http://192.168.108.102:8984/trserver/updatenamebyipv6/'
                ret = requests.post(url=url, data=json.dumps(data))
                print(f'{deviceip} 信息更新为 {devicename}')
                # sys.exit()
            except ValueError:
                print(f'{deviceip} 地址格式不对，请检查后再试')
            sys.exit()
        else:
            pass


    if args.ip == None:
        print("Roger's tracert v5.0")
        print("  usage: -h")
        sys.exit()

    # 以下是tracert处理过程
    OS_ID = os.getpid() % 0xffff    # 获取进程id(不能大于65535)
    TIMEOUT = 2                     # 默认2秒后超时

    # 先判断给出的目标ip是否合法
    # 目标IP地址
    version, _ip = getArgsIPInfo(args.ip)
    # print(version, argsipinfo)
    # 如果返回version为0，表示参数不正确，程序无法处理
    if 0 == version:
        print(_ip)
        sys.exit()

    try:
        # 处理IPv4地址
        if 4 == version:
            # 目标IP地址
            # dest_ip = socket.gethostbyname(_ip)
            dest_ip = _ip
            
            # 源ip地址
            _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _sock.connect((dest_ip, 0))
            src_ip, _ = _sock.getsockname()

            # 创建一个原始套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # 允许在IP头部上写数据
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            #roger print(f'源ip：{src_ip:20}目标ip：{dest_ip:20}进程号：{hex(OS_ID):20}')
            print()
            # print(f'通过最多 30 个跃点跟踪到 {sys.argv[1]} {[dest_ip]} 的路由')
            print(f'通过最多 30 个跃点跟踪到 {args.ip} {[dest_ip]} 的路由')
            print()
            # print(f'目标ip：{dest_ip}')
            # print(f'进程号：{hex(OS_ID)}')

            for ttl in range(0,30):							# 最大30跳
                print(f"{ttl+1:>3}     ", end='')        
                for i in range(0, 3):						# 每跳尝试3次
                    wait_for_seq = ttl * 3 + i + 1          # ICMP序列号

                    # 序列号为 wait_for_seq 的icmp包
                    icmp = ICMP_Packet(icmp_sequence = wait_for_seq)
                    icmp_packet = icmp.pack()

                    ip = IP_Packet(src_ip, dest_ip, ttl=ttl+1)
                    ip_packet = ip.pack()

                    # 记录发送icmp报文的时间
                    send_icmp_request_time = time.time()

                    # 发送IP数据报
                    sock.sendto(ip_packet + icmp_packet, (dest_ip, 0))  

                    times, info = reply_icmp(send_icmp_request_time, sock, wait_for_seq)
                    if times <  0:
                        if wait_for_seq % 3 == 0:
                            print(f'{"*":>4}{"请求超时":>19}')
                        else:
                            pass
                    else:
                        if info == dest_ip:
                            print(f'{int(times*1000):>4} ms', end='')
                            print(f'{info:>20}', end='')

                            # 在这里添加ip对应的设备名称
                            url = f'http://192.168.108.102:8984/trserver/getnamebyip/{info}'
                            ret = requests.get(url)
                            ret = ret.json()

                            # 判断是否为-hide模式
                            devicename = ret["ipinfo"].replace('"', '')
                            if args._hide and ret["dbinfo"] == 'ipdb':
                                # 如果为隐藏模式且，数据来源为本地数据库，则显示为*号
                                devicename = "* " * 3
                            
                            # 不是隐藏模式，或者数据来源不是本地数据库，则正常显示
                            print(" "*5, end='')
                            print(f"{devicename:<15}")

                            print()
                            print('跟踪完成。')

                            sys.exit()
                        elif info != "*":
                            print(f'{int(times*1000):>4} ms', end='')
                            print(f'{info:>20}', end='')

                            # 在这里添加ip对应的设备名称
                            url = f'http://192.168.108.102:8984/trserver/getnamebyip/{info}'
                            ret = requests.get(url)
                            ret = ret.json()

                            # 判断是否为-hide模式
                            devicename = ret["ipinfo"].replace('"', '')
                            if args._hide and ret["dbinfo"] == 'ipdb':
                                # 如果为隐藏模式且，数据来源为本地数据库，则显示为*号
                                devicename = "* " * 3
                            
                            # 不是隐藏模式，或者数据来源不是本地数据库，则正常显示
                            print(" "*5, end='')
                            print(f"{devicename:<15}")
                            break
                        else:
                            if wait_for_seq % 3 == 0:
                                print(f'{"*":>4} ms')
                            else:
                                pass

            print()
            print('跟踪完成。')
        else:
            # 处理IPv6地址
            dest_ip = _ip

            # 源ip地址
            _sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            _sock.connect((dest_ip, 0))
            src_ip, _, _, _ = _sock.getsockname()

            # 创建一个原始套接字
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_IP)

            # 允许在IP头部上写数据
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, 1)

            print()
            print(f'通过最多 30 个跃点跟踪到 {dest_ip} 的路由')
            print()        

            for ttl in range(0,30):                         # 最大30跳
                print(f"{ttl+1:>3}     ", end='')
                for i in range(0, 3):                       # 每跳尝试3次
                    wait_for_seq = ttl * 3 + i + 1          # ICMP序列号，也是回包中期待的序列号

                    # 创建ICMPv6数据包
                    icmp = ICMPv6_Packet(src_ip, dest_ip, icmp_sequence = wait_for_seq)
                    icmp_packet = icmp.pack()

                    # 创建IPv6数据包
                    ip = IPv6_Packet(src_ip, dest_ip, ttl=ttl+1)
                    ip_packet = ip.pack()

                    # 记录发送icmp报文的时间
                    send_icmp_request_time = time.time()

                    # 发送IP数据报
                    sock.sendto(ip_packet + icmp_packet, (dest_ip, 0))

                    # 获取返回的数据
                    times, info = ipv6_reply_icmp(send_icmp_request_time, sock, wait_for_seq)

                    if times <  0:
                        if wait_for_seq % 3 == 0:
                            print(f'{"*":>4}{"请求超时":>39}')
                        else:
                            pass
                    else:
                        if info == dest_ip:
                            print(f'{int(times*1000):>4} ms', end='')
                            print(f'{info:>40}', end='')

                            # 在这里添加ip对应的设备名称
                            url = f'http://192.168.108.102:8984/trserver/getnamebyipv6/{info}'
                            ret = requests.get(url)
                            ret = ret.json()

                            # 判断是否为-hide模式
                            devicename = ret["ipinfo"].replace('"', '')
                            if args._hide and ret["dbinfo"] == 'ipdb':
                                # 如果为隐藏模式且，数据来源为本地数据库，则显示为*号
                                devicename = "* " * 3
                            
                            # 不是隐藏模式，或者数据来源不是本地数据库，则正常显示
                            print(" "*5, end='')
                            print(f"{devicename:<15}")

                            print()
                            print('跟踪完成。')

                            sys.exit()
                        elif info != "*":
                            print(f'{int(times*1000):>4} ms', end='')
                            print(f'{info:>40}', end='')

                            # 在这里添加ip对应的设备名称
                            url = f'http://192.168.108.102:8984/trserver/getnamebyipv6/{info}'
                            ret = requests.get(url)
                            ret = ret.json()

                            # 判断是否为-hide模式
                            devicename = ret["ipinfo"].replace('"', '')
                            if args._hide and ret["dbinfo"] == 'ipdb':
                                # 如果为隐藏模式且，数据来源为本地数据库，则显示为*号
                                devicename = "* " * 3
                            
                            # 不是隐藏模式，或者数据来源不是本地数据库，则正常显示
                            print(" "*5, end='')
                            print(f"{devicename:<15}")
                            break
                        else:
                            if wait_for_seq % 3 == 0:
                                print(f'{"*":>4} ms')
                            else:
                                pass

            print()
            print('跟踪完成。')
    except Exception as e:
        print(f"错误: {e}")