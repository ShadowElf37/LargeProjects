import socket
import time
import struct


def binary(integer, size=8, padright=False):
    b = bin(integer)[2:]
    if len(b) > size and size != 0:
        raise ValueError('Binary sequence already longer than requested length')
    while len(b) < size:
        b = ('0' + b) if not padright else (b + '0')
    return b

def render(p):
    return p.generate_packet()

class Packet:
    def __init__(self, payload, seqnum, acknum, src_ip, dst_ip, src_port, dst_port, first_mid_last=1):
        """Packet(
        'some text',
        24,
        25,
        '192.168.1.1',
        '192.168.1.2',
        44519,
        80,
        1
        )"""
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.level2_header = ''
        self.ip_header = ''
        self.seqnum = seqnum
        self.acknum = acknum
        self.placement = first_mid_last  # 0 is first, 1 is mid, 2 is last
        self.generate_level2_header = self.generate_tcp_header
    def __repr__(self):
        return '<Packet object with a %s byte payload>' % len(self.payload)
    def __str__(self):
        return self.__repr__()

    def generate_packet(self):
        payload = struct.pack('!'+'B'*len(self.payload), *list(map(ord, self.payload)))
        self.level2_header = self.generate_level2_header(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.payload)
        level2_packet = self.level2_header + payload
        self.ip_header = self.generate_ip_header(self.src_ip, self.dst_ip, level2_packet)
        level1_packet = self.ip_header + level2_packet
        full_packet = level1_packet
        return full_packet

    def generate_tcp_header(self, src, dst, sport, dport, payload):
        source_port = binary(sport, 16)
        dest_port = binary(dport, 16)
        seqnum = binary(self.seqnum, 32)  # packet id
        acknum = binary(self.acknum, 32)  # the next packet's id
        data_offset = '0101'
        reserved = '000'
        flags = '0000' + ('1' if self.placement > 0 else '0') + '10' + ('1' if self.placement == 0 else '0') + ('1' if self.placement == 2 else '0')
        window = '1111111111111111'  # max we can receive back, 65535 is prob. good?
        checksum = '0000000000000000'
        urgent = '0000000000000000'
        almost_complete_header = source_port + dest_port + seqnum + acknum + data_offset + reserved + flags + window + checksum + urgent
        almost_complete_header_sans_checksum = source_port + dest_port + seqnum + acknum + data_offset + reserved + flags + window + urgent

        src = socket.gethostbyname(src).split('.')
        dst = socket.gethostbyname(dst).split('.')
        src = ''.join(list([binary(int(seg), 8) for seg in src]))
        dst = ''.join(list([binary(int(seg), 8) for seg in dst]))
        reserved2 = '00000000'
        protocol = '00000110'  # 6 is TCP
        tcp_length = binary(len(almost_complete_header) + len(payload), 16)  # TCP header and data

        pseudo_header = src + dst + reserved2 + protocol + tcp_length
        sumcheck = pseudo_header + almost_complete_header_sans_checksum + payload
        sumthing1 = [int(sumcheck[i * 16:(i + 1) * 16], 2) for i in range(len(sumcheck) // 16)]
        sumthing = binary(sum(sumthing1), 0)
        while len(sumthing) > 16:
            sumthing = binary(int(sumthing[-16:], 2) + int(sumthing[:-16], 2), 16)
        checksum = ''.join(list(map(lambda x: '1' if x == '0' else '0', sumthing)))

        header = source_port, dest_port, seqnum, acknum, data_offset + reserved + flags, window, checksum, urgent
        header = list(map(lambda x: int(x, 2), header))  # Convert to numbers for packing
        return struct.pack('!HHLLHHHH', *header)

    def generate_ip_header(self, src, dst, payload):
        version = '0100'  # IPv4
        header_length = '0101'  # Size in 32-bit sections
        DSCP = '000000'  # Classification of the packet - default to 0
        ECN = '00'  # Explicit Congestion Notification - well it's not congested
        total_length = binary(int(header_length, 2) + len(payload), 16)  # possibly not necessary? kernel supposedly sets for you, just make 0
        if int(total_length, 2) > 65535:
            raise OverflowError('Packet too large')
        identification = '1010101010101010'  # i think can be anything
        flags = '010'  # reserved 0, don't fragment, lot's of fragments
        frag_offset = '0000000000000'  # 13 bits
        ttl = '11111111'  # Max hops in the internet
        protocol = '00000110'  # 6 is TCP
        # checksum
        src_o = socket.gethostbyname(src).split('.')
        dst_o = socket.gethostbyname(dst).split('.')
        src = ''.join(list([binary(int(seg), 8) for seg in src_o]))
        dst = ''.join(list([binary(int(seg), 8) for seg in dst_o]))

        sumcheck = version + header_length + DSCP + ECN + total_length + identification + flags + frag_offset + ttl + protocol + src + dst
        sumthing1 = [int(sumcheck[i:i+16], 2) for i in range(0, len(sumcheck), 16)]
        sumthing = binary(sum(sumthing1), 0)
        while len(sumthing) > 16:
            sumthing = binary(int(sumthing[-16:], 2) + int(sumthing[:-16], 2), 16)
        checksum = binary(int(sumthing, 2) & 0xffff, 16)
        # sum of all 16-bit sections, inverted, and fit to 16 bits

        header = version + header_length, DSCP + ECN, total_length, identification, flags + frag_offset, ttl, protocol, checksum, src, dst
        headersum = sum(map(len, header)) / 32
        goodsum = int(header_length, 2)
        if headersum != goodsum:
            raise ValueError('IP header longer than expected')
        header = list(map(lambda x: int(x, 2), header[:-2]))  # Convert to numbers for packing
        src_b = b''.join(list(map(lambda x: chr(int(x)).encode('utf-8'), src_o)))
        dst_b = b''.join(list(map(lambda x: chr(int(x)).encode('utf-8'), dst_o)))
        header.append(src_b)
        header.append(dst_b)

        return struct.pack('!BBHHHBBH4s4s', *header)


class RawSocket(socket.socket):
    def __init__(self):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    def send_packet(self, packet, dest_addr=None):
        if dest_addr is None:
            dest_addr = (packet.dst_ip, packet.dst_port)
        send = self.sendto(render(packet), dest_addr)
        print('{0} bytes {1} sent to {2} on port {3}'.format(send, packet, dest_addr[0], dest_addr[1],))


s = RawSocket()
pkt = Packet('Hello', 0, 7, '192.168.1.173', '192.168.1.164', 50164, 37377)
s.send_packet(pkt, ('192.168.1.164', 37377))
s.close()