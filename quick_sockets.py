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

def ascii(sequence):
    if len(sequence) % 8 != 0:
        raise ValueError('Bad binary sequence, cannot convert to bytes')
    sequence = list([sequence[i * 8:(i+1) * 8] for i in range(len(sequence) // 8)])
    chars = ''.join(list(map(lambda x: chr(int(x, 2)), sequence)))
    return chars

class ConnectionType:
    TYPES = [socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_RAW]
    DEFAULT = socket.SOCK_STREAM
    TCP = socket.SOCK_STREAM
    UDP = socket.SOCK_DGRAM
    RAW = socket.SOCK_RAW
    IP = 'IP'

class Message:
    def __init__(self, bytes_or_string, protocol='UTF-8'):
        self.msg = bytes_or_string
        self.protocol = protocol

    def __repr__(self):
        return '<Message of size %s bytes>' % len(self.msg)

    def __str__(self):
        return self.__repr__()
    def __int__(self):
        return len(self.msg)

    def get_bytes(self):
        try:
            return str.encode(self.msg, self.protocol)
        except ValueError:
            return self.msg
    def get_text(self):
        try:
            return self.msg.decode(self.protocol)
        except AttributeError:
            return self.msg


class Log:
    def __init__(self):
        self.loglist = []

    def log(self, *msg):
        mesg = []
        for item in msg:
            mesg.append(str(item))
        m = ' '.join(mesg)+('.' if mesg[-1][-1] not in '.!?' else '')
        self.loglist.append((time.time(), m))
        return m

    def get_log(self, starti=0, stopi=-0):
        if stopi > len(self.loglist) or stopi is -0:
            stopi = len(self.loglist) + 1
        elif stopi < starti and stopi > 0:
            stopi = -1
        if starti < 0:
            starti = 0

        l = []
        for line in self.loglist:
            l.append(str(line[0])+':  '+str(line[1]))
        return '\n'.join(l[starti:stopi])


class Client:
    def __init__(self, addr, port, type=ConnectionType.TCP):
        self.type = type
        if self.type not in ConnectionType.TYPES:
            self.type = ConnectionType.DEFAULT
        self.addr = addr
        self.port = port
        self.socket = socket.socket(socket.AF_INET, self.type)
        self.BUFFER = 1024

    def connect(self):
        self.socket.connect((self.addr, self.port))
        return 0

    def receive(self):
        return Message(self.socket.recv(self.BUFFER))

    def send(self, msg):
        if self.type == ConnectionType.TCP:
            self.socket.send(msg.get_bytes())
        elif self.type == ConnectionType.UDP:
            self.socket.sendto(msg)
        return 0

    def send_packet(self, p):
        if self.type != ConnectionType.RAW:
            raise TypeError('Connection does not support raw packet construction')
        self.socket.send(p)
        return 0

    def close(self):
        self.socket.close()

class Server:
    def __init__(self, port, host=socket.gethostname()):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.host = host
        self.port = port
        self.MAX_CONNECTIONS = 5
        self.connections = dict()
        self.BUFFER = 1024
        self.VERBOSE = False
        self.Log = Log()

    def log(self, *m):
        if self.VERBOSE:
            print(self.Log.log(*m))
            return 0
        self.Log.log(*m)
        return 0

    def initialize(self):
        self.log('Connection established at', self.host, '('+socket.gethostbyname(socket.gethostname())+')', 'on port', self.port)
        self.socket.bind((self.host, self.port))
        return 0

    def open(self):
        self.log('Socket open, listening...')
        self.socket.listen(self.MAX_CONNECTIONS)
        return 0

    def accept_connection(self):
        c, a = self.socket.accept()
        self.log('New connection at', a[0], 'on port', a[1])
        self.connections[a] = c
        return a

    def receive(self, address):
        msg = Message(self.connections[address].recv(self.BUFFER))
        self.log('Message received from', str(address)+':', msg)
        return msg

    def receive_openly(self):
        m = self.socket.recvfrom(self.BUFFER)
        msg = Message(m[0])
        self.log('Message received from', str(m[1]) + ':', msg)
        return msg, m[1]

    def send(self, msg, address=None):
        if address == None:
            address = list(self.connections.keys())[-1]
        self.log('Message sent:', msg)
        self.connections[address].send(msg.get_bytes())
        return 0

    def terminate_connection(self, address=None):
        if address == None:
            address = self.connections[-1]
        self.log('Terminated connection at', address)
        self.connections[address].close()
        del self.connections[address]
        return 0

    def close(self):
        self.log('Socket closed')
        self.socket.close()
        self.connections.clear()
        return 0

s = Server(37377)
s.VERBOSE = True
s.initialize()
s.open()
client = s.accept_connection()
for i in range(5):
    s.receive(client)
s.close()

#print(s.Log.get_log())
