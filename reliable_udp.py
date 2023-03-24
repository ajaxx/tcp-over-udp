# A framework for reliable udp

import logging
import random
import socket
import struct

from enum import IntEnum
from utils import States

logger = logging.getLogger(__name__)

max_initial_sequence_no = 65536 * 1024

class ControlBits(IntEnum):
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128

class OptionBits(IntEnum):
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    MAX_SEGMENT_SIZE = 2

# unsupported option extensions
# SACK
# TIMESTAMP
# WINDOW_SCALE
    
def calc_checksum(data: bytes) -> int:
    """Calculates the TCP checksum for a byte array of data"""

    # The checksum field is the 16-bit ones' complement of the ones' complement sum of all 16-bit words in the
    # header and text. The checksum computation needs to ensure the 16-bit alignment of the data being
    # summed. If a segment contains an odd number of header and text octets, alignment can be achieved by
    # padding the last octet with zeros on its right to form a 16-bit word for checksum purposes. The pad is not
    # transmitted as part of the segment. While computing the checksum, the checksum field itself is replaced
    # with zeros.

    if len(data) % 2 == 1:
        # if the input is not aligned (2-byte) then add a null padding octet
        data += b"\x00"

    # unpack the data into an array of unsigned shorts
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    # sum the unsigned shorts
    chksum = sum(words)
    # one's complement
    #chksum = ~chksum

    # this is the long way with bit rotation logic
    chksum = (chksum >> 16) + (chksum & 0xffff)
    chksum += chksum >> 16
    chksum = ~chksum & 0xffff

    return chksum



class Packet:
    def __init__(self, data: bytes, addr: tuple):
        # the 'tcp' header should be 20-octets
        if len(data) < 20:
            raise ValueError(f'error processing packet from {addr} of length {len(data)}')

        self.addr = addr
        (
            self.src_port,
            self.dst_port,
            self.seq_no,
            self.ack_no,
            offset_and_reserved,
            self.control_bits,
            self.window_size,
            self.checksum,
            self.urgent
        ) = struct.unpack("!HHIIBBHHH", data[0:20])

        # offset
        self.offset = offset_and_reserved >> 4
        # reserved
        self.reserved = offset_and_reserved & 0x0f
        # there may be option data between 21 and 21 + offset
        doffset = 21 + self.offset
        # extract the options
        self.options = data[21:doffset]
        # extract the payload (if any)
        self.data = data[doffset:]
    
    def __repr__(self):
        return repr({
            'addr' : self.addr,
            'src_port' : self.src_port,
            'dst_port' : self.dst_port,
            'seq_no' : self.seq_no,
            'ack_no' : self.ack_no,
            'offset' : self.offset,
            'reserved' : self.reserved,
            'control' : self.control_bits,
            'window_size' : self.window_size,
            'checksum' : self.checksum,
            'urgent' : self.urgent,
            'options' : self.options,
            'payload' : self.data
        })
    
    @property
    def is_syn(self):
        return (self.control_bits == ControlBits.SYN)

    @property
    def is_syn_ack(self):
        return (self.control_bits == (ControlBits.SYN | ControlBits.ACK))

    @property
    def is_ack(self):
        return (self.control_bits == ControlBits.ACK)

    @property
    def is_fin_ack(self):
        return (self.control_bits == (ControlBits.ACK | ControlBits.FIN))

    @property
    def is_fin(self):
        return (self.control_bits == ControlBits.FIN)

# The connection object is a state machine that takes in packets
# and applies them to the state machine.

class Connection:
    def __init__(self, sock: socket.socket, state: States):
        # the socket associated with this connection
        self.sock = sock
        # get the source information for this socket
        (self.src_addr, self.src_port) = self.sock.getsockname()
        # get the source inet
        self.src_inet = socket.inet_aton(self.src_addr)
        # the state of the connection
        self._state = state
        # window size - maximum window size for starters
        self.window_size = 65535
        # maximum segment size
        self.mss = 536  # default for ipv4

    def get_state(self):
        return self._state
    
    def set_state(self, value):
        logger.info(f'set_state({self.state}): {value}')
        self._state = value

    state = property(fget = get_state, fset = set_state)

    def pseudo_ip_header(self, segment_length):
        return (
            self.src_inet + 
            self.dst_inet +
            b'\x00\x04' +
            segment_length.to_bytes(2, 'big')
        )

    def with_checksum(self, tcp_packet: bytes):
        # create the pseudo ip header
        ip_header = self.pseudo_ip_header(len(tcp_packet))
        # create checksum from the concatenated body parts
        tcp_checksum = calc_checksum(ip_header + tcp_packet)
        tcp_checksum = socket.htons(tcp_checksum)
        # now place the checksum into the packet data
        tcp_buffer = bytearray(tcp_packet)
        tcp_buffer[16] = (tcp_checksum >> 8) & 0x0f
        tcp_buffer[17] = (tcp_checksum & 0x0f)

        return bytes(tcp_buffer)

    def increment_seq_no(self):
        self.seq_no = self.seq_no + 1

    def syn(self):
        # set the TCP header fields for the SYN packet
        return self.with_checksum(
            struct.pack(
                "!HHIIBBHHHBBH",
                self.src_port, # 16-bits
                self.dst_port, # 16-bits
                self.seq_no, # 32-bits
                self.ack_no, # 32-bits
                5 << 4,  # 8-bits, offset + reserved
                int(ControlBits.SYN),  # 8-bits, control bits (SYN)
                self.window_size,  # 16-bits window size
                0,  # 16-bits, checksum (should be set to zero)
                0,  # 16-bits, urgent pointer (should be set to zero)
                2,  # option-kind (maximum segment size)
                4,  # option-length
                self.mss,  # maximum segment size
            )
        )
    
    def syn_ack(self):
        # set the TCP header fields for the SYN packet
        return self.with_checksum(
            struct.pack(
                "!HHIIBBHHHBBH",
                self.src_port,
                self.dst_port,
                self.seq_no,
                self.ack_no,
                5 << 4,
                int(ControlBits.SYN | ControlBits.ACK),  # 8-bits
                self.window_size,  # 16-bits window size
                0,  # 16-bits, checksum (should be set to zero)
                0,  # 16-bits, urgent pointer (should be set to zero)         
                2,  # option-kind (maximum segment size)
                4,  # option-length
                self.mss,  # maximum segment size
            )
        )

    def ack(self):
        # set the TCP header fields for the SYN packet
        return self.with_checksum(
            struct.pack(
                "!HHIIBBHHH",
                self.src_port,
                self.dst_port,
                self.seq_no,
                self.ack_no,
                0,
                int(ControlBits.ACK),  # 8-bits
                self.window_size,  # 16-bits window size
                0,  # 16-bits, checksum (should be set to zero)
                0   # 16-bits, urgent pointer (should be set to zero)         
            )
        )

    def fin(self):
        return self.with_checksum(
            struct.pack(
                "!HHIIBBHHH",
                self.src_port,
                self.dst_port,
                self.seq_no,
                self.ack_no,
                0,
                int(ControlBits.FIN),  # 8-bits
                self.window_size,  # 16-bits window size
                0,  # 16-bits, checksum (should be set to zero)
                0   # 16-bits, urgent pointer (should be set to zero)         
            )
        )


    def fsm_closed(self, packet: Packet):
        # The socket is currently closed and not listening.  Normally, we should
        # not be able to exit this state from an incoming packet.
        logger.info(f'fsm_closed({self.state}): packet = {packet}')

    def fsm_listen(self, packet: Packet):
        logger.info(f'fsm_listen({self.state}): packet = {packet}')

        # The connection is listening
        if packet.is_syn:
            # establish our endpoint information
            self.dst_addr = packet.addr[0]
            self.dst_port = packet.addr[1]
            self.dst_inet = socket.inet_aton(self.dst_addr)
            # establish our sequence number
            self.seq_no = random.randint(0, max_initial_sequence_no)
            # set our acknowlegement to their sequence number
            self.ack_no = packet.seq_no
            # send a syn-ack
            self.send_packet(self.syn_ack())
            self.state = States.SYN_RECEIVED
        else:
            logger.warn(f'fsm_listen({self.state}): unexpected')

    # the connection is in SYN_RECEIVED
    def fsm_syn_received(self, packet: Packet):
        logger.info(f'fsm_syn_received({self.state}): packet = {packet}')

        if packet.is_ack:
            self.state = States.ESTABLISHED
        elif packet.is_fin:
            self.state = States.CLOSING
        else:
            logger.warn(f'fsm_syn_received({self.state}): unexpected')

    # the connection is in SYN_SENT
    def fsm_syn_sent(self, packet: Packet):
        logger.info(f'fsm_syn_sent({self.state}): packet = {packet}')
        if packet.is_syn_ack:
            self.state = States.ESTABLISHED
            #
            self.ack_no = packet.seq_no
            # send an ack
            self.send_packet(self.ack())
            self.states = States.ESTABLISHED
        else:
            logger.warn(f'fsm_syn_sent({self.state}): unexpected')

    def fsm_established(self, packet: Packet):
        logger.info(f'fsm_established({self.state}): packet = {packet}')
        if packet.is_fin:
            self.send_packet(self.ack())
            self.state = States.CLOSE_WAIT
        else:
            logger.warn(f'fsm_established({self.state}): unexpected')



    def fsm_fin_wait_1(self, packet: Packet):
        logger.info(f'fsm_fin_wait_1({self.state}): packet = {packet}')
        if packet.is_fin_ack:
            self.send_packet(self.ack())
            self.state = States.TIME_WAIT
        elif packet.is_fin:
            self.send_packet(self.ack())
            self.state = States.CLOSING
        elif packet.is_ack:
            self.state = States.FIN_WAIT_2
        else:
            logger.warn(f'fsm_fin_wait_1({self.state}): unexpected')


    def fsm_fin_wait_2(self, packet: Packet):
        logger.info(f'fsm_fin_wait_2({self.state}): packet = {packet}')
        if packet.is_fin:
            self.send_packet(self.ack())
            self.state = States.TIME_WAIT
        else:
            logger.warn(f'fsm_fin_wait_2({self.state}): unexpected')


    def fsm_closing(self, packet: Packet):
        logger.info(f'fsm_closing({self.state}): packet = {packet}')
        if packet.is_ack:
            self.state = States.TIME_WAIT
        else:
            logger.warn(f'fsm_closing({self.state}): unexpected')


    # Receives and processes a packet.  The processing of a packet examines the
    # current state of the 'state machine' and determines how the packet should
    # be processed.

    async def recv_packet(self, packet: Packet):
        logger.info(f'recv_packet({self.state}): {self.src_addr}:{self.src_port} => {packet}')

        try:
            # handles an incoming packet from the parent handler
            if self.state == States.CLOSED:
                self.fsm_closed(packet)
            elif self.state == States.LISTEN:
                self.fsm_listen(packet)
            elif self.state == States.SYN_RECEIVED:
                self.fsm_syn_received(packet)
            elif self.state == States.SYN_SENT:
                self.fsm_syn_sent(packet)
            elif self.state == States.ESTABLISHED:
                self.fsm_established(packet)
            elif self.state == States.CLOSING:
                self.fsm_closing(packet)
            elif self.state == States.CLOSE_WAIT:
                self.fsm_close_wait(packet)
            elif self.state == States.LAST_ACK:
                self.fsm_last_ack(packet)
            elif self.state == States.FIN_WAIT_1:
                self.fsm_fin_wait_1(packet)
            elif self.state == States.FIN_WAIT_2:
                self.fsm_fin_wait_2(packet)
            elif self.state == States.TIME_WAIT:
                self.fsm_fin_time_wait(packet)
        finally:
            logger.info(f'recv_packet({self.state}): finished')

    # Sends a packet to the remote end.  This method does not change state, please
    # handle that elsewhere.

    def send_packet(self, message: bytes, increment_seq_no: bool = True):
        logger.info(f'send_packet({self.state}): {message}')
        self.sock.sendto(message, (self.dst_addr, self.dst_port))
        if increment_seq_no:
            self.seq_no += 1

    # wait for the next packet

    async def wait_packet(self):
        # receive the raw wire message
        (data, addr) = self.sock.recvfrom(4096)
        # decode into a packet
        packet = Packet(data, addr)
        # check the header against the incoming source
        if (packet.src_port != addr[1]):
            # protocol spoofing
            raise ValueError(f'Protocol spoofing, source port {packet.src_port} <> {addr[1]}')

        return packet

    # wait for one cycle in the state machine

    async def wait_one(self):
        logger.info(f'wait_one({self.state}): starting')

        try:
            while True:
                try:
                    # wait for a packet
                    packet = await self.wait_packet()
                    # if there is no packet keep waiting
                    if packet is None:
                        continue
                    # receive the packet into the state machine
                    await self.recv_packet(packet)
                    # return if there is no exception
                    return
                except socket.timeout:
                    pass
        finally:
            logger.info(f'wait_one({self.state}): finished')

    # wait until one of the target states is achieved

    async def wait_until(self, states):
        while True:
            if (self.state in states):
                return

            await self.wait_one()

    # Starts a connection with the remote end.  Sends a SYN packet and sets the
    # connection state to SYN_SENT.

    async def connect(self, dst_addr: str, dst_port: int):
        logger.info(f'connect({self.state}): start')

        try:
            self.dst_addr = socket.gethostbyname(dst_addr)
            self.dst_port = dst_port
            self.dst_inet = socket.inet_aton(self.dst_addr)
            # create a sequence number
            self.seq_no = random.randint(0, max_initial_sequence_no)
            # set the ack number
            self.ack_no = 0
            # create a SYN packet to send to the client
            self.send_packet(self.syn())
            self.state = States.SYN_SENT
            # process incoming messages until we reach the
            # established state or a terminal state
            await self.wait_until((States.ESTABLISHED, States.CLOSED))
        finally:
            logger.info(f'connect({self.state}): finished')

    # Sends a "message" (do not confuse with send packet)
    
    def send_message(self, message: bytes):
        # verify that the connection is in a valid state
        assert(self.state == States.ESTABLISHED)
        # send the message
        # TBD

    # Closes the connection

    async def close(self):
        # if the connection is already terminating
        if (self.state in (States.CLOSED, States.CLOSING, States.CLOSE_WAIT, States.FIN_WAIT_1, States.FIN_WAIT_2, States.TIME_WAIT)):
            return
        elif (self.state in (States.SYN_RECEIVED, States.ESTABLISHED)):
            self.send_packet(self.fin())
            self.state = States.FIN_WAIT_1
            await self.wait_until((States.CLOSED,))
        elif (self.state == States.SYN_SENT):
            self.state = States.CLOSED
        elif (self.state == States.LISTEN):
            self.state = States.CLOSED
        else:
            logger.warn(f'close(): Unhandled state transition: state = {self.state}')


class RUDPClient(socket.socket):
    def __init__(self):
        self.connection = None

    async def send_message(self, message: bytes):
        assert(self.connection is not None)
        self.connection.send_message(bytes)

    async def close(self):
        assert(self.connection is not None)
        await self.connection.close()

    async def connect(self, host: str, port: int):
        # create the socket (for communication)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the local address (random port) for return messages
        self.sock.bind(('', 0))
        # set the socket timeout so that we do not block indefinitely
        self.sock.settimeout(1.0)
        # bind it to a connection
        self.connection = Connection(self.sock, States.CLOSED)
        # establish the connection
        await self.connection.connect(host, port)
        # return the connection
        return self.connection

# The reliable udp server is a multiplexing listening entity.  It creates a socket for handling
# incoming requests and creates 'connections' (state machines) in response to inbound requests.
# In practice, you would want to limit these in the way that listen() and accept() do, but for
# this exercise, the connection are effectively unbound.

class RUDPServer:
    def __init__(self):
        self.connections = {}

    async def listen(self, port: int):
        self.host = '127.0.0.1' # temporary
        self.port = port
        logger.info(f'listen(): port = {port}')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.info(f'listen(): socket = {self.sock}')
        self.sock.bind((self.host, self.port))
        # set the socket timeout so that we do not block indefinitely
        self.sock.settimeout(1.0)
        logger.info('listen(): socket bound')
  
    async def recv_packet(self):
        """Waits for a single packet to arrive"""
        try:
            # receive the raw wire message
            (data, addr) = self.sock.recvfrom(4096)
            # decode into a packet
            packet = Packet(data, addr)
            # check the header against the incoming source
            if (packet.src_port != addr[1]):
                # protocol spoofing
                raise ValueError(f'Protocol spoofing, source port {packet.src_port} <> {addr[1]}')

            return packet
        except socket.timeout:
            #logger.warn('timeout exception on socket')
            pass

    async def dispatch(self):
        # the dispatch method is a state machine for the endpoint
        logger.debug('dispatch(): starting')

        # handle the next incoming packet
        while True:
            packet = await self.recv_packet()
            if packet is None:
                continue

            # now at this point we have received a packet but we are multiplexing
            # many different psuedo connections... moreover, this packet may belong
            # to one or it may not belong to any connection.  we need to determine
            # where this connection belongs.
            connection = self.connections.get(packet.addr)
            if connection is None:
                logger.info(f'dispatch(): new connection for {packet.addr}')
                # create the connection (state machine)
                self.connections[packet.addr] = connection = Connection(self.sock, States.LISTEN)            

            await connection.recv_packet(packet)
