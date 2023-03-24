import asyncio

from multiprocessing import Value
from utils import States

import multiprocessing
import utils
import logging
import logging.handlers
import argparse

from reliable_udp import RUDPClient

DEFAULT_UDP_IP = "127.0.0.1"
DEFAULT_UDP_PORT = 5005
MSS = 12  # maximum segment size

logger = logging.getLogger(__name__)

class Defunct:
    def handshake(self):
        if self.client_state == States.CLOSED:
            seq_num = utils.rand_int()
            syn_header = utils.Header(seq_num, 0, syn=1, ack=0)
            # for this case we send only header;
            # if you need to send data you will need to append it
            send_udp(syn_header.bits())
            self.update_state(States.SYN_SENT)
        else:
            pass

    def terminate(self):
        pass

    def update_state(self, new_state):
        if utils.DEBUG:
            print(self.client_state, "->", new_state)
        self.client_state = new_state

    def send_reliable_message(self, message):
        # send messages
        # we loop/wait until we receive all ack.
        pass

    # these two methods/function can be used receive messages from
    # server. the reason we need such mechanism is `recv` blocking
    # and we may never recieve a package from a server for multiple
    # reasons.
    # 1. our message is not delivered so server cannot send an ack.
    # 2. server responded with ack but it's not delivered due to
    # a network failure.
    # these functions provide a mechanism to receive messages for
    # 1 second, then the client can decide what to do, like retransmit
    # if not all packets are acked.
    # you are free to implement any mechanism you feel comfortable
    # especially, if you have a better idea ;)
    def receive_acks_sub_process(self, lst_rec_ack_shared):
        while True:
            recv_data, addr = sock.recvfrom(1024)
            header = utils.bits_to_header(recv_data)
            if header.ack_num > lst_rec_ack_shared.value:
                lst_rec_ack_shared.value = header.ack_num

    def receive_acks(self):
        # Start receive_acks_sub_process as a process
        lst_rec_ack_shared = Value("i", self.last_received_ack)
        p = multiprocessing.Process(
            target=self.receive_acks_sub_process, args=(lst_rec_ack_shared,)
        )
        p.start()
        # Wait for 1 seconds or until process finishes
        p.join(1)
        # If process is still active, we kill it
        if p.is_alive():
            p.terminate()
            p.join()
        # here you can update your client's instance variables.
        self.last_received_ack = lst_rec_ack_shared.value


# Parses command line arguments
def parseCmdLineArgs():
    parser = argparse.ArgumentParser(description="Web Client")
    parser.add_argument("-d", "--debug", dest="debug", action="store_true", help="Enable debugging logs")
    parser.add_argument("-l", dest="log", type=str, default=None, help="Log directory (if desired)")
    parser.add_argument("host", type=str)
    parser.add_argument("port", type=int)
    return parser.parse_args()

async def main_async(args):
    # we create a client, which establishes a connection
    client = RUDPClient()
    # connect to the endpoint - this is intentionally similar to the way
    # that the connect(2) method is exposed.
    await client.connect(args.host, args.port)
    # we send a message
    await client.send_message("This message is to be received in pieces")
    # we terminate the connection
    await client.close()

def main():
    args = parseCmdLineArgs()

    logging_level = logging.DEBUG if args.debug else logging.INFO
    logging_handlers = None
    if args.log is not None:
        logging_handlers = [
            logging.handlers.RotatingFileHandler(args.log),
            logging.StreamHandler(),
        ]

    logging.basicConfig(level=logging_level, handlers=logging_handlers)

    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()