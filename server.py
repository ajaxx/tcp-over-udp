import argparse
import asyncio
import logging
import logging.handlers
import socket
import utils
import struct

from utils import States
from reliable_udp import RUDPServer

logger = logging.getLogger(__name__)

# Receive a message and return header, body and addr
# addr is used to reply to the client
# this call is blocking
def recv_msg():
    data, addr = sock.recvfrom(1024)
    header = utils.bits_to_header(data)
    body = utils.get_body_from_data(data)
    return (header, body, addr)

def defunc():
    # the server runs in an infinite loop and takes
    # action based on current state and updates its state
    # accordingly
    # You will need to add more states, please update the possible
    # states in utils.py file
    while True:
        if server_state == States.CLOSED:
            # we already started listening, just update the state
            update_server_state(States.LISTEN)
        elif server_state == States.LISTEN:
            # we are waiting for a message
            header, body, addr = recv_msg()
            # if received message is a syn message, it's a connection
            # initiation
            if header.syn == 1:
                seq_number = utils.rand_int() # we randomly pick a sequence number
                ack_number = header.seq_num + 1

            # to be implemented

            ### sending message from the server:
            #   use the following method to send messages back to client
            #   addr is recieved when we receive a message from a client (see above)
            #   sock.sendto(your_header_object.bits(), addr)

        elif server_state == States.SYN_RECEIVED:
            pass
        elif server_state == States.SYN_SENT:
            pass
        else:
            pass

# Parses command line arguments
def parseCmdLineArgs():
    parser = argparse.ArgumentParser(description="Web Client")
    parser.add_argument("-d", "--debug", dest="debug", action="store_true", help="Enable debugging logs")
    parser.add_argument("-l", dest="log", type=str, default=None, help="Log directory (if desired)")
    parser.add_argument("-p", dest="port", type=int, default=5005, help="Port number")
    return parser.parse_args()

async def main():
    args = parseCmdLineArgs()

    logging_level = logging.DEBUG if args.debug else logging.INFO
    logging_handlers = None
    if args.log is not None:
        logging_handlers = [
            logging.handlers.RotatingFileHandler(args.log),
            logging.StreamHandler(),
        ]

    logging.basicConfig(level=logging_level, handlers=logging_handlers)

    # we create a server "pseudo-socket", which establishes a connection
    server = RUDPServer()
    # listen to the endpoint - this is intentionally similar to listen(2)
    await server.listen(args.port)
    # accept a connections
    try:
        await server.dispatch()
    except KeyboardInterrupt:
        logger.info('Exiting the application')

if __name__ == "__main__":
    asyncio.run(main())
