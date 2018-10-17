#!/usr/bin/env python3

import argparse
import logging
import os
import select
import socket
import subprocess
import sys

import paramiko  # pylint:disable=E0401

LOGGER = logging.getLogger()
LOGGER.addHandler(logging.StreamHandler(sys.stderr))


class AssuanAgentProxy(object):
    def __init__(self, agent_connection):
        # Create the TCP socket, bind to a system chosen port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()

        # Generate a new nonce
        # Sort out the SSH socket file from gpgconf.exe via subprocess
        # Clobber the SSH socket file with our newly crafted one
        self.nonce = os.urandom(16)
        socket_path = subprocess.check_output(("gpgconf.exe", "--list-dirs",
                                               "agent-ssh-socket")).strip()
        with open(socket_path, "wb") as fp:
            fp.write(("%d\n" % self.sock.getsockname()[1]).encode("ascii"))
            fp.write(self.nonce)

        self.connections = []
        self.conn = agent_connection

    def listen(self):
        """
        Listen on the TCP socket for connections, and handle all incoming requests in a single thread
        to prevent any clobbering of issues with the Pageant process.
        """
        LOGGER.debug("Listening to TCP socket...")

        while True:
            input_ready, _, _ = select.select([self.sock] + self.connections,
                                              [], [], 5)
            for sock in input_ready:
                if sock == self.sock:
                    # handle the server socket
                    try:
                        client, address = self.sock.accept()
                        LOGGER.debug("Accepting from (%s, %s)" %
                                     (str(client), str(address)))
                        LOGGER.debug("Checking nonce preamble from client")
                        buf = client.recv(16)
                        if buf != self.nonce:
                            LOGGER.debug(
                                "Nonce check failed (%s, %s), not accepting client"
                                % (repr(buf), repr(self.nonce)))
                            client.shutdown(socket.SHUT_RDWR)
                            client.close()
                        else:
                            LOGGER.debug(
                                "Nonce check succeeded, adding client")
                            self.connections.append(client)
                    except socket.error as e:
                        LOGGER.warn("Socket error encountered: %s" % str(e))
                else:
                    LOGGER.debug(
                        "Non-server socket %s received data" % str(sock))
                    buf = sock.recv(4096)
                    if len(buf) == 0:
                        LOGGER.info("Closing socket %s" % str(sock))
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                            sock.close()
                        except:
                            pass
                        self.connections = [
                            c for c in self.connections if c != sock
                        ]
                    else:
                        LOGGER.debug("Sending data to agent: %s" % repr(buf))
                        self.conn.send(buf)
                        resp = self.conn.recv(4096)
                        LOGGER.debug(
                            "Sending response to client: %s" % repr(resp))
                        sock.sendall(resp if resp != "" else b"")

        LOGGER.debug("Finished listening to TCP socket messages.")


def main(parsed_args):
    if sys.platform != "win32":
        LOGGER.error(
            "This proxy must be run as a Windows process to detect the Pageant process handle."
        )
        exit(1)

    # Attempt to get the get the agent target
    LOGGER.debug("Connecting to agent with Paramiko")
    agent = paramiko.Agent()

    if agent._conn is None:
        LOGGER.error("Unable to connect to SSH agent")

    if not isinstance(agent._conn, paramiko.win_pageant.PageantConnection):
        LOGGER.error("Established SSH agent is not a Pageant connection")
        exit(2)

    # Just use the PageantConnection, as that's all we want, really.
    LOGGER.debug("Constructing agent proxy")
    proxy = AssuanAgentProxy(agent._conn)

    if parsed_args.daemon:
        raise Exception("Not Implemented")
        # LOGGER.debug("Entering daemon context")
        # LOGGER.debug("Launching listen process inside of daemon")
        # proxy.listen()
        # LOGGER.debug("Listen process finished inside of daemon")
    else:
        proxy.listen()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=
        """A Python bridge to replace the gpg-agent SSH socket with one that proxies to the functioning Pageant mechanism."""
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        default=False,
        help="""Fork into the background quietly.""")
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="""Verbose log to stderr""")

    parsed_args = parser.parse_args()

    if parsed_args.verbose:
        LOGGER.setLevel(logging.DEBUG)

    main(parsed_args)
