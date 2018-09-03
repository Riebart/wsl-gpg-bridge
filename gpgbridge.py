#!/usr/bin/env python3

import os
import sys
import time
import socket
import select
import logging
import argparse
import threading
import subprocess


def handle(sock, address, remote_address, preamble):
    # Reference:
    # - https://dev.gnupg.org/T3883
    logging.debug("Opening socket to TCP side")
    rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rs.connect(remote_address)
    logging.debug("TCP socket open %s" % repr(rs))
    logging.debug("Sending connection nonce")
    rs.sendall(preamble)
    while True:
        input_ready, _, _ = select.select([rs, sock], [], [], 0.1)
        if rs in input_ready:
            logging.debug("TCP has stuff")
            buf = rs.recv(4096)
            # If we've been notified there's a receive, but no bytes read, then
            # we close the socket
            if len(buf) == 0:
                break
            else:
                logging.debug("To unix: %s" % repr(buf))
                sock.sendall(buf)
        if sock in input_ready:
            logging.debug("Unix has stuff")
            buf = sock.recv(4096)
            if len(buf) == 0:
                break  # Connection closed, see above.
            else:
                logging.debug("To remote: %s" % repr(buf))
                rs.sendall(buf)
    logging.debug("Closing unix socket %s" % repr(sock))
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    logging.debug("Closing TCP socket %s" % repr(rs))
    rs.shutdown(socket.SHUT_RDWR)
    rs.close()


def derive_assuan_socket(socket_type):
    logging.debug("Deriving Assuan socket location")
    windows_path = subprocess.check_output(("gpgconf.exe", "--list-dirs",
                                            socket_type)).strip()
    return subprocess.check_output(("wslpath", windows_path)).strip()


def derive_unix_socket(socket_type):
    logging.debug("Deriving unix socket location")
    return subprocess.check_output(("gpgconf", "--list-dirs",
                                    socket_type)).strip()


def start_listener(assuan_socket, unix_socket, no_clobber):
    logging.debug("Opening Assuan socket to read nonce: %s" % assuan_socket)
    with open(assuan_socket, "rb") as fp:
        windows_port = int(fp.readline().strip().decode("ascii"))
        windows_payload = fp.read()
        logging.debug("Read %d bytes of nonce for port %d" %
                      (len(windows_payload), windows_port))

    logging.debug("Setting up Unix socket")
    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # pylint: disable=E1101

    try:
        us.bind(unix_socket)
    except OSError as e:
        # If the errno is 98 (Address In Use), and we're clobbering, then try to remove it and re-bind
        if e.errno == 98 and not no_clobber:
            logging.debug(
                "Unix socket bind unsuccessful due to address already in use. Clobbering."
            )
            os.remove(unix_socket)
            us.bind(unix_socket)
        else:
            raise e

    logging.debug("Unix socket bind successful, listening...")
    us.listen(1)

    while True:
        input_ready, _, _ = select.select([us], [], [], 5)
        if len(input_ready) > 0:
            # handle the server socket
            try:
                client, address = us.accept()
                logging.debug(
                    "Accepting from (%s, %s)" % (str(client), str(address)))
                thread = threading.Thread(target=lambda c=client, a=address, r=('127.0.0.1', windows_port), p=windows_payload: handle(c, a, r, p))
                thread.start()
            except socket.error as e:
                logging.warn("Socket error encountered: %s" % str(e))


def start_gpg_agent(verbose):
    """
    Assuming that gpg-agent.exe is in the PATH, start it and fork it to the background.
    """
    # If the call returns 0, then an agent is running and available
    # If the call returns 2, then no agent is running
    logging.debug("Checking on current gpg-agent.exe processes")
    return_code = subprocess.call(
        ("gpg-agent.exe"),
        stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
        stderr=(None if verbose else subprocess.DEVNULL))  # pylint: disable=E1101

    if return_code == 2:
        logging.info(
            "No existing gpg-agent.exe process detected, starting a new one")
        # Since this is out of scope of the client, there's no harm in always exposing the SSH
        # functionality. This seems to be the default anyway.
        proc = subprocess.Popen(
            ("powershell.exe", "-command", "gpg-agent.exe", "--daemon",
             "--quiet", "--enable-ssh-support"),
            stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
            stderr=(None if verbose else subprocess.DEVNULL))  # pylint: disable=E1101

        agent_up = False
        for num_checks in range(30, 0, -1):
            logging.debug("Testing agent until it comes up. %d checks left." %
                          num_checks)
            return_code = subprocess.call(
                ("gpg-agent.exe"),
                stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
                stderr=(None if verbose else subprocess.DEVNULL))  # pylint: disable=E1101
            if return_code == 0:
                agent_up = True
                break
            else:
                time.sleep(1)

        if not agent_up:
            logging.error("Unable to bring up gpg-agent.exe")
            exit(1)

        logging.debug(
            "Killing process, agent should continue in the background")
        proc.kill()
        proc.communicate()


def __main(parsed_args):
    start_gpg_agent(parsed_args.verbose)
    threads = dict()

    for socket_name in [
            "agent-socket", "agent-extra-socket", "agent-browser-socket"
    ] + (["agent-ssh-socket"] if parsed_args.enable_ssh_support else []):
        assuan_socket = parsed_args.assuan_socket if \
            parsed_args.assuan_socket is not None else \
            derive_assuan_socket(socket_name)
        logging.debug("Assuan socket location set to \"%s\" for \"%s\"" %
                      (assuan_socket, socket_name))
        unix_socket = parsed_args.unix_socket if \
            parsed_args.unix_socket is not None else \
            derive_unix_socket(socket_name)
        logging.debug("Unix socket location set to \"%s\" for \"%s\"" %
                      (unix_socket, socket_name))

        logging.debug("Spawning listening thread for gpg-agent socket \"%s\"" %
                      socket_name)

        threads[socket_name] = threading.Thread(
            target=lambda
            a=assuan_socket,
            u=unix_socket,
            nc=parsed_args.no_clobber: start_listener(a, u, nc))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=
        """A Python bridge to permit WSL gpg toolchain elements to interact with a gpg-agent.exe running natively in Windows."""
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
    parser.add_argument(
        "--enable-ssh-support",
        action="store_true",
        default=False,
        help="""Enable listening on the SSH sockets as well""")
    parser.add_argument(
        "--assuan-socket",
        default=None,
        help=
        """Explicitly state the location of the Assuan socket to act as the TCP endpoint.
        If unspecified, use the value from gpgconf.exe.""")
    parser.add_argument(
        "--unix-socket",
        default=None,
        help=
        """Explicitly state the location of the filesystem location to act as the unix endpoint.
        If unspecified, use the value from gpgconf.""")
    parser.add_argument(
        "--no-clobber",
        action="store_true",
        default=False,
        help=
        """If Unix sockets exist, will not attempt to remove (clobber) them."""
    )

    parsed_args = parser.parse_args()

    if parsed_args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if parsed_args.daemon:
        try:
            import daemon  # pylint:disable=E0401
            with daemon.DaemonContext():
                __main(parsed_args)
        except:
            logging.error((
                "Failed to become a daemon, likely due to missing daemon library. "
                "HINT: Try a background process instead in a pinch."))
    else:
        __main(parsed_args)
