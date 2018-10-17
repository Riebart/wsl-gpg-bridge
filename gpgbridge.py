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


class AssuanAgentProxy(object):
    def __init__(self):
        LOGGER.debug("Importing paramiko")
        import paramiko  # pylint: disable=E0401

        # Attempt to get the get the agent target
        LOGGER.debug("Connecting to agent with Paramiko")
        agent = paramiko.Agent()

        if agent._conn is None:
            LOGGER.error("Unable to connect to SSH agent")
            exit(19)

        if not isinstance(agent._conn, paramiko.win_pageant.PageantConnection):
            LOGGER.error("Established SSH agent is not a Pageant connection")
            exit(20)

        LOGGER.debug(
            "Successfully found paramiko-provided pageant agent connection")
        self.conn = agent._conn

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


# # Once we daemonize, we don't have access to our path anymore, so this causes all kinds of isssues.
# # Use the non-daemon parent to get the absolute paths to the binaries we care about.
# BINARIES = {
#     bin_name: subprocess.check_output(("which",
#                                        bin_name)).decode("ascii").strip()
#     for bin_name in
#     ["gpg-agent.exe", "gpgconf.exe", "gpgconf", "wslpath", "powershell.exe"]
# }

LOGGER = logging.getLogger()
LOGGER.addHandler(logging.StreamHandler(sys.stderr))


def read_assuan_file(filename):
    LOGGER.debug("Opening Assuan socket to read nonce: %s" % filename)
    with open(filename, "rb") as fp:
        windows_port = int(fp.readline().strip().decode("ascii"))
        windows_payload = fp.read()
        LOGGER.debug("Read %d bytes of nonce for port %d" %
                     (len(windows_payload), windows_port))
    return ("127.0.0.1", windows_port), windows_payload


def handle(sock, address, sock_name):
    # Reference:
    # - https://dev.gnupg.org/T3883
    remote_address, preamble = read_assuan_file(sock_name)

    LOGGER.debug("Opening socket to TCP side")
    rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rs.connect(remote_address)
    LOGGER.debug("TCP socket open %s" % repr(rs))
    LOGGER.debug("Sending connection nonce")
    rs.sendall(preamble)
    while True:
        input_ready, _, _ = select.select([rs, sock], [], [], 0.1)
        if rs in input_ready:
            LOGGER.debug("TCP has stuff")
            buf = rs.recv(4096)
            # If we've been notified there's a receive, but no bytes read, then
            # we close the socket
            if len(buf) == 0:
                break
            else:
                LOGGER.debug("To unix: %s" % repr(buf))
                sock.sendall(buf)
        if sock in input_ready:
            LOGGER.debug("Unix has stuff")
            buf = sock.recv(4096)
            if len(buf) == 0:
                break  # Connection closed, see above.
            else:
                LOGGER.debug("To remote: %s" % repr(buf))
                rs.sendall(buf)
    LOGGER.debug("Closing unix socket %s" % repr(sock))
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    LOGGER.debug("Closing TCP socket %s" % repr(rs))
    rs.shutdown(socket.SHUT_RDWR)
    rs.close()


def derive_assuan_socket(socket_type):
    LOGGER.debug("Deriving Assuan socket location")
    windows_path = subprocess.check_output(("gpgconf.exe", "--list-dirs",
                                            socket_type)).strip()
    return subprocess.check_output(("wslpath", windows_path)).strip()


def derive_unix_socket(socket_type):
    LOGGER.debug("Deriving unix socket location")
    return subprocess.check_output(("gpgconf", "--list-dirs",
                                    socket_type)).strip()


def start_listener(assuan_socket, unix_socket, no_clobber):
    LOGGER.debug("Setting up Unix socket")
    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # pylint: disable=E1101

    try:
        us.bind(unix_socket)
    except OSError as e:
        # If the errno is 98 (Address In Use), and we're clobbering, then try to remove it and re-bind
        if e.errno == 98 and not no_clobber:
            LOGGER.debug(
                "Unix socket bind unsuccessful due to address already in use. Clobbering."
            )
            os.remove(unix_socket)
            us.bind(unix_socket)
        else:
            raise e

    LOGGER.debug("Unix socket bind successful, listening...")
    us.listen(1)

    while True:
        input_ready, _, _ = select.select([us], [], [], 5)
        if len(input_ready) > 0:
            # handle the server socket
            try:
                client, address = us.accept()
                LOGGER.debug(
                    "Accepting from (%s, %s)" % (str(client), str(address)))
                thread = threading.Thread(target=lambda c=client, a=address, s=assuan_socket: handle(c, a, s))
                thread.start()
            except socket.error as e:
                LOGGER.warn("Socket error encountered: %s" % str(e))


def start_gpg_agent(verbose, with_ssh_support):
    """
    Assuming that gpg-agent.exe is in the PATH, start it and fork it to the background.
    """
    # If the call returns 0, then an agent is running and available
    # If the call returns 2, then no agent is running
    LOGGER.debug(
        "Checking on current gpg-agent.exe processes: %s" % "gpg-agent.exe")
    returncode = subprocess.call(
        ("gpg-agent.exe", ),
        stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
        stderr=(None if verbose else subprocess.DEVNULL))  # pylint: disable=E1101

    if returncode == 2:
        LOGGER.info(
            "No existing gpg-agent.exe process detected, starting a new one")
        proc = subprocess.Popen(
            [
                # Not 100% sure why, but this only works if spawned under powershell
                "powershell.exe",
                "-command",
                "gpg-agent.exe",
                "--daemon",
                ("--verbose" if verbose else "--quiet")
            ] + (
                # Enable both SSH and PuTTY support.
                ["--enable-ssh-support", "--enable-putty-support"]
                if with_ssh_support else []),
            stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
            stderr=(None if verbose else subprocess.DEVNULL))  # pylint: disable=E1101

        agent_up = False
        for num_checks in range(30, 0, -1):
            LOGGER.debug("Testing agent until it comes up. %d checks left." %
                         num_checks)

            try:
                return_code = subprocess.call(
                    ("gpg-agent.exe"),
                    stdout=(None if verbose else subprocess.DEVNULL),  # pylint: disable=E1101
                    stderr=(None if verbose else subprocess.DEVNULL),
                    timeout=1)  # pylint: disable=E1101
            except subprocess.TimeoutExpired:
                return_code = None

            if return_code == 0:
                agent_up = True
                break
            else:
                time.sleep(1)

        if not agent_up:
            LOGGER.error("Unable to bring up gpg-agent.exe")
            exit(1)

        LOGGER.debug(
            "Killing process, agent should continue in the background")
        proc.kill()
        proc.communicate()


def __listen_loop(threads):
    LOGGER.debug("Starting all listening threads")
    for thread in threads.values():
        thread.start()
    LOGGER.info("All listening threads ready")

    LOGGER.debug("Waiting on the termination of main thread via join()")
    threads["agent-socket"].join()

    for thread in threads.values():
        try:
            thread.kill()
            thread.join()
        except:
            pass


def check_for_unix_agent():
    """
    Check to see if there is an existing Unix gpg-agent by attempting to connect to the gpg-agent
    socket.
    """
    unix_sock_name = derive_unix_socket("agent-socket")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # pylint: disable=E1101
    try:
        sock.connect(unix_sock_name)
        return True
    except ConnectionRefusedError:
        return False
    except FileNotFoundError:
        return False


def pageant_main(parsed_args):
    """
    Start the agent proxy between Pageant/Windows memory-mapping and Assuan sockets.
    """
    if sys.platform != "win32":
        LOGGER.error(
            "This proxy must be run as a Windows process to detect the Pageant process handle."
        )
        exit(17)

    LOGGER.debug("Constructing agent proxy")
    proxy = AssuanAgentProxy()
    LOGGER.debug("Listening on agent proxy")
    proxy.listen()


def get_windows_script_location():
    unix_path = os.path.realpath(__file__)
    windows_path = subprocess.check_output(
        ("wslpath", "-w", unix_path)).decode("utf-8").strip()
    return windows_path


def bridge_main(parsed_args):
    """
    Start the GPG bridge between Assuan and Unix sockets.
    """
    LOGGER.debug("Checking for existing Unix agent")
    if check_for_unix_agent():
        LOGGER.error("Existing Unix agent found. Not starting.")
        exit(2)

    LOGGER.info("Starting gpg-agent.exe process")
    start_gpg_agent(parsed_args.verbose, parsed_args.enable_ssh_support)
    threads = dict()

    for socket_name in [
            "agent-socket", "agent-extra-socket", "agent-browser-socket"
    ] + (["agent-ssh-socket"] if parsed_args.enable_ssh_support else []):
        assuan_socket = parsed_args.assuan_socket if \
            parsed_args.assuan_socket is not None else \
            derive_assuan_socket(socket_name)
        LOGGER.debug("Assuan socket location set to \"%s\" for \"%s\"" %
                     (assuan_socket, socket_name))
        unix_socket = parsed_args.unix_socket if \
            parsed_args.unix_socket is not None else \
            derive_unix_socket(socket_name)
        LOGGER.debug("Unix socket location set to \"%s\" for \"%s\"" %
                     (unix_socket, socket_name))

        LOGGER.debug("Crafting listening thread for gpg-agent socket \"%s\"" %
                     socket_name)

        threads[socket_name] = threading.Thread(
            target=lambda
            a=assuan_socket,
            u=unix_socket,
            nc=parsed_args.no_clobber: start_listener(a, u, nc))

    pageant_proxy_proc = None
    if parsed_args.enable_ssh_support:
        LOGGER.debug("Starting pageant proxy process")
        pageant_proxy_proc = subprocess.Popen(
            [
                "powershell.exe", "-command", "python3.exe",
                get_windows_script_location(), "--pageant-proxy"
            ] + (["--verbose"] if parsed_args.verbose else []),
            stdout=(None if parsed_args.verbose else subprocess.DEVNULL),
            stderr=(None if parsed_args.verbose else subprocess.DEVNULL))
        LOGGER.debug(
            "Pageant proxy started as WSL PID %d" % pageant_proxy_proc.pid)

    if parsed_args.daemon:
        try:
            import daemon  # pylint:disable=E0401
        except:
            LOGGER.error((
                "Failed to become a daemon, likely due to missing daemon library. "
                "HINT: Try a background process instead in a pinch."))

        LOGGER.debug("Entering daemon context")

        with daemon.DaemonContext():
            if parsed_args.verbose:
                LOGGER.addHandler(
                    logging.FileHandler("/tmp/gpgbridge.log", "w"))

            LOGGER.debug("Launching listen process inside of daemon")
            __listen_loop(threads)
            LOGGER.debug("Listen process finished inside of daemon")
    else:
        __listen_loop(threads)

    if pageant_proxy_proc is not None:
        LOGGER.debug("Killing and syncing with pagent proxy process")
        pageant_proxy_proc.kill()
        pageant_proxy_proc.communicate()


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
    parser.add_argument(
        "--pageant-proxy",
        action="store_true",
        default=False,
        help=
        """Start the necessary Windows process to interact with the Pageant agent through Assuan sockets."""
    )

    parsed_args = parser.parse_args()

    if parsed_args.verbose:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)

    if parsed_args.pageant_proxy:
        pageant_main(parsed_args)
    else:
        bridge_main(parsed_args)
