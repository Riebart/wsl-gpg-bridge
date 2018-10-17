# wsl-gpg-bridge

A Python bridge to provide a mechanism for WSL gpg to talk to a gpg-agent Windows binary.

## Motivation

Using a Yubikey or other PGP smart card is not supported in WSL `gpg` binaries, as there is no mechanism for WSL binaries to interact with USB devices (mass storage removable USB devices and serial interfaces are presented as abstracted concepts; filesystem mounts and serial devices respectively). However, the GnuPG Windows [releases](https://www.gnupg.org/download/index.html) are modern and fully support USB PGP Smart Card devices.

This script provides a mechanism for WSL `gpg` to talk to a Windows `gpg-agent` and leverage the cryptographic primitives on the Smart Card devices the Windows binary can access, without leaving the WSL environment. This is desirable in many cases as Windows binaries and shells do not behave well when piping binary data, which can cause problems in some workflows.

## Disclaimer

This is still very much a proof-of-concept-quality tool, and while it works in the few cases I've tried it in, there's no guarantees it'll work in all cases, or that it will be stable in any environment other than mine.

## Prerequisites

To use `gpgbridge.py` as a daemon, which you probably want, you'll need to install the `python-daemon` package with something like `pip3 install python-daemon`. Without this you might be able to get away with background it, but the daemon is _far_ preferable. Starting with Windows 10 1803, WSL supports daemon processes that live beyond any single shell lifespan, so it'll persist across multiple windows/shells/sleep-resume cycles.

## Using it

You will need to download and unpack the [GnuPG Windows binaries](https://www.gnupg.org/download/index.html).

- Make sure that the GnuPG binaries are in your Windows path (user or system, either will work).
  - Letting the installer run as admin adds them to the system PATH after installing to `Program Files (x86)`.
  - I unpack them into my `%LOCALAPPDATA%\Programs\gnupg` folder, then add `%LOCALAPPDATA%\Programs\gnupg\bin` to my user PATH environment variable, as this doesn't require administrative privileges.
  - Adding them to your PATH (user or system) in Windows also adds them to your PATH in WSL by default starting with Windows 10 1803.
- Use `gpgbridge.py` as a drop-in replacement for manually running `gpg-agent`. It takes care of:
  - Spawning the Windows processes
  - Using `gpgconf`/`gpgconf.exe` to determine proper locations of files to read/write
  - `wslpath` to translate paths back and forth between Windows and WSL

Example:

![Example demonstrating accessing a Yubikey from WSL gpg](example.gif)

### With `ssh-agent` support

The bridge supports `--enable-ssh-support`, and has one additional requirement:

- Make sure that Python 3.6+ is in your Windows path (user or system, either will work), and has Paramiko installed (`pip3 install parmaiko`)
- Exporting the necessary `SSH_AUTH_SOCK` is left up to the user, and it is not output like `ssh-agent -s` does.

  ```bash
  export SSH_AUTH_SOCK=`$ gpgconf --list-dirs agent-ssh-socket`
  ```

## Caveats

Note that this will redirect all private key operations through the Windows agent, and so any private keys in your WSL secring will not be available unless you import them on again on your Windows toolchain. Note that, since the agent is Windows, it will use the Windows pinentry binaries, which pop up a GUI dialog box, so you won't be using gpg pinentry dialogs typical of Unix CLI toolchains. Notably, this is kind of annoying as they cannot claim focus, so when they pop up there's an Alt+Tab/mouse maneuver to select the pinentry dialog.

## Known Bugs

### `--verbose` causes output issues

Because `--verbose` passes output from the Windows binaries to a Linux console, the extra `\r` characters and some other items cause all sorts of havoc. If you need/want to use `--verbose` for debugging or curiosity, I recommend something like the following to capture stderr and stdout, and remove the CR characters, keeping the terminal flow far closer to well behaved.

```bash
(./gpgbridge.py --verbose 2>&1) 2>&1 | tr -d '\r'
```

### `ssh-agent` related bugs

Support for the ssh-agent functionality doesn't work as nicely as it should, and is tied to the same bug that affects interop between OpenSSH-Win32 and GnuPG on Windows.

- Ref: https://dev.gnupg.org/T3883
- Ref: https://github.com/PowerShell/Win32-OpenSSH/issues/827

## Details

This script works by reading the special socket wrapper files (Assuan? I think?) that are written by the Windows binaries to allow them to talk to each other, since they predate the official support of [Unix sockets in Windows](https://blogs.msdn.microsoft.com/commandline/2018/02/07/windowswsl-interop-with-af_unix/). One could hope that in future builds those will be supported out of the box and we don't need to do this mess, but until then this will work fine.

The scripts starts by listening on a Unix socket (which, since gpg forces the use of sockets in standard locations now, should be in `~/.gnupg/S.gpg-agent` or something similar) in stream mode, and waits. Each time there is a connection to that listening socket, it spawns a thread that establishes a connection out tot he Windows socket, determined by reading the special wrapper files in `%APPDATA%/gnupg`, specifically the `%APPDATA%/gnupg/S.gpg-agent` file. This file has the TCP listening port the agent chose, a newline, and then some more goop (essentially authentication stuff, so you can't just connect to this socket and talk to the gpg-agent without also having some filesystem access). This script connects out to the socket, sends the goop, and then acts as `socat`, acting as a relay passing data back and forth between the sockets without modification or interpretation.

When either end closes the connection, the script closes the other end and terminates the thread.

### `ssh-agent` support details

Support for SSH agent socket is done in an _even more_ roundabout way. Because the Windows GnuPG `--enable-ssh-support` is broken, and doesn't work, but the `--enable-putty-support` works perfectly, we use the latter to provide the functionality instead. The only difference between `ssh-agent` and `pageant` is the transport for communication (Unix sockets vs Windows memory-mapped files), but otherwise the protocols are identical and so the solution is to provide a replacement TCP/Assuan socket for the one generated by `gpg-agent.exe` that proxies between TCP and Windows handle writes/reads.

Paramiko, Python's SSH library, contains a connection wrapper that handles communicating with `pageant` like a socket and so we use that for one side of this additional broken. The other side is simple TCP connection handling.

When `gpgbridge.py` is passed the `--enable-ssh-support` option, then the spawned `gpg-agent.exe` process is called with `--enable-putty-support` to provide the agent. Once the gpg agent is up and running, another bridge is started via a Windows `python3.exe` call (hence why it needs to be on the path) which:

- Loads Paramiko
- Finds and connects to the agent
- Opens a TCP listener on a system-determined port, and generates a new nonce
- Generates a new Assuan socket file, clobbering the one generated by `gpg-agent.exe`
- Enters a listening loop

This process lives as a WSL process, and is disowned, like the bridge itself, when the bridge daemonizes. The proxying of the Unix socket to the Assuan socket is handled by the bridge as normal, like all other sockets.
