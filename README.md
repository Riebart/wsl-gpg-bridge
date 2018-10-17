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

### The simple way

You still need to download and unpack the [GnuPG Windows binaries](https://www.gnupg.org/download/index.html).

- Make sure that the GnuPG binaries are in your Windows path (user or system, either will work).
  - I unpack them into my `%LOCALAPPDATA%\Programs\gnupg` folder, then add `%LOCALAPPDATA%\Programs\gnupg\bin` to my user PATH environment variable.
  - Adding them to your PATH in Windows also adds them to your PATH in WSL.
- Use `gpgbridge.py` as a drop-in replacement for manually running `gpg-agent`. It takes care of:
  - Spawning the Windows processes
  - Using `gpgconf`/`gpgconf.exe` to determine proper locations of files to read/write
  - `wslpath` to translate paths back and forth between Windows and WSL

Example:

![Example demonstrating accessing a Yubikey from WSL gpg](example.gif)

### The old, complicated way

- In Powershell:
  - Go download and unpack the latest GnuPG Windows release.
  - Insert your PGP Smart Card.
  - Start gpg-agent as a daemon on Windows
    - You can either run it yourself in the foreground for testing by running `gpg-agent --daemon` from a Powershell prompt, or run `gpg --card-status` from a Powershell prompt, which will spawn a background gpg-agent.
  - Note your Windows username, you'll need that.
- In WSL:
  - Download the Python script and run it with something like
  ```
  python3 gpgbridge.py /mnt/c/Users/${WindowsUserName}/AppData/Roaming/gnupg/S.gpg-agent ~/.gnupg/S.gpg-agent
  ```
  - In a new WSL window (since the above command will stay in the foreground), run `gpg --card-status`, and you should be able to see the script output what the agent and client are saying to each other over the socket broker.
  - If successful, `gpg --card-status` in WSL (calling the WSL binary, not the Windows binary you unpacked earlier) should produce some sensible output!

## Caveats

Note that this will redirect all private key operations through the Windows agent, and so any private keys in your WSL secring will not be available unless you import them on again on your Windows toolchain. Note that, since the agent is Windows, it will use the Windows pinentry binaries, which pop up a GUI dialog box, so you won't be using gpg pinentry dialogs typical of Unix CLI toolchains.

## Known Bugs

### `ssh-agent` Support

Support for the ssh-agent functionality doesn't work, and is tied to the same bug that affects interop between OpenSSH-Win32 and GnuPG on Windows.

- Ref: https://dev.gnupg.org/T3883
- Ref: https://github.com/PowerShell/Win32-OpenSSH/issues/827

## Details

This script works by reading the special socket wrapper files (Assuan? I think?) that are written by the Windows binaries to allow them to talk to each other, since they predate the official support of [Unix sockets in Windows](https://blogs.msdn.microsoft.com/commandline/2018/02/07/windowswsl-interop-with-af_unix/). One could hope that in future builds those will be supported out of the box and we don't need to do this mess, but until then this will work fine.

The scripts starts by listening on a Unix socket (which, since gpg forces the use of sockets in standard locations now, should be in `~/.gnupg/S.gpg-agent` or something similar) in stream mode, and waits. Each time there is a connection to that listening socket, it spawns a thread that establishes a connection out tot he Windows socket, determined by reading the special wrapper files in `%APPDATA%/gnupg`, specifically the `%APPDATA%/gnupg/S.gpg-agent` file. This file has the TCP listening port the agent chose, a newline, and then some more goop (essentially authentication stuff, so you can't just connect to this socket and talk to the gpg-agent without also having some filesystem access). This script connects out to the socket, sends the goop, and then acts as `socat`, acting as a relay passing data back and forth between the sockets without modification or interpretation.

When either end closes the connection, the script closes the other end and terminates the thread.
