# wsl-gpg-bridge

A Python bridge to provide a mechanism for WSL gpg to talk to a gpg-agent Windows binary.

## Motivation

Using a Yubikey or other PGP smart card is not supported in WSL `gpg` binaries, as there is no mechanism for WSL binaries to interact with USB devices (mass storage removable USB devices and serial interfaces are presented as abstracted concepts; filesystem mounts and serial devices respectively). However, the GnuPG Windows [releases](https://www.gnupg.org/download/index.html) are modern and fully support USB PGP Smart Card devices.

This script provides a mechanism for WSL `gpg` to talk to a Windows `gpg-agent` and leverage the cryptographic primitives on the Smart Card devices the Windows binary can access, without leaving the WSL environment. This is desirable in many cases as Windows binaries and shells do not behave well when piping binary data, which can cause problems in some workflows.

## Disclaimer

This is still very much a proof-of-concept-quality tool, and while it works in the few cases I've tried it in, there's no guarantees it'll work in all cases, or that it will be stable in any environment other than mind.

## Using it

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
