Motivation
==========

sshd implementation in Go, for the sole purpose of restricting the ports that
clients can request using direct-tcpip.

OpenSSH refuses to merge patches to support this, but there is a fork of OpenSSH
with patches that achieve something similar to this. [1]


[1] https://github.com/antonyantony/openssh

authorized_keys format
======================

Same as OpenSSH authorized_keys format.
Comment field contains the ports that are allowed to be forwarded, comma
separated::

    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPWEWu85yECrbmtL38wlFua3tBSqxTekCX/aU+dku+w 3333,3334

