Motivation
==========

sshd implementation in Go, for the sole purpose of restricting the ports that
clients can request using direct-tcpip and tcpip-forward / forwarded-tcpip.

OpenSSH refuses to merge patches to support this, but there is a fork of OpenSSH
with patches that achieve something similar to this. [1]


[1] https://github.com/antonyantony/openssh

authorized_keys format
======================

Same as OpenSSH authorized_keys format.
The options field contains the ports that are allowed to be forwarded, colon separated::

    ports=3333:4444 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPWEWu85yECrbmtL38wlFua3tBSqxTekCX/aU+dku+w COMMENTHERE
