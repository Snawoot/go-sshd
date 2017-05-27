Motivation
==========

sshd implementation in Go, for the sole purpose of restricting the ports that
clients can request using direct-tcpip and tcpip-forward / forwarded-tcpip.

OpenSSH so far refuses to merge patches to support this, but there is a fork of
OpenSSH with patches that achieve something similar to this. [1]


[1] https://github.com/antonyantony/openssh

authorized_keys format
======================

Compatible with OpenSSH authorized_keys format, not in specific options.

The options field contains the ports that are allowed to be forwarded, colon separated::

    remoteports=3333:4444 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPWEWu85yECrbmtL38wlFua3tBSqxTekCX/aU+dku+w COMMENTHERE

Adding allowed hosts along with these ports is something that needs to be done
in the future.

Running as non-root user
========================

You should not run this program as root. Due to the way Go is implemented,
setuid is non-trivial, so instead you need to set the CAP_NET_BIND_SERVICE
capability on the resulting binary:

    setcap 'cap_net_bind_service=+ep' go-sshd

Init script
===========

There is an init script for gentoo/alpine (OpenRC) users. SSHD_LISTEN needs to
be set in /etc/conf.d/go-sshd and the init-script goes in /etc/init.d/go-sshd
