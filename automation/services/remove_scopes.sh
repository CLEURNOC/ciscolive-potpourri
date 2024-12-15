#!/bin/sh

DHCP_SERVER=dc1-dhcp

scp ./remove_scopes.pl root@${DHCP_SERVER}:/root/remove_scopes.pl
ssh -2 root@${DHCP_SERVER} chmod +x /root/remove_scopes.pl
ssh -2 root@${DHCP_SERVER} /root/remove_scopes.pl
ssh -2 root@${DHCP_SERVER} rm -f /root/remove_scopes.pl