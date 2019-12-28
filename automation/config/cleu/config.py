class Config:
    WEBEX_TEAM = 'CLEUR 20 NOC'
    DNS_DOMAIN = 'ciscolive.network'
    DNS_BASE = 'https://dc1-dns.{}:8443/web-services/rest/resource/'.format(
        DNS_DOMAIN)
    DHCP_BASE = 'https://dc1-dhcp.{}:8443/web-services/rest/resource/'.format(
        DNS_DOMAIN)
    MONITORING = 'cl-monitoring.' + DNS_DOMAIN
    DHCP_SERVER = 'dc1-dhcp.' + DNS_DOMAIN
    PI = 'cl-pi.' + DNS_DOMAIN
    CMX_GW = 'http://cl-freebsd.{}:8002/api/v0.1/cmx'.format(DNS_DOMAIN)
    TOOL_BASE = 'https://tool.{}/n/static/port.html?'.format(DNS_DOMAIN)
    AD_DOMAIN = 'ad.' + DNS_DOMAIN
    AD_DN_BASE = 'cn=Users' + \
        ''.join([', dc={}'.format(x) for x in AD_DOMAIN.split('.')])
    TOOL = 'tool.' + DNS_DOMAIN
    VCENTER = 'cl-vcenter.' + AD_DOMAIN
    SMTP_SERVER = '10.100.252.13'
    VPN_SERVER = 'cl-production.ciscolive.eu'
    VPN_SERVER_IP = '64.103.25.43'
    CISCOLIVE_YEAR = '2020'
    PW_RESET_URL = 'https://cl-jump-01.{}:8443'.format(DNS_DOMAIN)
