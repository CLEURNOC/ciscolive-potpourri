class Config:
    WEBEX_TEAM = 'CLEUR 20 NOC'
    DNS_BASE = 'https://dc1-dns.ciscolive.local:8443/web-services/rest/resource/'
    DHCP_BASE = 'https://dc1-dhcp.ciscolive.network:8443/web-services/rest/resource/'
    DNS_DOMAIN = 'ciscolive.network'
    MONITORING = 'cl-monitoring.ciscolive.network'
    DHCP_SERVER = 'dc1-dhcp.ciscolive.network'
    PI = 'cl-pi.ciscolive.network'
    CMX_GW = 'http://cl-freebsd.ciscolive.network:8002/api/v0.1/cmx'
    TOOL_BASE = 'https://tool.ciscolive.network/n/static/port.html?'
    AD_DOMAIN = 'ad.' + DNS_DOMAIN
    TOOL = 'tool.ciscolive.network'
