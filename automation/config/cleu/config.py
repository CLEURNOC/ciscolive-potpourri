class Config:
    WEBEX_TEAM = "CLEUR 23 NOC"
    CISCOLIVE_YEAR = "2023"
    DNS_DOMAIN = "ciscolive.network"
    SMTP_SERVER = "10.100.252.13"
    VPN_SERVER_IP = "45.157.175.35"
    VPN_USER = "vpn"
    WSGI_SERVER = "10.100.252.13"
    DNS_SERVER = "10.100.253.21"
    CDNS_SERVERS = ["10.100.253.9", "10.100.254.9"]
    NETBOX_SERVER = "http://10.100.252.19:8000"

    PRIMARY_DNS = "dc1-dns"
    SECONDARY_DNS = "dc2-dns"

    DNS_BASE = "https://dc1-dns.{}:8443/web-services/rest/resource".format(DNS_DOMAIN)
    DHCP_BASE = "https://dc1-dhcp.{}:8443/web-services/rest/resource".format(DNS_DOMAIN)
    MONITORING = "cl-monitoring." + DNS_DOMAIN
    DHCP_SERVER = "dc1-dhcp." + DNS_DOMAIN
    PI = "cl-pi." + DNS_DOMAIN
    DNACS = ["cl-dnac04." + DNS_DOMAIN, "sdacleur20." + DNS_DOMAIN]
    SDA_BASE = "https://sdacleur20." + DNS_DOMAIN
    CMX_GW = "http://cl-freebsd.{}:8002/api/v0.1/cmx".format(DNS_DOMAIN)
    CMX = "https://cl-cmx-1." + DNS_DOMAIN
    TOOL = "tool." + DNS_DOMAIN
    TOOL_BASE = "https://{}/Port/Switchport.aspx?".format(TOOL)
    AD_DOMAIN = "ad." + DNS_DOMAIN
    AD_DN_BASE = "cn=Users" + "".join([", dc={}".format(x) for x in AD_DOMAIN.split(".")])
    VCENTER = "cl-vcenter." + DNS_DOMAIN
    PW_RESET_URL = "https://cl-jump-01.{}:8443".format(DNS_DOMAIN)
    CPNR_SERVERS = ["dc1-dhcp." + DNS_DOMAIN, "dc2-dhcp." + DNS_DOMAIN, "dc1-dns." + DNS_DOMAIN, "dc2-dns." + DNS_DOMAIN]
