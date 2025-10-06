class Config:
    WEBEX_TEAM = "CLEUR 26 NOC"
    CISCOLIVE_YEAR = "2026"
    DNS_DOMAIN = "ciscolive.network"
    SMTP_SERVER = "10.100.252.13"
    VPN_SERVER_IP = "45.157.175.59"
    VPN_USER = "vpn"
    WSGI_SERVER = "10.100.252.13"
    DNS_SERVER = "10.100.253.21"
    CDNS_SERVERS = ["10.100.253.9", "10.100.254.9"]
    DNS_SERVERS = ["10.100.253.21", "10.100.254.21"]
    NETBOX_SERVER = "https://cl-netbox.ciscolive.network"

    IPV6_PREFIX_SIZE = 48
    VLAN_OCTET = 2
    IDF_OCTET = 3
    IPV6_PREFIX = "2a11:d940:2::"

    REVERSE_ZONE_MAP = {
        "v4_private": "10.in-addr.arpa.",
        "v4_public": "13.97.83.in-addr.arpa.",
        "v6": "2.0.0.0.0.4.9.d.1.1.a.2.ip6.arpa.",
    }

    PRIMARY_DNS = "dc1-dns"
    SECONDARY_DNS = "dc2-dns"

    ISE_SERVER = "dc1-ise.ciscolive.network"

    DNS_BASE = "https://dc1-dns.{}:8443/web-services/rest/resource".format(DNS_DOMAIN)
    DHCP_BASE = "https://dc1-dhcp.{}:8443/web-services/rest/resource".format(DNS_DOMAIN)
    MONITORING = "cl-monitoring." + DNS_DOMAIN
    DHCP_SERVER = "dc1-dhcp." + DNS_DOMAIN
    # PI = "cl-pi." + DNS_DOMAIN

    def _DNACS(dom, dnacs=[f"dc{x}-cat-center" for x in range(1, 2)]):
        return [f"{d}.{dom}" for d in dnacs]

    # Remove DNACs for now until they are up.
    # def DNACS(dom):
    #    return []
    DNACS = _DNACS(DNS_DOMAIN)
    # SDA_BASE = "https://sdacleur20." + DNS_DOMAIN
    CMX_GW = "http://cl-freebsd.{}:8002/api/v0.1/cmx".format(DNS_DOMAIN)
    CMX = "https://cl-cmx." + DNS_DOMAIN
    TOOL = "tool." + DNS_DOMAIN
    TOOL_BASE = "https://{}/Port/Switchport.aspx?".format(TOOL)
    AD_DOMAIN = "ad." + DNS_DOMAIN
    AD_DN_BASE = "cn=Users" + "".join([", dc={}".format(x) for x in AD_DOMAIN.split(".")])
    VCENTER = "cl-vcenter." + DNS_DOMAIN
    PW_RESET_URL = "https://cl-jump-01.{}:8443".format(DNS_DOMAIN)
    CPNR_SERVERS = ["dc1-dhcp." + DNS_DOMAIN, "dc2-dhcp." + DNS_DOMAIN, "dc1-dns." + DNS_DOMAIN, "dc2-dns." + DNS_DOMAIN]
    UMBRELLA_ORGID = "1912631"
    LLAMA_URL = "https://cl-llama.ciscolive.network"
