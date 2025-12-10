class Config:
    WEBEX_TEAM = "CLEUR 26 NOC"
    CISCOLIVE_YEAR = "2026"
    DNS_DOMAIN = "cleur.network"
    SMTP_SERVER = "10.100.252.13"
    VPN_SERVER_IP = "45.157.175.59"
    VPN_USER = "vpn"
    WSGI_SERVER = "10.100.252.13"
    DNS_SERVER = "10.100.253.21"
    CDNS_SERVERS = ["10.100.253.9", "10.100.254.9"]
    DHCP_SERVERS = CDNS_SERVERS
    DNS_SERVERS = ["10.100.253.21", "10.100.254.21"]
    NETBOX_SERVER = f"https://cl-netbox.{DNS_DOMAIN}"

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

    ISE_SERVER = f"dc1-ise.{DNS_DOMAIN}"

    DNS_BASE = f"https://dc1-dns.{DNS_DOMAIN}:8443/web-services/rest/resource"
    DHCP_BASE = f"https://dc1-dhcp.{DNS_DOMAIN}:8443/web-services/rest/resource"
    MONITORING = f"cl-monitoring.{DNS_DOMAIN}"
    DHCP_SERVER = f"dc1-dhcp.{DNS_DOMAIN}"
    # PI = f"cl-pi.{DNS_DOMAIN}"

    def _DNACS(dom, dnacs=[f"dc{x}-cat-center" for x in range(1, 2)]):
        return [f"{d}.{dom}" for d in dnacs]

    # Remove DNACs for now until they are up.
    # def DNACS(dom):
    #    return []
    DNACS = _DNACS(DNS_DOMAIN)
    # SDA_BASE = f"https://sdacleur20.{DNS_DOMAIN}"
    CMX_GW = f"http://cl-freebsd.{DNS_DOMAIN}:8002/api/v0.1/cmx"
    CMX = f"https://cl-cmx.{DNS_DOMAIN}"
    TOOL = f"tool.{DNS_DOMAIN}"
    TOOL_BASE = f"https://{TOOL}/Port/Switchport.aspx?"
    AD_DOMAIN = f"ad.{DNS_DOMAIN}"
    AD_DN_BASE = "cn=Users" + "".join([f", dc={x}" for x in AD_DOMAIN.split(".")])
    VCENTER = f"cl-vcenter.{DNS_DOMAIN}"
    PW_RESET_URL = f"https://cl-jump-01.{DNS_DOMAIN}:8443"
    CPNR_SERVERS = [f"dc1-dhcp.{DNS_DOMAIN}", f"dc2-dhcp.{DNS_DOMAIN}", f"dc1-dns.{DNS_DOMAIN}", f"dc2-dns.{DNS_DOMAIN}"]
    UMBRELLA_ORGID = "1912631"
    LLAMA_URL = f"https://cl-llama.{DNS_DOMAIN}"
    AI_USES_OLLAMA = True
    AI_HOST = LLAMA_URL
