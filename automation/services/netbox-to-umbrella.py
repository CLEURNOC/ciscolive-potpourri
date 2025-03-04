#!/usr/bin/env python
#
# Copyright (c) 2017-2025  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from elemental_utils import ElementalNetbox  # type: ignore
from typing import List, Dict
import os
import logging.config
import logging
from logzero import setup_logger
import ipaddress
import requests
import time
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

logging.config.fileConfig(os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/dns_logger.conf"))
logger = setup_logger()
logger.setLevel(logging.INFO)


class UmbrellaAPI:
    def __init__(self):
        try:
            self.access_token = self.getAccessToken()
            if self.access_token is None:
                raise Exception("Request for access token failed")
        except Exception as e:
            print(e)

    def getAccessToken(self):
        try:
            payload = {}
            rsp = requests.post(
                "https://api.umbrella.com/auth/v2/token", data=payload, auth=(CLEUCreds.UMBRELLA_KEY, CLEUCreds.UMBRELLA_SECRET)
            )
            rsp.raise_for_status()
        except Exception as e:
            print(e)
            return None
        else:
            clock_skew = 300
            self.access_token_expiration = int(time.time()) + rsp.json()["expires_in"] - clock_skew
            return rsp.json()["access_token"]


def refreshToken(decorated):
    def wrapper(api, *args, **kwargs):
        if int(time.time()) > api.access_token_expiration:
            api.access_token = api.getAccessToken()
        return decorated(api, *args, **kwargs)

    return wrapper


@refreshToken
def add_site(api, name):
    """Add a new site to Umbrella."""

    api_uri = "https://api.umbrella.com/deployments/v2/sites"

    response = requests.post(
        api_uri,
        json={"name": name},
        headers={"Authorization": f"Bearer {api.access_token}"},
    )

    if response.status_code != 200:
        logger.error("HTTP Status code: %d\n%s", response.status_code, response.text)

    return response


@refreshToken
def get_sites(api, limit=10, page=1):
    """Get all Umbrella Sites."""

    get_all_pages = False
    results = []
    response = None

    if page == -1:
        get_all_pages = True
        page = 1

    while True:
        api_uri = "https://api.umbrella.com/deployments/v2/sites?limit={}&page={}".format(limit, page)
        response = requests.get(api_uri, headers={"Authorization": f"Bearer {api.access_token}", "Accept": "application/json"})

        if response.status_code != 200:
            logger.error("HTTP Status code: %d\n%s", response.status_code, response.text)
            if get_all_pages:
                raise Exception(
                    "HTTP Status code: %d\n%s",
                    response.status_code,
                    response.text,
                )
            else:
                return response

        curr_results = response.json()

        if len(curr_results) == 0 or not get_all_pages:
            break

        results += curr_results
        page += 1

    if get_all_pages:
        return results

    return response


@refreshToken
def get_internal_networks(api, limit=10, page=1):
    """Get all Umbrella Internal Networks."""

    get_all_pages = False
    results = []
    response = None

    if page == -1:
        get_all_pages = True
        page = 1

    while True:
        api_uri = "https://api.umbrella.com/deployments/v2/internalnetworks?limit={}&page={}".format(limit, page)
        response = requests.get(api_uri, headers={"Authorization": f"Bearer {api.access_token}", "Accept": "application/json"})

        if response.status_code != 200:
            logger.error("HTTP Status code: %d\n%s", response.status_code, response.text)
            if get_all_pages:
                raise Exception(
                    "HTTP Status code: %d\n%s",
                    response.status_code,
                    response.text,
                )
            else:
                return response

        curr_results = response.json()

        if len(curr_results) == 0 or not get_all_pages:
            break

        results += curr_results
        page += 1

    if get_all_pages:
        return results

    return response


@refreshToken
def add_internal_network(api, name, ipaddress, prefixlen, siteid):
    """Add a new internal network to Umbrella."""

    api_uri = "https://api.umbrella.com/deployments/v2/internalnetworks"

    payload = {
        "name": name,
        "ipAddress": ipaddress,
        "prefixLength": int(prefixlen),
        "siteId": int(siteid),
    }

    response = requests.post(api_uri, json=payload, headers={"Authorization": f"Bearer {api.access_token}"})

    if response.status_code != 200:
        logger.error("HTTP Status code: %d\n%s", response.status_code, response.text)

    return response


def truncate_network_name(name: str, suffix: int = None) -> str:
    """
    Truncate an internal network name to work with Umbrella

    :param name: Name to possibly truncate
    :param suffix: Optional suffix to apply
    :return truncated name
    """
    trunc_name = name[0:50]

    if suffix:
        ssuffix = "." + str(suffix)
        endl = 50 - len(ssuffix)
        trunc_name = name[0:endl] + ssuffix

    name = trunc_name

    return name


def get_network_name(name: str, int_networks: List[Dict]) -> str:
    """
    Return a unique internal network name

    :param name: Candidate network name
    :param int_networks: List of internal networks
    :return unique new network name
    """

    suffix = None
    net_name = name
    while True:
        net_name = truncate_network_name(name, suffix)
        if not any(d["name"] == net_name for d in int_networks):
            break

        if not suffix:
            suffix = 1
        else:
            suffix += 1

    return net_name


# def create_all_sites(prefixes: List, umbr_cred: str, umbr_sites: List[Dict]) -> int:
#     """
#     Create any NetBox site that is missing in Umbrella

#     :param prefixes: List of NetBox IP address prefixes
#     :param umbr_cred: Credential to use to login to the Umbrella API
#     :param umbr_sites: List of current Umbrella sites
#     """

#     errors = 0

#     for prefix in prefixes:
#         if not prefix.vrf:
#             continue

#         # We only want to add private networks as internal.
#         prefix_object = ipaddress.ip_network(prefix.prefix)
#         if not prefix_object.is_private:
#             continue

#         # Prefer to name sites based on the VRF name.  However, if the VRF name is the global VRF, then use
#         # the tenant name instead.
#         site_name = "Default Site"

#         if not any(d["name"] == site_name for d in umbr_sites):
#             new_site = umbr_api.management.add_site(name=site_name, orgid=C.UMBRELLA_ORGID, cred=umbr_cred)
#             if new_site.status_code != 200:
#                 logger.warning(f"⛔️ Failed to create new Umbrella site {site_name}: {new_site.json()}")
#                 errors += 1
#                 continue

#             logger.info(f"🎨 Created Umbrella site {site_name}")
#             umbr_sites.append(new_site.json())

#     return errors


def main():
    os.environ["NETBOX_ADDRESS"] = C.NETBOX_SERVER
    os.environ["NETBOX_API_TOKEN"] = CLEUCreds.NETBOX_API_TOKEN

    errors = 0

    api = UmbrellaAPI()

    umbr_sites = get_sites(api, page=-1, limit=200)
    umbr_int_networks = get_internal_networks(api, page=-1, limit=200)

    enb = ElementalNetbox()

    nb_prefixes = [prefix for prefix in enb.ipam.prefixes.all() if prefix.tenant and prefix.vlan]
    # errors += create_all_sites(prefixes=nb_prefixes, umbr_cred=umbr_cred, umbr_sites=umbr_sites)

    for prefix in nb_prefixes:
        create_new = True
        site_name = "Default Site"

        # We only want to add private networks as internal.
        prefix_object = ipaddress.ip_network(prefix.prefix)
        if not prefix_object.is_private:
            continue

        siteid = [s["siteId"] for s in umbr_sites if s["name"] == site_name][0]
        vlan = prefix.vlan
        vlan.full_details()
        if str(vlan.group) == "DC1 VLANs":
            vlan_name = vlan.name.format(dc="1")
        elif str(vlan.group.name) == "DC2 VLANs":
            vlan_name = vlan.name.format(dc="2")
        else:
            vlan_name = vlan.name

        # We don't want a guaranteed-unique name yet, just one that is the right length.
        # If the name exists and the address/prefix length are the same, don't do anything.
        umbr_name = truncate_network_name(f"{vlan_name} : {prefix.tenant.name}")
        (addr, plen) = str(prefix).split("/")
        for int_network in umbr_int_networks:
            if int_network["siteId"] == siteid:
                if int_network["name"] == umbr_name:
                    if addr == int_network["ipAddress"] and int(plen) == int(int_network["prefixLength"]):
                        create_new = False

                    break

        if create_new:
            new_net = add_internal_network(
                api,
                name=umbr_name,
                ipaddress=addr,
                prefixlen=plen,
                siteid=siteid,
            )
            if new_net.status_code != 200:
                logger.warning(
                    f"⛔️ Failed to create new internal network {umbr_name} with network IP {addr} and prefix length {plen} for site "
                    f"{site_name}: {new_net.json()}"
                )
                errors += 1
                continue

            logger.info(
                f"🎨 Created new Umbrella internal network {umbr_name} with network IP {addr} and prefix length {plen} "
                f"for site {site_name}"
            )
            umbr_int_networks.append(new_net.json())

    exit(errors)


if __name__ == "__main__":
    main()
