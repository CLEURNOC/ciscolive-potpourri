#!/usr/bin/env python

from elemental_utils import ElementalNetbox
from elemental_utils.utils import check_environment
import csv
import argparse
import sys
from typing import List, Dict


def get_vlan_list(file: str) -> List[Dict]:
    """
    Given a CSV file input, provide a list of VLAN dicts.
    """

    REQ_FIELDS = 6

    vlans = []

    with open(file, encoding="utf8") as csvin:
        csvin = csv.reader(csvin)

        for rnum, row in enumerate(csvin):
            if row[0].startswith(";"):
                continue

            if len(row) < REQ_FIELDS:
                raise ValueError(f"Invalid number of fields for row {rnum}.  Must be {REQ_FIELDS} fields but is {len(row)}")

            if not row[0].isnumeric():
                raise ValueError(f"Invalid VLAN ID on row {rnum}: {row[0]}")

            vlan_id = int(row[0])

            if vlan_id < 1 or vlan_id > 4094:
                raise ValueError(f"Invalid VLAN ID on row {rnum}.  Should be between 1 and 4094.")

            if row[2] != "" and row[3] != "":
                raise ValueError(f"Cannot specify both a site and a group on row {rnum}")

            vlan_data = {
                "id": vlan_id,
                "name": row[1],
                "site": row[2],
                "group": row[3],
                "tenant": row[4],
                "description": row[5],
            }

            vlans.append(vlan_data)

    return vlans


def main():
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Add VLANs to NetBox")
    parser.add_argument("--file", "-f", metavar="<input CSV file>", help="Path to the input CSV file", required=True)
    args = parser.parse_args()

    enb = ElementalNetbox(None, None, ignore_tls=True)

    vlans = get_vlan_list(args.file)

    for vlan in vlans:
        if vlan["site"] != "":
            nb_vlan = enb.ipam.vlans.get(vid=vlan["id"], site=vlan["site"])
            vlan_site = {"slug": vlan["site"]}
            vlan_group = None
        else:
            nb_vlan = enb.ipam.vlans.get(vid=vlan["id"], group=vlan["group"])
            vlan_site = None
            vlan_group = {"slug": vlan["group"]}

        vlan_data = {
            "vid": vlan["id"],
            "name": vlan["name"],
            "site": vlan_site,
            "group": vlan_group,
            "tenant": {"slug": vlan["tenant"]},
            "description": vlan["description"],
        }

        if not nb_vlan:
            print(f"Creating VLAN {vlan['id']} with parameters {vlan_data}")
            try:
                nb_vlan = enb.ipam.vlans.create(**vlan_data)
            except Exception as e:
                print(f"Failed to create VLAN {vlan['id']}: {e}")

            continue

        print(f"Updating VLAN {vlan['id']} with parameters {vlan_data}")

        nb_vlan.name = vlan["name"]
        nb_vlan.site = vlan_site
        nb_vlan.group = vlan_group
        nb_vlan.tenant = {"slug": vlan["tenant"]}
        nb_vlan.descrption = vlan["description"]

        try:
            nb_vlan.save()
        except Exception as e:
            print(f"Failed to update VLAN {vlan['id']}: {e}")


if __name__ == "__main__":
    main()
