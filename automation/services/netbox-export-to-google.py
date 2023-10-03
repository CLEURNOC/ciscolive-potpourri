#!/usr/bin/env python

from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import pynetbox
import os
import csv
import io
import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore

CREDS_FILE = "gs_token.json"
SHEET_ID = "1kKOqbK_y3l6Ume-MSkLg1nTVbw571mcq3EOQw5IWuWQ"


def main() -> None:
    """Export NetBox IP address data to a Google Sheet"""
    global creds, SHEET_ID

    # Connect to NetBox
    nb = pynetbox.api(C.NETBOX_SERVER, CLEUCreds.NETBOX_API_TOKEN)

    # Get all IP addresses from NetBox
    try:
        ips = list(nb.ipam.ip_addresses.all())
    except Exception as e:
        print(f"ERROR: Failed to get IPs from NetBox: {e}")
        exit(1)

    headers = [
        "Address",
        "VRF",
        "Status",
        "Role",
        "Tenant",
        "Assigned",
        "DNS name",
        "Description",
        "ID",
        "Tenant Group",
        "NAT (Inside)",
        "NAT (Outside)",
        "Comments",
        "Tags",
        "Created",
        "Last updated",
        "Interface",
        "Parent",
        "List of additional CNAMEs",
    ]

    output = io.StringIO()
    dict_writer = csv.DictWriter(output, headers)
    dict_writer.writeheader()

    for ip in ips:
        tenant = None
        tenant_group = None
        if ip.tenant:
            ip.tenant.full_details()
            tenant = ip.tenant.name
            tenant_group = str(ip.tenant.group)

        parent = None
        if ip.assigned_object:
            if ip.assigned_object_type == "virtualization.vminterface":
                parent = ip.assigned_object.virtual_machine.name
            elif ip.assigned_object_type == "dcim.interface":
                parent = ip.assigned_object.device.name

        row = {
            "Address": ip.address,
            "VRF": str(ip.vrf),
            "Status": ip.status.label,
            "Role": str(ip.role),
            "Tenant": tenant,
            "Assigned": ip.assigned_object_id,
            "DNS name": ip.dns_name,
            "Description": ip.description,
            "ID": ip.id,
            "Tenant Group": tenant_group,
            "NAT (Inside)": str(ip.nat_inside),
            "NAT (Outside)": str(ip.nat_outside),
            "Comments": ip.comments,
            "Tags": str(ip.tags),
            "Created": str(ip.created),
            "Last updated": str(ip.last_updated),
            "Interface": str(ip.assigned_object),
            "Parent": parent,
            "List of additional CNAMEs": ip.custom_fields["CNAMEs"],
        }

        dict_writer.writerow(row)

    output.seek(0)

    new_values = []
    new_values.append(headers)
    dict_reader = csv.DictReader(output)
    for row in dict_reader:
        r = []
        for header in headers:
            r.append(row[header])

        new_values.append(r)

    gs_service = build("sheets", "v4", credentials=creds)

    ip_sheet = gs_service.spreadsheets()
    ip_result = (
        ip_sheet.values().update(spreadsheetId=SHEET_ID, range="IPs!A1:ZZ", body={"values": new_values}, valueInputOption="RAW").execute()
    )
    print(ip_result)

    output.close()


if __name__ == "__main__":
    if not os.path.isfile(CREDS_FILE):
        print(f"ERROR: Token file {CREDS_FILE} does not exist!  Please re-authenticate this app.")
        exit(1)

    creds = Credentials.from_authorized_user_file(CREDS_FILE, ["https://www.googleapis.com/auth/spreadsheets"])
    if not creds.valid:
        creds.refresh(Request())

    with open(CREDS_FILE, "w") as fd:
        fd.write(creds.to_json())

    main()
