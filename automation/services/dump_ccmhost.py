#!/usr/bin/env python3

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

import requests

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
except Exception:
    InsecureRequestWarning = None

try:
    import CLEUCreds  # type: ignore
except Exception:
    CLEUCreds = None

DEFAULT_URL = "https://dc1-dns.cleur.network:8443/web-services/rest/resource/CCMHost"
DEFAULT_ZONE_ORIGIN = "cleur.network"
DEFAULT_OUTPUT = "ccmhost.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch CCMHost records using Link header pagination and dump JSON output.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="Base CCMHost URL")
    parser.add_argument("--zone-origin", default=DEFAULT_ZONE_ORIGIN, help="zoneOrigin query parameter")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output JSON file")
    parser.add_argument("--auth", help="Authorization header value")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args()


def build_headers(auth_value: Optional[str]) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if auth_value:
        headers["Authorization"] = auth_value
    elif CLEUCreds is not None and hasattr(CLEUCreds, "JCLARKE_BASIC"):
        headers["Authorization"] = CLEUCreds.JCLARKE_BASIC
    return headers


def get_next_link(response: requests.Response) -> Optional[str]:
    if "Link" not in response.headers:
        return None
    links = requests.utils.parse_header_links(response.headers["Link"])
    for link in links:
        if link.get("rel") == "next" and link.get("url"):
            return link["url"]
    return None


def fetch_all(url: str, params: Dict[str, str], headers: Dict[str, str], verify: bool) -> List[Any]:
    items: List[Any] = []
    next_url: Optional[str] = url
    next_params: Optional[Dict[str, str]] = params

    while next_url:
        response = requests.get(next_url, params=next_params, headers=headers, verify=verify)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            items.extend(data)
        else:
            items.append(data)

        next_url = get_next_link(response)
        next_params = None

    return items


def main() -> int:
    args = parse_args()

    if args.insecure and InsecureRequestWarning is not None:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    headers = build_headers(args.auth)
    params = {"zoneOrigin": args.zone_origin}

    try:
        records = fetch_all(args.url, params, headers, verify=not args.insecure)
    except Exception as exc:
        sys.stderr.write(f"Failed to fetch CCMHost records: {exc}\n")
        return 1

    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        sys.stderr.write(f"Failed to write output file {args.output}: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
