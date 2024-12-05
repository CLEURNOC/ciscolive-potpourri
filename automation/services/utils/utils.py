from elemental_utils import ElementalDns, ElementalCdns
from elemental_utils import cpnr
from typing import List
import concurrent.futures
import logging


def normalize_cnames(cnames: List[str], domain: str) -> List[str]:
    """
    Given a list of CNAMEs, ensure each one is stripped, ends with a '.'
    and has the default domain name if another domain name is not present.

    Args:
        :cnames List[str]: List of CNAMEs to normalize
        :domain str: Default domain name to append to unqualified CNAMEs

    Returns:
        :List[str]: Normalized list of CNAMEs
    """

    cnames = [s.strip() for s in cnames]
    cnames = list(map(lambda s: s + "." if ("." in s and not s.endswith(".")) else s, cnames))
    cnames = list(map(lambda s: s + f".{domain}" if (not s.endswith(".")) else s, cnames))

    return cnames


def dedup_cnames(cnames: List[str], domain: str) -> List[str]:
    """
    Ensure a list of CNAMEs is unique

    Args:
        :cnames List[str]: List of CNAMEs to check
        :domain str: Domain name to append to those unqualified CNAMEs

    Returns:
        :List[str]: De-duped list of CNAMEs
    """
    cname_dict = {}
    cname_list = normalize_cnames(cnames, domain)
    for c in cname_list:
        cname_dict[c] = True

    return list(cname_dict.keys())


def get_cname_record(alias: str, domain: str, edns: ElementalDns) -> cpnr.models.model.Record:
    """Get a CNAME RRSet if it exists.

    Args:
        :alias str: Alias for which to search
        :domain str: Domain name in which to look for the CNAME alias
        :edns ElementalDns: ElementalDns object that is the auth DNS

    Returns:
        :Record: Resource Record set if CNAME is found else (or if auth DNS cannot be found) None
    """
    return edns.rrset.get(alias, zoneOrigin=domain)


def launch_parallel_task(
    task, task_name: str, iterator: list, name_attribute: str, workers: int = 20, stop_on_error: bool = False, /, *args
) -> bool:
    """Execute a parallel task using thread pools.

    Args:
        :task (function): Task/function to execute
        :task_name str: Description of the task
        :iterator list: List of items on which to run the task
        :name_attribute str: Name of the attribute to identify the item
        :workers int: Number of threads to use (default: 20)
        :stop_on_error bool: Whether to stop if an error is encountered (default: False)
        :*args: Arguments to the task

    Returns:
        :bool: True if the task succeeded, False otherwise
    """
    logger = logging.getLogger(__name__)
    result = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_task = {executor.submit(task, item, *args): item for item in iterator}
        for ft in concurrent.futures.as_completed(future_task):
            item = future_task[ft]
            try:
                ft.result()
            except Exception as e:
                if not name_attribute:
                    logger.exception(f"⛔️ Failed to {task_name} for {item}: {e}")
                else:
                    logger.exception(f"⛔️ Failed to {task_name} for {getattr(item, name_attribute)}: {e}")
                result = False
                if stop_on_error:
                    break

    return result


def restart_dns_servers(edns: ElementalDns, cdnses: list) -> None:
    """Restart all affected DNS servers.

    Args:
        :edns ElementalDns: ElementalDns object to restart
        :ecdns ElementalCdns: ElementalCdns object to restart
    """
    # return
    logger = logging.getLogger(__name__)
    # A sync is not required here
    # try:
    #     edns.sync_ha_pair(instance="DNSHA", add_params={"mode": "exact", "direction": "fromMain"})
    # except Exception:
    #     # This can fail when we don't yet have an HA pair.
    #     pass
    # edns.reload_server()
    # logger.info(f"🏁 Reloaded server {edns.base_url}")

    # Restart each applicable CDNS server.
    for cdns in cdnses:
        ecdns = ElementalCdns(url=f"https://{cdns}:8443/")
        ecdns.reload_server()
        logger.info(f"🏁 Reloaded CDNS server {ecdns.base_url}")


def get_reverse_zone(ip: str) -> str:
    """Get the reverse zone for an IP.

    Args:
        :ip str: IP address to parse

    Returns:
        :str: Reverse zone name
    """
    octets = ip.split(".")
    rzone_name = f"{'.'.join(octets[::-1][1:])}.in-addr.arpa."

    return rzone_name


def parse_txt_record(txt_record: str) -> dict:
    """Parse a NetBox TXT record and return a dict of it.

    Args:
        :txt_record str: String representation of the TXT record data

    Returns:
        :dict: Dict of the results with each field a key
    """
    result = {}

    txt_record = txt_record.strip('"')
    if not txt_record.startswith("v=_netbox"):
        raise ValueError(f"Invalid NetBox TXT record data: {txt_record}")

    key_vals = txt_record.split(" ")
    for key_val in key_vals:
        if "=" in key_val:
            (key, value) = key_val.split("=")
            result[key] = value
        else:
            result[key_val] = None

    return result
