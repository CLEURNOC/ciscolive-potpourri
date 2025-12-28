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

import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer  # type: ignore
from prometheus_client import CollectorRegistry, Counter
from prometheus_client.exposition import choose_encoder
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Adjust START_TIME to the start of the event (convert datetime string to UNIX epoch milliseconds)
START_TIME = int(datetime.fromisoformat("2025-12-11T00:00:00").timestamp() * 1000)

PORT = 8093


class UmbrellaAPI(object):
    def __init__(self):
        try:
            self.access_token = self.getAccessToken()
            if not self.access_token:
                raise Exception("Request for access token failed")
        except Exception as e:
            logger.error(f"Failed to initialize UmbrellaAPI: {e}", exc_info=True)

    def getAccessToken(self):
        try:
            payload = {}
            rsp = requests.post(
                "https://api.umbrella.com/auth/v2/token",
                data=payload,
                auth=(CLEUCreds.UMBRELLA_KEY, CLEUCreds.UMBRELLA_SECRET),
                timeout=30,
            )
            rsp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to get access token: {e}", exc_info=True)
            return None
        else:
            clock_skew = 300
            response_data = rsp.json()
            expires_in = response_data.get("expires_in")
            if expires_in is None:
                logger.error("Missing 'expires_in' in token response")
                return None
            self.access_token_expiration = int(time.time()) + int(expires_in) - clock_skew
            access_token = response_data.get("access_token")
            if not access_token:
                logger.error("Missing 'access_token' in token response")
                return None
            return access_token


def refreshToken(decorated):
    def wrapper(api, *args, **kwargs):
        if int(time.time()) > api.access_token_expiration:
            api.access_token = api.getAccessToken()
        return decorated(api, *args, **kwargs)

    return wrapper


@refreshToken
def get_umbrella_activity(api: UmbrellaAPI) -> int | None:
    try:
        response = requests.get(
            f"https://reports.api.umbrella.com/v2/organizations/{C.UMBRELLA_ORGID}/requests-by-timerange?from={START_TIME}&to=now&limit=168",
            headers={"Authorization": f"Bearer {api.access_token}"},
            timeout=30,
        )
        response.raise_for_status()
    except Exception as e:
        logger.error("Failed to get stats: %s" % str(e), exc_info=True)
        return None

    j = response.json()

    total = 0
    for n in j["data"]:
        total += n["count"]

    return total


@dataclass
class MetricsCollector(object):
    """Collects and exposes DNS server metrics."""

    registry: CollectorRegistry
    umbrella: ClassVar[UmbrellaAPI] = UmbrellaAPI()
    queriesTotal: Counter
    umbrellaQueriesTotal: Counter

    URL: ClassVar[dict[str, dict[str, str]]] = {
        "url": "https://{server}:8443/web-services/rest/stats/DNSServer",
        "params": {"nrClass": "DNSServerQueryStats"},
    }

    @classmethod
    def create(cls) -> "MetricsCollector":
        registry = CollectorRegistry()
        queriesTotal = Counter(
            "dns_queries_total",
            "Total number of DNS queries",
            ["server"],
            registry=registry,
        )
        umbrellaQueriesTotal = Counter(
            "dns_umbrella_queries_total",
            "Total number of DNS queries forwarded to Umbrella",
            ["server"],
            registry=registry,
        )
        return cls(registry=registry, queriesTotal=queriesTotal, umbrellaQueriesTotal=umbrellaQueriesTotal)

    def _fetch_dns_metrics(self, server: str) -> dict | None:
        url = self.URL["url"].format(server=server)
        try:
            response = requests.get(
                url,
                params=self.URL["params"],
                auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD),
                headers={"Accept": "application/json"},
                verify=False,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get stats from {server}: {e}", exc_info=True)
            return None

    def _fetch_umbrella_metrics(self) -> int | None:
        return get_umbrella_activity(self.umbrella)

    def _parse_metric(self, metrics: dict, key: str) -> int | None:
        value = metrics.get(key)
        if value is None:
            logger.warning(f"Metric {key} not found in response")
            return None
        return int(value)

    def collect_metrics(self) -> None:
        logger.info("Starting DNS metrics collection")
        for server in C.DNS_SERVERS:
            metrics = self._fetch_dns_metrics(server)
            if metrics is None:
                continue

            total_queries = self._parse_metric(metrics, "queriesTotal")
            if total_queries is not None:
                # Set absolute counter value since API returns cumulative total
                self.queriesTotal.labels(server=server)._value.set(total_queries)

        umbrella_total = self._fetch_umbrella_metrics()
        if umbrella_total is not None:
            # Set absolute counter value since API returns cumulative total
            self.umbrellaQueriesTotal.labels(server="umbrella")._value.set(umbrella_total)

        logger.info(f"Collected metrics: DNS Queries Total - {total_queries}, Umbrella Queries Total - {umbrella_total}")


def create_app(collector: MetricsCollector) -> Flask:
    """Create and configure the Flask application.

    Args:
        collector: The MetricsCollector instance
    Returns:
        Configured Flask application
    """
    app = Flask("DNS Metrics Exporter")

    @app.route("/metrics")
    def metrics() -> Response:
        collector.collect_metrics()
        encoder, content_type = choose_encoder(request.headers.get("Accept"))
        data = encoder(collector.registry)
        return Response(data, content_type=content_type)

    return app


def main() -> None:
    collector = MetricsCollector.create()
    app = create_app(collector)
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)
    logger.info(f"Starting DNS Metrics Exporter on {C.WSGI_SERVER} port {PORT}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down DNS Metrics Exporter")
        http_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
