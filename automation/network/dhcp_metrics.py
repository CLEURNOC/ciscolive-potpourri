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
from dataclasses import dataclass
from typing import ClassVar

import CLEUCreds  # type: ignore
import requests
from cleu.config import Config as C  # type: ignore
from flask import Flask, Response
from gevent.pywsgi import WSGIServer  # type: ignore
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, generate_latest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

PORT = 8083


@dataclass
class MetricsCollector(object):
    """Collects and exposes DHCP server metrics."""

    registry: CollectorRegistry
    acksPerSecond: Gauge
    activeLeases: Gauge
    discovers: Counter
    droppedTotal: Counter
    offers: Counter
    requests: Counter

    URL: ClassVar[dict[str, dict[str, str]]] = {
        "url": "https://{server}:8443/web-services/rest/stats/DHCPServer",
        "params": {"nrClass": "DHCPServerActivityStats"},
    }

    @classmethod
    def create(cls) -> "MetricsCollector":
        """Factory method to create a MetricsCollector instance."""
        registry = CollectorRegistry()

        acksPerSecond = Gauge(
            "dhcp_acks_per_second",
            "DHCP Acknowledgements per second",
            ["server"],
            registry=registry,
        )

        activeLeases = Gauge(
            "dhcp_active_leases",
            "Number of active DHCP leases",
            ["server"],
            registry=registry,
        )

        discovers = Counter(
            "dhcp_discovers_total",
            "Total number of DHCP Discover messages",
            ["server"],
            registry=registry,
        )

        droppedTotal = Counter(
            "dhcp_dropped_total",
            "Total number of dropped DHCP messages",
            ["server"],
            registry=registry,
        )

        offers = Counter(
            "dhcp_offers_total",
            "Total number of DHCP Offer messages",
            ["server"],
            registry=registry,
        )

        requests = Counter(
            "dhcp_requests_total",
            "Total number of DHCP Request messages",
            ["server"],
            registry=registry,
        )

        return cls(
            registry=registry,
            acksPerSecond=acksPerSecond,
            activeLeases=activeLeases,
            discovers=discovers,
            droppedTotal=droppedTotal,
            offers=offers,
            requests=requests,
        )

    def _fetch_dhcp_metrics(self, server: str) -> dict | None:
        """Fetch DHCP metrics from the server."""
        url = self.URL["url"].format(server=server)
        params = self.URL["params"]
        try:
            response = requests.get(
                url,
                auth=(CLEUCreds.CPNR_USERNAME, CLEUCreds.CPNR_PASSWORD),
                headers={"Accept": "application/json"},
                params=params,
                verify=False,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch DHCP metrics from {server}: {e.response.text if e.response else str(e)}")
            return None

    def _parse_metric(self, metrics: dict, key: str) -> int:
        """Parse a metric value from the metrics dictionary."""
        value = metrics.get(key)
        if value is None:
            logger.warning(f"Metric {key} not found in the response.")
            return 0
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.error(f"Invalid value for metric {key}: {value}")
            return 0

    def collect_metrics(self) -> None:
        """Collect metrics from all configured DHCP servers."""
        logger.info("Starting DHCP metrics collection")

        for server in C.DHCP_SERVERS:
            logger.debug(f"Collecting metrics from {server}")

            metrics = self._fetch_dhcp_metrics(server)
            if not metrics:
                continue

            acks_per_second = self._parse_metric(metrics, "acksPerSecond")
            active_leases = self._parse_metric(metrics, "activeLeases")
            discovers = self._parse_metric(metrics, "discovers")
            dropped_total = self._parse_metric(metrics, "droppedTotal")
            offers = self._parse_metric(metrics, "offers")
            requests = self._parse_metric(metrics, "requests")

            self.acksPerSecond.labels(server=server).set(acks_per_second)
            self.activeLeases.labels(server=server).set(active_leases)
            self.discovers.labels(server=server).inc(discovers)
            self.droppedTotal.labels(server=server).inc(dropped_total)
            self.offers.labels(server=server).inc(offers)
            self.requests.labels(server=server).inc(requests)

            logger.debug(
                f"Updated metrics for {server}: "
                f"acksPerSecond={acks_per_second}, activeLeases={active_leases}, "
                f"discovers={discovers}, droppedTotal={dropped_total}, "
                f"offers={offers}, requests={requests}"
            )


def create_app(collector: MetricsCollector) -> Flask:
    """Create and configure the Flask application.

    Args:
        collector: The MetricsCollector instance
    Returns:
        Configured Flask application
    """
    app = Flask("DHCP Metrics Exporter")

    @app.route("/metrics")
    def metrics() -> Response:
        collector.collect_metrics()
        data = generate_latest(collector.registry)
        return Response(data, mimetype=CONTENT_TYPE_LATEST)

    return app


def main() -> None:
    """Main entry point for the DHCP metrics exporter."""
    collector = MetricsCollector.create()
    app = create_app(collector)

    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)
    logger.info(f"Starting DHCP metrics exporter on port {PORT}")
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down DHCP metrics exporter")
        http_server.stop()
    except Exception as e:
        logger.error(f"Error running DHCP metrics exporter: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
