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

"""CPNR Metrics Exporter for Prometheus.

This script collects disk utilization metrics from CPNR servers via SSH
and exposes them as Prometheus metrics.
"""

import logging
import re
import shlex
import sys
from dataclasses import dataclass
from subprocess import CompletedProcess, run
from typing import ClassVar

from cleu.config import Config as C  # type: ignore
from flask import Flask, Response
from gevent.pywsgi import WSGIServer  # type: ignore
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

PORT = 8085


@dataclass
class MetricsCollector:
    """Collects and exposes CPNR server metrics."""

    registry: CollectorRegistry
    disk_utilization: Gauge

    # Class variable for command configuration
    COMMANDS: ClassVar[dict[str, dict[str, str]]] = {"df -h /": {"pattern": r"(\d+)%"}}

    @classmethod
    def create(cls) -> "MetricsCollector":
        """Create a new MetricsCollector with initialized metrics."""
        registry = CollectorRegistry()

        disk_utilization = Gauge(
            "cpnr_disk_utilization_percent",
            "CPNR server root filesystem utilization percentage",
            ["server"],
            registry=registry,
        )

        logger.info("Initialized Prometheus metrics collector")
        return cls(registry=registry, disk_utilization=disk_utilization)

    def _execute_ssh_command(self, server: str, command: str) -> CompletedProcess[str] | None:
        """Execute a command on a remote server via SSH.

        Args:
            server: The server hostname or IP address
            command: The command to execute

        Returns:
            CompletedProcess result or None if execution failed
        """
        ssh_command = f"ssh -2 root@{server} {command}"
        try:
            result = run(
                shlex.split(ssh_command),
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.error(
                    f"Command failed on {server}: {command} - " f"stdout: {result.stdout.strip()}, stderr: {result.stderr.strip()}"
                )
                return None

            return result

        except Exception as e:
            logger.error(f"Exception executing command on {server}: {command} - {e}")
            return None

    def _parse_disk_utilization(self, output: str) -> int | None:
        """Parse disk utilization percentage from df command output.

        Args:
            output: The command output to parse

        Returns:
            Utilization percentage as integer, or None if parsing failed
        """
        if match := re.search(self.COMMANDS["df -h /"]["pattern"], output):
            return int(match.group(1))
        return None

    def collect_metrics(self) -> None:
        """Collect metrics from all configured CPNR servers."""
        logger.info("Starting metrics collection")

        for server in C.CPNR_SERVERS:
            logger.debug(f"Collecting metrics from {server}")

            if result := self._execute_ssh_command(server, "df -h /"):
                if utilization := self._parse_disk_utilization(result.stdout.strip()):
                    self.disk_utilization.labels(server=server).set(utilization)
                    logger.debug(f"Updated disk utilization for {server}: {utilization}%")
                else:
                    logger.warning(f"Failed to parse disk utilization for {server}")

        logger.info("Metrics collection completed")


def create_app(collector: MetricsCollector) -> Flask:
    """Create and configure the Flask application.

    Args:
        collector: The MetricsCollector instance

    Returns:
        Configured Flask application
    """
    app = Flask("CPNR Metrics Exporter")

    @app.route("/metrics")
    def metrics() -> Response:
        """Prometheus metrics endpoint."""
        collector.collect_metrics()
        return Response(generate_latest(collector.registry), mimetype=CONTENT_TYPE_LATEST)

    @app.route("/health")
    def health() -> tuple[str, int]:
        """Health check endpoint."""
        return "OK", 200

    return app


def main() -> None:
    """Main entry point for the CPNR metrics exporter."""
    logger.info("Starting CPNR Metrics Exporter")
    logger.info(f"Monitoring servers: {', '.join(C.CPNR_SERVERS)}")

    collector = MetricsCollector.create()
    app = create_app(collector)

    logger.info(f"Starting HTTP server on {C.WSGI_SERVER}:{PORT}")
    http_server = WSGIServer((C.WSGI_SERVER, PORT), app)

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down gracefully")
        http_server.stop()
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
