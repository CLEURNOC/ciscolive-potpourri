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

"""Network Metrics Exporter.

This script collects various metrics (MAC counts, ARP entries, NAT statistics, etc.)
from network devices via SSH and exports them to Prometheus.
"""

import argparse
import json
import logging
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import CLEUCreds  # type: ignore
from cleu.config import Config as C  # type: ignore
from flask import Flask, Response, request
from gevent.pywsgi import WSGIServer  # type: ignore
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from prometheus_client import CollectorRegistry, Gauge
from prometheus_client.exposition import choose_encoder
from sparker import MessageType, Sparker  # type: ignore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONFIG_FILE = Path(__file__).parent / "poll_macs_config.json"
DEFAULT_WEBEX_ROOM = "Core Alarms"
DEFAULT_PORT = 8081
DEFAULT_COLLECTION_INTERVAL = 300  # 5 minutes


@dataclass
class CommandConfig:
    """Configuration for a command to execute."""

    command: str
    pattern: str
    metric: str | None = None
    metrics: list[str] | None = None
    threshold: str | None = None
    thresholds: list[str] | None = None


@dataclass
class DeviceTarget:
    """Target device configuration."""

    device: str
    commands: list[str]
    device_type: str = "cisco_ios"


@dataclass
class MonitorConfig:
    """Configuration for metrics monitoring."""

    webex_room: str
    commands: dict[str, CommandConfig]
    devices: list[dict]
    worker_pool_size: int = 20
    connection_timeout: int = 5
    collection_interval: int = DEFAULT_COLLECTION_INTERVAL


@dataclass
class MetricsCollector:
    """Collects and exposes network device metrics."""

    registry: CollectorRegistry
    config: MonitorConfig
    targets: list[DeviceTarget]
    gauges: dict[str, Gauge]
    spark: Sparker
    last_collection_time: datetime | None = field(default=None, init=False)
    collection_lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    stop_event: threading.Event = field(default_factory=threading.Event, init=False)

    @classmethod
    def create(cls, config: MonitorConfig, targets: list[DeviceTarget]) -> "MetricsCollector":
        """Factory method to create a MetricsCollector instance."""
        registry = CollectorRegistry()
        gauges: dict[str, Gauge] = {}
        spark = Sparker(token=CLEUCreds.SPARK_TOKEN)

        # Create Gauge metrics for all unique metric names
        metric_names = set()
        for cmd_config in config.commands.values():
            if cmd_config.metric:
                metric_names.add(cmd_config.metric)
            if cmd_config.metrics:
                metric_names.update(cmd_config.metrics)

        for metric_name in metric_names:
            gauges[metric_name] = Gauge(
                metric_name,
                f"Network device metric: {metric_name}",
                ["device"],
                registry=registry,
            )

        return cls(
            registry=registry,
            config=config,
            targets=targets,
            gauges=gauges,
            spark=spark,
        )

    def _check_threshold(
        self,
        metric_name: str,
        value: str,
        threshold: str,
    ) -> None:
        """Check if a metric violates its threshold and send notification."""
        if not threshold or not (threshold.startswith("==") or threshold.startswith("<") or threshold.startswith(">")):
            return

        try:
            if eval(f"{value} {threshold}"):
                self.spark.post_to_spark(
                    C.WEBEX_TEAM,
                    self.config.webex_room,
                    f"Metric **{metric_name}** has violated threshold {threshold}, currently {value}",
                    MessageType.WARNING,
                )
        except Exception as e:
            logger.error(f"Failed to check threshold for {metric_name}: {e}")

    def _set_metric_value(self, metric_name: str, device: str, value: str) -> None:
        """Set a metric value for a device."""
        try:
            self.gauges[metric_name].labels(device=device).set(float(value))
        except Exception as e:
            logger.error(f"Failed to set metric {metric_name} for {device}: {e}")

    def _set_metrics_to_zero(self, target: DeviceTarget) -> None:
        """Set all metrics for a device to zero (on connection/command failure)."""
        for command_name in target.commands:
            if command_name in self.config.commands:
                cmd_config = self.config.commands[command_name]
                if cmd_config.metric:
                    self._set_metric_value(cmd_config.metric, target.device, "0")
                elif cmd_config.metrics:
                    for metric in cmd_config.metrics:
                        self._set_metric_value(metric, target.device, "0")

    def _process_command_output(
        self,
        target: DeviceTarget,
        cmd_config: CommandConfig,
        output: str,
    ) -> None:
        """Process output from a single command and update metrics."""
        if match := re.search(cmd_config.pattern, output, re.DOTALL):
            if cmd_config.metric:
                # Single metric
                value = match.group(1)
                self._set_metric_value(cmd_config.metric, target.device, value)
                if cmd_config.threshold:
                    self._check_threshold(cmd_config.metric, value, cmd_config.threshold)

            elif cmd_config.metrics:
                # Multiple metrics
                for i, metric in enumerate(cmd_config.metrics, start=1):
                    value = match.group(i)
                    self._set_metric_value(metric, target.device, value)
                    if cmd_config.thresholds and i <= len(cmd_config.thresholds):
                        self._check_threshold(metric, value, cmd_config.thresholds[i - 1])
        else:
            # Pattern didn't match, set to zero
            if cmd_config.metric:
                self._set_metric_value(cmd_config.metric, target.device, "0")
            elif cmd_config.metrics:
                for metric in cmd_config.metrics:
                    self._set_metric_value(metric, target.device, "0")

    def _collect_device_metrics(self, target: DeviceTarget) -> None:
        """Collect metrics from a single device."""
        device_params = {
            "device_type": target.device_type,
            "host": target.device,
            "username": CLEUCreds.NET_USER,
            "password": CLEUCreds.NET_PASS,
            "timeout": self.config.connection_timeout,
        }

        try:
            with ConnectHandler(**device_params) as ssh:
                logger.debug(f"Connected to {target.device}")

                for command_name in target.commands:
                    if command_name not in self.config.commands:
                        logger.warning(f"Unknown command {command_name} for {target.device}")
                        continue

                    cmd_config = self.config.commands[command_name]

                    try:
                        output = ssh.send_command(cmd_config.command, read_timeout=30)
                        self._process_command_output(target, cmd_config, output)
                    except Exception as e:
                        logger.error(f"Failed to execute {command_name} on {target.device}: {e}")
                        # Set zeros for failed command
                        if cmd_config.metric:
                            self._set_metric_value(cmd_config.metric, target.device, "0")
                        elif cmd_config.metrics:
                            for metric in cmd_config.metrics:
                                self._set_metric_value(metric, target.device, "0")

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            error_type = "timeout" if isinstance(e, NetmikoTimeoutException) else "authentication"
            logger.error(f"Connection {error_type} for {target.device}")
            self._set_metrics_to_zero(target)
        except Exception as e:
            logger.error(f"Failed to connect to {target.device}: {e}")
            self._set_metrics_to_zero(target)

    def collect_metrics(self) -> None:
        """Collect metrics from all devices in parallel using threads."""
        with self.collection_lock:
            logger.info(f"Starting network metrics collection from {len(self.targets)} devices")
            start_time = time.time()

            with ThreadPoolExecutor(max_workers=self.config.worker_pool_size) as executor:
                futures = {executor.submit(self._collect_device_metrics, target): target for target in self.targets}

                for future in as_completed(futures, timeout=120):
                    target = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Failed to collect metrics from {target.device}: {e}")

            self.last_collection_time = datetime.now()
            elapsed = time.time() - start_time
            logger.info(f"Network metrics collection completed in {elapsed:.2f} seconds")

    def _periodic_collection_loop(self) -> None:
        """Run periodic metrics collection in the background."""
        logger.info(f"Starting periodic collection thread (interval: {self.config.collection_interval}s)")

        # Do an initial collection
        try:
            self.collect_metrics()
        except Exception as e:
            logger.error(f"Initial metrics collection failed: {e}")

        while not self.stop_event.is_set():
            # Wait for the collection interval or until stop is signaled
            if self.stop_event.wait(timeout=self.config.collection_interval):
                break

            try:
                self.collect_metrics()
            except Exception as e:
                logger.error(f"Periodic metrics collection failed: {e}")

        logger.info("Periodic collection thread stopped")

    def start_periodic_collection(self) -> None:
        """Start the background thread for periodic metrics collection."""
        collection_thread = threading.Thread(target=self._periodic_collection_loop, daemon=True)
        collection_thread.start()
        logger.info("Periodic collection thread started")

    def stop(self) -> None:
        """Signal the background collection thread to stop."""
        logger.info("Stopping periodic collection...")
        self.stop_event.set()


def load_config_file(config_file: Path) -> dict:
    """Load configuration from JSON file.

    Args:
        config_file: Path to configuration file

    Returns:
        Configuration dictionary
    """
    try:
        with config_file.open("r") as fd:
            config = json.load(fd)
            logger.info(f"Loaded configuration from {config_file}")
            return config
    except Exception as e:
        logger.error(f"Failed to load configuration file {config_file}: {e}")
        sys.exit(1)


def parse_commands(commands_dict: dict) -> dict[str, CommandConfig]:
    """Parse commands configuration into CommandConfig objects.

    Args:
        commands_dict: Raw commands dictionary

    Returns:
        Dictionary mapping command names to CommandConfig objects
    """
    parsed = {}
    for name, cmd_data in commands_dict.items():
        parsed[name] = CommandConfig(
            command=cmd_data["command"],
            pattern=cmd_data["pattern"],
            metric=cmd_data.get("metric"),
            metrics=cmd_data.get("metrics"),
            threshold=cmd_data.get("threshold"),
            thresholds=cmd_data.get("thresholds"),
        )
    return parsed


def expand_device_targets(devices_config: list[dict]) -> list[DeviceTarget]:
    """Expand device configuration into individual targets.

    Args:
        devices_config: List of device configuration dictionaries

    Returns:
        List of DeviceTarget objects
    """
    targets: list[DeviceTarget] = []

    for device_spec in devices_config:
        device_type = device_spec.get("type", "cisco_ios")
        commands = device_spec["commands"]

        if "list" in device_spec:
            for dev in device_spec["list"]:
                targets.append(DeviceTarget(device=dev, commands=commands, device_type=device_type))

        elif "range" in device_spec:
            pattern = device_spec["pattern"]
            range_spec = device_spec["range"]
            for i in range(range_spec["min"], range_spec["max"] + 1):
                targets.append(
                    DeviceTarget(
                        device=pattern.format(str(i)),
                        commands=commands,
                        device_type=device_type,
                    )
                )

        elif "subs" in device_spec:
            pattern = device_spec["pattern"]
            for sub in device_spec["subs"]:
                targets.append(
                    DeviceTarget(
                        device=pattern.format(sub),
                        commands=commands,
                        device_type=device_type,
                    )
                )

        elif "file" in device_spec:
            file_path = Path(device_spec["file"])
            try:
                with file_path.open("r") as fd:
                    device_list = json.load(fd)
                    for dev in device_list:
                        targets.append(
                            DeviceTarget(
                                device=dev,
                                commands=commands,
                                device_type=device_type,
                            )
                        )
            except Exception as e:
                logger.error(f"Failed to load device file {file_path}: {e}")

    logger.info(f"Expanded {len(targets)} device targets")
    return targets


def create_app(collector: MetricsCollector) -> Flask:
    """Create and configure the Flask application.

    Args:
        collector: The MetricsCollector instance
    Returns:
        Configured Flask application
    """
    app = Flask("Network Metrics Exporter")

    @app.route("/metrics")
    def metrics() -> Response:
        # Return cached metrics from memory (collected periodically in background)
        encoder, content_type = choose_encoder(request.headers.get("Accept"))
        data = encoder(collector.registry)

        # Add custom header with last collection time
        response = Response(data, content_type=content_type)
        if collector.last_collection_time:
            response.headers["X-Last-Collection"] = collector.last_collection_time.isoformat()
        return response

    return app


def main() -> None:
    """Main entry point for the network metrics exporter."""
    parser = argparse.ArgumentParser(description="Network device metrics exporter for Prometheus")
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to configuration file (default: {DEFAULT_CONFIG_FILE})",
    )
    parser.add_argument(
        "--webex-room",
        default=DEFAULT_WEBEX_ROOM,
        help=f"Webex room for notifications (default: {DEFAULT_WEBEX_ROOM})",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Number of parallel workers (default: 20)",
    )
    parser.add_argument(
        "--collection-interval",
        type=int,
        default=DEFAULT_COLLECTION_INTERVAL,
        help=f"Metrics collection interval in seconds (default: {DEFAULT_COLLECTION_INTERVAL})",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    # Load configuration
    config_data = load_config_file(args.config)

    # Parse configuration
    commands_dict = parse_commands(config_data.get("commands", {}))
    devices_config = config_data.get("devices", [])

    config = MonitorConfig(
        webex_room=args.webex_room,
        commands=commands_dict,
        devices=devices_config,
        worker_pool_size=args.workers,
        collection_interval=args.collection_interval,
    )

    # Expand device targets
    targets = expand_device_targets(devices_config)

    if not targets:
        logger.error("No device targets found")
        sys.exit(1)

    # Create metrics collector
    collector = MetricsCollector.create(config, targets)

    # Start periodic collection in background
    collector.start_periodic_collection()

    # Create Flask app
    app = create_app(collector)

    # Start HTTP server
    http_server = WSGIServer((C.WSGI_SERVER, args.port), app)
    logger.info(
        f"Starting network metrics exporter on {C.WSGI_SERVER} port {args.port} " f"(collection interval: {args.collection_interval}s)"
    )
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down network metrics exporter")
        collector.stop()
        http_server.stop()
    except Exception as e:
        logger.error(f"Error running network metrics exporter: {e}")
        collector.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
