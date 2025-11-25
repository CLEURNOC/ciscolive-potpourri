# Syslog-ng Filter Scripts

## Overview

This directory contains Python-based syslog-ng filter scripts that monitor network infrastructure for critical events and send real-time alerts to Webex Teams spaces. These filters process syslog messages from network devices, detect specific fault conditions, and provide immediate visibility to the NOC team during Cisco Live Europe events.

**Architecture:** Syslog messages → syslog-ng → Python filter scripts → Webex Teams notifications

## Scripts

### 1. `err_disable.py` - Port Error-Disable Monitoring

Monitors switchports entering and recovering from error-disabled state, providing real-time visibility into port-level failures.

#### Script Purpose

Detects when network switch ports are automatically disabled due to errors (security violations, link flaps, BPDU guard, etc.) and when they recover. This is critical for identifying and resolving connectivity issues quickly during live events.

#### Detection Patterns

**Error-Disable Detected:**

- Pattern: `putting [port] in err-disable state`
- Extracts: Port name, reason for disable
- Action: Sends **WARNING** message to Webex Teams
- Tracking: Records timestamp in cache file

**Recovery Detected:**

- Pattern: `recover from .+? err-disable state on [port]`
- Delay: 30-second debounce period (prevents flapping alerts)
- Action: Sends **GOOD** message to Webex Teams
- Cleanup: Removes port from cache

#### Script Configuration

```python
SPARK_ROOM = "Err Disable Alarms"  # Webex Teams space name
CACHE_FILE = "/home/jclarke/err_disable_cache.json"  # State tracking
```

**Dependencies:**

- `sparker` - Webex Teams API wrapper
- `CLEUCreds` - Credentials module
- `cleu.config` - Configuration framework

**Required Environment:**

- `CLEUCreds.SPARK_TOKEN` - Webex bot token
- `C.WEBEX_TEAM` - Webex Team name
- `C.TOOL_BASE` - Base URL for port management tool links

#### Alert Message Format

**Error-Disable Alert:**

```text
Port [Gi1/0/1] on **SWITCH-NAME** (hostname) has been put in an err-disable state because [reason]
```

**Recovery Alert:**

```text
Port [Gi1/0/1] on **SWITCH-NAME** (hostname) is recovering from err-disable
```

#### Features

##### 1. Tool Integration

- Generates clickable links to port management interface
- Links include switch name and port name parameters
- Format: `C.TOOL_BASE?switchname=SWITCH&portname=PORT`

##### 2. Flap Prevention

- 30-second debounce timer prevents alert storms
- Only sends recovery if port has been stable for 30 seconds
- Cache tracks last err-disable timestamp per port

##### 3. Persistent State

- JSON cache file tracks active err-disabled ports
- Survives script restarts
- Format: `{"hostname:port": timestamp_ms, ...}`

#### Alert Experience

##### Scenario 1: Port Security Violation

```text
11:23:45 → WARNING: Port Gi1/0/12 on **IDF-3-SW1** (idf3-sw1) has been put in an err-disable state because psecure-violation
```

- NOC team sees immediate alert in "Err Disable Alarms" space
- Clickable port link allows instant access to port configuration
- Team can investigate cause and remediate

##### Scenario 2: Port Recovery

```text
11:25:30 → GOOD: Port Gi1/0/12 on **IDF-3-SW1** (idf3-sw1) is recovering from err-disable
```

- 30 seconds after administrator enables the port
- Confirms issue is resolved
- Reduces follow-up monitoring burden

##### Scenario 3: Flapping Port (Prevented)

```text
11:23:45 → Port goes err-disable
11:23:50 → Port recovers (no alert - within 30s window)
11:23:55 → Port goes err-disable again (new alert)
```

- Debounce logic prevents spam from unstable ports
- Only sends recovery if port is stable for 30+ seconds

---

### 2. `ipsla_timeout.py` - Internet Connectivity Monitoring

Monitors IP SLA probes that track external Internet connectivity by detecting timeout thresholds for IPv4 and IPv6 connections.

#### Alert Purpose

Provides early warning when Internet connectivity is lost or degraded. Uses IP SLA probes (typically to public DNS servers like Google's 8.8.8.8 and 2001:4860:4860::8888) to detect outages before users report issues.

#### Alert Detection Logic

**Timeout Threshold Occurred:**

- Pattern: `RTT-3-IPSLATHRESHOLD: IP SLAs([1|2]): Threshold Occurred for timeout`
- SLA ID 1 = IPv4 connectivity
- SLA ID 2 = IPv6 connectivity
- Trigger: 3 consecutive failed pings
- Action: Sends **DANGER** alert to Webex Teams

**Timeout Threshold Cleared:**

- Pattern: `Threshold Cleared for timeout`
- Action: Sends **RELAX** message to Webex Teams

#### Alert Configuration

```python
SPARK_ROOM = "Core Alarms"  # Webex Teams space name
```

**Note:** This script uses legacy Python 2 syntax and older configuration format (hardcoded team/room names).

#### Notification Format

**Connectivity Down:**

```text
DANGER: IPv4 connectivity is down to Google's DNS from CORE-RTR-1 (lost 3 consecutive pings)
```

**Connectivity Restored:**

```text
RELAX: IPv4 connectivity to Google's DNS from CORE-RTR-1 has been restored
```

#### Operational Experience

##### Scenario 1: ISP Outage

```text
14:32:10 → DANGER: IPv4 connectivity is down to Google's DNS from CORE-RTR-1 (lost 3 consecutive pings)
14:32:12 → DANGER: IPv6 connectivity is down to Google's DNS from CORE-RTR-1 (lost 3 consecutive pings)
```

- Immediate alert when both IPv4 and IPv6 fail
- NOC team knows to check ISP connection
- Can proactively notify users before ticket flood

##### Scenario 2: Partial Connectivity

```text
15:45:22 → DANGER: IPv6 connectivity is down to Google's DNS from CORE-RTR-1 (lost 3 consecutive pings)
```

- Only IPv6 affected, IPv4 still working
- Indicates potential routing issue
- Allows targeted troubleshooting

##### Scenario 3: Restoration

```text
14:40:15 → RELAX: IPv4 connectivity to Google's DNS from CORE-RTR-1 has been restored
14:40:17 → RELAX: IPv6 connectivity to Google's DNS from CORE-RTR-1 has been restored
```

- Clear confirmation service is restored
- Timestamps help calculate outage duration

#### IP SLA Configuration Example

For reference, typical IP SLA configuration on Cisco routers:

```cisco
ip sla 1
 icmp-echo 8.8.8.8 source-interface GigabitEthernet0/0
 threshold 3000
 timeout 5000
 frequency 10
ip sla schedule 1 life forever start-time now

ip sla 2
 icmp-echo 2001:4860:4860::8888 source-interface GigabitEthernet0/0
 threshold 3000
 timeout 5000
 frequency 10
ip sla schedule 2 life forever start-time now
```

---

### 3. `ps_fail.py` - Power Supply Failure Monitoring

Detects power supply failures or shutdowns on network devices, providing immediate notification of hardware failures that could impact redundancy.

#### Hardware Alert Purpose

Alerts NOC team when power supplies fail on critical infrastructure. While devices may continue operating on remaining power supplies, loss of redundancy creates single-point-of-failure risk requiring immediate attention.

#### Hardware Detection Logic

**Power Supply Failure:**

- Pattern: `Power supply (\d+) has failed or shutdown`
- Extracts: Power supply number (1, 2, etc.)
- Action: Posts alert to Webex Teams

#### Hardware Alert Configuration

```python
SPARK_ROOM = "Data Center Alarms"  # Webex Teams space name
```

**Note:** This script uses legacy Python 2 syntax and older configuration format.

#### Hardware Alert Format

**Power Supply Failure:**

```text
Power supply **2** on **DC-CORE-SW1** has failed or shutdown
```

#### Hardware Alert Experience

##### Scenario 1: Redundant Power Supply Failure

```text
09:15:33 → Power supply **2** on **DC-CORE-SW1** has failed or shutdown
```

- Device continues operating on power supply 1
- NOC team schedules replacement
- Prevents future outage if remaining PS fails

##### Scenario 2: Environmental Issue

```text
09:15:33 → Power supply **2** on **DC-CORE-SW1** has failed or shutdown
09:15:35 → Power supply **1** on **DC-CORE-SW1** has failed or shutdown
```

- Multiple failures indicate power circuit problem
- Team checks PDU/UPS status immediately
- Prevents cascading failures

##### Scenario 3: Single-PS Device

```text
10:42:19 → Power supply **1** on **IDF-ACCESS-SW** has failed or shutdown
```

- Critical alert - device may be down
- Immediate investigation required
- May correlate with user connectivity reports

---

### 4. `qfp_alerts.py` - Quantum Flow Processor Load Monitoring

Monitors CPU load on Cisco ASR/ISR router Quantum Flow Processors (QFPs), detecting performance degradation before it impacts traffic.

#### QFP Alert Purpose

Provides early warning when router data plane processors exceed safe operating thresholds. High QFP load can indicate DDoS attacks, misconfigured features, or capacity issues requiring immediate attention.

#### QFP Detection Logic

**High Load Threshold Exceeded:**

- Pattern: `MCPRP-QFP-ALERT: Slot: (\d+), QFP:(\d+), Load (\d+%) exceeds the setting threshold.(\d+%)`
- Extracts: Slot number, QFP number, current load %, threshold %
- Action: Sends **BAD** message to Webex Teams

**Load Recovered:**

- Pattern: `Slot: (\d+), QFP:(\d+), Load (\d+%) recovered`
- Extracts: Slot, QFP, recovered load %
- Action: Sends **GOOD** message to Webex Teams

#### QFP Alert Configuration

```python
SPARK_ROOM = "Core Alarms"  # Webex Teams space name
```

**Dependencies:**

- `sparker` - Webex Teams API wrapper with MessageType support
- `CLEUCreds` - Credentials module
- `cleu.config` - Configuration framework

#### QFP Alert Format

**High Load Alert:**

```text
Slot 0, QFP 0 on device **CORE-RTR-1** has a load of 85% which exceeds the threshold of 75%
```

**Load Recovered:**

```text
RELAX: Slot 0, QFP 0 on device **CORE-RTR-1** is now recovered at load 45%
```

#### QFP Alert Experience

##### Scenario 1: Normal Traffic Spike

```text
16:30:15 → Slot 0, QFP 0 on device **EDGE-RTR** has a load of 82% which exceeds the threshold of 75%
16:32:45 → RELAX: Slot 0, QFP 0 on device **EDGE-RTR** is now recovered at load 58%
```

- Brief load spike during peak hours
- Recovers automatically
- Team monitors for pattern

##### Scenario 2: DDoS Attack

```text
11:15:23 → Slot 0, QFP 0 on device **EDGE-RTR** has a load of 95% which exceeds the threshold of 75%
11:15:45 → Slot 1, QFP 0 on device **EDGE-RTR** has a load of 93% which exceeds the threshold of 75%
```

- Multiple QFPs at high load simultaneously
- Indicates widespread traffic issue
- Team enables DDoS mitigation

##### Scenario 3: Performance Degradation

```text
14:20:10 → Slot 0, QFP 0 on device **CORE-RTR-2** has a load of 88% which exceeds the threshold of 75%
(No recovery message - sustained high load)
```

- Continuous high load without recovery
- May indicate misconfiguration or capacity issue
- Requires immediate investigation

#### QFP Load Threshold Configuration

Typical router configuration to generate these alerts:

```cisco
platform qfp utilization monitor load 75
```

---

## Syslog-ng Integration

### Input Format

All scripts expect syslog messages formatted by syslog-ng with tilde (`~`) delimiters:

```text
hostname~message_header~message_body
```

**Examples:**

```text
SWITCH-01~: ~%PM-4-ERR_DISABLE: psecure-violation error detected on Gi1/0/12, putting Gi1/0/12 in err-disable state
CORE-RTR~: ~%RTT-3-IPSLATHRESHOLD: IP SLAs(1): Threshold Occurred for timeout
DC-SW-01~: ~%C4K_CHASSIS-3-POWERSUPPLYBAD: Power supply 2 has failed or shutdown
```

### Syslog-ng Configuration Example

```conf
# Define source for network syslog
source s_network {
    udp(port(514));
    tcp(port(514));
};

# Filter for err-disable messages
filter f_err_disable {
    match("err-disable" value("MESSAGE"));
};

# Filter for IP SLA timeout messages
filter f_ipsla {
    match("IPSLATHRESHOLD.*timeout" value("MESSAGE"));
};

# Filter for power supply failures
filter f_power_supply {
    match("Power supply.*failed" value("MESSAGE"));
};

# Filter for QFP alerts
filter f_qfp {
    match("QFP-ALERT|QFP.*Load.*recovered" value("MESSAGE"));
};

# Destination for err-disable script
destination d_err_disable {
    program("/usr/bin/python3 /opt/ciscolive/automation/syslog-ng-filters/err_disable.py"
        template("$HOST~$MSGHDR~$MSG\n")
    );
};

# Destination for ipsla script
destination d_ipsla {
    program("/usr/bin/python3 /opt/ciscolive/automation/syslog-ng-filters/ipsla_timeout.py"
        template("$HOST~$MSG\n")
    );
};

# Destination for power supply script
destination d_ps_fail {
    program("/usr/bin/python3 /opt/ciscolive/automation/syslog-ng-filters/ps_fail.py"
        template("$HOST~$MSG\n")
    );
};

# Destination for QFP alerts script
destination d_qfp {
    program("/usr/bin/python3 /opt/ciscolive/automation/syslog-ng-filters/qfp_alerts.py"
        template("$HOST~$MSG\n")
    );
};

# Log paths
log {
    source(s_network);
    filter(f_err_disable);
    destination(d_err_disable);
};

log {
    source(s_network);
    filter(f_ipsla);
    destination(d_ipsla);
};

log {
    source(s_network);
    filter(f_power_supply);
    destination(d_ps_fail);
};

log {
    source(s_network);
    filter(f_qfp);
    destination(d_qfp);
};
```

### Important Notes

1. **Script Execution**: Scripts run as persistent programs, reading from stdin in infinite loops
2. **Message Format**: Each script expects specific delimiter format (`~` separated fields)
3. **Blocking Behavior**: Scripts block waiting for input, processing messages as they arrive
4. **Error Handling**: syslog-ng will restart scripts if they exit unexpectedly

---

## Setup and Deployment

### Prerequisites

**System Requirements:**

- Linux server running syslog-ng (3.x or newer)
- Python 3.x (note: `ipsla_timeout.py` and `ps_fail.py` may need Python 2 → 3 migration)
- Network connectivity to syslog sources
- Internet access for Webex Teams API

**Python Dependencies:**

- `sparker` - Webex Teams API wrapper library
- `CLEUCreds` - Credentials management module
- `cleu.config` - Configuration framework

### Installation Steps

1. **Install syslog-ng:**

   ```bash
   # Ubuntu/Debian
   sudo apt-get install syslog-ng syslog-ng-core
   
   # RHEL/CentOS
   sudo yum install syslog-ng
   ```

2. **Install Python dependencies:**

   ```bash
   sudo pip3 install sparker
   ```

3. **Deploy scripts:**

   ```bash
   sudo mkdir -p /opt/ciscolive/automation/syslog-ng-filters
   sudo cp *.py /opt/ciscolive/automation/syslog-ng-filters/
   sudo chmod +x /opt/ciscolive/automation/syslog-ng-filters/*.py
   ```

4. **Configure credentials:**

   Create or update `/opt/ciscolive/CLEUCreds.py`:

   ```python
   SPARK_TOKEN = "Bot_token_from_Webex_developer_portal"
   ```

5. **Configure syslog-ng:**

   Add filter configurations to `/etc/syslog-ng/syslog-ng.conf` (see examples above)

6. **Create Webex Teams spaces:**

   - "Err Disable Alarms" - For port error-disable notifications
   - "Core Alarms" - For IPSLA and QFP alerts
   - "Data Center Alarms" - For power supply failures

7. **Add bot to spaces:**

   Add the Webex bot (using SPARK_TOKEN) to all required spaces

8. **Create cache directory:**

   ```bash
   sudo mkdir -p /home/jclarke
   sudo touch /home/jclarke/err_disable_cache.json
   sudo chmod 644 /home/jclarke/err_disable_cache.json
   ```

9. **Test configuration:**

   ```bash
   sudo syslog-ng -s  # Syntax check
   sudo systemctl restart syslog-ng
   sudo systemctl status syslog-ng
   ```

10. **Verify syslog reception:**

    ```bash
    sudo tcpdump -i any port 514 -n
    ```

### Configuration Tuning

**Adjust QFP Threshold (on routers):**

```cisco
platform qfp utilization monitor load 75  # 75% threshold
```

**Adjust err-disable debounce timer** (in `err_disable.py`):

```python
if int(time.time() * 1000) - curr_ports[f"{host}:{m.group(1)}"] >= 30000:
    # Change 30000 to desired milliseconds (30000 = 30 seconds)
```

**Change Webex Teams rooms** (in each script):

```python
SPARK_ROOM = "Your Custom Room Name"
```

---

## Troubleshooting

### Scripts Not Sending Alerts

**Check syslog-ng logs:**

```bash
sudo tail -f /var/log/syslog | grep syslog-ng
sudo journalctl -u syslog-ng -f
```

**Verify script execution:**

```bash
ps aux | grep err_disable
ps aux | grep ipsla_timeout
ps aux | grep ps_fail
ps aux | grep qfp_alerts
```

**Test script manually:**

```bash
echo "TESTSWITCH~: ~test: putting Gi1/0/1 in err-disable state" | python3 err_disable.py
```

**Check Webex bot token:**

```bash
python3 -c "from sparker import Sparker; import CLEUCreds; s = Sparker(token=CLEUCreds.SPARK_TOKEN); print(s.get_members('TEAM_NAME'))"
```

### Messages Not Matching Filters

**Enable syslog-ng debugging:**

```bash
sudo syslog-ng -Fevd
```

**Test regex patterns:**

```python
import re
msg = "Your actual syslog message"
m = re.search(r'putting ([^\s]+) in err-disable state', msg)
print(m.group(1) if m else "No match")
```

**Verify message format:**

Check that syslog-ng template produces correct format:

```bash
logger -p local0.info -t TESTHOST "Test message"
# Should appear in script as: TESTHOST~message
```

### Cache File Issues (err_disable.py)

**Permissions:**

```bash
sudo chown syslog:syslog /home/jclarke/err_disable_cache.json
sudo chmod 644 /home/jclarke/err_disable_cache.json
```

**Corrupted cache:**

```bash
sudo rm /home/jclarke/err_disable_cache.json
echo "{}" | sudo tee /home/jclarke/err_disable_cache.json
sudo systemctl restart syslog-ng
```

### High CPU Usage

**Symptom:** Syslog-ng or Python scripts consuming excessive CPU

**Causes:**

- Message flood from network devices
- Inefficient regex patterns
- Infinite loop in script

**Solutions:**

- Add rate limiting in syslog-ng
- Optimize regex patterns
- Add message throttling to scripts

```conf
# Rate limiting in syslog-ng
filter f_err_disable_ratelimit {
    match("err-disable" value("MESSAGE"))
    and rate-limit(100/60);  # Max 100 messages per 60 seconds
};
```

---

## Monitoring and Maintenance

### Health Checks

**Daily:**

- Verify scripts are running: `ps aux | grep -E "err_disable|ipsla|ps_fail|qfp"`
- Check for syslog-ng errors: `sudo journalctl -u syslog-ng --since today`
- Confirm bot is in all Webex spaces

**Weekly:**

- Review alert volume and patterns
- Test alert delivery with manual syslog injection
- Verify cache file growth (err_disable.py)

**Pre-Event:**

- Test all alert types with simulated syslog messages
- Verify Webex Teams spaces are accessible
- Confirm network devices are sending syslog correctly
- Check disk space for cache files and logs

### Log Rotation

Configure logrotate for syslog-ng logs:

```bash
# /etc/logrotate.d/syslog-ng
/var/log/syslog-ng/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/bin/killall -HUP syslog-ng
    endscript
}
```

### Performance Metrics

Monitor these metrics during events:

- **Message rate**: Syslog messages/second received
- **Processing latency**: Time from syslog receipt to Webex notification
- **Alert volume**: Alerts sent per hour by type
- **Script restarts**: Number of times syslog-ng restarts filter scripts

### Backup and Recovery

**Backup configuration:**

```bash
sudo tar czf syslog-filters-backup-$(date +%Y%m%d).tar.gz \
    /etc/syslog-ng/syslog-ng.conf \
    /opt/ciscolive/automation/syslog-ng-filters/ \
    /home/jclarke/err_disable_cache.json
```

**Recovery procedure:**

1. Restore syslog-ng configuration
2. Restore filter scripts
3. Recreate Webex Teams spaces if needed
4. Re-add bot to spaces
5. Restart syslog-ng service
6. Verify alert delivery

---

## Alert Response Guidelines

### Err-Disable Alerts

**Immediate Actions:**

1. Click port link to view configuration
2. Check port logs for root cause
3. Verify device connectivity
4. Clear err-disable if appropriate: `shutdown` → `no shutdown`

**Common Causes:**

- Port security violations (MAC address limit)
- BPDU guard (spanning-tree protection)
- Link flapping (bad cable/SFP)
- UDLD (unidirectional link detection)

### IP SLA Timeout Alerts

**Immediate Actions:**

1. Verify Internet connectivity from multiple sources
2. Check ISP circuit status
3. Review BGP/routing tables
4. Test connectivity to multiple external hosts

**Escalation Criteria:**

- Both IPv4 and IPv6 down simultaneously
- No recovery within 5 minutes
- Multiple sites affected

### Power Supply Failure Alerts

**Immediate Actions:**

1. Verify device operational status
2. Check redundant power supplies
3. Schedule hardware replacement
4. Monitor device temperature

**Critical Scenarios:**

- Single power supply devices (immediate risk)
- Multiple failures in same rack (PDU issue)
- Data center environmental alerts

### QFP Load Alerts

**Immediate Actions:**

1. Check traffic patterns (NetFlow/NBAR)
2. Review recent configuration changes
3. Look for DDoS indicators
4. Monitor for sustained high load

**Investigation Steps:**

- `show platform hardware qfp active datapath utilization`
- `show platform hardware qfp active feature cpu`
- `show processes cpu platform sorted`

---

## Version Information

**Last Updated:** November 24, 2025  
**Maintainer:** Joe Clarke <jclarke@cisco.com>  
**License:** BSD-style (see file headers)

**Script Versions:**

- `err_disable.py` - Python 3, modern Sparker API
- `ipsla_timeout.py` - Python 2 (requires migration)
- `ps_fail.py` - Python 2 (requires migration)
- `qfp_alerts.py` - Python 3, modern Sparker API

**Known Issues:**

- `ipsla_timeout.py` and `ps_fail.py` use legacy Python 2 syntax
- Legacy scripts use hardcoded team/room names instead of configuration
- No built-in rate limiting (relies on syslog-ng configuration)

**Future Enhancements:**

- Migrate all scripts to Python 3
- Centralize configuration (use cleu.config for all scripts)
- Add rate limiting and deduplication logic
- Implement alert suppression during maintenance windows
- Add metrics collection for alert volume tracking
