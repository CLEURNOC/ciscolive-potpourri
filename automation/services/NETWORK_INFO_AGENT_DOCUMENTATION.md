# Network Info Agent Documentation

## Overview

The Network Info Agent is an AI-powered chatbot system designed for the Cisco Live Europe Network Operations Center (NOC). It provides network administrators with an intelligent interface to query and manage network infrastructure through natural language conversations in Webex Teams.

The system consists of two main components:

- **MCP Server** (`dhcp_mcp_server.py`): FastMCP-based tool server exposing network operations
- **MCP Client** (`dhcp_mcp_client.py`): FastAPI-based Webex bot that processes user queries

## Architecture

```text
┌─────────────────┐
│  Webex Teams    │
│     (User)      │
└────────┬────────┘
         │ POST /chat (webhook)
         ▼
┌─────────────────────────────┐
│  dhcp_mcp_client.py         │
│  (FastAPI + FastMCP Client) │
│                             │
│  • Webhook handler          │
│  • Conversation processor   │
│  • LLM integration (Ollama) │
└────────┬────────────────────┘
         │ stdio transport
         ▼
┌─────────────────────────────┐
│  dhcp_mcp_server.py         │
│  (FastMCP Server)           │
│                             │
│  • Network tools            │
│  • DHCP operations          │
│  • Device queries           │
└─────────────────────────────┘
```

## Prerequisites

### System Requirements

- Python 3.10 or higher
- Virtual environment (recommended)
- Network access to:
  - Webex Teams API
  - Ollama/LLM endpoint
  - NetBox
  - Cisco Prime Network Registrar (CPNR)
  - Cisco Identity Services Engine (ISE)
  - Cisco Catalyst Center (formerly DNA Center)
  - DNS servers

### Python Dependencies

Key dependencies include:

- `fastmcp` - Model Context Protocol framework
- `fastapi` - Web framework for webhook handling
- `uvicorn` - ASGI server
- `httpx` - Async HTTP client
- `pynetbox` - NetBox API client
- `ollama` - LLM client
- `sparker` - Webex Teams API wrapper
- `dns.asyncresolver` - Async DNS resolution
- `pydantic` - Data validation
- `xmltodict` - XML parsing

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

### Environment Variables

The agent requires several environment variables to be configured:

#### Core Configuration

- `DHCP_BOT_NAME` - Bot display name (default: "DHCP Agent")
- `DHCP_BOT_SPARK_ROOM` - Webex room name (default: "DHCP Queries")
- `DHCP_BOT_CALLBACK_URL` - Webhook URL (must end with `/chat`)
- `DHCP_BOT_ME` - Bot email address
- `DHCP_BOT_MODEL` - LLM model name (default: "gpt-oss")
- `LOG_LEVEL` - Logging level: DEBUG, INFO, WARNING, ERROR (default: "INFO")
- `DHCP_BOT_TLS_VERIFY` - Enable TLS verification (default: "true")

#### Network System Integration

- `NETBOX_SERVER` - NetBox API URL
- `NETBOX_API_TOKEN` - NetBox authentication token
- `CPNR_USERNAME` - CPNR API username
- `CPNR_PASSWORD` - CPNR API password
- `DHCP_BASE` - CPNR API base URL
- `DHCP_SERVER` - DHCP server hostname
- `ISE_SERVER` - ISE server hostname
- `ISE_API_USER` - ISE API username
- `ISE_API_PASS` - ISE API password
- `DNACS` - Comma-separated list of Catalyst Center hostnames
- `DNS_DOMAIN` - Default DNS domain for lookups
- `COLLAB_WEBEX_TOKEN` - Token for Webex device queries

#### Credentials Module

The client also requires a `CLEUCreds` module with:

- `SPARK_TOKEN` - Webex bot token
- `CALLBACK_TOKEN` - Webhook signature secret
- `LLAMA_USER` - Ollama authentication username
- `LLAMA_PASSWORD` - Ollama authentication password

#### Configuration Module

The client requires a `cleu.config.Config` module with:

- `WEBEX_TEAM` - Webex team name
- `LLAMA_URL` - Ollama server URL
- Other system URLs

### Testing Mode

Set `DHCP_BOT_IS_TESTING=true` to use test/stub implementations of tools (useful for development without full infrastructure access).

## Starting the Agent

The Network Info Agent must be started with **uvicorn** using **exactly one worker** to ensure proper resource management and state consistency.

### Production Startup

```bash
cd /path/to/ciscolive/automation/services
source /path/to/venv/bin/activate
uvicorn dhcp_mcp_client:app --host 0.0.0.0 --port 9999 --workers 1
```

### Development Startup (with auto-reload)

```bash
uvicorn dhcp_mcp_client:app --host 0.0.0.0 --port 9999 --workers 1 --reload
```

### Important: Single Worker Requirement

**You MUST use `--workers 1`**. Using multiple workers will cause:

- Duplicate webhook registrations
- Inconsistent bot state across workers
- MCP client connection conflicts
- Resource leaks from unclosed connections

The application lifecycle management (`lifespan` context manager) handles:

- Webhook registration on startup
- MCP client initialization
- Resource cleanup on shutdown
- Proper async session management

## Available Tools

The MCP server exposes the following tools to the AI agent:

### 1. NetBox Integration

#### `get_object_info_from_netbox`

Query NetBox network source of truth for devices and VMs.

**Inputs:**

- `ip` (IPAddress): IP address to look up
- `hostname` (Hostname): Hostname to look up
- *Note: Only one of ip or hostname may be specified*

**Returns:**

- List of objects with name, type (device/VM), IP, responsible people, and usage notes

**Example queries:**

- "What device has IP 10.1.1.1?"
- "Show me details for host switch-01"

### 2. Webex Device Information

#### `get_webex_device_info`

Retrieve comprehensive Webex device details.

**Inputs:**

- `mac` (MACAddress): Device MAC address
- `ip` (IPAddress): Device IP address  
- `device_name` (String): Device name (or SEP MAC format)
- *Note: Only one parameter may be specified*

**Returns:**

- Device name, product, type, MAC, IP, serial number, software version
- Connection status and active interface
- Workspace location, temperature, and humidity

**Example queries:**

- "Show me the Webex device with MAC 00:11:22:33:44:55"
- "What's the temperature in the room with IP 10.2.3.4?"

### 3. Utility Functions

#### `convert_celsius_to_fahrenheit`

Convert temperature from Celsius to Fahrenheit.

**Inputs:**

- `degrees_celsius` (int): Temperature in Celsius (≥ -273)

**Returns:**

- Temperature in Fahrenheit (int)

**Example queries:**

- "Convert 22 degrees Celsius to Fahrenheit"

#### `generate_password`

Generate secure random passwords using the `hankify-pw` utility.

**Inputs:**

- `words` (int): Number of words (3-6, default: 3)
- `add_symbol` (bool): Include symbol (default: false)

**Returns:**

- Generated password string

**Example queries:**

- "Generate a 4-word password"
- "Create a password with a symbol"

### 4. ISE Client Lookup

#### `get_user_details_from_ise`

Query Cisco ISE for client authentication and session details.

**Inputs:**

- `username` (string): Username to look up
- `mac` (MACAddress): Client MAC address
- `ip` (IPAddress): Client IP address
- *Note: Only one parameter may be specified*

**Returns:**

- Username, client MAC, NAS IP, client IPv4/IPv6 addresses
- Authentication timestamp
- Associated access point, VLAN, and SSID

**Example queries:**

- "Show me ISE details for user jdoe"
- "What AP is MAC aa:bb:cc:dd:ee:ff connected to?"

### 5. Catalyst Center Client Lookup

#### `get_client_details_from_cat_center`

Query Cisco Catalyst Center for client health and connectivity.

**Inputs:**

- `username` (string): Username to look up
- `mac` (MACAddress): Client MAC address
- `ip` (IPAddress): Client IP address
- *Note: Only one parameter may be specified*

**Returns:**

- User, MAC, device type, OS type
- Health scores (overall, onboard, connect)
- Associated SSID and location

**Example queries:**

- "What's the health score for user jsmith?"
- "Show me Catalyst Center details for 10.5.6.7"

### 6. DHCP Operations (CPNR)

#### `get_dhcp_lease_info_from_cpnr`

Retrieve DHCP lease information from CPNR.

**Inputs:**

- `ip` (IPAddress): Lease IP address
- `mac` (MACAddress): Client MAC address
- *Note: Only one parameter may be specified*

**Returns:**

- List of leases with IP, hostname, MAC, scope, state
- DHCP relay info (switch, VLAN, port)
- Reservation status

**Example queries:**

- "Show DHCP lease for 10.10.10.10"
- "What switch port is MAC 11:22:33:44:55:66 connected to?"

#### `create_dhcp_reservation_in_cpnr`

Create a DHCP reservation for an existing lease.

**Inputs:**

- `ip` (IPAddress): IP address to reserve

**Returns:**

- Boolean success status

**Authorization:** No restrictions

**Example queries:**

- "Create a reservation for 10.20.30.40"
- "Reserve IP 192.168.1.100"

#### `delete_dhcp_reservation_from_cpnr`

Delete a DHCP reservation.

**Inputs:**

- `ip` (IPAddress): Reserved IP address

**Returns:**

- Boolean success status

**Authorization:** Restricted to specific email addresses (`jclarke@cisco.com`, `josterfe@cisco.com`, `anjesani@cisco.com`)

**Example queries:**

- "Delete reservation for 10.20.30.40"

### 7. DNS Lookups

#### `perform_dns_lookup`

Perform forward or reverse DNS lookups.

**Inputs:**

- `ip` (IPAddress): IP for reverse lookup (PTR)
- `hostname` (Hostname): Hostname for forward lookup (A, AAAA, CNAME)
- *Note: Only one parameter may be specified*

**Returns:**

- Query string, record type(s), list of results

**Example queries:**

- "What's the hostname for 10.1.2.3?"
- "Resolve server-01 to IP"

## Usage Examples

### Basic Queries

**NetBox lookup:**

```text
User: "What device has IP 10.100.50.25?"
Bot: Looks up the IP in NetBox and returns device details
```

**DHCP troubleshooting:**

```text
User: "Show me the DHCP lease for MAC aa:bb:cc:dd:ee:ff"
Bot: Returns lease details including connected switch and port
```

**Client troubleshooting:**

```text
User: "What's wrong with user jsmith's connection?"
Bot: Queries ISE and Catalyst Center, returns health scores and connection details
```

### Multi-Tool Queries

The agent can chain multiple tools together:

```text
User: "Find the switch port for IP 10.5.10.20"
Bot: 
1. Queries DHCP for MAC address
2. Queries DHCP lease for relay info (switch/port)
3. Returns combined results
```

```text
User: "Show me everything about user jdoe"
Bot:
1. Queries ISE for authentication details
2. Queries Catalyst Center for health scores
3. Queries DHCP for IP/lease info
4. Returns comprehensive report
```

### Conversational Context

The bot maintains conversation threads in Webex:

```text
User: "Show DHCP lease for 10.1.1.50"
Bot: [Returns lease info with MAC aa:bb:cc:dd:ee:ff]

User: "Now show me ISE details for that MAC"
Bot: [Automatically uses aa:bb:cc:dd:ee:ff from previous response]
```

## System Prompt

The agent operates under a comprehensive system prompt that:

- Restricts tool usage to explicitly available tools
- Enforces tool chaining for complete answers
- Requires Webex-compatible markdown (no tables)
- Mandates attribution of data sources
- Addresses users by name
- Uses emojis for visual clarity

## Security Features

### Webhook Validation

- HMAC-SHA1 signature verification on all incoming webhooks
- Payload structure validation
- Room ID verification

### Authorization

- Tool-level authorization using `auth_list` metadata
- Restricted operations (e.g., delete) limited to specific users
- Bot ignores its own messages to prevent loops

### TLS/SSL

- Configurable TLS verification
- Secure credential management through modules

## Logging

Structured logging with context:

- Timestamp, log level, filename, function, line number
- Process ID and thread ID
- Configurable log levels (DEBUG, INFO, WARNING, ERROR)

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
uvicorn dhcp_mcp_client:app --workers 1 --port 9999
```

## Error Handling

### Client-Side

- Webhook signature failures return 403
- Invalid payloads return 422
- Room ID mismatches return 422
- Processing errors post to Webex with traceback

### Server-Side

- ToolError exceptions for operation failures
- Detailed error messages passed back to LLM
- Graceful degradation (skip failed tools, continue with others)

### Resource Management

- Automatic cleanup via lifespan context manager
- Async context managers for HTTP clients (Sparker, httpx)
- MCP client properly closed on shutdown
- Webhook unregistration on shutdown

## Troubleshooting

### Bot Not Responding

1. Check webhook registration: Look for startup logs showing webhook ID
2. Verify callback URL is accessible from Webex
3. Check bot is in correct Webex room
4. Verify LOG_LEVEL is set appropriately

### Tool Failures

1. Check environment variables are set correctly
2. Verify network connectivity to backend systems
3. Review server logs for ToolError exceptions
4. Test with `DHCP_BOT_IS_TESTING=true` to use stubs

### MCP Connection Issues

1. Ensure `dhcp_mcp_server.py` is in the working directory
2. Verify Python environment has all dependencies
3. Check MCP server logs for initialization errors
4. Confirm stdio transport is working

### Multiple Workers Error

If you accidentally start with multiple workers:

1. Stop all uvicorn processes
2. Check for duplicate webhooks in Webex
3. Clean up any orphaned MCP server processes
4. Restart with `--workers 1`

## Development

### Adding New Tools

1. Define input/output Pydantic models in `dhcp_mcp_server.py`
2. Implement tool function with `@server_mcp.tool()` decorator
3. Add proper type hints and docstrings
4. Set appropriate annotations (readOnlyHint, destructiveHint)
5. Restart MCP server to register new tool
6. Tool automatically available to client via MCP

### Testing

Use testing mode to develop without full infrastructure:

```bash
export DHCP_BOT_IS_TESTING=true
uvicorn dhcp_mcp_client:app --workers 1 --port 9999 --reload
```

Test functions (prefixed with `test_`) return sample data.

### Local Development

1. Create `.env` file with required variables
2. Use `--reload` flag for auto-restart on code changes
3. Point callback URL to ngrok or similar tunnel
4. Monitor logs in real-time

## Production Deployment

### FreeBSD rc.d Service (Recommended)

The agent is typically deployed on FreeBSD. Create `/usr/local/etc/rc.d/network_info_agent`:

```sh
#!/bin/sh
#
# PROVIDE: network_info_agent
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="network_info_agent"
rcvar="network_info_agent_enable"

load_rc_config $name

: ${network_info_agent_enable:="NO"}
: ${network_info_agent_user:="nocuser"}
: ${network_info_agent_dir:="/opt/ciscolive/automation/services"}
: ${network_info_agent_env:="/opt/ciscolive/.env"}
: ${network_info_agent_venv:="/opt/ciscolive/venv"}
: ${network_info_agent_port:="9999"}

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-p ${pidfile} -t ${name} -u ${network_info_agent_user} \
    ${network_info_agent_venv}/bin/uvicorn dhcp_mcp_client:app \
    --host 0.0.0.0 --port ${network_info_agent_port} --workers 1"

start_precmd="${name}_prestart"

network_info_agent_prestart()
{
    if [ -f "${network_info_agent_env}" ]; then
        . ${network_info_agent_env}
        export $(cut -d= -f1 ${network_info_agent_env})
    fi
    cd ${network_info_agent_dir}
}

run_rc_command "$1"
```

Enable and start the service:

```sh
chmod +x /usr/local/etc/rc.d/network_info_agent
echo 'network_info_agent_enable="YES"' >> /etc/rc.conf
service network_info_agent start
```

### Linux Systemd Service Example

For Linux deployments, create `/etc/systemd/system/network-info-agent.service`:

```ini
[Unit]
Description=Network Info Agent
After=network.target

[Service]
Type=simple
User=nocuser
WorkingDirectory=/opt/ciscolive/automation/services
Environment="PATH=/opt/ciscolive/venv/bin"
EnvironmentFile=/opt/ciscolive/.env
ExecStart=/opt/ciscolive/venv/bin/uvicorn dhcp_mcp_client:app --host 0.0.0.0 --port 9999 --workers 1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable network-info-agent
systemctl start network-info-agent
```

### Best Practices

1. **Always use exactly 1 worker** for uvicorn
2. Run behind a reverse proxy (nginx, Apache) for TLS termination
3. Use a process manager (systemd, supervisord) for auto-restart
4. Implement proper log rotation
5. Monitor webhook health and re-register if needed
6. Keep credentials in secure environment files (not in code)
7. Regularly update dependencies for security patches

## Performance Considerations

- **Connection Pooling**: HTTP clients use connection pooling for efficiency
- **Async Operations**: All I/O operations are async (httpx, FastMCP)
- **Resource Cleanup**: Proper async context managers prevent leaks
- **LLM Timeout**: Ollama client has 240s timeout for complex queries
- **REST Timeouts**: Network APIs have configurable timeouts (default 10s)
- **DNS Timeout**: DNS queries timeout after 5s

## Support and Maintenance

### Log Locations

- Application logs: stdout/stderr (captured by systemd or process manager)
- Webex webhook delivery: Check Webex Developer Portal

### Health Checks

- FastAPI automatic docs: <http://localhost:9999/docs>
- Webhook status: Check registered webhooks in Webex API
- MCP connection: Look for startup initialization logs

### Version Information

- Copyright: 2025 Joe Clarke <jclarke@cisco.com>
- License: BSD-style license (see file headers)

---

**Note**: This documentation describes the Network Info Agent as implemented in the Cisco Live Europe NOC environment. Adapt configuration and deployment details to your specific infrastructure requirements.
