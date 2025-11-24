# Active Directory User Management Utilities

## Overview

This directory contains utilities for managing Active Directory (AD) users for Cisco Live Europe events. The tools integrate with Webex Teams to extract user information and provide a web-based password reset interface.

**⚠️ IMPORTANT: These scripts must run on CL-JUMP-1 (Windows host) with direct AD access. They cannot be run on Linux due to dependencies on `pyad` and `pywin32` libraries.**

## Scripts

### 1. `create_users.py` - Automated AD User Provisioning

Automatically creates Active Directory user accounts from Webex Team membership with proper configuration, group membership, and password policies.

**🔑 KEY SCRIPT: This is the most critical provisioning script and should be run once on CL-JUMP-1 ahead of the event to create all NOC user accounts.**

#### Script Purpose

Synchronizes Cisco employees in a Webex Team to Active Directory by automatically creating user accounts with appropriate attributes, group assignments, and security settings. This eliminates manual provisioning and ensures consistent account configuration.

#### Provisioning Requirements

**Python Dependencies:**

- `pyad` - Python Active Directory library
- `sparker` - Webex Teams API wrapper
- `CLEUCreds` - Credentials module
- `cleu.config` - Configuration module

**System Requirements:**

- **CL-JUMP-1 (Windows Server)** - Must run on this specific Windows host with AD domain membership
- **Network Access** - Direct connectivity to Active Directory Domain Controller
- **AD Permissions** - Account must have rights to create users and modify group membership
- **Cannot run on Linux** - Requires Windows-only libraries (`pyad`, `pywin32`)

#### Script Configuration

**Environment Variables (via CLEUCreds and Config):**

- `CLEUCreds.SPARK_TOKEN` - Webex bot authentication token
- `CLEUCreds.DEFAULT_USER_PASSWORD` - Default password assigned to new accounts
- `C.WEBEX_TEAM` - Webex Team ID to synchronize from
- `C.AD_DN_BASE` - LDAP base DN (e.g., "OU=NOC Users,DC=ad,DC=cleur,DC=network")
- `C.DNS_DOMAIN` - Internal DNS domain (e.g., "cleur.network")
- `C.AD_DOMAIN` - Active Directory domain (e.g., "ad.cleur.network")

**Default Settings:**

```python
DEFAULT_GROUP = "CL NOC Users"  # Group assigned to all new users
```

#### Script Usage

**Basic Execution:**

```powershell
python create_users.py
```

**With Output Logging:**

```powershell
python create_users.py > created_users.log 2> errors.log
```

**Scheduled Provisioning (Windows Task Scheduler):**

```powershell
schtasks /create /tn "AD User Provisioning" /tr "C:\Python39\python.exe C:\scripts\AD\create_users.py" /sc daily /st 06:00 /ru SYSTEM
```

#### Execution Process Flow

1. **Retrieve Webex Team Members**
   - Authenticates to Webex using bot token
   - Fetches all members from configured team

2. **Connect to Active Directory**
   - Establishes connection to AD
   - Navigates to base DN organizational unit

3. **Process Each Member**
   - Filters for Cisco email addresses (`@cisco.com`)
   - Extracts username and full name
   - Checks if user already exists in AD

4. **User Creation** (if not exists)
   - Creates new AD user with full name as CN
   - Sets default password
   - Configures user attributes
   - Applies password policies
   - Adds to default group
   - Pauses 1 second for AD replication

5. **User Update** (if exists)
   - Updates `otherMailbox` attribute only
   - Skips other modifications

#### User Attributes Set

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `cn` | Full Name | Common Name (FirstName LastName) |
| `sAMAccountName` | Username | Windows logon name |
| `userPrincipalName` | `username@AD_DOMAIN` | Modern authentication format |
| `mail` | Webex email | External email address |
| `otherMailbox` | `username@DNS_DOMAIN` | Internal email address |
| `password` | Default password | From `CLEUCreds.DEFAULT_USER_PASSWORD` |

#### Password Policies Applied

- **Force password change on login**: Enabled
- **Password not required**: Disabled (enforces password requirement)
- **Account status**: Enabled by default

#### Output Examples

**Successful Creation:**

```text
Added user jsmith
Added user mjones
Added user bwilson
```

**Skipping Existing Users:**

```text
Not creating jdoe (John Doe) as they already exist.
Not creating agarcia (Alice Garcia) as they already exist.
```

**Error Scenarios:**

```text
Failed to create user tking: ('Unable to create user', 'A constraint violation occurred.')
Error adding user mlee (maybe duplicate?)
Error setting password policy for user rjones: Access denied
Unable to get members from Webex Teams.
Make sure the bot is part of the Webex team.
```

#### Script Error Handling

**Duplicate Detection:**

- Checks if user exists before creation
- Updates `otherMailbox` attribute if user already exists
- Prevents duplicate account errors

**Constraint Violations:**

- Catches AD constraint errors (e.g., duplicate sAMAccountName)
- Attempts to delete partially created user
- Logs error and continues with remaining users

**Permission Errors:**

- Logs access denied errors for password policy changes
- Continues processing other users
- Provides detailed traceback for debugging

**API Failures:**

- Detects Webex API connection issues
- Provides guidance on bot membership requirements
- Exits gracefully with error message

#### Rate Limiting

The script includes a 1-second delay between user creations:

```python
time.sleep(1)  # Allow AD replication between operations
```

This prevents:

- Overwhelming the Domain Controller
- Replication conflicts
- Temporary lockouts from rapid operations

#### Security Considerations

**Permissions:**

- Run with a service account that has minimal required privileges
- Grant only "Create user objects" and "Modify group membership" rights
- Avoid using Domain Admin credentials

**Password Management:**

- Store `DEFAULT_USER_PASSWORD` securely in `CLEUCreds` module
- Rotate default password regularly
- Users must change password on first login (enforced by script)

**Audit Trail:**

- Redirect output to log files for compliance
- Monitor stderr for errors and security events
- Review AD audit logs for account creation events

**Access Control:**

- Restrict script execution to authorized administrators
- Protect `CLEUCreds.py` file with appropriate permissions
- Use Windows Task Scheduler with specific service account

#### Troubleshooting

**Bot Not in Team:**

```text
Unable to get members from Webex Teams.
Make sure the bot is part of the Webex team.
```

**Solution:** Add the Webex bot to the target team.

**Duplicate User Errors:**

```text
Error adding user jsmith (maybe duplicate?)
```

**Solution:** User with same sAMAccountName or userPrincipalName already exists. Check AD for conflicts.

**Permission Denied:**

```text
Error setting password policy for user mjones: Access denied
```

**Solution:** Ensure running account has rights to modify user password policies.

**Connection Failures:**

Check:

- Network connectivity to Domain Controller
- DNS resolution for AD domain
- Firewall rules for LDAP/LDAPS ports (389/636)

#### Best Practices

**Operational:**

- Run during maintenance windows for initial bulk provisioning
- Schedule daily runs for incremental updates
- Monitor logs for failures and take corrective action
- Verify AD replication after large batch operations

**Integration:**

- Use with `reset_password.py` for user self-service
- Integrate with monitoring to alert on failures

**Testing:**

- Test with a small test team before production runs
- Verify all attributes are set correctly
- Check group membership assignments
- Test password policy enforcement

**Maintenance:**

- Review and update `DEFAULT_GROUP` as needed
- Keep dependencies updated
- Audit created accounts against authorized roster
- Clean up test accounts after validation

---

### 2. `reset_password.py` - Web-Based Password Reset Portal

A Flask web application that provides a self-service password reset interface for Active Directory users.

**🌐 PRODUCTION SERVICE: This web application is hosted on CL-JUMP-1 and runs continuously throughout the event to provide self-service password resets.**

#### Portal Purpose

Allows event attendees and NOC staff to reset their AD passwords through a secure web interface. Supports first-time password changes and includes special handling for VPN users.

#### Portal Requirements

**Python Dependencies:**

- `Flask` - Web framework
- `pyad` - Python Active Directory library
- `pythoncom` - Python COM interface
- `pywin32` - Windows-specific Python extensions
- `CLEUCreds` - Credentials module
- `cleu.config` - Configuration module

**System Requirements:**

- **CL-JUMP-1 (Windows Server)** - Must run on this specific Windows host with AD domain membership
- **SSL Certificates** - Let's Encrypt wildcard certificates (`chain.pem` and `privkey.pem`) provided ahead of the event
- **Network Access** - Access to Active Directory Domain Controller
- **Syslog Server** - For audit logging (optional)
- **Cannot run on Linux** - Requires Windows-only libraries (`pyad`, `pywin32`, `pythoncom`)

#### Portal Configuration

**Environment Variables (via CLEUCreds and Config):**

- `CLEUCreds.SPARK_TOKEN` - Not used by this script
- `CLEUCreds.AD_ADMIN` - AD administrator username for password operations
- `CLEUCreds.AD_PASSWORD` - AD administrator password
- `CLEUCreds.DEFAULT_USER_PASSWORD` - Default password for first-time users
- `CLEUCreds.CALLBACK_TOKEN` - Not used by this script
- `C.AD_DOMAIN` - Active Directory domain (e.g., "ad.cleur.network")
- `C.AD_DN_BASE` - LDAP base DN (e.g., "OU=Users,DC=ad,DC=cleur,DC=network")
- `C.VPN_USER` - Special VPN account that cannot use the portal
- `C.TOOL` - Syslog server hostname for audit logs

**Application Settings:**

```python
AD_DC = "dc1-ad." + C.AD_DOMAIN  # Domain Controller hostname
HOST = "10.100.252.25"            # Web server bind address (internal)
PORT = 8443                       # HTTPS port
```

**Production URL:** `https://cl-jump-01.cleur.network:8443`

#### Installation

1. **Install Python dependencies:**

   ```powershell
   pip install -r requirements.txt
   ```

2. **Configure SSL certificates:**

   Place Let's Encrypt wildcard certificates in the script directory:
   - `chain.pem` - SSL certificate chain (provided ahead of event)
   - `privkey.pem` - Private key (provided ahead of event)

3. **Set up credentials modules:**

   Ensure `CLEUCreds.py` and `cleu/config.py` are properly configured.

4. **Verify AD connectivity:**

   Test connection to Domain Controller from the server.

#### Portal Usage

**Starting the Server:**

```powershell
# Start the password reset web server
python reset_password.py
```

The server will start on `https://10.100.252.25:8443` (internal) and is accessible at `https://cl-jump-01.cleur.network:8443`

**Accessing the Portal:**

1. Navigate to `https://cl-jump-01.cleur.network:8443/` in a web browser
2. Authenticate with AD credentials (HTTP Basic Auth)
3. Fill out the password reset form
4. Submit to change password

**VPN User Mode:**

For users connected via VPN, append query parameter:

```text
https://cl-jump-01.cleur.network:8443/?vpnuser=true
```

This provides special instructions to reconnect VPN after password change.

#### Features

##### 1. HTTP Basic Authentication

- Users authenticate with current AD credentials
- Username format: `username` or `username@domain`
- VPN user account (`C.VPN_USER`) is blocked from access

##### 2. First-Time Login Detection

Automatically detects first-time users (new accounts with default password):

- Checks `pwdLastSet` attribute
- If `highpart=0` and `lowpart=0`, user has never set password
- Allows login with default password on first use

##### 3. Password Complexity Validation

Enforced by Active Directory policy:

- Typically requires: uppercase, lowercase, number, special character
- Minimum length (usually 8+ characters)
- Cannot reuse recent passwords

##### 4. Barcode Label Printing

For first-time users:

- Sends syslog message to printing system
- Format: `PRINT-LABEL: requesting to print label for userid <username>`
- Instructs user to visit Dave Shen for physical label

##### 5. Session Management

- Server-side sessions track authentication state
- Stores user DN (Distinguished Name) and username
- Session cleared on logout or after password reset
- Auto-logout after 60 seconds (for security)

##### 6. Audit Logging

Logs password reset events via syslog:

- Facility: `LOG_LOCAL7` (23)
- Severity: `LOG_NOTICE` (5)
- Destination: Configurable syslog server

#### API Endpoints

##### `GET /`

**Description:** Display password reset form

**Authentication:** Required (HTTP Basic Auth with AD credentials)

**Response:** HTML form for password reset

**Query Parameters:**

- `vpnuser` (optional) - Set to "true" for VPN users

##### `POST /reset-password`

**Description:** Process password reset request

**Authentication:** Required

**Form Parameters:**

- `new_pass` (required) - New password
- `new_pass_confirm` (required) - Password confirmation
- `vpnuser` (optional) - "true" if VPN user

**Responses:**

- **200 OK** - Password changed successfully
- **401 Unauthorized** - Authentication failed
- **500 Error** - Password change failed (HTML error message)

**Validation:**

- Both fields must be non-empty
- Passwords must match
- Must meet AD complexity requirements

##### `GET /logout`

**Description:** Clear session and log out

**Authentication:** Not required

**Response:** Redirect to `/` (302)

#### Security Features

1. **HTTPS Only** - All traffic encrypted with SSL/TLS
2. **HTTP Basic Auth** - Standard authentication mechanism
3. **Session Security** - Server-side session management with Flask
4. **Credential Validation** - All AD operations validated through AD itself
5. **Privileged Operations** - Password changes use dedicated admin account
6. **Audit Trail** - All password resets logged via syslog
7. **Auto-Logout** - Automatic session timeout after success
8. **VPN User Protection** - Special VPN account cannot reset password

#### Portal Process Flow

1. **User visits portal** → HTTP Basic Auth challenge
2. **User enters AD credentials** → Backend validates against AD
3. **First-time detection:**
   - Query AD for user's `pwdLastSet` attribute
   - If never set, allow login with default password
4. **Display form** → User enters new password (twice)
5. **Submit form:**
   - Validate passwords match and are non-empty
   - Connect to AD as administrator
   - Call `aduser.set_password(new_pw)`
   - Grant password lease
6. **Success actions:**
   - If first-time: Send syslog for label printing
   - If VPN user: Display VPN reconnection instructions
   - Clear session
   - Auto-logout after 60 seconds

#### Error Messages

**Empty Password:**

```html
<p>You must specify a new password.</p>
```

**Password Mismatch:**

```html
<p>Passwords did not match</p>
```

**AD Error:**

```html
<h1>Password Reset Failed!</h1>
<p>[Detailed error from AD]</p>
```

**Common AD Errors:**

- Password does not meet complexity requirements
- Password has been used recently
- Account locked or disabled
- Network connectivity issue to Domain Controller

#### Customization

**Change Bind Address/Port:**

```python
app.run(host="<ip-address>", port=<port>, threaded=True, ssl_context=("chain.pem", "privkey.pem"))
```

**Modify Auto-Logout Timeout:**

Change the JavaScript timeout (in milliseconds):

```html
<script>setTimeout(function() { window.location = '/logout'; }, 60000);</script>
```

**Custom Success Message:**

Edit the HTML response in the `reset_password()` function.

#### Deployment

**Windows Service Deployment:**

1. Use `nssm` (Non-Sucking Service Manager) or similar:

   ```powershell
   nssm install CLPasswordReset "C:\Python39\python.exe" "C:\path\to\reset_password.py"
   nssm set CLPasswordReset AppDirectory "C:\path\to\AD"
   nssm start CLPasswordReset
   ```

2. Or use Task Scheduler to run at startup

**IIS Deployment (Alternative):**

Configure IIS with FastCGI and wfastcgi for Flask app hosting.

**Reverse Proxy (Recommended):**

Run behind nginx or Apache for:

- SSL termination
- Load balancing
- Better logging
- URL rewriting

Example nginx config:

```nginx
server {
    listen 443 ssl;
    server_name cl-jump-01.cleur.network;

    ssl_certificate /path/to/chain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass https://10.100.252.25:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Portal Troubleshooting

##### Issue: "Failed to verify credentials"

- Check AD_DC hostname resolves correctly
- Verify AD_DN_BASE is correct
- Ensure user exists in specified OU
- Check network connectivity to Domain Controller

##### Issue: "Password Reset Failed"

- Verify AD admin credentials are correct
- Check user account is not locked or disabled
- Ensure password meets complexity requirements
- Review AD security event logs

##### Issue: First-time users cannot log in

- Verify `CLEUCreds.DEFAULT_USER_PASSWORD` matches the actual default password
- Check user account was created with password set to "must change at next logon"
- Verify `pwdLastSet` attribute is properly zeroed

##### Issue: SSL/TLS errors

- Verify Let's Encrypt wildcard certificates (`chain.pem` and `privkey.pem`) exist in script directory
- Check certificates are not expired (Let's Encrypt certs valid for 90 days)
- Ensure private key matches certificate

##### Issue: pythoncom errors

- Run `pythoncom.CoInitialize()` at start of AD operations
- May need to run in STA (Single-Threaded Apartment) mode
- Check pywin32 is properly installed for Windows

#### Monitoring

**Key Metrics:**

- Number of password resets per day
- Failed authentication attempts
- First-time user activations
- Error rate

**Logging:**

Check application logs for:

- Authentication failures
- Password reset operations
- AD connectivity issues
- Exception tracebacks

**Syslog Monitoring:**

Monitor syslog for:

- `PRINT-LABEL` messages for first-time users
- Password reset audit events

## Overall Security Considerations

### create_users.py

1. **Webex Token Security:**
   - Store `SPARK_TOKEN` securely in credentials module
   - Use read-only bot token if possible
   - Rotate tokens periodically

2. **Data Privacy:**
   - Only extracts public Webex display names and email addresses
   - No sensitive personal information exposed
   - Consider GDPR compliance for employee data

### reset_password.py

1. **Administrative Credentials:**
   - Use dedicated service account for `AD_ADMIN`
   - Grant minimum required AD permissions
   - Store credentials in secure module, not in code
   - Rotate passwords regularly

2. **HTTPS Only:**
   - Never run over HTTP (plain text)
   - Use valid SSL certificates from trusted CA
   - Enable HSTS (HTTP Strict Transport Security)
   - Disable weak cipher suites

3. **Session Security:**
   - Flask secret key must be strong and random
   - Currently uses `CLEUCreds.AD_PASSWORD` - consider separate secret
   - Store sessions server-side only
   - Implement session timeout

4. **Rate Limiting:**
   - Consider adding rate limiting to prevent brute force
   - Implement CAPTCHA for repeated failures
   - Lock accounts after multiple failed attempts

5. **Audit Trail:**
   - All password changes logged via syslog
   - Centralize logs to SIEM system
   - Monitor for suspicious patterns
   - Retain logs per compliance requirements

6. **Network Security:**
   - Run on internal network only (not Internet-facing)
   - Firewall to specific IP ranges
   - VPN required for remote access
   - Consider multi-factor authentication

## Integration with Other Tools

### reset_password.py Integration

**Integration Points:**

1. **Barcode Printing System:**
   - Listens for syslog messages with "PRINT-LABEL"
   - Automatically prints user labels
   - Requires configured syslog server

2. **VPN Portal:**
   - Link to password reset from VPN login page
   - Use `?vpnuser=true` parameter
   - Provides reconnection instructions

3. **SIEM/Logging:**
   - Forward syslog to central logging
   - Correlate with AD security logs
   - Alert on anomalous patterns

4. **Help Desk Integration:**
   - Link from internal help desk portal
   - Reduce password reset tickets
   - Self-service reduces support burden

## Common Workflows

### New Event Setup

1. **Create Webex Team** for the event
2. **Add bot** to the Webex Team
3. **Add users** to the Webex Team
4. **Run create_users.py** on CL-JUMP-1 to provision AD accounts
5. **Verify account creation** in Active Directory
6. **Deploy reset_password.py** on CL-JUMP-1 (if not already running)
7. **Communicate portal URL** to users

### User Onboarding

1. **User receives default credentials** (email, badge, etc.)
2. **User connects to network** (WiFi or VPN)
3. **User accesses password reset portal**
4. **User authenticates** with default password
5. **User sets new password**
6. **First-time users get barcode label** from Dave Shen
7. **User can now access all systems**

### Troubleshooting User Issues

1. **Check Webex Team membership** if user not in CSV
2. **Verify AD account exists** in correct OU
3. **Check account not locked** in AD
4. **Review syslog** for error messages
5. **Test portal access** from user's network
6. **Verify SSL certificate validity**
7. **Check AD connectivity** from web server

## Maintenance

### Regular Tasks

**Weekly:**

- Monitor syslog for errors
- Check SSL certificate expiry
- Review failed authentication logs

**Per Event:**

- Update Webex Team membership
- Regenerate user CSV
- Clean up old AD accounts
- Rotate default password

**Annually:**

- Update Python dependencies
- Renew SSL certificates
- Review security configurations
- Test disaster recovery procedures

### Backup and Recovery

**Configuration Backup:**

- `CLEUCreds.py` module
- `cleu/config.py` settings
- SSL certificates (encrypted)
- Application scripts

**Recovery Procedure:**

1. Restore scripts and configuration files
2. Install Python dependencies
3. Verify AD connectivity
4. Test with non-production account
5. Enable production access

## Appendix

### Required Modules

**CLEUCreds Module:**

Must provide:

- `SPARK_TOKEN` - Webex bot token
- `AD_ADMIN` - AD administrator username
- `AD_PASSWORD` - AD administrator password
- `DEFAULT_USER_PASSWORD` - Default password for new users

**cleu.config Module:**

Must provide:

- `WEBEX_TEAM` - Webex Team name
- `AD_DOMAIN` - AD domain (e.g., "ad.cleur.network")
- `AD_DN_BASE` - LDAP base DN
- `VPN_USER` - VPN service account username
- `TOOL` - Syslog server hostname

### Dependencies Reference

See `requirements.txt` for Python package versions.

**Key Dependencies:**

- Flask 1.1.1 (Web framework)
- pyad 0.6.0 (AD integration)
- pywin32 227 (Windows COM)
- requests 2.22.0 (HTTP client)

**Security Note:** These versions are from 2019. Consider updating to latest stable versions and testing thoroughly.

### Related Documentation

- [Sparker Library](../spark/README.md) - Webex API wrapper documentation
- [Network Info Agent](../NETWORK_INFO_AGENT_DOCUMENTATION.md) - Related automation
- Active Directory Administration Guides
- Windows Server Security Best Practices

---

**Version:** 1.0  
**Last Updated:** November 24, 2025  
**Maintainer:** Joe Clarke <jclarke@cisco.com>  
**License:** BSD-style (see file headers)
