# WAZUH-UTILS

A small sidecar API on the **Wazuh master**. It places files that the Wazuh API cannot upload into an agent group's shared folder (`/var/ossec/etc/shared/<group>/`). CoPilot calls it. The master's cluster sync then copies those files to the workers, and from there to the agents.

| Route                                  | What it writes                                                                              | Auth                                                                              |
| -------------------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `POST /provision_worker/sysmon-config` | `Windows_<customer_code>/sysmon_config.xml` (must be `<Sysmon>` XML, max 5 MB)              | Required once a key is configured (open without one, for backwards compatibility) |
| `POST /provision_worker/shared-files`  | Only `sysmon_watchdog.ps1` / `sysmon_config_reload.ps1`, into an existing `Windows_*` group | **Always** required; disabled when no key is configured                           |

`/shared-files` places scripts that Windows agents run **as SYSTEM** through a command wodle in the group's `agent.conf`. Treat the API key like a domain admin credential. The route accepts:

-   only the two allow-listed file names;
-   only for an existing `Windows_*` group;
-   each file with its sha256, sent as a separate form field and checked before anything is written;
-   optionally only hashes from a pinned allow-list (`WAZUH_UTILS_ALLOWED_SHA256`). With the allow-list set, a stolen key still cannot place arbitrary code.

Every write goes through file descriptors (directory opened with `O_NOFOLLOW`, temp file created `O_EXCL|O_NOFOLLOW`, `fchmod`/`fchown`, rename within the directory). A symlink planted in the group folder can therefore never redirect it, and Wazuh never sees a half-written file. Files end up `wazuh:wazuh 0660`. Unauthenticated or oversized requests are refused from their headers, before any body is read. The service never creates group directories: the group must already exist on the manager.

## Configuration

| Variable                     | Meaning                                                                                                                       |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `WAZUH_UTILS_API_KEY_FILE`   | Path to a root-only file holding the bearer token (preferred).                                                                |
| `WAZUH_UTILS_API_KEY`        | The token itself (alternative to the file).                                                                                   |
| `WAZUH_UTILS_ALLOWED_SHA256` | Optional allow-list for `/shared-files`: comma-separated `name:sha256` (bound to that file name, preferred) or bare `sha256`. |
| `WAZUH_UTILS_SHARED_DIR`     | Shared groups directory. Default `/var/ossec/etc/shared`.                                                                     |

A key file that is configured but unreadable makes every route refuse with 503. It never silently falls back to "no key".

CoPilot needs the same key and the sidecar's https URL in its `.env`: `WAZUH_UTILS_API_KEY`, `WAZUH_UTILS_URL=https://<master>:5003`, and, for a self-signed certificate, `WAZUH_UTILS_CA_BUNDLE`.

## Install / upgrade on a master

Requires CoPilot with the Sysmon-health change (socfortress/CoPilot#1343) or later. That version sends the key, uses `WAZUH_UTILS_URL`, and pins the sidecar certificate.

```bash
cd /opt/socfortress/integrations/WAZUH-UTILS && git pull
/opt/socfortress/integrations/wazuh_utils_venv/bin/pip install -r requirements.in
install -d -m 750 -o root -g wazuh /etc/socfortress

# 1. API key: one per master, created once (re-running keeps it). Give the same
#    value to CoPilot as WAZUH_UTILS_API_KEY.
[ -s /etc/socfortress/wazuh-utils.key ] || ( umask 077; openssl rand -hex 32 > /etc/socfortress/wazuh-utils.key )

# 2. TLS certificate whose subjectAltName is the address CoPilot uses in
#    WAZUH_UTILS_URL. (The Wazuh API's own certificate does not carry that name,
#    so CoPilot could not verify it.) Self-signed: copy wazuh-utils.crt to the
#    CoPilot host and point WAZUH_UTILS_CA_BUNDLE at it.
MASTER_IP=<address CoPilot connects to>
[ -s /etc/socfortress/wazuh-utils.crt ] || openssl req -x509 -newkey rsa:3072 -sha256 -days 1825 -nodes \
  -subj "/CN=wazuh-utils" -addext "subjectAltName=IP:${MASTER_IP}" \
  -keyout /etc/socfortress/wazuh-utils-tls.key -out /etc/socfortress/wazuh-utils.crt
chown root:wazuh /etc/socfortress/wazuh-utils-tls.key /etc/socfortress/wazuh-utils.crt
chmod 640 /etc/socfortress/wazuh-utils-tls.key
```

Use `DNS:<name>` instead of `IP:` if CoPilot reaches the master by host name.

`/etc/systemd/system/socfortress-wazuh-utils.service`. The service runs as **wazuh**, not root. The group folders are wazuh-writable, so nothing else is needed. The API key arrives through systemd's credential mechanism, so it never sits in the environment.

```ini
[Unit]
Description=SocFortress Wazuh Utils

[Service]
WorkingDirectory=/opt/socfortress/integrations/WAZUH-UTILS
ExecStart=/opt/socfortress/integrations/wazuh_utils_venv/bin/uvicorn app:app --host <SERVER_IP> --port 5003 --workers 2 --timeout-keep-alive 60 --limit-concurrency 32 --ssl-certfile /etc/socfortress/wazuh-utils.crt --ssl-keyfile /etc/socfortress/wazuh-utils-tls.key
Restart=always
User=wazuh
Group=wazuh
LoadCredential=api-key:/etc/socfortress/wazuh-utils.key
Environment=WAZUH_UTILS_API_KEY_FILE=%d/api-key
Environment=VIRTUAL_ENV=/opt/socfortress/integrations/wazuh_utils_venv
Environment=PATH=/opt/socfortress/integrations/wazuh_utils_venv/bin:/usr/local/bin:/usr/bin:/bin
# Optional: pin the exact scripts CoPilot ships, bound to their names (sha256 values
# from CoPilot's backend/app/active_response/assets/sysmon_health/manifest.json).
# Environment=WAZUH_UTILS_ALLOWED_SHA256=sysmon_watchdog.ps1:<sha256>,sysmon_config_reload.ps1:<sha256>
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/ossec/etc/shared /opt/socfortress/integrations/WAZUH-UTILS

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl restart socfortress-wazuh-utils.service
```

Also restrict port 5003 at the firewall to the CoPilot host.

**Upgrade order.** Once the key and https are on, CoPilot builds older than #1343 can no longer deploy Sysmon configs:

-   without the key they get 401;
-   over plain http they get a dropped connection.

1. Update CoPilot and set `WAZUH_UTILS_URL=https://<MASTER_IP>:5003`, `WAZUH_UTILS_API_KEY` and `WAZUH_UTILS_CA_BUNDLE`. CoPilot cannot reach the sidecar from this step until step 2 is done: it refuses to send the key over http, and the old sidecar does not speak https. Do the two steps back to back.
2. Restart this service with the new unit.

**Behaviour change.** `/sysmon-config` no longer creates a missing `Windows_<code>` folder; it answers 404. The folder exists for every group the manager knows, so a 404 means the code does not match a group. Previously the file silently went to a folder no agent read.

## Development

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.in -r requirements-dev.in
python -m pytest            # tests/ use a temporary shared dir, no Wazuh needed
pre-commit run --all-files
```
