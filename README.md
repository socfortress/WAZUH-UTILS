# Customer-Provisioning-Worker

Copilot Customer Provisioning Worker that runs on the Wazuh Worker node. This application deploys a Wazuh Worker node via a docker container for the provided customer.

## Virtual Python Environment

```
python3 -m venv wazuh_utils_env
```

```
source wazuh_utils_env/bin/activate
```

```
pip install -r requirements.in
```

## Run as Service

Create a service and run the script as a service:

```
nano /etc/systemd/system/socfortress-wazuh-utils.service
```

```
[Unit]
Description=SocFortress Wazuh Utils

[Service]
WorkingDirectory=/opt/WAZUH-UTILS
ExecStart=/opt/wazuh_utils_env/bin/uvicorn wazuh_utils:app --host *SERVER_IP* --port 5003 --workers 2 --timeout-keep-alive 60
Restart=always
User=root
Group=root
Environment=VIRTUAL_ENV=/opt/wazuh_utils_env
Environment=PATH=/opt/wazuh_utils_env/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
```

```
systemctl start socfortress-wazuh-utils.service
```
