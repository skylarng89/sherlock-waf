# Microsoft Sentinel

Send CEF over syslog to a Linux log forwarder that runs the Azure Monitor Agent (AMA). The **Common Event Format (CEF) via AMA** connector writes the messages to the `CommonSecurityLog` table in your Log Analytics workspace. The older CEF connector that used the Log Analytics agent is deprecated; use the AMA connector.

Source: [Ingest syslog and CEF messages to Microsoft Sentinel with the Azure Monitor Agent](https://learn.microsoft.com/azure/sentinel/connect-cef-syslog).

## Prerequisites

- A Sentinel workspace and the **Common Event Format** solution installed from the Content hub (it provides the connector).
- A Linux log forwarder VM (Azure VM, or Azure Arc-connected machine) with Python 2.7 or 3 and `rsyslog` or `syslog-ng`, and the Azure Monitor Agent installed.
- Azure roles to create a data collection rule (DCR): Monitoring Contributor, plus the VM roles the connector page lists.
- Network path from the Sherlock node to the forwarder on port 514 (the installer script opens UDP and TCP 514; the AMA then reads from the local daemon on port 28330).

## Set up the connector

1. Sentinel → Configuration → Data connectors → **Common Event Format (CEF) via AMA** → Open connector page → **+ Create data collection rule**.
2. Pick the log forwarder as the resource.
3. Collect tab: choose facility **local0** (Sherlock's default facility is 16 = `local0`; change `facility` in Sherlock if you want another) and a minimum log level of **Info**. Sherlock maps finding severity to syslog severity as critical=2, error=3, warning=4, notice=5, info=6, so a threshold above Info drops lower-severity events. Audit records use severity 6, and 4 for actions containing `failed` or `denied`.
4. Do not select the same facility for a Syslog-stream rule on the same forwarder, or Microsoft warns of duplicate ingestion into `Syslog` and `CommonSecurityLog`.
5. Run the installation script from the connector page on the forwarder (it configures the syslog daemon).

DCR stream for CEF is `Microsoft-CommonSecurityLog`; the DCR data source looks like:

```json
"dataSources": {
  "syslog": [
    {
      "name": "SherlockCEF",
      "streams": ["Microsoft-CommonSecurityLog"],
      "facilityNames": ["local0"],
      "logLevels": ["Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
    }
  ]
}
```

## Sherlock settings

Inside a private network, TCP to the forwarder:

<!-- validate:syslog -->

```json
{
  "network": "tcp",
  "address": "cef-forwarder.example.internal:514",
  "format": "cef",
  "facility": 16,
  "app_name": "sherlock"
}
```

Across an untrusted network, configure `rsyslog` or `syslog-ng` on the forwarder for TLS first (Microsoft's guide links the procedures), then:

<!-- validate:syslog -->

```json
{
  "network": "tls",
  "address": "cef-forwarder.example.internal:6514",
  "format": "cef",
  "tls": { "server_name": "cef-forwarder.example.internal" }
}
```

Stream `events` for detections; add an exporter with stream `audit` for administrator activity. Audit CEF records have signature id `audit.<action>` so they are easy to separate.

Sherlock sends RFC 5424 messages (`<134>1 <time> <host> sherlock - event - CEF:0|Sherlock|...`). Microsoft's examples use RFC 3164 style messages; **verify against your AMA and daemon version** that the CEF body is extracted from the RFC 5424 line (check with the test below and the troubleshooting guide linked on the Microsoft page).

## Verify

1. Sherlock **Test** button, then wait; logs can take up to 20 minutes to appear.
2. Query:

```kusto
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "Sherlock" and DeviceProduct == "Sherlock WAF"
| project TimeGenerated, DeviceEventClassID, Activity, LogSeverity, SourceIP, RequestMethod, RequestURL, DeviceAction
```

3. On the forwarder: `sudo tcpdump -i any port 514 or 28330 -A -vv` shows arriving messages; `sudo systemctl status azuremonitoragent.service rsyslog.service`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Nothing in `CommonSecurityLog` | DCR facility/level matches Sherlock's `facility` and severities; DCR associated with the forwarder; Microsoft's CEF/syslog AMA troubleshooting page |
| Rows in `Syslog` instead | CEF body not recognised: confirm the message contains `CEF:0|`; keep Syslog and CEF DCRs on different facilities |
| Missing low-severity events | DCR log level is above Info |
| `sherlock_exporter_send_failures_total` rising | forwarder unreachable or TCP 514 closed; firewall; daemon not listening (`netstat -lnptv`) |
| Duplicates | expected after retries; deduplicate on `AdditionalExtensions` / `cs2` (event id) |

The CEF `cs1`/`cs2`/`cn1` labelled fields appear in `DeviceCustomString1`/`2` and `DeviceCustomNumber1` with their labels in `DeviceCustomString1Label` and so on; **verify against your schema version**.

## Security notes

Restrict the forwarder's port 514 to the Sherlock node. Use TLS between Sherlock and the forwarder when they are not on the same trusted segment. Sherlock's audit records carry actor ids and IPs: limit workbook access accordingly.
