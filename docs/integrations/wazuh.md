# Wazuh

Send Sherlock events to the Wazuh manager's remote syslog listener and add a decoder and rule for them.

## Prerequisites

- Wazuh manager with a `<remote>` block of `connection` `syslog` (below). The listener accepts syslog over TCP or UDP and only from addresses in `<allowed-ips>`. **Verify against your Wazuh version** whether the syslog listener supports TLS; in the documentation we could confirm only plain TCP/UDP. If it does not, terminate TLS on a local `rsyslog` or `stunnel` that relays to the manager, and use `"network": "tls"` to that relay.

## Wazuh manager configuration

In `/var/ossec/etc/ossec.conf` (then restart the manager):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.0.2.10</allowed-ips>
  <local_ip>192.0.2.5</local_ip>
</remote>
```

`allowed-ips` is the Sherlock node (more than one line allowed). To see what arrives while you test, enable archives (`<logall_json>yes</logall_json>`) temporarily.

## Sherlock settings

TCP, newline framing (Wazuh reads one syslog message per line), JSON payload:

<!-- validate:syslog -->

```json
{
  "network": "tcp",
  "address": "wazuh-manager.example.internal:514",
  "format": "json",
  "framing": "newline",
  "app_name": "sherlock"
}
```

CEF payload instead:

<!-- validate:syslog -->

```json
{
  "network": "tcp",
  "address": "wazuh-manager.example.internal:514",
  "format": "cef",
  "framing": "newline"
}
```

## Decoder and rules

Put these in `/var/ossec/etc/decoders/local_decoder.xml` and `/var/ossec/etc/rules/local_rules.xml`. They are **illustrative**: Wazuh's decoder syntax and the layout of the pre-decoded syslog header differ between versions, so always test with `/var/ossec/bin/wazuh-logtest` using a real line from the archives, and adjust.

```xml
<!-- local_decoder.xml -->
<decoder name="sherlock">
  <prematch>CEF:0\|Sherlock\|Sherlock WAF\|</prematch>
</decoder>
```

```xml
<!-- local_rules.xml -->
<group name="sherlock,waf,">
  <rule id="100100" level="5">
    <decoded_as>sherlock</decoded_as>
    <description>Sherlock WAF event</description>
  </rule>
  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <match>act=block</match>
    <description>Sherlock WAF blocked a request</description>
  </rule>
</group>
```

A decoder alone creates no alerts; the rule does. For the JSON format, prefer Wazuh's JSON decoder after a prematch on the `sherlock` program name, then write rules on the decoded fields (**verify against your version**).

## Verify

1. **Test** button in Sherlock; in Wazuh `grep "connectivity test" /var/ossec/logs/archives/archives.json`.
2. Run `wazuh-logtest`, paste a CEF line copied from the archives, and confirm the decoder and rule `100100` match.
3. Trigger a blocked request; rule `100101` should alert.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Nothing arrives | `allowed-ips`, the manager restarted, port reachable (`tcpdump -i any port 514`) |
| Arrives but no alert | decoder prematch does not match the line; run `wazuh-logtest` |
| Messages merged or cut | framing: use `newline` |
| `sherlock_exporter_send_failures_total` rising | manager listener down, firewall, wrong protocol (tcp vs udp) |
| Events rejected as duplicates | not applicable: Wazuh does not deduplicate; use `cs2` (event id) in your own correlation |

## Security notes

The syslog listener is unauthenticated: allow only Sherlock's address. Use a TLS relay across untrusted networks.
