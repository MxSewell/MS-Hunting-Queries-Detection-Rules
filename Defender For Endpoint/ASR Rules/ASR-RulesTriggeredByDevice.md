# Detect the amount of ASR events that have been triggered for each device 

## Query Information

#### Description
This query gives an overview of the amount of ASR triggers for each device. A high amount of triggers can indicate that suspicious activities are performed on a device. Both audited and blocked events are listed. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

## Defender XDR
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
#### If you want to return raw events for a specific device
DeviceEvents
| where ActionType startswith "Asr"
| where DeviceName == "CONTOSO-LAPTOP01"
| sort by Timestamp desc

#### If you want to return blocked only events
DeviceEvents
| where ActionType !contains "Audited"
| sort by Timestamp desc

## Sentinel
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
