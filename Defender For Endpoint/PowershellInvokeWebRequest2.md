DeviceProcessEvents
| where FileName == "powershell.exe"
| where AccountName != @"system"
| where ProcessCommandLine matches regex "(Invoke-WebRequest|IEX|FromBase64String|Invoke-Expression)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine