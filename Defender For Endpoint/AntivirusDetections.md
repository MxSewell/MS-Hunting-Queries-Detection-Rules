DeviceEvents
| where ActionType == "AntivirusDetection"
| extend af = parse_json(AdditionalFields)
| project
    Timestamp = format_datetime(Timestamp, 'yyyy-MM-dd HH:mm:ss'),
    DeviceName,
    Threat          = tostring(af.ThreatName),
    Severity        = tostring(af.Severity),
    Category        = tostring(af.Category),
    FileName,
    FilePath        = tostring(af.FilePath),
    SHA1            = tostring(af.SHA1),
    MD5             = tostring(af.MD5),
    Action          = coalesce(tostring(af.Action), tostring(af.ActionName), tostring(af.RemediationAction)),
    WasRemediated   = case(
                        tobool(af.WasRemediated) == true, "Yes",
                        tobool(af.WasRemediated) == false, "No",
                        tostring(af.RemediationStatus)
                      ),
    ReportSource    = tostring(af.ReportSource)
| order by Timestamp desc