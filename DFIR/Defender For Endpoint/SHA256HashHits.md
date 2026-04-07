// Hash hits (subset from CISA tables - add more from STIX as desired)
let Start = ago(30d);
let Sha256 = dynamic([
    "321ea554a469f37f77f49255324aa7a13f080a0d16042d7b8bafad128d860951",
    "ca53fabc32fc7b9d0441806ccf239b16644a75c5ad7104db640e2ec2338c29c8"
]);
union
(DeviceFileEvents | where Timestamp >= Start | where SHA256 in (Sha256)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName),
(DeviceProcessEvents | where Timestamp >= Start | where InitiatingProcessSHA256 in (Sha256) or SHA256 in (Sha256)
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine);