let LatestNChanges = 181;
// Deduplicate identity info FIRST
let IdentityDedup =
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | where CreatedDateTime < ago(30d)        // Exclude users created in last 30 days
    | where IsAccountEnabled == true
    | project AccountObjectId;
AADSignInEventsBeta
| where Timestamp > ago(24h)
// Collect the last event for each account
| summarize arg_max(Timestamp, *) by AccountObjectId
| where isnotempty(LastPasswordChangeTimestamp)
// Filter using identity properties WITHOUT duplicating rows
| join kind=leftsemi IdentityDedup on AccountObjectId
// Calculate the period between now and the last password change
| extend DaysSinceLastPasswordChange =
    datetime_diff('day', now(), LastPasswordChangeTimestamp)
| project-rename LastSignIn = Timestamp
| project LastSignIn, AccountObjectId, AccountUpn, ErrorCode,
          DaysSinceLastPasswordChange, IsExternalUser, IsGuestUser, IsManaged
// Select the top n accounts
| top LatestNChanges by DaysSinceLastPasswordChange desc