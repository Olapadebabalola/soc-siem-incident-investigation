# Incident Investigation Timeline

## Timeline

| Time | Event ID | Event | Analyst Assessment |
|---|---:|---|---|
| 09:01:12 | 4625 | Failed authentication for jsmith | Initial authentication anomaly |
| 09:01:18 | 4625 | Failed authentication | Pattern developing |
| 09:01:25 | 4625 | Failed authentication | Repeated authentication failure |
| 09:01:31 | 4625 | Failed authentication | Continued failures |
| 09:01:42 | 4625 | Failed authentication | Fifth observed failure |
| 09:02:03 | 4624 | Successful authentication | Requires correlation |
| 09:02:15 | 4672 | Special privileges assigned | Elevated concern |
| 09:02:44 | 4688 | powershell.exe created | Suspicious in context |
| 09:03:02 | 4688 | rundll32.exe created | Additional execution activity |
| 09:03:21 | 5156 | Outbound connection to 203.0.113.50:443 | Network artifact identified |
| 09:04:01 | 4698 | WindowsUpdateCheck scheduled task created | Potential persistence |
| 09:04:25 | 5156 | Additional outbound connection | Continued network activity |
| 09:05:10 | 4688 | powershell.exe executed | Continued execution |
| 09:09:10 | 4634 | jsmith logoff | User session terminated |
| 09:12:04 | 4698 | WindowsUpdateCheck task observed under SYSTEM | Persistence concern increased |
| 09:13:11 | 5156 | Outbound connection under SYSTEM | Continued post-session activity |
| 09:14:20 | 4688 | powershell.exe executed | Additional suspicious execution |
| 09:15:02 | 4104 | PowerShell EncodedCommand logged | High-interest PowerShell activity |
| 09:16:30 | 5156 | Additional outbound connection | Continued network communication |

## Timeline Assessment

The timeline demonstrates that the investigation is not based on a
single isolated security event.

Authentication anomalies were followed by privilege assignment,
process execution, network communication, scheduled-task creation,
and additional PowerShell activity.

Most importantly, activity associated with the scheduled task and
network communication continued after the original user session,
increasing concern that persistence may have been established.
