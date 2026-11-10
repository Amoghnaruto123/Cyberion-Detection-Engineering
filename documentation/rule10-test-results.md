# Rule 10 - Suspicious Local Administrators Group Addition

- Rule: win_suspicious_local_admin_group_addition
- MITRE ATT&CK: T1098.007 - Additional Local or Domain Groups
- Dataset: Network_Service_Guest_added_to_admins_4732.evtx
- Log source: Windows Security Event ID 4732
- Events analyzed: 2
- Events matched: 2

## Matched Events

| Initiating Account | Added Member SID | Target Group |
|---|---|---|
| IEUser | S-1-5-20 (Network Service) | Administrators |
| IEUser | SID ending in -501 (Guest) | Administrators |

## Assessment

The detection identified two account additions to the local Administrators group.

Both changes are suspicious in this attack-oriented sample because they grant privileged group membership.

The rule successfully matched both events.

This is a positive test result. Benign testing and false-positive tuning remain pending.
