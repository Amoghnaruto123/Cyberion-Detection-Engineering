# Rule 11 - Hidden Local Account Creation via SAM Registry

- Rule: win_hidden_local_account_creation
- MITRE ATT&CK: T1136.001 - Create Account: Local Account
- Dataset: persistence_hidden_local_account_sysmon.evtx
- Log source: Sysmon Event ID 13
- Events matched: 1

## Matched Event

- Process: lsass.exe
- Process ID: 648
- Account name: hideme0007$
- Registry path: HKLM\SAM\SAM\Domains\Account\Users\Names
- Registry operation: SetValue
- Registry details: Binary Data

## Assessment

The detection identified a modification to the Windows SAM account-name registry path associated with a hidden local account.

The rule successfully matched the attack-oriented EVTX sample.

The dollar sign in the account name is a suspicious indicator in this context, but does not independently prove malicious activity.

This is a positive test result. Benign testing and false-positive tuning remain pending.
