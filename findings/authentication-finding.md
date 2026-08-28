# Authentication Analysis

## Observation

The simulated security-event dataset shows five consecutive failed
authentication attempts against the `jsmith` account from `10.10.20.15`
on `WKSTN-104` between 09:01:12 and 09:01:42.

A successful authentication occurred at 09:02:03 from the same source
and against the same host/account.

## Initial Assessment

The sequence represents suspicious authentication activity because
multiple authentication failures were followed shortly by a successful
authentication.

## Classification

**Status:** Suspicious — requires further investigation

**Current determination:** Not yet classified as a confirmed compromise.

## Next Investigation Step

Investigate activity occurring immediately after the successful
authentication, including:

- Privilege assignment
- Process creation
- Network connections
- Persistence mechanisms
- PowerShell activity
