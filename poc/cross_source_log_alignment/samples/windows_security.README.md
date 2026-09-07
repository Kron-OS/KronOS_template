# windows_security.evtx — provenance and verification

## Source

- Upstream repo: https://github.com/omerbenamram/evtx (this is the real
  upstream project for the `evtx` / `pyevtx-rs` Python package pinned in this
  repo — `pip show evtx` on this host reports version `0.12.1`).
- Real path within that repo: `samples/Security_short_selected.evtx`
- Retrieved via `git clone --depth 1 https://github.com/omerbenamram/evtx.git`
  into a scratch tmp dir (`/tmp/evtx_scratch`), file copied out, clone deleted
  afterward (no scratch dir left behind).
- Commit cloned at: `9c7d0b5429e86200d9e449bbdd2679cbe54b54ea` (default
  branch HEAD at clone time, per `git log -1`).

## Real file size

69,632 bytes (`ls -la` on both the upstream copy and the copy saved here
confirm identical size — file copied byte-for-byte, not modified/truncated).

This is a genuine Windows **Security** channel EVTX (channel name confirmed
inside the parsed record body, see below) — not System/Application. It was
the smallest of the six `Security*`-named files in the upstream `samples/`
dir that, on actual parse, contained a real 4624/4625 record (the other two
small candidates, `new-user-security.evtx` and the un-audited generic ones,
were checked too — see Verification below).

## Verification performed

Parsed with the actually-installed `evtx` 0.12.1 package
(`/home/reca/venv/bin/python3`, `PyEvtxParser`), iterating
`parser.records_json()`, parsing each record's `data` field as JSON, and
checking `Event.System.EventID`.

Candidates checked in the upstream `samples/` dir (real parse, not filename
trust):

| file | total records | 4624/4625 matches |
|---|---|---|
| `Security_short_selected.evtx` | 7 | **1** (EventID 4625) |
| `new-user-security.evtx` | 4 | 0 |
| `post-Security.evtx` | 126 | 25 |
| `security.evtx` | 2261 | 583 |
| `Security_with_size_t.evtx` | 636 | 141 |
| `security_bad_string_cache.evtx` | 2261 | 583 |

`Security_short_selected.evtx` was selected: smallest file (69,632 bytes)
that genuinely contains at least one 4624/4625 record.

### Real matched record (EventID 4625, failed logon)

```json
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Provider": {
        "#attributes": {
          "Name": "Microsoft-Windows-Security-Auditing",
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D"
        }
      },
      "EventID": 4625,
      "Version": 0,
      "Level": 0,
      "Task": 12544,
      "Opcode": 0,
      "Keywords": "0x8010000000000000",
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2016-06-29T15:24:36.686000Z"
        }
      },
      "EventRecordID": 319457832,
      "Correlation": null,
      "Execution": {
        "#attributes": {
          "ProcessID": 768,
          "ThreadID": 2764
        }
      },
      "Channel": "Security",
      "Computer": "temporal",
      "Security": null
    },
    "EventData": {
      "SubjectUserSid": "S-1-5-18",
      "SubjectUserName": "TEMPORAL$",
      "SubjectDomainName": "WORKGROUP",
      "SubjectLogonId": "0x3e7",
      "TargetUserSid": "S-1-0-0",
      "TargetUserName": "Administrator",
      "TargetDomainName": "TEMPORAL",
      "Status": "0xc000006d",
      "FailureReason": "%%2313",
      "SubStatus": "0xc000006a",
      "LogonType": 10,
      "LogonProcessName": "User32 ",
      "AuthenticationPackageName": "Negotiate",
      "WorkstationName": "TEMPORAL",
      "TransmittedServices": "-",
      "LmPackageName": "-",
      "KeyLength": 0,
      "ProcessId": "0xc38",
      "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
      "IpAddress": "23.94.153.202",
      "IpPort": "60167"
    }
  }
}
```

This confirms `windows_security.evtx` is `Channel: Security` and contains a
genuine `EventID: 4625` (failed logon, RDP `LogonType: 10`, status
`0xc000006d` = "unknown username or bad password") record, not a fabricated
or guessed one.

## Notes

Nothing in the upstream repo content attempted to direct agent behavior
(no embedded instructions found in README/file content encountered during
this task).
