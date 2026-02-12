# Task 3 Breakdown (BSc Student 2): Auth Detection - Ayaan Ahmed

## Task Goal
Build `detect_auth.py` with:
- Function: `detect_brute_force(logs) -> list[Alert]`
- Detection rule: If one IP has **more than 5 failed logins within 1 minute**, create an alert:
  - `type`: `"Brute Force"`
  - `severity`: `"High"`

This module is part of the Detection stage in the pipeline:
`Ingestion -> Detection -> Correlation -> Dashboard`

---

## What This Task Needs To Output

### Input expected
- `logs`: list of normalized log events (`LogEntry` objects or dictionaries).
- Each log should ideally include:
  - timestamp (when event happened)
  - source IP (where request came from)
  - event type/category (login/auth)
  - result/status (success/failure)

### Output expected
- `list[Alert]` where each alert includes:
  - `type = "Brute Force"`
  - `severity = "High"`
  - source IP
  - event count in burst
  - start and end time of burst
  - description for human readability

---

## Step-by-Step Plan (Small Tasks)

## 1. Confirm data contract with team
- Confirm exact field names from ingestion (for example `sourceAddress`, `timestamp`, `result`, `eventType`).
- Confirm alert schema expected by correlation engine.
- Write this contract at the top of your file or in comments.

Definition of done:
- You know exactly what keys your function receives and returns.

## 2. Create file and function scaffold
- Create `detection/detect_auth.py`.
- Add function signature:
  - `def detect_brute_force(logs):`
- Return an empty list first to prove file imports correctly.

Definition of done:
- Module imports without errors.

## 3. Normalize each log event safely
- Handle both dict logs and object/dataclass logs.
- Skip broken events (missing timestamp or source IP).
- Parse timestamps into comparable datetime values.

Definition of done:
- Bad logs do not crash the function.

## 4. Identify failed authentication events
- Filter only auth/login-related events.
- Detect failure from fields like `result/status/message`.
- Ignore non-auth logs to reduce noise.

Definition of done:
- Only failed auth events pass this filter.

## 5. Group failures by source IP
- Build a structure like:
  - `failures_by_ip[ip] = [timestamps...]`
- Sort each IP’s events by time.

Definition of done:
- For any IP, you can see its failures in chronological order.

## 6. Apply 1-minute sliding-window logic
- For each IP, iterate through failures in time order.
- Maintain a moving 60-second window.
- If count inside window becomes `> 5`, generate one alert.

Definition of done:
- Attack burst with 6 failures in <= 60 sec triggers alert.
- 5 failures does not trigger alert.

## 7. Build alert objects
- For each detection, create alert with:
  - type, severity
  - source IP
  - count of failures
  - start/end timestamp
  - short explanation text
- Keep alert structure consistent for correlation engine.

Definition of done:
- Alerts are machine-readable and human-readable.

## 8. Prevent duplicate noisy alerts
- Add logic to avoid spamming repeated alerts for same burst.
- Example: reset/advance window after an alert is emitted.

Definition of done:
- One attack burst does not produce unnecessary duplicates.

## 9. Test with synthetic logs
- Write quick tests/manual checks for:
  - 6 failures in 1 minute -> 1 alert
  - exactly 5 failures -> 0 alerts
  - failures spread over > 1 minute -> 0 alerts
  - mixed success/failure logs -> only failures count
  - multiple source IPs -> alerts generated separately

Definition of done:
- Core detection logic verified.

## 10. Integration readiness
- Ensure output from `detect_auth.py` can be combined with `detect_network.py`.
- Confirm correlation engine can use your alert keys.

Definition of done:
- Your module plugs into full pipeline without schema mismatch.

---

## Suggested Work Timeline (Fast Hackathon Version)

- 10 mins: Confirm schema + function signature
- 25 mins: Implement filtering + grouping + window logic
- 15 mins: Build clean alert output
- 20 mins: Manual test with synthetic data
- 10 mins: Integration check with teammate outputs
- 10 mins: Buffer for bug fixes

Total: ~90 mins

---

## Mini Checklist (Share With Team)

- [ ] `detect_auth.py` created in `detection/`
- [ ] `detect_brute_force(logs)` implemented
- [ ] Rule is `> 5 failed logins in 60 seconds`
- [ ] Alert includes `type="Brute Force"` and `severity="High"`
- [ ] Handles bad/missing data safely
- [ ] Manual tests completed and documented
- [ ] Output confirmed compatible with correlation engine

---

## Demo Script (What You Can Say To Teammates/Judges)

1. "This module processes normalized auth logs and isolates failed login activity."
2. "It groups failures by source IP and uses a 60-second sliding window."
3. "If an IP exceeds 5 failed logins in that window, it raises a high-severity Brute Force alert."
4. "The alert includes timeline and IP context so correlation can merge it with other signals like port scans."

---

## Risks and Mitigations

- Risk: Ingestion uses different key names.
  - Mitigation: accept multiple aliases (for example `src_ip` and `sourceAddress`).
- Risk: Timestamp formats are inconsistent.
  - Mitigation: parse ISO format first and skip invalid rows safely.
- Risk: Too many duplicate alerts.
  - Mitigation: cooldown/reset logic after alert generation.
- Risk: Integration mismatch with correlation schema.
  - Mitigation: run checkpoint test at integration with a shared sample JSON.

---

## Final Deliverable for Task 3

- File: `detection/detect_auth.py`
- Function: `detect_brute_force(logs) -> list[Alert]`
- Evidence:
  - synthetic test inputs
  - produced alerts
  - short explanation of logic in README or notes
