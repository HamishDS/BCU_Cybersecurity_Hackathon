# Task 3 Test Plan: `detect_brute_force(logs)` (10 Tests)

## Scope
Validate `core/detect_auth.py` for:
- Correct brute-force detection rule: `> 5` failed logins in `60s` per source IP.
- Correct alert payload structure.
- Robustness to mixed/bad input formats.

## Function Under Test
- `detect_brute_force(logs) -> list[dict]`

---

## Alert Pass Criteria (for any positive detection)
An alert is valid only if it contains:
- `type = "Brute Force"`
- `severity = "High"`
- `sourceAddress` (string IP)
- `eventCount` (int, expected `>= 6`)
- `startTime` and `endTime` (ISO datetime strings)

---

## Test Cases

### 1. Basic trigger: 6 failed logins in under 60 seconds
- Purpose: Verify core detection works.
- Input:
  - Same IP, 6 failed auth events between `t=0s` and `t=50s`.
- Expected:
  - `len(alerts) == 1`
  - Alert has `sourceAddress` = test IP
  - `eventCount == 6`

### 2. Boundary: exactly 5 failed logins in 60 seconds
- Purpose: Verify threshold is strictly `> 5`.
- Input:
  - Same IP, 5 failed auth events within 60s.
- Expected:
  - `len(alerts) == 0`

### 3. Outside window: 6 failed logins spread over more than 60 seconds
- Purpose: Verify sliding-window timing constraint.
- Input:
  - Same IP, 6 failed events from `t=0s` to `t=70s`.
- Expected:
  - `len(alerts) == 0`

### 4. Mixed outcomes: failed + successful logins
- Purpose: Ensure only failures count.
- Input:
  - Same IP, 6 auth events in 60s but only 4 are failed.
- Expected:
  - `len(alerts) == 0`

### 5. Multi-IP independence
- Purpose: Ensure counts are isolated per IP.
- Input:
  - IP A: 6 failed in 60s.
  - IP B: 5 failed in 60s.
- Expected:
  - `len(alerts) == 1`
  - Alert only for IP A.

### 6. Non-auth noise in logs
- Purpose: Ensure non-auth events are ignored.
- Input:
  - Same IP, many events like DNS/HTTP/port scan with failure words but no auth/login context.
  - Fewer than 6 true failed auth events.
- Expected:
  - `len(alerts) == 0`

### 7. Field alias compatibility
- Purpose: Validate key alias support.
- Input:
  - Use aliases:
    - IP via `src_ip` or `source_ip`
    - Time via `time` or `eventTime`
    - Event via `event_type` or `action`
    - Result via `status` or `outcome`
  - 6 failed events in 60s.
- Expected:
  - `len(alerts) == 1`
  - Alert still includes normalized `sourceAddress` output.

### 8. Timestamp format handling (`Z` timezone)
- Purpose: Confirm ISO `Z` parsing.
- Input:
  - 6 failed auth events in UTC format like `2026-02-12T10:00:00Z`.
- Expected:
  - `len(alerts) == 1`
  - No parsing errors.

### 9. Missing/invalid required fields
- Purpose: Ensure robustness, no crash.
- Input:
  - Some logs missing IP.
  - Some logs missing timestamp.
  - Some logs with invalid timestamp strings.
- Expected:
  - Function completes without exception.
  - Invalid entries skipped.
  - Alerting only based on valid entries.

### 10. Input type flexibility (dict + dataclass/object)
- Purpose: Validate `_to_dict` behavior.
- Input:
  - Mixed list of:
    - dict logs
    - dataclass log entries
    - simple class instances with `__dict__`
  - Include 6 valid failed auth events for one IP in 60s.
- Expected:
  - `len(alerts) == 1`
  - No type-related errors.

---

## Execution Checklist
- [ ] Run all 10 tests manually or via `pytest`.
- [ ] Record pass/fail for each.
- [ ] For failures, capture: input sample, observed output, expected output, fix owner.
- [ ] Re-run failed tests after fixes.

---

## Suggested Evidence for Team Demo
- Screenshot or output snippet for:
  - Test 1 (positive detection)
  - Test 2 (boundary no-alert)
  - Test 5 (multi-IP behavior)
  - Test 9 (robustness to bad logs)
