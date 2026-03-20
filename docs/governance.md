# AEGIS-SILENTIUM — Governance, Ethics & Legal Policy

**Version:** 10.0  
**Effective:** 2026-01-01  
**Owner:** AEGIS Project Lead  
**Review cadence:** Quarterly

---

## 1. Purpose and scope

AEGIS-SILENTIUM is a command-and-control framework designed exclusively for:
- Authorised red team engagements contracted in writing
- Penetration testing within explicitly scoped environments
- Security research on systems you own or have written permission to test
- Training environments isolated from production networks

This policy applies to every operator, contractor, and organisation operating AEGIS infrastructure. Violation of this policy may result in immediate access revocation and legal consequences.

---

## 2. Authorisation requirements

**Before any operation:**

1. A signed Rules of Engagement (RoE) document must exist naming:
   - The contracting organisation
   - The specific systems and IP ranges in scope
   - The explicit activities permitted (scanning, exploitation, persistence, etc.)
   - The engagement window (start/end date-time in UTC)
   - Emergency stop contacts for both parties

2. The RoE must be stored in `docs/engagements/` with the engagement ID matching the campaign name in AEGIS.

3. Two senior operators must countersign any engagement that includes:
   - Exploitation of production systems
   - Exfiltration of live data
   - Persistence mechanisms
   - Payloads targeting end-user devices

4. Any activity outside the documented scope must be immediately halted and reported to the engagement lead.

**No exceptions.** The technical capability to do something is not authorisation to do it.

---

## 3. Operator roles and responsibilities

| Role       | Can do                                           | Cannot do without escalation |
|------------|--------------------------------------------------|-------------------------------|
| `ghost`    | View dashboards and reports                      | Everything below              |
| `operator` | Create tasks, manage campaigns, chat             | Exploitation, payloads        |
| `senior`   | Full operational access: exploits, payloads, listeners | Admin ops, key management |
| `lead`     | Operator management, settings, audit review      | Secret rotation, system config |
| `admin`    | All of the above, plus key rotation              | Nothing — full responsibility |

All operators are personally accountable for actions taken under their handle. Shared accounts are prohibited.

---

## 4. Data handling

### 4.1 Sensitive data classification

| Data type              | Classification | Retention    | Handling                          |
|-----------------------|----------------|-------------|-----------------------------------|
| Operator credentials   | SECRET         | Until revoked | PBKDF2-hashed; never logged      |
| JWT secrets            | SECRET         | Rotate ≤ 90d | Never stored in plain text        |
| Target host data       | CONFIDENTIAL   | 90 days      | Encrypted at rest                 |
| Captured credentials   | CONFIDENTIAL   | 30 days      | Stored encrypted; access logged   |
| Surveillance data      | CONFIDENTIAL   | 30 days      | Purged after engagement close     |
| Payloads               | CONFIDENTIAL   | 30 days      | Marked expired post-engagement    |
| Operator audit trail   | INTERNAL       | 365 days     | Immutable; admin read-only        |
| Chat messages          | INTERNAL       | 90 days      | No PII; engagement-scoped only    |

### 4.2 Post-engagement cleanup

Within 7 days of engagement close:
1. Run `/api/admin/retention/run` to sweep expired data
2. Export and deliver the final report
3. Deactivate all temporary operator accounts
4. Revoke all sessions (`/api/admin/operators/{handle}/sessions/revoke`)
5. Archive the engagement folder to offline storage
6. Verify no AEGIS infrastructure is reachable from the target environment

### 4.3 Data breach response

If AEGIS infrastructure or operator credentials are believed to be compromised:
1. Immediately rotate JWT secret: `POST /api/admin/secrets/rotate/jwt`
2. Revoke all active sessions
3. Rotate Fernet key: `POST /api/admin/secrets/rotate/fernet`
4. Notify the engagement client and project lead within 1 hour
5. Preserve audit logs before any cleanup
6. Document the incident in `docs/incidents/`

---

## 5. Prohibited activities

The following are prohibited regardless of technical capability or scope:

- Attacks on systems not explicitly listed in the signed RoE
- Exfiltration of data beyond what is necessary to demonstrate impact
- Destruction of data or production systems
- Targeting critical infrastructure (hospitals, utilities, emergency services) except in documented, government-authorised engagements
- Use of AEGIS against political, civil, or journalistic targets
- Operating payloads that self-propagate or spread beyond the agreed scope
- Bypassing audit logging or suppressing events from the audit trail
- Sharing operator credentials, JWT tokens, or Fernet keys outside the team
- Using AEGIS for any purpose not covered by a valid engagement

---

## 6. Incident classification and escalation

| Severity | Description                              | Escalation window | Notification |
|----------|------------------------------------------|--------------------|--------------|
| P1       | Active compromise of AEGIS infrastructure | Immediate          | All operators + legal |
| P1       | Out-of-scope systems impacted             | Immediate          | Client + legal |
| P2       | Credentials or keys may be exposed        | < 1 hour           | Lead + admin |
| P2       | Unexpected data exfiltration              | < 1 hour           | Client + lead |
| P3       | Operator authentication anomaly           | < 4 hours          | Lead          |
| P4       | Policy deviation (minor)                  | < 24 hours         | Team lead     |

All incidents must be documented in `docs/incidents/INC-YYYY-NNN.md` using the standard template.

---

## 7. Audit and accountability

- All operator actions are recorded in the `operator_audit` table and retained for 365 days
- Audit records are append-only — no operator, including admins, can modify them
- The `audit:view` permission is required to read audit records
- Quarterly reviews of operator accounts and access must be performed by a lead or admin
- Operators inactive for > 90 days should be deactivated
- Audit log export must be included in every engagement close-out report

---

## 8. Legal and contractual

This software is provided under a restrictive licence. Operators agree that:

1. They hold the legal authority or written authorisation to conduct any operation
2. They comply with all applicable laws in the jurisdiction of the target systems
3. They accept personal liability for any out-of-scope or unauthorised activity
4. AEGIS Project and its contributors bear no liability for misuse

Applicable regulations may include (non-exhaustive):
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- EU Cybersecurity Act / NIS2 Directive
- Local equivalents in the operator's jurisdiction

When in doubt: **get written authorisation first**.

---

## 9. Policy review and exceptions

- This policy is reviewed every quarter or after any P1/P2 incident
- Exception requests must be submitted in writing to the project lead with a documented risk justification
- Approved exceptions are time-limited (max 90 days) and logged in `docs/policy-exceptions.md`

---

*End of governance document.*
