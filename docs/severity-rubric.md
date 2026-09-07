# Severity rubric

Findings carry a qualitative severity, not a CVSS score.

CVSS asks for attack complexity, privileges required, user interaction and
scope. This tool observes a configuration from outside the application. It does
not know whether the origin holds authenticated data, whether an injection sink
exists for a missing CSP to mitigate, or what a disclosed credential unlocks.
Producing a 7.4 from those unknowns would assert a precision the evidence does
not support, and reviewers reasonably treat a scanner's invented CVSS numbers as
a reason to distrust the rest of the output.

So severity here answers one question: **how much does this weaken the security
of the application, given only what was observed?** Impact is judged as if the
application is a typical authenticated web application. Where that assumption
does not hold, the severity should be adjusted during review — which is what the
baseline file in `parapet.yml` is for.

## Levels

| Severity | Meaning | Examples |
| --- | --- | --- |
| **critical** | Confirmed disclosure of secrets, or a weakness that yields access on its own. Act before the next deploy. | Readable `.env` file; expired certificate |
| **high** | Directly exploitable weakness, or disclosure of source or credentials-adjacent material. Act this sprint. | Credentialed CORS reflection; password form posting over `http`; readable `.git`; self-signed or hostname-mismatched certificate |
| **medium** | Removes a defensive layer, or is exploitable only in combination with something else. Schedule it. | Missing CSP; no clickjacking protection; missing HSTS; deprecated TLS versions; session cookie without `HttpOnly` |
| **low** | Hardening gap or minor information disclosure. Fix opportunistically. | Missing `nosniff`; missing `Referrer-Policy`; version banners; missing SRI; exposed source map |
| **info** | Observation, or a note about something browsers already handle. Not a defect. | No `Permissions-Policy`; missing `rel=noopener`; TLS 1.3 not offered; no `security.txt` |

## Confidence

Severity says how much it matters. Confidence says how much the evidence
supports the claim, and the two are reported separately so a reviewer can triage
on either.

| Confidence | Meaning |
| --- | --- |
| **confirmed** | The observation *is* the weakness. The scanner sent an arbitrary `Origin` and the server reflected it. |
| **firm** | The observation is definitive, but impact depends on the application. A missing CSP is certain; whether it matters depends on whether an injection sink exists. |
| **tentative** | The observation is suggestive and needs a human. Cookie naming heuristics land here — `sid` *probably* carries session state, but that is a convention, not a contract. |

## Rules the checks follow

**Severity reflects the observed state, not the worst imaginable one.** Missing
`rel=noopener` is `info` because browsers have implied it since 2021. Calling it
`low` because it was once exploitable would inflate the count.

**Absence of a defence is not the same as presence of a flaw.** A missing CSP is
`medium`: it removes a mitigation. Credentialed CORS reflection is `high`: it
*is* the disclosure.

**Where a modifier changes the impact, it changes the severity.** CORS findings
hinge on `Access-Control-Allow-Credentials`. Cookie findings escalate when the
name suggests session state. This is why severity is computed in the check
rather than attached to the check id.

**A finding that browsers reject outright is reported as a configuration error,
not as an exploit.** `Access-Control-Allow-Origin: *` with credentials is `low`:
browsers refuse the combination, so nothing is exposed — but the policy is not
doing what its author intended, and the usual "fix" makes it far worse.

## Choosing a CI threshold

`--fail-on` defaults to `high`, which fails a build on confirmed exploitable
weaknesses while letting hardening work be scheduled rather than blocking.

Tightening to `medium` is reasonable for a new application where the header
baseline is being established. It is usually the wrong first move on an existing
one: the initial run will fail, and the response tends to be to disable the
gate. Record the current state in `baseline` instead, fail on `high`, and empty
the baseline over time.
