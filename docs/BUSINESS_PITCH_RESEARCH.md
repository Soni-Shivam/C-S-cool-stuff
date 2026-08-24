# DRISHTI Business Pitch Research

**Research date:** 2026-08-25
**Status:** evidence-backed pitch hypothesis, not a revenue forecast

## Executive thesis

DRISHTI is a defensive investigation workspace for suspicious Android packages. Its
commercial wedge is not “another APK scanner.” It is the combination of:

1. a fast static triage result;
2. bounded, tool-using reverse engineering tied to exact code and evidence;
3. controlled re-execution when a sample appears to wait for a target environment; and
4. an append-only signed ledger that lets an analyst defend every claim later.

The strongest initial buyer hypothesis is a mobile threat-research or fraud-intelligence
team at a bank, wallet, insurer, telco, incident-response firm, or government CERT. These
teams receive APKs from customer reports, takedown investigations, partner escalations,
and threat feeds. They need an investigation record, not only a vulnerability list.

## Why the problem is credible

The Reserve Bank of India reported **13,516 card/internet fraud cases in 2024-25** in its
supervisory returns. The amount involved was ₹520 crore, but RBI explicitly warns that
the entire reported amount is not necessarily diverted. This establishes operational
fraud volume; it does **not** establish the share attributable to Android malware or a
DRISHTI-addressable market. [RBI Annual Report 2024-25](https://www.rbi.org.in/scripts/AnnualReportPublications.aspx?Id=1436)

Environment-aware behavior is a documented malware-analysis problem, not a demo
invention. ThreatFabric documented a BankBot dropper that checked a hardcoded target-app
list and started dropper behavior only when one of those apps was installed.
[ThreatFabric BankBot campaign analysis](https://www.threatfabric.com/blogs/new-campaigns-spread-banking-malware-through-google-play)

OWASP defines mobile application security testing as involving static and dynamic
analysis and describes MASTG as a guide for mobile testing and reverse engineering. That
supports DRISHTI’s combined-analysis method, while also making clear that static plus
dynamic analysis alone is not a unique category.
[OWASP MASTG](https://mas.owasp.org/MASTG/)

Zimperium’s 2025 report is vendor research, so its measurements should be presented with
that caveat. It reports that up to 34% of Android apps in its dataset lacked basic code
protection and 43% were vulnerable to PII leakage. These figures support buyer concern
about mobile risk but are not DRISHTI performance claims.
[Zimperium 2025 Global Mobile Threat Report](https://zimperium.com/hubfs/Reports/2025%20Global%20Mobile%20Threat%20Report.pdf)

## Competitive landscape

| Option | What it credibly does | DRISHTI positioning |
|---|---|---|
| MobSF | Open-source automated mobile security and malware analysis with static and dynamic analysis | Integrate or coexist; compete on evidence-grounded investigation, environment-aware reruns, and analyst workflow rather than claiming MobSF is static-only. |
| NowSecure Platform | Binary analysis, authenticated real-device execution, static/dynamic correlation, and evidence artifacts for mobile AppSec | Strong enterprise benchmark. DRISHTI’s narrower hypothesis is suspicious-APK malware triage, closed-loop environment synthesis, and cryptographic claim provenance. This distinction needs customer validation. |
| Zimperium | Enterprise mobile threat defense and mobile app protection/research | Adjacent platform competitor; DRISHTI is an analyst investigation system, not an on-device MTD agent. |
| Manual JADX/Ghidra/Frida workflow | Maximum analyst control and adaptability | DRISHTI should reduce repetitive evidence collection while preserving code, tool-call, and run provenance. Time savings are unmeasured until a structured analyst study runs. |
| Antivirus / reputation lookup | Fast known-bad verdicts at large scale | DRISHTI is for ambiguous or novel samples where behavior, code path, and defensible explanation matter. Reputation remains an input, never ground truth. |

Sources: [MobSF documentation](https://mobsf.github.io/docs/),
[NowSecure Platform](https://www.nowsecure.com/products/platform/), and
[Zimperium 2025 report](https://zimperium.com/hubfs/Reports/2025%20Global%20Mobile%20Threat%20Report.pdf).

## Product package

**Investigation workspace:** upload or reference an APK, inspect static findings and
decompiled sink paths, review model interpretations, trace claims to ledger evidence,
and export a grounded report.

**Contained dynamic lab:** a separately controlled service that restores an immutable
Android snapshot, verifies network containment, detonates, records provenance, and
stops compute when idle. Google documents nested KVM support on Compute Engine; DRISHTI
adds stricter VPC and runtime admission controls around it.
[Google Cloud nested virtualization](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview)

**Evaluation and governance:** model outputs are evaluated against evidence-backed
cases; tool calls are schema validated, bounded, and recorded. OpenRouter standardizes
user-defined tool calls across supported models, while the application remains
responsible for validating and executing the requested functions.
[OpenRouter tool-calling documentation](https://openrouter.ai/docs/guides/features/tool-calling)

## Commercial hypotheses to test

Do not put prices or TAM on a slide before interviews. Test these packaging hypotheses:

| Hypothesis | Buyer | Charging unit | Validation question |
|---|---|---|---|
| Analyst seat + run allowance | Bank fraud/threat team | annual seat plus contained runs | Does the evidence workflow replace enough manual casework to own a budget line? |
| Private deployment | Bank, government, regulated enterprise | annual platform license and support | Is private sample custody a procurement requirement or only a preference? |
| Investigation API | MDR, CERT, threat-intel vendor | analyzed package or monthly volume | Is machine-readable evidence more valuable than another risk score? |
| Expert escalation | Teams without Android RE staff | case package | Will buyers pay for analyst-reviewed conclusions on inconclusive or high-risk samples? |

## Buyer discovery plan

Run 12 structured interviews: four bank fraud/mobile-security teams, three CERT/MDR
analysts, three mobile AppSec teams, and two threat-intelligence vendors. Ask for the
last real APK investigation, the tools and handoffs used, elapsed analyst time, evidence
needed for escalation, sample-custody constraints, and why the case was inconclusive.

Success criteria for the next pitch iteration:

- at least five buyers confirm environment-gated or dynamically hidden behavior as a
  recurring investigation problem;
- at least five can identify a current owner and budget category;
- at least three agree to test DRISHTI on a historical, legally shareable case;
- a measured study shows whether DRISHTI changes analyst time, evidence completeness,
  unsupported-claim rate, or final disposition consistency.

Until those interviews and measurements exist, present the business model, time saving,
and accuracy improvement as hypotheses. Present the implemented containment, evidence,
and tool-validation controls as product facts backed by the repository tests.
