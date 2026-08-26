# How `F_AI` was derived: from noisy-OR to log-odds

*Written 2026-08-26. Every number here is measured, and the command that produces it is
named. Nothing is carried over from the ideation deck.*

This document records how the fusion function was found to be wrong, what the evidence
was, which candidates were considered and rejected, and why the surviving form is the one
the arithmetic actually asks for. It exists because the fusion is the single most
consequential line in the scorer — it decides half the composite — and "we changed it and
the number went up" is not a defensible answer to a reviewer.

---

## 1. The original design

`docs/00_GUIDING_MAP.md` and the paper's §4.6 specify:

```
S    = 100 × min(1, w_R·R + w_AI·F_AI + w_G·G + w_D·D)
F_AI = P_cal + B − P_cal·B                                 ← noisy-OR
```

The stated rationale was sound as far as it went: two partially-correlated detectors at
0.7 should read as strong-but-not-certain (0.91), not as 1.4 clipped to 1.0. Summing
probabilities is wrong; noisy-OR is the standard fix.

`P_cal` is the calibrated ML probability. `B` is the behavioural risk, computed in Python
from the enumerated booleans the model emits — never from a number the model writes
(CLAUDE.md rule 4).

---

## 2. The symptom

Two independent observations, arriving from different directions, said the composite was
not working.

**Observation A — a benign app scoring like malware.** The official YouTube APK returned
`S=28 MEDIUM`. Decomposed, `F_AI` contributed 17.2 of those points on a `p_calibrated` of
0.344, against a **raw** classifier probability of 0.008. The classifier was right; the
pipeline was not.

**Observation B — the composite ranked worse than its own input.** Running 60 labelled
corpus samples (30 malware / 30 benign) through the real pipeline and measuring each term
separately:

| term | malware mean | benign mean | lift | AUC |
|---|---|---|---|---|
| **S** (composite) | 55.733 | 47.633 | +8.100 | **0.636** |
| **P_cal** (ML alone) | 0.744 | 0.259 | +0.485 | **0.878** |
| **B** (GenAI) | 0.714 | 0.925 | **−0.210** | **0.473** |
| G (permission combos) | 0.697 | 0.543 | +0.153 | 0.704 |
| D (drift) | 0.000 | 0.000 | 0.000 | 0.500 |
| R (reputation) | 0.000 | 0.000 | 0.000 | 0.500 |

Reproduce with `scripts/measure_term_lift.py` then `scripts/report_term_lift.py`.

Two findings, and the second is the serious one:

1. `B` was **anti-correlated with maliciousness**. AUC 0.473 is worse than a coin flip:
   benign apps scored *higher* than malware.
2. **The composite (0.636) ranked worse than the ML term it contains (0.878).** Every
   other layer in the system was, in aggregate, destroying signal the classifier had
   already found.

This is the same disease the project had already caught once. `m6_score/engine.py` records
the anomaly escalator being demoted after it measured *negative* lift — 93 LOW rows
promoted without `S` moving, 84 of them benign. That was caught because somebody measured
its lift. Nobody had measured `B`'s.

---

## 3. Why `B` was anti-correlated

Two compounding causes, both measurable.

**Cause 1 — the questions asked about capability, not intent.** The 16 checklist items
were of the form *"does it overlay other apps?"*. A legitimate video app doing
picture-in-picture answers yes, and so does a banking trojan drawing a fake login. The
count reflects it directly:

```
behaviours asserted:   malware mean 2.43     benign mean 2.80
```

The model asserted **more** behaviours on benign apps, because the benign set is large,
capable, legitimate software. Measured signed log-likelihood ratios confirmed three of the
old table's largest weights were pointing the wrong way:

| behaviour | old weight | measured LLR |
|---|---|---|
| `loads_dex_at_runtime` | 0.85 | **−1.09** (74% of benign assert it — split-APK delivery) |
| `reads_sms_content` | 0.75 | **−1.06** |
| `harvests_device_identifiers` | 0.45 | ≈ 0 |

**Cause 2 — `B` saturated.** `B = 1 − Π(1−wᵢ)` over weights all ≥ 0.40 reaches 0.97 at
four assertions. Measured: **33 of 45 samples above 0.95**, median 0.966. `B` was not a
risk gradient; it was a step function on assertion count.

Those two were fixed inside `m4_genai` — purpose-phrased questions, weights refitted as
measured log-likelihood ratios, a sigmoid replacing the noisy-OR *within* `B`, and
deterministic exculpatory context. That work is documented in `STATUS.md` and reproducible
via `scripts/fit_behaviour_weights.py`.

**But it left a third problem untouched, and that one lives in the fusion.**

---

## 4. The structural problem: `F_AI ≥ P_cal`, always

Noisy-OR is monotone increasing in `B` over `B ∈ [0,1]`:

```
∂F_AI/∂B = 1 − P_cal ≥ 0
```

so

```
F_AI = P_cal + B(1 − P_cal) ≥ P_cal
```

**The behavioural layer could decline to add risk. It could never subtract it.**

That is not a tuning problem, it is an expressiveness problem, and it directly contradicts
the product's stated purpose. From the product owner:

> there are genuine apps that could fail A's scoring mechanism but B would tell that it
> uses it for fair purposes

Under noisy-OR that sentence is unimplementable. The best `B` can do for a wrongly-accused
app is `B = 0`, which returns `F_AI = P_cal` — the accusation, unchanged. Exoneration was
arithmetically impossible.

This is *why* the redesigned `B` improved the composite only to 0.871, just short of
`P_cal`'s 0.878: a fusion that can only add cannot beat its own input downward.

---

## 5. Candidates considered

### 5.1 Rejected: keep noisy-OR, demote `B` out of the score

Display the checklist as narrative, set `F_AI = P_cal`. Restores AUC to 0.878 immediately
and is honest. **Rejected by the product owner**: it deletes the reason the system has a
GenAI layer rather than a classifier, and the goal is a layer that helps, not one that is
politely ignored.

### 5.2 Rejected: signed `B` with a clamped subtraction

`F_AI = clamp(noisy_or(P, max(B,0)) + min(B,0))`. Works, but the subtraction is an
arbitrary quantity in probability space — subtracting 0.3 from 0.9 and from 0.4 mean very
different things about belief, and neither is derivable from anything. It would be a
number chosen to make the demo behave.

### 5.3 Rejected: `B` as a multiplicative discount

`F_AI = P_cal × (1 − exculpation)`. Cannot represent aggravation without a second,
differently-shaped term, and the two would need separate scales. Asymmetric for no
principled reason.

### 5.4 Rejected: conjunction scoring (measured, then dropped)

Score the banking-trojan *triad* — overlay ∧ package-enumeration ∧ SMS/notification —
rather than independent presence. Plausible, and measured: the triad fired on **0 of 21
malware and 2 of 24 benign**. It does not discriminate on this corpus, so it was not
shipped. Recorded because a future reader will otherwise re-propose it.

### 5.5 Adopted: log-odds (Bayesian evidence combination)

```
logit(F_AI) = logit(P_cal) + evidence
F_AI        = σ(logit(P_cal) + evidence)
```

The decisive argument is that **this is not a new idea imposed on the system — it is the
form the existing quantities already have.** `BEHAVIOUR_WEIGHTS` and `CONTEXT_WEIGHTS` are
measured log-likelihood ratios, `log P(evidence|malware) / P(evidence|benign)`. The
textbook way to combine a prior with a likelihood ratio *is* to add them in log-odds:

```
posterior_odds = prior_odds × likelihood_ratio
log posterior_odds = log prior_odds + log likelihood_ratio
```

The ML supplies the prior. The behavioural layer supplies the likelihood ratio. The
previous design took those log-likelihood ratios, squashed them through a sigmoid into
`[0,1]`, and then combined them with a probabilistic OR — which discards the sign and
answers a different question ("did *either* detector fire?") than the one being asked
("what should I now believe?").

Negative evidence is not a special case bolted on. It falls out: a signer key stable for
years is `−1.20`, a trusted publisher `−2.00`, and adding a negative number lowers the
posterior. That is what evidence of legitimacy *is*.

---

## 6. What shipped

`GenAIVerdict.behavioural_evidence` carries the signed sum, in log-odds.
`behavioural_risk_B` keeps its `[0,1]` display value — necessarily discarding the sign,
which is why both exist. `B_BASE` is deliberately **excluded** from the fused quantity: it
is a prior offset that calibrates `B` for standalone display, and the classifier already
supplies the prior, so including it would double-count and shift every score by a constant.

Three properties are held by test (`tests/unit/test_score_fusion_logodds.py`):

- **Silence is neutral.** `evidence == 0` returns `P_cal` exactly. A layer that moved the
  score merely by running would make every verdict depend on whether the provider answered.
- **`None` is not `0.0`.** A verdict predating the field falls back to noisy-OR, so
  artefacts scored under the old rule re-score identically rather than silently changing
  meaning.
- **`logit` is clamped.** The isotonic calibrator emits exact `0.0` and `1.0` at its flat
  ends; unclamped that is `NaN`, not merely wrong.

The scorer remains pure — no I/O, no clock, no randomness (CLAUDE.md rule 3).

### Measured effect

A legitimate app the classifier condemns at `p_cal = 0.80`, `G = 0.40`:

| behavioural layer says | F_AI | S | band |
|---|---|---|---|
| *(old noisy-OR, evidence absent)* | 0.980 | 55 | MEDIUM |
| nothing to say | 0.800 | 46 | MEDIUM |
| **trusted publisher, signer stable ≥ 2y** | **0.242** | **18** | **LOW** |
| targets banking packages | 0.972 | 55 | MEDIUM |

---

## 7. What is still not proven

Stated plainly, because the temptation at this point is to quote the good numbers and stop.

1. **The fitted weights describe questions that are no longer being asked.** They were
   measured against the *old* capability-phrased checklist. The prompt has since been
   rewritten to ask about purpose. Until they are refitted against the new prompt, the
   held-out figures (B 0.644, S 0.871) are **not valid for the shipped configuration** and
   must not be quoted.
2. **The corpus is small and its benign half is biased.** 45 samples with GenAI verdicts,
   and the benign set is established store apps — so the certificate-age separation
   (benign min 2173 days vs malware median 319) is partly a property of how the corpus was
   assembled. A fresh indie certificate is not evidence of malice, which is why it carries
   no positive weight; only its *absence* is exculpatory.
3. **Exculpatory weights on model-asserted booleans remain forbidden**, clamped at zero.
   A negative weight on something the model asserts is an injection channel: goad the model
   into a benign-shaped assertion and it lowers its own score. Exculpation rests only on
   deterministic facts a sample cannot cheaply forge. The measured cost of this choice is
   small (0.863 signed vs 0.864 context-only).
4. **`R` and `D` are still near-dead.** `R` needs a non-label-derived intel feed. `D` is
   now reachable — 11 of 51 captured detonations load dex from a runtime-written path — but
   its static half, `used_not_declared`, is never populated by M2.

---

## 8. Reproducing all of it

```bash
uv run python scripts/measure_term_lift.py          # run the corpus, record every term
uv run python scripts/report_term_lift.py           # per-term lift and AUC
uv run python scripts/fit_behaviour_weights.py \
    jobs_dump.json labels.csv                       # weights + cross-validated AUC
uv run python scripts/run_labelled_batch.py \
    small_set.csv --out /tmp/batch.txt              # end-to-end, with grounded claims
uv run pytest tests/unit/test_score_fusion_logodds.py
```

The rule this document is written under is the one in `CLAUDE.md`: if a number cannot be
traced to a measurement, it does not go in the report — and that applies to the fusion
function itself as much as to anything it produces.
