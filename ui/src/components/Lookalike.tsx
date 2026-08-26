/**
 * "Truecaller reads your SMS too. Here is why we flag one and not the other."
 *
 * The panel for contract A13 (`m2_static/lookalike.py`). It is the answer to the only
 * question a room ever asks a detector — *does it just flag everything?* — and the
 * order of the panel is the argument:
 *
 *   1. what this sample has in COMMON with software the reader already trusts,
 *   2. only then, what separates them.
 *
 * Reversing that order would make it read like every other permission report, which
 * is exactly the failure the module was written to avoid.
 *
 * Absent signals are drawn, never dropped. On a sample that is not blocked, the list
 * of things we looked for and did not find IS the evidence — a panel that only ever
 * showed what fired would be empty for precisely the app we most need to explain.
 *
 * No colour claims safety. `indeterminate` is drawn neutral rather than green,
 * because the module never returns "benign" and this panel must not imply one.
 */

import { Panel, Tag } from './primitives'
import type { BenignLookalikeVerdict, LookalikeAssessment, LookalikeSignal } from '../api/types'

const VERDICT_LABEL: Record<BenignLookalikeVerdict, string> = {
  trojan_shape: 'trojan shape',
  legitimate_privileged: 'legitimate privileged app',
  indeterminate: 'indeterminate',
}

const VERDICT_TONE: Record<BenignLookalikeVerdict, 'bad' | 'good' | 'neutral'> = {
  trojan_shape: 'bad',
  // A statement about the signer, not a clean bill of health for the code — hence
  // the tooltip on the tag rather than an unqualified green.
  legitimate_privileged: 'good',
  indeterminate: 'neutral',
}

/** Signal ids in words an analyst reads once, not identifiers they decode. */
const SIGNAL_LABEL: Record<string, string> = {
  financial_app_roster: 'carries a roster of banking / UPI packages',
  sms_and_network_share_entrypoint: 'reads messages on the same path that talks to the network',
  otp_lexicon: 'cares about OTPs and card numbers specifically',
  overlay_after_package_enumeration: 'picks what to draw over after asking what is installed',
  launcher_icon_hiding: 'can hide its own launcher icon',
  accessibility_acts_on_the_user: 'uses accessibility to tap on the user’s behalf',
  second_stage_dropper: 'can load a second stage',
  freshly_minted_certificate: 'signed by an unknown key minted days ago',
}

function label(signal: LookalikeSignal): string {
  return SIGNAL_LABEL[signal.id] ?? signal.id.replace(/_/g, ' ')
}

function SignalRow({ signal }: { signal: LookalikeSignal }) {
  return (
    <li className="flex items-start gap-2 border-b border-line-soft py-1.5 last:border-0">
      <span
        aria-hidden
        className={`mt-0.5 font-mono text-xs ${signal.present ? 'text-bad' : 'text-good'}`}
      >
        {signal.present ? '✕' : '✓'}
      </span>
      <span className="flex-1">
        <span className={`text-sm ${signal.present ? 'text-fg' : 'text-muted'}`}>
          {label(signal)}
        </span>
        <span className="mt-0.5 block text-[11px] text-muted">{signal.detail}</span>
      </span>
      <span className="font-mono text-[11px] text-dim" title="weight in the trojan-shape score">
        {signal.weight.toFixed(2)}
      </span>
    </li>
  )
}

export function LookalikePanel({ lookalike }: { lookalike: LookalikeAssessment }) {
  const present = lookalike.signals.filter((s) => s.present)
  const absent = lookalike.signals.filter((s) => !s.present)

  return (
    <Panel
      title="Is this just a privileged app?"
      subtitle="The permission is the capability. It is not the intent."
      right={
        <div className="flex items-center gap-2">
          <Tag
            tone={VERDICT_TONE[lookalike.verdict]}
            title={
              lookalike.verdict === 'legitimate_privileged'
                ? 'A statement about the signer, not a certification of the code.'
                : 'This module never returns "benign". Indeterminate is the best available.'
            }
          >
            {VERDICT_LABEL[lookalike.verdict]}
          </Tag>
          <span className="font-mono text-[11px] text-muted">
            trojan-shape {lookalike.trojan_score.toFixed(2)}
          </span>
        </div>
      }
    >
      <div className="space-y-4">
        {lookalike.shared_permissions.length > 0 && (
          <div className="rounded border border-line-soft bg-ground-2 p-3">
            <p className="text-sm text-fg">
              Holds{' '}
              <span className="font-semibold">{lookalike.shared_permissions.length}</span>{' '}
              permission{lookalike.shared_permissions.length === 1 ? '' : 's'} that caller-ID,
              SMS-backup and anti-spam apps hold too.
            </p>
            <p className="mt-1 text-xs text-muted">
              Truecaller reads your SMS as well. The permission set alone is not the finding —
              these capabilities are shared with software half of India already trusts.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {lookalike.shared_permissions.map((permission) => (
                <span
                  key={permission}
                  title={permission}
                  className="rounded bg-ground px-1.5 py-0.5 font-mono text-[10px] text-muted"
                >
                  {permission.split('.').pop()}
                </span>
              ))}
            </div>
          </div>
        )}

        {lookalike.targeted_financial_packages.length > 0 && (
          <div className="rounded border border-bad/40 bg-bad/5 p-3">
            <p className="text-sm text-bad">
              References {lookalike.targeted_financial_packages.length} known banking / UPI
              package{lookalike.targeted_financial_packages.length === 1 ? '' : 's'}.
            </p>
            <p className="mt-1 text-xs text-muted">
              This is the discriminator that carries the most weight. A caller-ID app does not
              ship a list of Indian bank package names; an app that chooses what to draw over
              does.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {lookalike.targeted_financial_packages.map((pkg) => (
                <span key={pkg} className="rounded bg-ground px-1.5 py-0.5 font-mono text-[10px] text-bad">
                  {pkg}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <h4 className="text-xs font-semibold tracking-wide text-fg uppercase">
              What separates it from those apps
            </h4>
            {present.length === 0 ? (
              <p className="mt-2 text-sm text-muted italic">
                No trojan-shape signal fired.
              </p>
            ) : (
              <ul className="mt-1">
                {present.map((signal) => (
                  <SignalRow key={signal.id} signal={signal} />
                ))}
              </ul>
            )}
          </div>
          <div>
            <h4 className="text-xs font-semibold tracking-wide text-muted uppercase">
              Looked for and did not find
            </h4>
            {absent.length === 0 ? (
              <p className="mt-2 text-sm text-muted italic">Every signal fired.</p>
            ) : (
              <ul className="mt-1">
                {absent.map((signal) => (
                  <SignalRow key={signal.id} signal={signal} />
                ))}
              </ul>
            )}
          </div>
        </div>

        <p className="border-t border-line-soft pt-3 text-xs text-muted">{lookalike.rationale}</p>
      </div>
    </Panel>
  )
}
