/**
 * The analyst affordances, tested where the logic is — not in the markup.
 *
 * Three of these guard honesty properties rather than convenience:
 *
 *  - a filtered list must state the total, because "12 permissions" and "12 of 122
 *    permissions" are different claims and only one of them is true;
 *  - `collectIocs` must never emit a placeholder or an empty field, because its whole
 *    purpose is to be pasted into a blocklist or a ticket, and a blank line pasted into
 *    a SIEM rule is worse than nothing;
 *  - matching is case- and separator-insensitive because an analyst types `read_sms`,
 *    `READ_SMS` and `read sms` interchangeably and should find the same thing.
 */

import { describe, expect, it } from 'vitest'
import { collectIocs, matches, summarise } from './analyst'

describe('matches', () => {
  it('is case-insensitive', () => {
    expect(matches('android.permission.READ_SMS', 'read_sms')).toBe(true)
    expect(matches('android.permission.READ_SMS', 'READ_SMS')).toBe(true)
  })

  it('ignores separators, so a typed space finds an underscore', () => {
    expect(matches('android.permission.READ_SMS', 'read sms')).toBe(true)
    expect(matches('com.example.app', 'com example')).toBe(true)
  })

  it('matches on any part, not just the start', () => {
    expect(matches('android.permission.SYSTEM_ALERT_WINDOW', 'alert')).toBe(true)
  })

  it('an empty query matches everything, so the list is never empty by default', () => {
    expect(matches('anything', '')).toBe(true)
    expect(matches('anything', '   ')).toBe(true)
  })

  it('does not match what is absent', () => {
    expect(matches('android.permission.INTERNET', 'camera')).toBe(false)
  })

  it('searches every field it is given, not only the first', () => {
    expect(matches(['MainActivity', 'activity', 'exported'], 'exported')).toBe(true)
  })
})

describe('summarise', () => {
  it('states the total whenever a filter is hiding something', () => {
    expect(summarise(12, 122)).toBe('showing 12 of 122')
  })

  it('says only the count when nothing is hidden', () => {
    expect(summarise(122, 122)).toBe('122')
  })

  it('is explicit when a filter matched nothing', () => {
    expect(summarise(0, 122)).toBe('no matches in 122')
  })

  it('handles an empty source without claiming a filter hid it', () => {
    expect(summarise(0, 0)).toBe('none')
  })
})

describe('collectIocs', () => {
  const full = {
    sha256: 'a'.repeat(64),
    packageName: 'com.evil.app',
    hosts: ['c2.example', 'ip-api.com'],
    urls: ['http://c2.example/api/v1', 'http://ip-api.com/json'],
  }

  it('produces one indicator per line, ready to paste', () => {
    const lines = collectIocs(full).split('\n').filter(Boolean)
    expect(lines).toContain('sha256:' + 'a'.repeat(64))
    expect(lines).toContain('package:com.evil.app')
    expect(lines).toContain('host:c2.example')
    expect(lines).toContain('url:http://c2.example/api/v1')
  })

  it('omits fields that are absent rather than emitting a blank', () => {
    const text = collectIocs({ sha256: null, packageName: null, hosts: [], urls: [] })
    expect(text).toBe('')
  })

  it('never emits a line with nothing after the prefix', () => {
    const text = collectIocs({ sha256: '', packageName: '  ', hosts: [''], urls: ['  '] })
    expect(text).toBe('')
  })

  it('de-duplicates, because the same host appears in many flows', () => {
    const text = collectIocs({
      sha256: null,
      packageName: null,
      hosts: ['c2.example', 'c2.example'],
      urls: [],
    })
    expect(text.split('\n').filter(Boolean)).toEqual(['host:c2.example'])
  })

  it('keeps a stable order so two copies of the same job compare equal', () => {
    expect(collectIocs(full)).toBe(collectIocs({ ...full, hosts: [...full.hosts].reverse() }))
  })
})
