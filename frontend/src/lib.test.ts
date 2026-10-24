import { describe, expect, it } from 'vitest'
import { shortHash, statusLabel } from './lib'

describe('display helpers', () => {
  it('turns persisted status values into readable labels', () => {
    expect(statusLabel('no_evidence_backed_risk_findings')).toBe('No Evidence Backed Risk Findings')
  })

  it('shortens immutable identifiers without changing short values', () => {
    expect(shortHash('0123456789abcdef')).toBe('0123456789ab…')
    expect(shortHash('deadbeef')).toBe('deadbeef')
  })
})
