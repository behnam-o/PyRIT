import type { RegisteredComponentReference, ScorerInstance, TargetInstance, TargetReference } from '@/types'
import { isEligibleChatScorer } from '@/utils/scorerPresentation'
import { targetReference } from '@/utils/targetIdentity'

interface NewAttackFields {
  readonly objective?: string
  readonly target?: string
  readonly scorer?: string
}

export function parseNewAttackLink(search: string): NewAttackFields | null {
  const params = new URLSearchParams(search)
  const keys = ['objective', 'target', 'scorer'] as const
  if (!keys.some((key) => params.has(key))) return null
  const fields: { objective?: string; target?: string; scorer?: string } = {}
  for (const key of keys) {
    const values = params.getAll(key)
    if (values.length > 1) throw new Error(`The new attack link contains duplicate ${key} parameters.`)
    if (values.length === 0) continue
    const value = values[0]
    if (value.length > (key === 'objective' ? 10000 : 128)
      || (key !== 'objective' && !/^[A-Za-z0-9_.-]+$/.test(value))) {
      throw new Error(`The new attack link contains an invalid ${key}.`)
    }
    fields[key] = value
  }
  return fields
}

export function resolveNewAttackLink(
  fields: NewAttackFields, targets: TargetInstance[], scorers: ScorerInstance[],
): { objective?: string; target?: TargetReference; scorer?: RegisteredComponentReference } {
  const result: { objective?: string; target?: TargetReference; scorer?: RegisteredComponentReference } = {}
  if (fields.objective !== undefined) result.objective = fields.objective
  if (fields.target !== undefined) {
    const target = targets.find((item) => item.target_registry_name === fields.target)
    if (!target) throw new Error(`Target "${fields.target}" is not registered. Check the link or deployment configuration.`)
    result.target = targetReference(target)
  }
  if (fields.scorer !== undefined) {
    const scorer = scorers.find((item) => item.scorer_registry_name === fields.scorer)
    if (!scorer || !isEligibleChatScorer(scorer)) {
      throw new Error(`Scorer "${fields.scorer}" is not available for chat scoring.`)
    }
    result.scorer = { registry_name: scorer.scorer_registry_name, identifier_hash: scorer.identifier.hash }
  }
  return result
}
