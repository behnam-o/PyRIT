import type { ScorerInstance, TargetInstance } from '@/types'
import { parseNewAttackLink, resolveNewAttackLink } from './newAttackLink'

const target: TargetInstance = {
  target_registry_name: 'ctf_llm_01',
  identifier: { class_name: 'OpenAIChatTarget', class_module: 'pyrit.prompt_target', hash: 'target-hash' },
}
const scorer: ScorerInstance = {
  scorer_registry_name: 'ctf_llm_feedback',
  identifier: { class_name: 'WorkshopLLMScorer', class_module: 'workshop', hash: 'score-hash', scorer_type: 'true_false' },
}

describe('new attack links', () => {
  it('decodes encoded objectives and resolves names to current registered identities', () => {
    const fields = parseNewAttackLink('?objective=Explain+%26+test%3F%0Anew+line&target=ctf_llm_01&scorer=ctf_llm_feedback')
    expect(fields).not.toBeNull()
    if (!fields) throw new Error('Expected parsed link')
    expect(resolveNewAttackLink(fields, [target], [scorer])).toEqual({
      objective: 'Explain & test?\nnew line',
      target: { registryName: 'ctf_llm_01', identifierHash: 'target-hash' },
      scorer: { registry_name: 'ctf_llm_feedback', identifier_hash: 'score-hash' },
    })
  })
  it('leaves absent options at their normal defaults', () => {
    expect(parseNewAttackLink('')).toBeNull()
    expect(resolveNewAttackLink({ objective: '' }, [], [])).toEqual({ objective: '' })
  })
  it.each(['?target=https://evil.example', '?target=', '?scorer=a&scorer=b', '?objective=' + 'x'.repeat(10001)])(
    'rejects malformed or duplicate prefill: %s', (query: string) => {
      expect(() => parseNewAttackLink(query)).toThrow()
    },
  )
  it('never silently substitutes an unknown target or scorer', () => {
    expect(() => resolveNewAttackLink({ target: 'missing' }, [target], [scorer])).toThrow('not registered')
    expect(() => resolveNewAttackLink({ scorer: 'missing' }, [target], [scorer])).toThrow('not available')
    expect(() => resolveNewAttackLink({ scorer: scorer.scorer_registry_name }, [target],
      [{ ...scorer, chat_scoring_disabled_reason: 'Not usable in chat' }])).toThrow('not available')
  })
})
