import type { BackendMessage, BackendMessagePiece, PromptResponseError } from '@/types'

import { buildAgentTranscript } from './transcriptItems'

function piece(
  id: string, role: string, dataType: string, value: string, responseError: PromptResponseError = 'none',
): BackendMessagePiece {
  return {
    id,
    role,
    original_value_data_type: dataType,
    converted_value_data_type: dataType,
    converted_value: value,
    scores: [],
    response_error: responseError,
  }
}

function message(...pieces: BackendMessagePiece[]): BackendMessage {
  return { turn_number: 0, role: pieces[0]?.role ?? 'user', message_pieces: pieces, created_at: '2026-01-01T00:00:00Z' }
}

describe('buildAgentTranscript', () => {
  it('shows text and tool calls with their results, without the system prompt or reasoning', () => {
    const call = { type: 'function_call', call_id: 'call-1', name: 'list_scenarios', arguments: '{}' }
    const result = { type: 'function_call_output', call_id: 'call-1', output: '{"scenarios":[]}' }

    const items = buildAgentTranscript([
      message(piece('system', 'system', 'text', 'You are the PyRIT agent')),
      message(piece('question', 'user', 'text', 'What scenarios exist?')),
      message(
        piece('thinking', 'assistant', 'reasoning', '{"type":"reasoning"}'),
        piece('call', 'assistant', 'function_call', JSON.stringify(call)),
      ),
      message(piece('result', 'tool', 'function_call_output', JSON.stringify(result))),
      message(piece('answer', 'assistant', 'text', 'There are none.')),
    ])

    expect(items).toEqual([
      { kind: 'user', id: 'question', text: 'What scenarios exist?' },
      { kind: 'tool', id: 'call', name: 'list_scenarios', arguments: '{}', output: '{"scenarios":[]}' },
      { kind: 'assistant', id: 'answer', text: 'There are none.' },
    ])
  })

  it('shows the first line of an error and a malformed call without a result', () => {
    const items = buildAgentTranscript([
      message(piece('call', 'assistant', 'function_call', 'not json')),
      message(piece('error', 'assistant', 'text', 'max_tool_rounds=25 exhausted.\nTraceback (most recent call last):', 'processing')),
    ])

    expect(items).toEqual([
      { kind: 'tool', id: 'call', name: 'an unknown tool', arguments: '', output: undefined },
      { kind: 'error', id: 'error', text: 'max_tool_rounds=25 exhausted.' },
    ])
  })
})
