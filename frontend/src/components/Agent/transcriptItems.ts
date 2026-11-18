import type { AgentTranscriptItem, BackendMessage, BackendMessagePiece } from '@/types'

interface ToolPayload {
  readonly call_id?: unknown
  readonly name?: unknown
  readonly arguments?: unknown
  readonly output?: unknown
}

function parseToolPayload(value: string): ToolPayload {
  try {
    const parsed: unknown = JSON.parse(value)
    return typeof parsed === 'object' && parsed !== null ? parsed : {}
  } catch {
    return {}
  }
}

function asText(value: unknown): string {
  if (value === undefined) return ''
  return typeof value === 'string' ? value : JSON.stringify(value)
}

function toTranscriptItem(
  piece: BackendMessagePiece,
  role: string,
  outputs: ReadonlyMap<string, string>,
): AgentTranscriptItem | null {
  if (piece.response_error !== 'none') {
    // Saved errors end with a traceback; the first line says what went wrong.
    return { kind: 'error', id: piece.id, text: piece.converted_value.split('\n')[0] ?? '' }
  }
  if (piece.converted_value_data_type === 'function_call') {
    const call = parseToolPayload(piece.converted_value)
    const output = typeof call.call_id === 'string' ? outputs.get(call.call_id) : undefined
    const name = typeof call.name === 'string' ? call.name : 'an unknown tool'
    return { kind: 'tool', id: piece.id, name, arguments: asText(call.arguments), output }
  }
  if (piece.converted_value_data_type === 'text' && (role === 'user' || role === 'assistant')) {
    return { kind: role, id: piece.id, text: piece.converted_value }
  }
  return null
}

/**
 * Turns saved agent messages into chat rows: user and assistant text, one row per tool call
 * with its result, and errors. The system prompt and reasoning are not shown.
 */
export function buildAgentTranscript(messages: readonly BackendMessage[]): AgentTranscriptItem[] {
  const pieces = messages.flatMap((message) =>
    message.message_pieces.map((piece) => ({ piece, role: piece.role ?? message.role })),
  )
  const outputs = new Map<string, string>()
  for (const { piece } of pieces) {
    if (piece.converted_value_data_type !== 'function_call_output') continue
    const result = parseToolPayload(piece.converted_value)
    if (typeof result.call_id === 'string') outputs.set(result.call_id, asText(result.output))
  }
  const items: AgentTranscriptItem[] = []
  for (const { piece, role } of pieces) {
    const item = toTranscriptItem(piece, role, outputs)
    if (item) items.push(item)
  }
  return items
}
