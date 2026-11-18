import { useCallback, useEffect, useState } from 'react'

import { agentSessionsApi } from '@/services/api'
import { toApiError } from '@/services/errors'
import type { AgentSession, AgentSessionMessagesResponse } from '@/types'

/** The longest session title the backend accepts, in characters. */
export const SESSION_TITLE_MAX_LENGTH = 100
// Keys the new chat, which has no session ID yet, in per-session state.
const NEW_CHAT = ''

interface AgentSessions {
  sessions: AgentSession[]
  sessionsError: string
  renameError: string
  /** The open session's conversation, once loaded. */
  conversation: AgentSessionMessagesResponse | null
  conversationError: string
  /** The message the agent is answering in the open session, or the new chat's first message while it starts. */
  pendingText?: string
  sendError: string
  /** Whether the agent is answering a message in this session. */
  isAnswering: (sessionId: string) => boolean
  /** Creates a session titled after its first message; resolves to it, or null if that failed. Send the message with `send`. */
  start: (text: string, targetRegistryName: string) => Promise<AgentSession | null>
  /** Sends to any session; each session answers one message at a time. Resolves to whether the agent replied. */
  send: (sessionId: string, text: string, targetRegistryName: string) => Promise<boolean>
  rename: (sessionId: string, title: string) => Promise<void>
}

/** A copy of the record without the key. */
function withoutEntry<Value>(record: Readonly<Record<string, Value>>, key: string): Record<string, Value> {
  const next = { ...record }
  delete next[key]
  return next
}

/** The newer of two reads of a session, so a load that started before a reply arrived cannot hide the reply. */
function newer(
  current: AgentSessionMessagesResponse | undefined,
  next: AgentSessionMessagesResponse,
): AgentSessionMessagesResponse {
  return current !== undefined && Date.parse(current.session.updated_at) > Date.parse(next.session.updated_at)
    ? current
    : next
}

/** A message as a one-line title, cut to the backend's limit without splitting a character. */
function titleFrom(text: string): string {
  const characters = Array.from(text.trim().split(/\s+/).join(' '))
  return characters.length <= SESSION_TITLE_MAX_LENGTH
    ? characters.join('')
    : `${characters.slice(0, SESSION_TITLE_MAX_LENGTH - 1).join('')}…`
}

/** Loads saved agent sessions and the open one, and sends messages to any session. */
export function useAgentSessions(openSessionId: string | undefined): AgentSessions {
  const [sessions, setSessions] = useState<AgentSession[]>([])
  const [sessionsError, setSessionsError] = useState('')
  const [renameError, setRenameError] = useState('')
  const [conversations, setConversations] = useState<Record<string, AgentSessionMessagesResponse>>({})
  const [loadErrors, setLoadErrors] = useState<Record<string, string>>({})
  const [pending, setPending] = useState<Record<string, string>>({})
  const [sendErrors, setSendErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    let ignore = false
    agentSessionsApi.list()
      .then((result) => { if (!ignore) setSessions(result.items) })
      .catch((cause: unknown) => { if (!ignore) setSessionsError(toApiError(cause).detail) })
    return () => { ignore = true }
  }, [])

  useEffect(() => {
    if (openSessionId === undefined) return
    let ignore = false
    agentSessionsApi.getMessages(openSessionId)
      .then((result) => {
        if (ignore) return
        setConversations((previous) => ({ ...previous, [openSessionId]: newer(previous[openSessionId], result) }))
        setLoadErrors((previous) => withoutEntry(previous, openSessionId))
      })
      .catch((cause: unknown) => {
        if (!ignore) setLoadErrors((previous) => ({ ...previous, [openSessionId]: toApiError(cause).detail }))
      })
    return () => { ignore = true }
  }, [openSessionId])

  const start = useCallback(async (text: string, targetRegistryName: string): Promise<AgentSession | null> => {
    setPending((previous) => ({ ...previous, [NEW_CHAT]: text }))
    setSendErrors((previous) => withoutEntry(previous, NEW_CHAT))
    try {
      const session = await agentSessionsApi.create({
        title: titleFrom(text),
        target_registry_name: targetRegistryName,
      })
      setSessions((previous) => [session, ...previous])
      setConversations((previous) => ({ ...previous, [session.id]: { session, messages: [] } }))
      return session
    } catch (cause: unknown) {
      setSendErrors((previous) => ({ ...previous, [NEW_CHAT]: toApiError(cause).detail }))
      return null
    } finally {
      setPending((previous) => withoutEntry(previous, NEW_CHAT))
    }
  }, [])

  const send = useCallback(async (sessionId: string, text: string, targetRegistryName: string): Promise<boolean> => {
    setPending((previous) => ({ ...previous, [sessionId]: text }))
    setSendErrors((previous) => withoutEntry(previous, sessionId))
    try {
      const result = await agentSessionsApi.send(sessionId, { target_registry_name: targetRegistryName, text })
      setConversations((previous) => ({ ...previous, [sessionId]: newer(previous[sessionId], result) }))
      setSessions((previous) => [result.session, ...previous.filter((session) => session.id !== sessionId)])
      return true
    } catch (cause: unknown) {
      setSendErrors((previous) => ({ ...previous, [sessionId]: toApiError(cause).detail }))
      return false
    } finally {
      setPending((previous) => withoutEntry(previous, sessionId))
    }
  }, [])

  const rename = useCallback(async (sessionId: string, title: string): Promise<void> => {
    setRenameError('')
    try {
      const renamed = await agentSessionsApi.rename(sessionId, { title })
      setSessions((previous) => previous.map((session) => (session.id === renamed.id ? renamed : session)))
    } catch (cause: unknown) {
      setRenameError(toApiError(cause).detail)
    }
  }, [])

  const openKey = openSessionId ?? NEW_CHAT
  return {
    sessions,
    sessionsError,
    renameError,
    conversation: openSessionId === undefined ? null : conversations[openSessionId] ?? null,
    conversationError: openSessionId === undefined ? '' : loadErrors[openSessionId] ?? '',
    pendingText: pending[openKey],
    sendError: sendErrors[openKey] ?? '',
    isAnswering: (sessionId: string) => pending[sessionId] !== undefined,
    start,
    send,
    rename,
  }
}
