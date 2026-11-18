import { useState } from 'react'
import type { FormEvent, KeyboardEvent } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router'
import {
  Button,
  Input,
  MessageBar,
  MessageBarBody,
  Select,
  Spinner,
  Text,
  Textarea,
  mergeClasses,
} from '@fluentui/react-components'
import { ChatAddRegular, CheckmarkRegular, DismissRegular, EditRegular, SendRegular } from '@fluentui/react-icons'

import { SESSION_TITLE_MAX_LENGTH, useAgentSessions } from '@/hooks/useAgentSessions'
import type { AgentSession, TargetInstance } from '@/types'
import { targetModelName, targetType } from '@/utils/targetIdentity'

import AgentTranscript from './AgentTranscript'
import { useAgentPageStyles } from './AgentPage.styles'
import { buildAgentTranscript } from './transcriptItems'

const AGENT_PATH = '/agent'
// Only this target type runs tool calls itself, which the agent relies on.
const AGENT_TARGET_TYPE = 'OpenAIResponseTarget'
// Keys the new chat's draft, which has no session ID yet.
const NEW_CHAT_DRAFT = ''
const EXAMPLE_PROMPTS = [
  'What scenarios can I run, and what do they test?',
  'Show my recent scenario runs and how they went.',
  'Start a small scan of my target with the default techniques.',
] as const

interface AgentPageProps {
  /** Registered targets; the ones that can run tools are offered as the agent's model. */
  targets: TargetInstance[]
  /** Whether the target registry is still loading, so an empty list is not yet meaningful. */
  targetsLoading: boolean
}

interface TitleEdit {
  readonly sessionId: string
  readonly title: string
}

interface StartedSession {
  /** The new-chat history entry that the session was started from. */
  readonly locationKey: string
  readonly sessionId: string
}

function sessionPath(session: AgentSession): string {
  return `${AGENT_PATH}/${encodeURIComponent(session.id)}`
}

function targetLabel(target: TargetInstance): string {
  const model = targetModelName(target)
  return model ? `${target.target_registry_name} (${model})` : target.target_registry_name
}

/** Chat with an agent that uses this PyRIT server's tools, with saved sessions on the side. */
export default function AgentPage({ targets, targetsLoading }: AgentPageProps) {
  const styles = useAgentPageStyles()
  const navigate = useNavigate()
  const location = useLocation()
  const { sessionId: routeSessionId } = useParams<{ sessionId?: string }>()
  const [started, setStarted] = useState<StartedSession | null>(null)
  // The router opens a started session in a transition that commits after this page's own updates, so show the
  // session meanwhile; otherwise the empty new chat flashes in between.
  const sessionId = routeSessionId ?? (started?.locationKey === location.key ? started.sessionId : undefined)
  const agent = useAgentSessions(sessionId)
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [chosenTarget, setChosenTarget] = useState<string | null>(null)
  const [titleEdit, setTitleEdit] = useState<TitleEdit | null>(null)

  const agentTargets = targets.filter((target: TargetInstance) => targetType(target) === AGENT_TARGET_TYPE)
  const agentTargetNames = agentTargets.map((target: TargetInstance) => target.target_registry_name)
  const targetName = [chosenTarget, agent.conversation?.session.target_registry_name]
    .find((name) => name != null && agentTargetNames.includes(name)) ?? agentTargetNames[0] ?? ''
  const draftKey = sessionId ?? NEW_CHAT_DRAFT
  const draft = drafts[draftKey] ?? ''
  const text = draft.trim()
  const canSend = text !== '' && targetName !== '' && agent.pendingText === undefined

  function setDraft(key: string, value: string): void {
    setDrafts((previous) => ({ ...previous, [key]: value }))
  }

  // Puts back a message that was not sent, unless a new one was started in its place.
  function restoreDraft(key: string, value: string): void {
    setDrafts((previous) => (previous[key] ? previous : { ...previous, [key]: value }))
  }

  async function handleSend(): Promise<void> {
    if (!canSend) return
    setDraft(draftKey, '')
    let sendTo = sessionId
    if (sendTo === undefined) {
      const session = await agent.start(text, targetName)
      if (session === null) {
        restoreDraft(NEW_CHAT_DRAFT, text)
        return
      }
      sendTo = session.id
      setStarted({ locationKey: location.key, sessionId: session.id })
      // Replace the new chat, so going back does not reopen it empty.
      void navigate(sessionPath(session), { replace: true })
    }
    if (!(await agent.send(sendTo, text, targetName))) restoreDraft(sendTo, text)
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>): void {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault()
      void handleSend()
    }
  }

  async function handleRename(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (titleEdit === null || titleEdit.title.trim() === '') return
    setTitleEdit(null)
    await agent.rename(titleEdit.sessionId, titleEdit.title)
  }

  const isNewChat = sessionId === undefined && agent.pendingText === undefined
  const isLoading = sessionId !== undefined && agent.conversation === null && agent.conversationError === ''

  return (
    <div className={styles.root}>
      <nav className={styles.sessions} aria-label="Agent sessions">
        <Button
          appearance="primary"
          icon={<ChatAddRegular />}
          className={styles.button}
          onClick={() => { void navigate(AGENT_PATH) }}
        >
          New chat
        </Button>
        {agent.sessionsError && (
          <MessageBar intent="error">
            <MessageBarBody>Could not load sessions: {agent.sessionsError}</MessageBarBody>
          </MessageBar>
        )}
        {agent.renameError && (
          <MessageBar intent="error">
            <MessageBarBody>Could not rename: {agent.renameError}</MessageBarBody>
          </MessageBar>
        )}
        <ul className={styles.sessionList}>
          {agent.sessions.map((session: AgentSession) => (
            <li key={session.id} className={styles.sessionItem}>
              {titleEdit?.sessionId === session.id ? (
                <form className={styles.titleForm} onSubmit={(event) => { void handleRename(event) }}>
                  <Input
                    aria-label="Session title"
                    className={styles.titleInput}
                    value={titleEdit.title}
                    maxLength={SESSION_TITLE_MAX_LENGTH}
                    onChange={(_, data) => setTitleEdit({ sessionId: session.id, title: data.value })}
                    onKeyDown={(event: KeyboardEvent<HTMLInputElement>) => {
                      if (event.key === 'Escape') setTitleEdit(null)
                    }}
                    // eslint-disable-next-line jsx-a11y/no-autofocus -- focus moves into the editor the user just opened
                    autoFocus
                  />
                  <Button
                    type="submit"
                    appearance="subtle"
                    size="small"
                    aria-label="Save title"
                    icon={<CheckmarkRegular />}
                    className={styles.iconButton}
                    disabled={titleEdit.title.trim() === ''}
                  />
                  <Button
                    appearance="subtle"
                    size="small"
                    aria-label="Cancel rename"
                    icon={<DismissRegular />}
                    className={styles.iconButton}
                    onClick={() => setTitleEdit(null)}
                  />
                </form>
              ) : (
                <>
                  <Link
                    to={sessionPath(session)}
                    className={mergeClasses(styles.sessionLink, session.id === sessionId && styles.activeSession)}
                    aria-current={session.id === sessionId ? 'page' : undefined}
                  >
                    <span className={styles.ellipsis}>{session.title}</span>
                    <span className={mergeClasses(styles.ellipsis, styles.sessionTarget)}>
                      {session.target_registry_name}
                    </span>
                  </Link>
                  {agent.isAnswering(session.id) && <Spinner size="extra-tiny" aria-label="The agent is working" />}
                  <Button
                    appearance="subtle"
                    size="small"
                    aria-label={`Rename ${session.title}`}
                    icon={<EditRegular />}
                    className={styles.iconButton}
                    onClick={() => setTitleEdit({ sessionId: session.id, title: session.title })}
                  />
                </>
              )}
            </li>
          ))}
        </ul>
      </nav>

      <section className={styles.chat} aria-label="Agent chat">
        {!targetsLoading && agentTargets.length === 0 && (
          <MessageBar intent="warning" className={styles.notice}>
            <MessageBarBody>
              The agent needs an OpenAIResponseTarget, the target type that can call tools.{' '}
              <Link to="/registry/targets">Add one in the registry.</Link>
            </MessageBarBody>
          </MessageBar>
        )}
        {agent.conversationError && (
          <MessageBar intent="error" className={styles.notice}>
            <MessageBarBody>Could not load this session: {agent.conversationError}</MessageBarBody>
          </MessageBar>
        )}
        {isLoading ? (
          <Spinner className={styles.center} label="Loading conversation…" />
        ) : isNewChat ? (
          <div className={styles.center}>
            <Text as="h1" size={600} weight="semibold">PyRIT agent</Text>
            <Text>Ask about scenarios, techniques, and datasets, start runs, or analyze results.</Text>
            <div className={styles.examples}>
              {EXAMPLE_PROMPTS.map((prompt: string) => (
                <Button key={prompt} className={styles.button} onClick={() => setDraft(draftKey, prompt)}>
                  {prompt}
                </Button>
              ))}
            </div>
          </div>
        ) : (
          <AgentTranscript
            items={agent.conversation ? buildAgentTranscript(agent.conversation.messages) : []}
            pendingText={agent.pendingText}
          />
        )}
        {agent.sendError && (
          <MessageBar intent="error" className={styles.notice}>
            <MessageBarBody>Could not send: {agent.sendError}</MessageBarBody>
          </MessageBar>
        )}
        <div className={styles.composer}>
          <Select
            aria-label="Model"
            className={styles.model}
            value={targetName}
            disabled={agentTargets.length === 0}
            onChange={(_, data) => setChosenTarget(data.value)}
          >
            {agentTargets.map((target: TargetInstance) => (
              <option key={target.target_registry_name} value={target.target_registry_name}>
                {targetLabel(target)}
              </option>
            ))}
          </Select>
          <Textarea
            aria-label="Message the agent"
            className={styles.input}
            placeholder="Ask the agent… (Enter to send, Shift+Enter for a new line)"
            resize="vertical"
            value={draft}
            onChange={(_, data) => setDraft(draftKey, data.value)}
            onKeyDown={handleKeyDown}
          />
          <Button
            appearance="primary"
            aria-label="Send"
            icon={<SendRegular />}
            className={styles.sendButton}
            disabled={!canSend}
            onClick={() => { void handleSend() }}
          />
        </div>
      </section>
    </div>
  )
}
