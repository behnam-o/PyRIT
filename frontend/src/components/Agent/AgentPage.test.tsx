import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FluentProvider, webLightTheme } from '@fluentui/react-components'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'

import { agentSessionsApi } from '@/services/api'
import { deferred } from '@/test-utils/deferred'
import { makeTarget } from '@/test-utils/targetFixtures'
import type { AgentSession, AgentSessionMessagesResponse, BackendMessage, TargetInstance } from '@/types'

import AgentPage from './AgentPage'

jest.mock('@/services/api', () => ({
  agentSessionsApi: { list: jest.fn(), getMessages: jest.fn(), create: jest.fn(), rename: jest.fn(), send: jest.fn() },
}))

const TARGETS: TargetInstance[] = [
  makeTarget({ target_registry_name: 'responses', target_type: 'OpenAIResponseTarget', model_name: 'gpt-5' }),
  makeTarget({ target_registry_name: 'other-responses', target_type: 'OpenAIResponseTarget' }),
  makeTarget({ target_registry_name: 'chat', target_type: 'OpenAIChatTarget' }),
]
const SAVED: AgentSession = {
  id: 'saved',
  title: 'Which scenarios exist?',
  target_registry_name: 'other-responses',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}
const OTHER: AgentSession = { ...SAVED, id: 'other', title: 'Recent runs', target_registry_name: 'responses' }

function textMessage(id: string, role: string, value: string, dataType = 'text'): BackendMessage {
  return {
    turn_number: 0,
    role,
    created_at: '2026-01-01T00:00:00Z',
    message_pieces: [{
      id,
      role,
      original_value_data_type: dataType,
      converted_value_data_type: dataType,
      converted_value: value,
      scores: [],
      response_error: 'none',
    }],
  }
}

function conversation(session: AgentSession, ...messages: BackendMessage[]): AgentSessionMessagesResponse {
  return { session, messages }
}

function LocationProbe() {
  return <span data-testid="location">{useLocation().pathname}</span>
}

function renderPage(path: string, targets: TargetInstance[] = TARGETS, targetsLoading = false): void {
  render(
    <FluentProvider theme={webLightTheme}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/agent/:sessionId?"
            element={<><AgentPage targets={targets} targetsLoading={targetsLoading} /><LocationProbe /></>}
          />
          <Route path="/registry/targets" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    </FluentProvider>,
  )
}

describe('AgentPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.mocked(agentSessionsApi.list).mockResolvedValue({ items: [SAVED] })
  })

  it('creates a session titled after the first message, opens it, and sends the message to it', async () => {
    const user = userEvent.setup()
    const created = { ...SAVED, id: 'created', title: 'Hello there', target_registry_name: 'responses' }
    const answered = { ...created, updated_at: '2026-01-01T00:00:05Z' }
    const loading = deferred<AgentSessionMessagesResponse>()
    jest.mocked(agentSessionsApi.create).mockResolvedValue(created)
    jest.mocked(agentSessionsApi.getMessages).mockReturnValue(loading.promise)
    jest.mocked(agentSessionsApi.send).mockResolvedValue(conversation(
      answered,
      textMessage('u', 'user', 'Hello\n there'),
      textMessage('a', 'assistant', 'Hi there.'),
    ))
    renderPage('/agent')

    const model = screen.getByRole('combobox', { name: 'Model' })
    expect(within(model).getAllByRole('option').map((option) => option.textContent)).toEqual([
      'responses (gpt-5)',
      'other-responses',
    ])
    await user.type(screen.getByRole('textbox', { name: 'Message the agent' }), 'Hello{Shift>}{Enter}{/Shift} there{Enter}')

    expect(await screen.findByText('Hi there.')).toBeInTheDocument()
    expect(agentSessionsApi.create).toHaveBeenCalledWith({ title: 'Hello there', target_registry_name: 'responses' })
    expect(agentSessionsApi.send).toHaveBeenCalledWith('created', {
      target_registry_name: 'responses',
      text: 'Hello\n there',
    })
    expect(screen.getByTestId('location')).toHaveTextContent('/agent/created')
    expect(screen.getByRole('link', { name: /^Hello there/ })).toHaveAttribute('aria-current', 'page')

    // A load that started before the reply arrived must not hide the reply.
    expect(agentSessionsApi.getMessages).toHaveBeenCalledWith('created')
    await act(async () => { loading.resolve(conversation(created)) })
    expect(screen.getByText('Hi there.')).toBeInTheDocument()
  })

  it('opens a saved session with collapsed tool calls and continues it with its model', async () => {
    const user = userEvent.setup()
    const call = { type: 'function_call', call_id: 'call-1', name: 'list_scenarios', arguments: '{}' }
    const result = { type: 'function_call_output', call_id: 'call-1', output: '{"scenarios":["foundry"]}' }
    jest.mocked(agentSessionsApi.getMessages).mockResolvedValue(conversation(
      SAVED,
      textMessage('s', 'system', 'You are the PyRIT agent'),
      textMessage('u', 'user', 'Which scenarios exist?'),
      textMessage('c', 'assistant', JSON.stringify(call), 'function_call'),
      textMessage('o', 'tool', JSON.stringify(result), 'function_call_output'),
      textMessage('a', 'assistant', 'Only **foundry**.'),
    ))
    const sending = deferred<AgentSessionMessagesResponse>()
    jest.mocked(agentSessionsApi.send).mockReturnValue(sending.promise)
    renderPage('/agent/saved')

    expect(await screen.findByText('foundry')).toBeInTheDocument()
    expect(agentSessionsApi.getMessages).toHaveBeenCalledWith('saved')
    expect(screen.queryByText('You are the PyRIT agent')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Used list_scenarios' }))
    expect(screen.getByText(/"foundry"/)).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Model' })).toHaveValue('other-responses')

    await user.type(screen.getByRole('textbox', { name: 'Message the agent' }), 'Run it')
    await user.click(screen.getByRole('button', { name: 'Send' }))

    expect(agentSessionsApi.send).toHaveBeenCalledWith('saved', { target_registry_name: 'other-responses', text: 'Run it' })
    expect(screen.getByText('The agent is working…')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    sending.resolve(conversation(SAVED, textMessage('u2', 'user', 'Run it'), textMessage('a2', 'assistant', 'Started.')))
    expect(await screen.findByText('Started.')).toBeInTheDocument()
    expect(screen.queryByText('The agent is working…')).not.toBeInTheDocument()
  })

  it('lets other sessions chat while one is answering, and keeps a failed message in its own session', async () => {
    const user = userEvent.setup()
    jest.mocked(agentSessionsApi.list).mockResolvedValue({ items: [SAVED, OTHER] })
    jest.mocked(agentSessionsApi.getMessages).mockImplementation(async (sessionId: string) =>
      conversation(sessionId === OTHER.id ? OTHER : SAVED))
    const slowSend = deferred<AgentSessionMessagesResponse>()
    jest.mocked(agentSessionsApi.send)
      .mockReturnValueOnce(slowSend.promise)
      .mockResolvedValueOnce(conversation(OTHER, textMessage('u', 'user', 'Any runs?'), textMessage('a', 'assistant', 'None yet.')))
    renderPage('/agent/saved')
    const sessions = screen.getByRole('navigation', { name: 'Agent sessions' })
    const composer = screen.getByRole('textbox', { name: 'Message the agent' })

    await user.type(composer, 'Run it{Enter}')
    await user.type(composer, 'And then?')
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(within(sessions).getByRole('progressbar', { name: 'The agent is working' })).toBeInTheDocument()
    await user.clear(composer)

    await user.click(within(sessions).getByRole('link', { name: /^Recent runs/ }))
    expect(screen.queryByText('The agent is working…')).not.toBeInTheDocument()
    await user.type(composer, 'Any runs?{Enter}')
    expect(await screen.findByText('None yet.')).toBeInTheDocument()

    slowSend.reject(new Error('Model timed out'))
    await waitFor(() => { expect(within(sessions).queryByRole('progressbar')).not.toBeInTheDocument() })
    expect(screen.queryByText(/Could not send/)).not.toBeInTheDocument()
    expect(composer).toHaveValue('')

    await user.click(within(sessions).getByRole('link', { name: /^Which scenarios exist\?/ }))
    expect(await screen.findByText(/Could not send: Model timed out/)).toBeInTheDocument()
    expect(composer).toHaveValue('Run it')
  })

  it('renames a session from the list, or leaves it unchanged on Escape', async () => {
    const user = userEvent.setup()
    jest.mocked(agentSessionsApi.rename).mockResolvedValue({ ...SAVED, title: 'Scenario ideas' })
    renderPage('/agent')

    await user.click(await screen.findByRole('button', { name: 'Rename Which scenarios exist?' }))
    await user.type(screen.getByRole('textbox', { name: 'Session title' }), ' (draft){Escape}')
    expect(screen.getByRole('link', { name: /^Which scenarios exist\?/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Rename Which scenarios exist?' }))
    const title = screen.getByRole('textbox', { name: 'Session title' })
    expect(title).toHaveValue('Which scenarios exist?')
    await user.clear(title)
    await user.type(title, 'Scenario ideas{Enter}')

    expect(await screen.findByRole('link', { name: /^Scenario ideas/ })).toBeInTheDocument()
    expect(agentSessionsApi.rename).toHaveBeenCalledTimes(1)
    expect(agentSessionsApi.rename).toHaveBeenCalledWith('saved', { title: 'Scenario ideas' })
  })

  it('keeps the first message and shows why when a session cannot be created', async () => {
    const user = userEvent.setup()
    jest.mocked(agentSessionsApi.create).mockRejectedValue(new Error('Target is unavailable'))
    renderPage('/agent')

    await user.click(screen.getByRole('button', { name: 'What scenarios can I run, and what do they test?' }))
    await user.click(screen.getByRole('button', { name: 'Send' }))

    expect(await screen.findByText(/Could not send: Target is unavailable/)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveValue(
      'What scenarios can I run, and what do they test?',
    )
    expect(agentSessionsApi.send).not.toHaveBeenCalled()
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/agent$/)
  })

  it('shows load errors for the session list and the open session', async () => {
    jest.mocked(agentSessionsApi.list).mockRejectedValue(new Error('List failed'))
    jest.mocked(agentSessionsApi.getMessages).mockRejectedValue(new Error('Session failed'))
    renderPage('/agent/saved')

    expect(await screen.findByText(/Could not load sessions: List failed/)).toBeInTheDocument()
    expect(await screen.findByText(/Could not load this session: Session failed/)).toBeInTheDocument()
  })

  it('asks for a target that can run tools when none is registered', async () => {
    const user = userEvent.setup()
    renderPage('/agent', [TARGETS[2] as TargetInstance])

    expect(screen.getByRole('combobox', { name: 'Model' })).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: 'Message the agent' }), 'Hello')
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    await user.click(screen.getByRole('link', { name: 'Add one in the registry.' }))
    await waitFor(() => { expect(screen.getByTestId('location')).toHaveTextContent('/registry/targets') })
  })

  it('does not ask for a target while targets are still loading', async () => {
    renderPage('/agent', [], true)

    expect(await screen.findByRole('heading', { name: 'PyRIT agent' })).toBeInTheDocument()
    expect(screen.queryByText(/The agent needs an OpenAIResponseTarget/)).not.toBeInTheDocument()
  })
})
