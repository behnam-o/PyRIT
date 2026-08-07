import { FluentProvider, webLightTheme } from '@fluentui/react-components'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { targetsApi } from '@/services/api'

import PersistedTargets from './PersistedTargets'

jest.mock('@/services/api', () => ({
  targetsApi: {
    listPersistedTargets: jest.fn(),
    createPersistedTarget: jest.fn(),
    deletePersistedTarget: jest.fn(),
  },
}))

const mockedTargetsApi = jest.mocked(targetsApi)

function TestWrapper({ children }: { children: React.ReactNode }) {
  return <FluentProvider theme={webLightTheme}>{children}</FluentProvider>
}

describe('PersistedTargets', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockedTargetsApi.listPersistedTargets.mockResolvedValue({
      items: [{
        id: 'target-id',
        display_name: 'Production responses',
        endpoint: 'https://example.openai.azure.com',
        model_name: 'gpt-4o',
        auth_mode: 'identity',
      }],
    })
  })

  it('renders persisted records without active-target controls', async () => {
    render(<TestWrapper><PersistedTargets /></TestWrapper>)

    expect(await screen.findByText('Production responses')).toBeInTheDocument()
    expect(screen.getByText('gpt-4o')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /set active/i })).not.toBeInTheDocument()
  })

  it('adds a persisted target with a display name', async () => {
    const user = userEvent.setup()
    mockedTargetsApi.createPersistedTarget.mockResolvedValue({
      id: 'new-id',
      display_name: 'Test responses',
      endpoint: 'https://example.test',
      model_name: 'o3',
      auth_mode: 'api_key',
    })
    render(<TestWrapper><PersistedTargets /></TestWrapper>)
    await screen.findByText('Production responses')

    await user.click(screen.getByRole('button', { name: 'Add Target' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Test responses' } })
    fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: 'https://example.test' } })
    fireEvent.change(screen.getByLabelText('Model name'), { target: { value: 'o3' } })
    fireEvent.change(screen.getByLabelText('API key'), { target: { value: 'secret' } })
    await user.click(within(dialog).getByRole('button', { name: 'Add Target' }))

    await waitFor(() => {
      expect(mockedTargetsApi.createPersistedTarget).toHaveBeenCalledWith({
        display_name: 'Test responses',
        endpoint: 'https://example.test',
        model_name: 'o3',
        auth_mode: 'api_key',
        api_key: 'secret',
      })
    })
  })

  it('removes a persisted target by id', async () => {
    const user = userEvent.setup()
    mockedTargetsApi.deletePersistedTarget.mockResolvedValue()
    render(<TestWrapper><PersistedTargets /></TestWrapper>)

    await user.click(await screen.findByRole('button', { name: 'Remove Production responses' }))

    await waitFor(() => expect(mockedTargetsApi.deletePersistedTarget).toHaveBeenCalledWith('target-id'))
    expect(screen.queryByText('Production responses')).not.toBeInTheDocument()
  })
})