import type { ReactNode } from 'react'

import { FluentProvider, webLightTheme } from '@fluentui/react-components'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useLocation } from 'react-router'

import { datasetsApi } from '@/services/api'
import type { DatasetInfo, DatasetSeed, DatasetSeedsResponse } from '@/types'

import DatasetBrowser from './DatasetBrowser'

jest.mock('@/services/api', () => ({
  datasetsApi: { listDatasets: jest.fn(), listSeeds: jest.fn(), loadDataset: jest.fn() },
}))

const mockListDatasets = jest.mocked(datasetsApi.listDatasets)
const mockListSeeds = jest.mocked(datasetsApi.listSeeds)
const mockLoadDataset = jest.mocked(datasetsApi.loadDataset)

const ALPHA: DatasetInfo = { name: 'alpha', is_loaded: true, can_load: true }
const LOCAL: DatasetInfo = { name: 'local/example', is_loaded: true, can_load: true }

const SEED: DatasetSeed = {
  id: 'seed-1',
  name: 'Greeting',
  value: 'Hello, {{name}}!\nA second line.',
  data_type: 'text',
  seed_type: 'prompt',
  role: 'user',
  language: 'en',
  group_id: 'group-1',
  sequence: 0,
}

function seedPage(items: DatasetSeed[] = [SEED], total = items.length, offset = 0): DatasetSeedsResponse {
  return { items, total, offset, limit: 25 }
}

function TestWrapper({ children }: { readonly children: ReactNode }) {
  return <FluentProvider theme={webLightTheme}>{children}</FluentProvider>
}

function LocationDisplay() {
  const location = useLocation()
  return <output aria-label="Current URL">{location.pathname}{location.search}</output>
}

function renderBrowser(path = '/datasets') {
  return render(
    <TestWrapper>
      <MemoryRouter initialEntries={[path]}>
        <DatasetBrowser />
        <LocationDisplay />
      </MemoryRouter>
    </TestWrapper>,
  )
}

describe('DatasetBrowser', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockListDatasets.mockResolvedValue({ items: [ALPHA, LOCAL] })
    mockListSeeds.mockResolvedValue(seedPage())
    mockLoadDataset.mockResolvedValue(ALPHA)
  })

  it('should search dataset names without loading seeds until one is selected', async () => {
    const user = userEvent.setup()
    renderBrowser()

    expect(screen.getByText('Select a dataset to view its seeds.')).toBeInTheDocument()
    await screen.findByRole('button', { name: 'alpha' })
    await user.type(screen.getByRole('textbox', { name: 'Search datasets' }), ' LOCAL ')
    expect(screen.getByRole('button', { name: 'local/example' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'alpha' })).not.toBeInTheDocument()
    expect(screen.getByText('1 of 2 datasets')).toBeInTheDocument()
    expect(mockListSeeds).not.toHaveBeenCalled()
    expect(mockLoadDataset).not.toHaveBeenCalled()

    await user.clear(screen.getByRole('textbox', { name: 'Search datasets' }))
    await user.type(screen.getByRole('textbox', { name: 'Search datasets' }), 'missing')
    expect(screen.getByText('No datasets match your search.')).toBeInTheDocument()
  })

  it('should select a dataset, persist its name in the URL, and copy an expanded seed', async () => {
    const user = userEvent.setup()
    const writeText = jest.spyOn(navigator.clipboard, 'writeText')
    renderBrowser()

    await user.click(await screen.findByRole('button', { name: 'local/example' }))
    expect(mockListSeeds).toHaveBeenCalledWith('local/example', 25, 0)
    expect(screen.getByLabelText('Current URL')).toHaveTextContent('/datasets?dataset=local%2Fexample')
    expect(screen.getByRole('button', { name: 'local/example' })).toHaveAttribute('aria-pressed', 'true')
    await user.click(await screen.findByRole('button', { name: 'Expand seed 1' }))
    expect(screen.getByLabelText('Seed value')).toHaveTextContent('Hello, {{name}}!')
    expect(JSON.parse(screen.getByLabelText('Seed 1 JSON').textContent ?? '')).toEqual(SEED)
    await user.click(screen.getByRole('button', { name: 'Copy value' }))
    expect(writeText).toHaveBeenCalledWith(SEED.value)
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('should open a dataset from a deep link and paginate loaded seeds', async () => {
    const user = userEvent.setup()
    mockListSeeds.mockResolvedValueOnce(seedPage([SEED], 26))
      .mockResolvedValueOnce(seedPage([{ ...SEED, id: 'seed-26', name: 'Last seed' }], 26, 25))
      .mockResolvedValueOnce(seedPage([SEED], 26))
    renderBrowser('/datasets?dataset=alpha')

    expect(await screen.findByText('1-1 of 26 seeds')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('26-26 of 26 seeds')).toBeInTheDocument()
    expect(mockListSeeds).toHaveBeenLastCalledWith('alpha', 25, 25)
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Previous' }))
    expect(await screen.findByText('Greeting')).toBeInTheDocument()
    expect(mockListSeeds).toHaveBeenLastCalledWith('alpha', 25, 0)
  })

  it('should reset pagination when selecting another dataset and ignore late responses', async () => {
    const user = userEvent.setup()
    let resolveOldPage: (response: DatasetSeedsResponse) => void = () => {
      throw new Error('Old page request has not started')
    }
    mockListSeeds.mockResolvedValueOnce(seedPage([SEED], 26))
      .mockImplementationOnce(() => new Promise<DatasetSeedsResponse>((resolve) => { resolveOldPage = resolve }))
      .mockResolvedValueOnce(seedPage([{ ...SEED, id: 'new', name: 'New dataset seed' }]))
    renderBrowser('/datasets?dataset=alpha')

    await user.click(await screen.findByRole('button', { name: 'Next' }))
    await user.click(screen.getByRole('button', { name: 'local/example' }))
    expect(await screen.findByText('New dataset seed')).toBeInTheDocument()
    await act(async () => { resolveOldPage(seedPage([SEED], 26, 25)) })
    expect(screen.queryByText('Greeting')).not.toBeInTheDocument()
    expect(mockListSeeds).toHaveBeenLastCalledWith('local/example', 25, 0)
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled()
  })

  it('should show no loaded seeds without suggesting that browsing downloads a dataset', async () => {
    mockListSeeds.mockResolvedValue(seedPage([]))
    renderBrowser('/datasets?dataset=alpha')
    expect(await screen.findByText('No loaded seeds')).toBeInTheDocument()
    expect(screen.getByText(/Browsing alone does not download datasets/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument()
  })

  it('should show a loading state and an empty catalog', async () => {
    mockListDatasets.mockResolvedValue({ items: [] })
    renderBrowser()
    expect(screen.getByText('Loading datasets...')).toBeInTheDocument()
    expect(await screen.findByText('No datasets available.')).toBeInTheDocument()
  })

  it('should display dataset errors and allow retry', async () => {
    const user = userEvent.setup()
    mockListDatasets.mockRejectedValueOnce(new Error('Catalog unavailable'))
    renderBrowser()
    expect(await screen.findByText(/Could not load datasets/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('button', { name: 'alpha' })).toBeInTheDocument()
    expect(mockListDatasets).toHaveBeenCalledTimes(2)
  })

  it('should display seed errors and allow retry', async () => {
    const user = userEvent.setup()
    mockListSeeds.mockRejectedValueOnce(new Error('Seeds unavailable'))
    renderBrowser('/datasets?dataset=alpha')
    expect(await screen.findByText(/Could not load seeds/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Greeting')).toBeInTheDocument()
    expect(mockListSeeds).toHaveBeenCalledTimes(2)
  })

  it('should refresh both the catalog and selected dataset while preserving search', async () => {
    const user = userEvent.setup()
    renderBrowser('/datasets?dataset=alpha')
    await screen.findByText('Greeting')
    await user.type(screen.getByRole('textbox', { name: 'Search datasets' }), 'alp')
    await user.click(screen.getByRole('button', { name: 'Refresh' }))
    await waitFor(() => { expect(mockListSeeds).toHaveBeenCalledTimes(2) })
    expect(mockListDatasets).toHaveBeenCalledTimes(2)
    expect(await screen.findByText('Greeting')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Search datasets' })).toHaveValue('alp')
  })

  it('should display clipboard failure instead of claiming success', async () => {
    const user = userEvent.setup()
    jest.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('Permission denied'))
    renderBrowser('/datasets?dataset=alpha')
    await user.click(await screen.findByRole('button', { name: 'Expand seed 1' }))
    await user.click(screen.getByRole('button', { name: 'Copy value' }))
    expect(await screen.findByText(/Could not copy/)).toBeInTheDocument()
    expect(screen.queryByText('Copied')).not.toBeInTheDocument()
  })

  it('should display non-text values as inert references and preserve literal template text', async () => {
    const user = userEvent.setup()
    mockListSeeds.mockResolvedValue(seedPage([{
      ...SEED, name: null, value: 'https://example.test/{{image}}.png',
      data_type: 'image_path', role: null, language: null, group_id: null, sequence: null,
    }]))
    renderBrowser('/datasets?dataset=alpha')
    expect(await screen.findByLabelText('Seed value')).toHaveTextContent('https://example.test/{{image}}.png')
    await user.click(screen.getByRole('button', { name: 'Expand seed 1' }))
    expect(screen.getByText('Stored value only; media is not opened.')).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })

  it('should show type and content columns while keeping metadata collapsed', async () => {
    renderBrowser('/datasets?dataset=alpha')
    const table = await screen.findByRole('table', { name: 'Dataset seed contents' })
    expect(within(table).getAllByRole('columnheader').map((cell: HTMLElement) => cell.textContent))
      .toEqual(['Seed / data type', 'Content'])
    const row = within(table).getAllByRole('row')[1]
    const cells = within(row).getAllByRole('cell')
    expect(cells).toHaveLength(2)
    expect(cells[0]).toHaveTextContent('prompt')
    expect(cells[0]).toHaveTextContent('text')
    expect(cells[1]).toHaveTextContent('Hello, {{name}}!')
    expect(screen.getByRole('button', { name: 'Expand seed 1' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText('Seed 1 JSON')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Copy value' })).not.toBeInTheDocument()
  })

  it('should expand a prettified JSON record with content, types, and metadata using the keyboard', async () => {
    const user = userEvent.setup()
    renderBrowser('/datasets?dataset=alpha')
    const expand = await screen.findByRole('button', { name: 'Expand seed 1' })
    expand.focus()
    await user.keyboard('{Enter}')
    const details = screen.getByRole('group', { name: 'Seed 1 details' })
    const json = within(details).getByLabelText('Seed 1 JSON').textContent ?? ''
    expect(JSON.parse(json)).toEqual(SEED)
    expect(json).toContain('\n  "seed_type": "prompt",\n  "data_type": "text",\n  "value": ')
    expect(screen.getByRole('button', { name: 'Collapse seed 1' })).toHaveAttribute('aria-expanded', 'true')
    await user.keyboard(' ')
    expect(screen.queryByRole('group', { name: 'Seed 1 details' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Expand seed 1' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('should expand only the chosen row and number rows across pages', async () => {
    const user = userEvent.setup()
    mockListSeeds.mockResolvedValueOnce(seedPage([SEED, { ...SEED, id: 'seed-2', name: null }], 26))
      .mockResolvedValueOnce(seedPage([{ ...SEED, id: 'seed-26', name: null }], 26, 25))
    renderBrowser('/datasets?dataset=alpha')
    await user.click(await screen.findByRole('button', { name: 'Expand seed 2' }))
    expect(JSON.parse(screen.getByLabelText('Seed 2 JSON').textContent ?? '')).toEqual({
      ...SEED, id: 'seed-2', name: null,
    })
    expect(screen.queryByLabelText('Seed 1 JSON')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByRole('button', { name: 'Expand seed 26' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText('Seed 2 JSON')).not.toBeInTheDocument()
  })

  it('should copy the complete JSON record without altering content or dropping null fields', async () => {
    const user = userEvent.setup()
    const writeText = jest.spyOn(navigator.clipboard, 'writeText')
    const seed: DatasetSeed = { ...SEED, value: 'Hello "{{name}}"!\nNext line\\path', group_id: null, name: null }
    mockListSeeds.mockResolvedValue(seedPage([seed]))
    renderBrowser('/datasets?dataset=alpha')
    await user.click(await screen.findByRole('button', { name: 'Expand seed 1' }))
    const displayedJson = screen.getByLabelText('Seed 1 JSON').textContent ?? ''
    await user.click(screen.getByRole('button', { name: 'Copy JSON' }))
    expect(writeText).toHaveBeenCalledWith(displayedJson)
    expect(JSON.parse(displayedJson)).toEqual(seed)
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('should label empty content while copying the original empty value', async () => {
    const user = userEvent.setup()
    const writeText = jest.spyOn(navigator.clipboard, 'writeText')
    mockListSeeds.mockResolvedValue(seedPage([{ ...SEED, value: '', name: null }]))
    renderBrowser('/datasets?dataset=alpha')
    expect(await screen.findByText('(Empty value)')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Expand seed 1' }))
    await user.click(screen.getByRole('button', { name: 'Copy value' }))
    expect(writeText).toHaveBeenCalledWith('')
  })

  it('should replace the load action with a single loaded indicator in both panels', async () => {
    mockListDatasets.mockResolvedValue({ items: [ALPHA, { ...LOCAL, can_load: false }] })
    renderBrowser('/datasets?dataset=alpha')

    const catalog = screen.getByRole('region', { name: 'Dataset catalog' })
    expect(await within(catalog).findByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
    expect(within(catalog).getByRole('button', { name: 'Loaded local/example' })).toBeDisabled()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load alpha' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load local/example' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Dataset seeds' }))
      .getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
    expect(mockLoadDataset).not.toHaveBeenCalled()
  })

  it.each(['Dataset catalog', 'Dataset seeds'])(
    'should load from %s and synchronize both panels without duplicate requests',
    async (regionName: string) => {
      const user = userEvent.setup()
      mockListDatasets.mockResolvedValue({ items: [{ ...ALPHA, is_loaded: false }, LOCAL] })
      mockListSeeds.mockResolvedValueOnce(seedPage([])).mockResolvedValue(seedPage())
      let finishLoad: (dataset: DatasetInfo) => void = () => { throw new Error('Load not started') }
      mockLoadDataset.mockImplementationOnce(() => new Promise<DatasetInfo>((resolve) => { finishLoad = resolve }))
      renderBrowser('/datasets?dataset=alpha')
      const catalog = screen.getByRole('region', { name: 'Dataset catalog' })
      const details = screen.getByRole('region', { name: 'Dataset seeds' })
      const source = screen.getByRole('region', { name: regionName })

      expect(await within(catalog).findByRole('button', { name: 'Load alpha' })).toBeEnabled()
      expect(screen.queryByRole('button', { name: 'Loaded alpha' })).not.toBeInTheDocument()
      await screen.findByText('No loaded seeds')
      await user.click(within(source).getByRole('button', { name: 'Load alpha' }))
      expect(mockLoadDataset).toHaveBeenCalledWith('alpha')
      expect(within(catalog).getByRole('button', { name: 'Loading alpha' })).toBeDisabled()
      expect(within(details).getByRole('button', { name: 'Loading alpha' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled()
      expect(screen.queryByRole('button', { name: 'Loaded alpha' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Load alpha' })).not.toBeInTheDocument()
      await user.click(within(details).getByRole('button', { name: 'Loading alpha' }))
      expect(mockLoadDataset).toHaveBeenCalledTimes(1)

      await act(async () => { finishLoad(ALPHA) })
      expect(await screen.findByText('Greeting')).toBeInTheDocument()
      expect(within(catalog).getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
      const refreshedDetails = screen.getByRole('region', { name: 'Dataset seeds' })
      expect(within(refreshedDetails).getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
      expect(screen.getAllByRole('button', { name: 'Loaded alpha' })).toHaveLength(2)
      expect(screen.queryByRole('button', { name: 'Load alpha' })).not.toBeInTheDocument()
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
      expect(mockListSeeds).toHaveBeenCalledTimes(2)
      expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled()
    },
  )

  it('should show loading failures in both panels and allow retry', async () => {
    const user = userEvent.setup()
    mockListDatasets.mockResolvedValue({ items: [{ ...ALPHA, is_loaded: false }] })
    mockLoadDataset.mockRejectedValueOnce(new Error('Provider unavailable')).mockResolvedValueOnce(ALPHA)
    renderBrowser('/datasets?dataset=alpha')
    const details = screen.getByRole('region', { name: 'Dataset seeds' })

    await user.click(await within(details).findByRole('button', { name: 'Load alpha' }))
    expect(await within(details).findByText(/Could not load dataset/)).toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Dataset catalog' }))
      .getByText(/Could not load dataset/)).toBeInTheDocument()
    expect(within(details).getByRole('button', { name: 'Load alpha' })).toBeEnabled()
    await user.click(within(details).getByRole('button', { name: 'Load alpha' }))
    await waitFor(() => {
      expect(within(screen.getByRole('region', { name: 'Dataset seeds' }))
        .getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
    })
    expect(screen.queryByText(/Could not load dataset/)).not.toBeInTheDocument()
  })

  it('should not claim a dataset is loaded if the provider stored no seeds', async () => {
    const user = userEvent.setup()
    mockListDatasets.mockResolvedValue({ items: [{ ...ALPHA, is_loaded: false }] })
    mockLoadDataset.mockResolvedValueOnce({ ...ALPHA, is_loaded: false })
    renderBrowser('/datasets?dataset=alpha')
    const details = screen.getByRole('region', { name: 'Dataset seeds' })

    await user.click(await within(details).findByRole('button', { name: 'Load alpha' }))
    expect(await screen.findByText('Loading completed, but no seeds were stored. Check the backend logs.')).toBeInTheDocument()
    const refreshedDetails = screen.getByRole('region', { name: 'Dataset seeds' })
    expect(within(refreshedDetails).queryByRole('button', { name: 'Loaded alpha' })).not.toBeInTheDocument()
    expect(within(refreshedDetails).getByRole('button', { name: 'Load alpha' })).toBeEnabled()
  })

  it('should keep loading state associated with the dataset when the selection changes', async () => {
    const user = userEvent.setup()
    let finishLoad: (dataset: DatasetInfo) => void = () => { throw new Error('Load not started') }
    mockListDatasets.mockResolvedValue({ items: [{ ...ALPHA, is_loaded: false }, LOCAL] })
    mockLoadDataset.mockImplementationOnce(() => new Promise<DatasetInfo>((resolve) => { finishLoad = resolve }))
    renderBrowser('/datasets?dataset=alpha')
    const catalog = screen.getByRole('region', { name: 'Dataset catalog' })

    await user.click(await within(catalog).findByRole('button', { name: 'Load alpha' }))
    await user.click(within(catalog).getByRole('button', { name: 'local/example' }))
    expect(screen.getByRole('heading', { name: 'local/example' })).toBeInTheDocument()
    await act(async () => { finishLoad(ALPHA) })
    expect(screen.getByRole('heading', { name: 'local/example' })).toBeInTheDocument()
    expect(within(catalog).getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
    await user.click(within(catalog).getByRole('button', { name: 'alpha' }))
    expect(within(screen.getByRole('region', { name: 'Dataset seeds' }))
      .getByRole('button', { name: 'Loaded alpha' })).toBeDisabled()
  })

  it('should not offer loading for an unknown dataset deep link', async () => {
    renderBrowser('/datasets?dataset=missing')
    await screen.findByRole('button', { name: 'alpha' })
    expect(screen.queryByRole('button', { name: 'Load missing' })).not.toBeInTheDocument()
    expect(mockLoadDataset).not.toHaveBeenCalled()
  })
})
