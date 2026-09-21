import { type ChangeEvent, useEffect, useId, useRef, useState } from 'react'

import {
  Button, Input, mergeClasses, MessageBar, MessageBarBody, Spinner,
  Table, TableBody, TableCell, TableHeader, TableHeaderCell, TableRow, Text, Tooltip,
} from '@fluentui/react-components'
import type { InputOnChangeData } from '@fluentui/react-components'
import {
  ArrowDownloadRegular, ArrowSyncRegular, CheckmarkRegular,
  ChevronDownRegular, ChevronRightRegular, CopyRegular, SearchRegular,
} from '@fluentui/react-icons'
import { useSearchParams } from 'react-router'

import { datasetsApi } from '@/services/api'
import { toApiError } from '@/services/errors'
import type { DatasetInfo, DatasetListResponse, DatasetSeed, DatasetSeedsResponse } from '@/types'

import { useDatasetBrowserStyles } from './DatasetBrowser.styles'

const PAGE_SIZE = 25

interface DatasetLoadState {
  readonly pending: boolean
  readonly error: string | null
  readonly revision: number
}

interface DatasetLoadButtonProps {
  readonly dataset: DatasetInfo
  readonly pending: boolean
  readonly onLoad: (name: string) => void
  readonly compact?: boolean
}

function DatasetLoadButton({ dataset, pending, onLoad, compact = false }: DatasetLoadButtonProps) {
  const styles = useDatasetBrowserStyles()
  const description = dataset.is_loaded ? 'Already loaded in memory'
    : !dataset.can_load ? 'No registered provider is available'
      : 'Load into memory. Remote datasets may require a download.'
  const action = dataset.is_loaded ? 'Loaded' : pending ? 'Loading' : 'Load'

  return (
    <Tooltip content={description} relationship="description">
      <Button
        className={styles.touchTarget}
        appearance={dataset.is_loaded ? 'transparent' : 'secondary'}
        icon={dataset.is_loaded ? <CheckmarkRegular /> : pending ? <Spinner size="tiny" /> : <ArrowDownloadRegular />}
        disabled={pending || dataset.is_loaded || !dataset.can_load}
        aria-label={`${action} ${dataset.name}`}
        onClick={() => { onLoad(dataset.name) }}
      >{compact ? undefined : dataset.is_loaded ? 'Loaded' : pending ? 'Loading...' : 'Load dataset'}</Button>
    </Tooltip>
  )
}

interface SeedTableRowProps {
  readonly seed: DatasetSeed
  readonly number: number
}

function SeedTableRow({ seed, number }: SeedTableRowProps) {
  const styles = useDatasetBrowserStyles()
  const detailsId = useId()
  const [expanded, setExpanded] = useState(false)
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copying' | 'copied' | 'error'>('idle')
  const { seed_type: seedType, data_type: dataType, value, ...metadata } = seed
  const seedJson = expanded ? JSON.stringify({ seed_type: seedType, data_type: dataType, value, ...metadata }, null, 2) : ''

  async function handleCopy(content: string): Promise<void> {
    setCopyStatus('copying')
    try {
      await navigator.clipboard.writeText(content)
      setCopyStatus('copied')
    } catch {
      setCopyStatus('error')
    }
  }

  return (
    <>
      <TableRow>
        <TableCell className={styles.seedCell}>
          <div className={styles.seedIdentity}>
            <Button
              className={styles.touchTarget}
              appearance="transparent"
              size="small"
              icon={expanded ? <ChevronDownRegular /> : <ChevronRightRegular />}
              aria-label={`${expanded ? 'Collapse' : 'Expand'} seed ${number}`}
              aria-expanded={expanded}
              aria-controls={expanded ? detailsId : undefined}
              onClick={() => { setExpanded(!expanded) }}
            />
            <div className={styles.seedTypes} title={`${seed.seed_type} / ${seed.data_type}`}>
              <Text size={200} weight="semibold" wrap={false}>{seed.seed_type}</Text>
              <Text size={200} className={styles.subtitle} wrap={false}> / </Text>
              <Text size={200} className={styles.subtitle} wrap={false}>{seed.data_type}</Text>
            </div>
          </div>
        </TableCell>
        <TableCell className={styles.seedCell}>
          <div className={styles.valuePreview} aria-label="Seed value">
            {seed.name && <><Text size={200} weight="semibold" wrap={false}>{seed.name}</Text>{': '}</>}
            {seed.value || '(Empty value)'}
          </div>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow id={detailsId}>
          <TableCell colSpan={2} className={styles.detailsCell}>
            <div className={styles.seedDetails} role="group" aria-label={`Seed ${number} details`}>
              <div className={styles.header}>
                <Text size={200} weight="semibold">Seed {number} JSON</Text>
                <div className={styles.copyActions}>
                  <Button
                    className={styles.touchTarget}
                    size="small"
                    icon={<CopyRegular />}
                    disabled={copyStatus === 'copying'}
                    onClick={() => { void handleCopy(seed.value) }}
                  >Copy value</Button>
                  <Button
                    className={styles.touchTarget}
                    size="small"
                    icon={<CopyRegular />}
                    disabled={copyStatus === 'copying'}
                    onClick={() => { void handleCopy(seedJson) }}
                  >Copy JSON</Button>
                  {copyStatus === 'copied' && <Text role="status"> Copied</Text>}
                </div>
              </div>
              <pre className={styles.jsonValue} tabIndex={0} aria-label={`Seed ${number} JSON`}>
                {seedJson}
              </pre>
              {seed.data_type !== 'text' && (
                <Text size={200} className={styles.subtitle}>Stored value only; media is not opened.</Text>
              )}
              {copyStatus === 'error' && (
                <MessageBar intent="error">
                  <MessageBarBody>Could not copy. Select the text and copy it manually.</MessageBarBody>
                </MessageBar>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

interface SeedPageProps {
  readonly datasetName: string
  readonly offset: number
  readonly onOffsetChange: (offset: number) => void
}

function SeedPage({ datasetName, offset, onOffsetChange }: SeedPageProps) {
  const styles = useDatasetBrowserStyles()
  const [data, setData] = useState<DatasetSeedsResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let ignore = false
    datasetsApi.listSeeds(datasetName, PAGE_SIZE, offset)
      .then((response: DatasetSeedsResponse) => { if (!ignore) setData(response) })
      .catch((reason: unknown) => { if (!ignore) setError(toApiError(reason).detail) })
    return () => { ignore = true }
  }, [datasetName, offset, attempt])

  if (error) {
    return (
      <MessageBar intent="error">
        <MessageBarBody>
          Could not load seeds: {error}
          <Button className={styles.touchTarget} onClick={() => {
            setError(null)
            setAttempt(attempt + 1)
          }}>Retry</Button>
        </MessageBarBody>
      </MessageBar>
    )
  }
  if (!data) return <Spinner label="Loading seeds..." />
  if (data.total === 0) {
    return (
      <div className={styles.empty}>
        <Text as="p" weight="semibold">No loaded seeds</Text>
        <Text>Use Load dataset when a provider is available, or load seeds using PyRIT and refresh.
          Browsing alone does not download datasets.</Text>
      </div>
    )
  }

  return (
    <>
      <div className={styles.header}>
        <Text size={200} role="status">
          {data.items.length > 0 ? `${offset + 1}-${offset + data.items.length} of ${data.total} seeds` : 'No seeds on this page'}
        </Text>
        <div className={styles.header}>
          <Button className={styles.touchTarget} size="small" disabled={offset === 0}
            onClick={() => { onOffsetChange(Math.max(0, offset - PAGE_SIZE)) }}>Previous</Button>
          <Button className={styles.touchTarget} size="small" disabled={offset + PAGE_SIZE >= data.total}
            onClick={() => { onOffsetChange(offset + PAGE_SIZE) }}>Next</Button>
        </div>
      </div>
      <div className={styles.tableContainer} role="region" aria-label="Seed table" tabIndex={0}>
        <Table size="extra-small" className={styles.seedTable} aria-label="Dataset seed contents">
          <TableHeader className={styles.tableHeader}>
            <TableRow>
              <TableHeaderCell className={styles.typeColumn}>Seed / data type</TableHeaderCell>
              <TableHeaderCell>Content</TableHeaderCell>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.map((seed: DatasetSeed, index: number) => (
              <SeedTableRow key={seed.id} seed={seed} number={offset + index + 1} />
            ))}
          </TableBody>
        </Table>
      </div>
    </>
  )
}

interface DatasetSeedsProps {
  readonly datasetName: string
  readonly dataset?: DatasetInfo
  readonly loadState?: DatasetLoadState
  readonly onLoad: (name: string) => void
}

function DatasetSeeds({ datasetName, dataset, loadState, onLoad }: DatasetSeedsProps) {
  const styles = useDatasetBrowserStyles()
  const [offset, setOffset] = useState(0)

  return (
    <section className={mergeClasses(styles.panel, styles.seedPanel)} aria-label="Dataset seeds">
      <div className={styles.header}>
        <Text as="h2" size={500} weight="semibold" className={styles.datasetName}>{datasetName}</Text>
        {dataset && (
          <DatasetLoadButton dataset={dataset} pending={loadState?.pending ?? false} onLoad={onLoad} />
        )}
      </div>
      {loadState?.error && (
        <MessageBar intent="error"><MessageBarBody>{loadState.error}</MessageBarBody></MessageBar>
      )}
      <Text size={200} className={styles.subtitle}>Expand a row to view the full seed as JSON.</Text>
      <SeedPage key={offset} datasetName={datasetName} offset={offset} onOffsetChange={setOffset} />
    </section>
  )
}

interface DatasetCatalogProps {
  readonly datasetName: string
  readonly search: string
  readonly onSearchChange: (search: string) => void
  readonly onSelect: (name: string) => void
  readonly onRefresh: () => void
  readonly data: DatasetListResponse | null
  readonly error: string | null
  readonly loads: Record<string, DatasetLoadState>
  readonly onLoad: (name: string) => void
}

function DatasetCatalog({
  datasetName, search, onSearchChange, onSelect, onRefresh, data, error, loads, onLoad,
}: DatasetCatalogProps) {
  const styles = useDatasetBrowserStyles()

  const filtered = data?.items.filter((dataset: DatasetInfo) =>
    dataset.name.toLowerCase().includes(search.trim().toLowerCase()),
  ) ?? []

  return (
    <section className={styles.panel} aria-label="Dataset catalog">
      <Input
        className={styles.search}
        contentBefore={<SearchRegular />}
        aria-label="Search datasets"
        placeholder="Search datasets"
        value={search}
        onChange={(_: ChangeEvent<HTMLInputElement>, input: InputOnChangeData) => {
          onSearchChange(input.value)
        }}
      />
      <Text size={200} className={styles.subtitle}>A check mark means the dataset is loaded.</Text>
      {error ? (
        <MessageBar intent="error">
          <MessageBarBody>
            Could not load datasets: {error}
            <Button className={styles.touchTarget} onClick={onRefresh}>Retry</Button>
          </MessageBarBody>
        </MessageBar>
      ) : !data ? <Spinner label="Loading datasets..." /> : (
        <>
          <Text size={200} className={styles.subtitle} role="status">
            {filtered.length} of {data.items.length} datasets
          </Text>
          {data.items.length === 0 ? <Text>No datasets available.</Text>
            : filtered.length === 0 ? <Text>No datasets match your search.</Text>
              : (
                <div className={styles.datasetList} role="region" aria-label="Available datasets" tabIndex={0}>
                  {filtered.map((dataset: DatasetInfo) => (
                    <div key={dataset.name} className={styles.stack}>
                      <div className={styles.datasetRow}>
                        <Button
                          className={styles.datasetButton}
                          appearance={dataset.name === datasetName ? 'primary' : 'subtle'}
                          aria-pressed={dataset.name === datasetName}
                          onClick={() => { onSelect(dataset.name) }}
                        >{dataset.name}</Button>
                        <DatasetLoadButton dataset={dataset} pending={loads[dataset.name]?.pending ?? false}
                          onLoad={onLoad} compact />
                      </div>
                      {loads[dataset.name]?.error && (
                        <MessageBar intent="error">
                          <MessageBarBody>{dataset.name}: {loads[dataset.name].error}</MessageBarBody>
                        </MessageBar>
                      )}
                    </div>
                  ))}
                </div>
              )}
        </>
      )}
    </section>
  )
}

export default function DatasetBrowser() {
  const styles = useDatasetBrowserStyles()
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [revision, setRevision] = useState(0)
  const [catalog, setCatalog] = useState<DatasetListResponse | null>(null)
  const [catalogError, setCatalogError] = useState<string | null>(null)
  const [loads, setLoads] = useState<Record<string, DatasetLoadState>>({})
  const inFlight = useRef(new Set<string>())
  const mounted = useRef(false)
  const datasetName = searchParams.get('dataset') ?? ''
  const selectedDataset = catalog?.items.find((dataset: DatasetInfo) => dataset.name === datasetName)
  const loading = Object.values(loads).some((load: DatasetLoadState) => load.pending)

  useEffect(() => {
    let ignore = false
    mounted.current = true
    datasetsApi.listDatasets()
      .then((response: DatasetListResponse) => { if (!ignore) setCatalog(response) })
      .catch((reason: unknown) => { if (!ignore) setCatalogError(toApiError(reason).detail) })
    return () => { ignore = true; mounted.current = false }
  }, [revision])

  function handleRefresh(): void {
    setCatalog(null)
    setCatalogError(null)
    setLoads({})
    setRevision(revision + 1)
  }

  async function handleLoad(name: string): Promise<void> {
    if (inFlight.current.has(name)) return
    inFlight.current.add(name)
    setLoads((previous: Record<string, DatasetLoadState>) => ({
      ...previous, [name]: { pending: true, error: null, revision: previous[name]?.revision ?? 0 },
    }))
    try {
      const result = await datasetsApi.loadDataset(name)
      if (!mounted.current) return
      setCatalog((previous: DatasetListResponse | null) => previous && ({
        items: previous.items.map((dataset: DatasetInfo) => dataset.name === name ? result : dataset),
      }))
      setLoads((previous: Record<string, DatasetLoadState>) => ({
        ...previous,
        [name]: {
          pending: false,
          error: result.is_loaded ? null : 'Loading completed, but no seeds were stored. Check the backend logs.',
          revision: (previous[name]?.revision ?? 0) + 1,
        },
      }))
    } catch (reason: unknown) {
      if (!mounted.current) return
      setLoads((previous: Record<string, DatasetLoadState>) => ({
        ...previous,
        [name]: {
          pending: false,
          error: `Could not load dataset: ${toApiError(reason).detail}`,
          revision: previous[name]?.revision ?? 0,
        },
      }))
    } finally {
      inFlight.current.delete(name)
    }
  }

  function handleSelect(name: string): void {
    const next = new URLSearchParams(searchParams)
    next.set('dataset', name)
    setSearchParams(next)
  }

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <div className={styles.stack}>
          <Text as="h1" size={800} weight="bold">Datasets</Text>
          <Text className={styles.subtitle}>Browse available datasets and inspect seeds already loaded in memory.</Text>
        </div>
        <Button className={styles.touchTarget} icon={<ArrowSyncRegular />} disabled={loading}
          onClick={handleRefresh}>Refresh</Button>
      </div>
      <div className={styles.layout}>
        <DatasetCatalog datasetName={datasetName} search={search} data={catalog} error={catalogError} loads={loads}
          onLoad={(name: string) => { void handleLoad(name) }}
          onSearchChange={setSearch} onSelect={handleSelect} onRefresh={handleRefresh} />
        {datasetName
          ? <DatasetSeeds key={`${revision}:${datasetName}:${loads[datasetName]?.revision ?? 0}`} datasetName={datasetName}
            dataset={selectedDataset} loadState={loads[datasetName]}
            onLoad={(name: string) => { void handleLoad(name) }} />
          : <div className={mergeClasses(styles.panel, styles.empty)}><Text>Select a dataset to view its seeds.</Text></div>}
      </div>
    </div>
  )
}
