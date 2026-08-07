import { useState, useEffect, useCallback } from 'react'
import {
  tokens,
  Text,
  Button,
  Link,
  Spinner,
  Tab,
  TabList,
} from '@fluentui/react-components'
import { AddRegular, ArrowSyncRegular } from '@fluentui/react-icons'

import { targetsApi } from '@/services/api'
import { toApiError } from '@/services/errors'
import type { TargetInstance } from '@/types'
import { targetType } from '@/utils/targetIdentity'

import CreateTargetDialog from './CreateTargetDialog'
import TargetTable from './TargetTable'
import { useTargetConfigStyles } from './TargetConfig.styles'

type TargetConfigPane = 'instances' | 'openai'

interface TargetConfigProps {
  activeTarget: TargetInstance | null
  onSetActiveTarget: (target: TargetInstance) => void
}

export default function TargetConfig({ activeTarget, onSetActiveTarget }: TargetConfigProps) {
  const styles = useTargetConfigStyles()
  const [targets, setTargets] = useState<TargetInstance[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [selectedPane, setSelectedPane] = useState<TargetConfigPane>('instances')
  // Counter used to re-trigger the fetch effect from event handlers (Refresh,
  // dialog close) without invoking setState synchronously in the effect body.
  const [refetchCount, setRefetchCount] = useState(0)

  // Retry fetching targets a few times with backoff. The Vite dev proxy
  // returns 502 while the backend is still starting, so a single failed
  // request on initial page load would show a confusing error to the user.
  useEffect(() => {
    const maxRetries = 3
    let cancelled = false

    const attempt = async (n: number): Promise<void> => {
      try {
        const response = await targetsApi.listTargets(200)
        if (cancelled) return
        setTargets(response.items)
        setError(null)
        setLoading(false)
      } catch (err) {
        if (cancelled) return
        if (n < maxRetries) {
          await new Promise(r => setTimeout(r, (n + 1) * 1000))
          if (cancelled) return
          return attempt(n + 1)
        }
        setError(toApiError(err).detail)
        setLoading(false)
      }
    }

    attempt(0)
    return () => {
      cancelled = true
    }
  }, [refetchCount])

  const fetchTargets = useCallback(() => {
    setLoading(true)
    setError(null)
    setRefetchCount(c => c + 1)
  }, [])

  const handleTargetCreated = useCallback(() => {
    setDialogOpen(false)
    fetchTargets()
  }, [fetchTargets])

  const openAiTargets = targets.filter((target: TargetInstance) => targetType(target) === 'OpenAIChatTarget')
  const activeOpenAiTarget = activeTarget && targetType(activeTarget) === 'OpenAIChatTarget'
    ? activeTarget
    : null

  const handlePaneSelect = (_event: unknown, data: { value: unknown }): void => {
    if (data.value === 'instances' || data.value === 'openai') {
      setSelectedPane(data.value)
    }
  }

  return (
    <div className={styles.root} data-testid="target-config">
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <Text as="h1" size={600} weight="semibold">Target Configuration</Text>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
            Manage targets for attack sessions. Select a target to use in the chat view.
          </Text>
        </div>
        <div className={styles.headerActions}>
          <Button
            className={styles.headerAction}
            appearance="subtle"
            icon={<ArrowSyncRegular />}
            onClick={fetchTargets}
            disabled={loading}
          >
            Refresh
          </Button>
          <Button
            className={styles.headerAction}
            appearance="primary"
            icon={<AddRegular />}
            onClick={() => setDialogOpen(true)}
          >
            New Target
          </Button>
        </div>
      </div>

      <TabList
        className={styles.tabList}
        selectedValue={selectedPane}
        onTabSelect={handlePaneSelect}
        aria-label="Target configuration views"
      >
        <Tab value="instances">Target Instances</Tab>
        <Tab value="openai">OpenAI Target Configs</Tab>
      </TabList>

      {loading && (
        <div className={styles.loadingState}>
          <Spinner label="Loading targets..." />
        </div>
      )}

      {error && (
        <div className={styles.errorState}>
          <Text>Error: {error}</Text>
        </div>
      )}

      {!loading && !error && selectedPane === 'instances' && targets.length === 0 && (
        <div className={styles.emptyState}>
          <Text size={500} weight="semibold">No Targets Configured</Text>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
            Add a target manually, or configure an initializer in your <code>~/.pyrit/.pyrit_conf</code> file
            to auto-populate targets from your <code>.env</code> and <code>.env.local</code> files.
            For example, add <code>target</code> to the <code>initializers</code> list to register
            available prompt targets automatically. See the{' '}
            <Link
              href="https://github.com/microsoft/PyRIT/blob/main/.pyrit_conf_example"
              target="_blank"
              rel="noopener noreferrer"
              inline
            >
              .pyrit_conf_example
            </Link>{' '}
            for details.
          </Text>
          <Button
            className={styles.touchTarget}
            appearance="primary"
            icon={<AddRegular />}
            onClick={() => setDialogOpen(true)}
          >
            Create First Target
          </Button>
        </div>
      )}

      {!loading && !error && selectedPane === 'instances' && targets.length > 0 && (
        <TargetTable
          targets={targets}
          activeTarget={activeTarget}
          onSetActiveTarget={onSetActiveTarget}
        />
      )}

      {!loading && !error && selectedPane === 'openai' && (
        <div className={styles.pane}>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
            OpenAI chat targets added here are saved for reuse when database-backed target initialization is enabled.
          </Text>
          {openAiTargets.length === 0 ? (
            <div className={styles.emptyState}>
              <Text size={500} weight="semibold">No OpenAI Target Configs</Text>
              <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
                Create an OpenAI chat target to add a reusable configuration.
              </Text>
              <Button
                className={styles.touchTarget}
                appearance="primary"
                icon={<AddRegular />}
                onClick={() => setDialogOpen(true)}
              >
                Add OpenAI Target
              </Button>
            </div>
          ) : (
            <TargetTable
              targets={openAiTargets}
              activeTarget={activeOpenAiTarget}
              onSetActiveTarget={onSetActiveTarget}
            />
          )}
        </div>
      )}

      <CreateTargetDialog
        key={selectedPane}
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onCreated={handleTargetCreated}
        existingTargets={targets}
        initialTargetType={selectedPane === 'openai' ? 'OpenAIChatTarget' : undefined}
      />
    </div>
  )
}
