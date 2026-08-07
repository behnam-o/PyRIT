import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Badge,
  Button,
  Dropdown,
  Field,
  MessageBar,
  MessageBarBody,
  Option,
  Spinner,
  Text,
} from '@fluentui/react-components'
import { ArrowSyncRegular, PlayRegular } from '@fluentui/react-icons'
import { attacksApi, scenariosApi, targetsApi } from '../../services/api'
import { toApiError } from '../../services/errors'
import type {
  BackendMessage,
  RegisteredScenario,
  ScenarioAttackResult,
  ScenarioResult,
  ScenarioRunSummary,
  TargetInstance,
} from '../../types'
import { useScenariosStyles } from './Scenarios.styles'

interface ScenariosProps {
  activeTarget: TargetInstance | null
  labels: Record<string, string>
}

interface AttackResultItemProps {
  attack: ScenarioAttackResult
}

const TERMINAL_STATES = new Set(['COMPLETED', 'FAILED', 'CANCELLED'])
const POLL_INTERVAL_MS = 3_000

function messageText(message: BackendMessage): string {
  return message.message_pieces
    .map((piece) => piece.converted_value)
    .filter(Boolean)
    .join('\n')
}

function AttackResultItem({ attack }: AttackResultItemProps) {
  const styles = useScenariosStyles()
  const [messages, setMessages] = useState<BackendMessage[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadMessages = useCallback(() => {
    if (messages || loading) return
    setLoading(true)
    attacksApi.getMessages(attack.attack_result_id, attack.conversation_id)
      .then((response) => {
        setMessages(response.messages)
        setError(null)
      })
      .catch((err: unknown) => setError(toApiError(err).detail))
      .finally(() => setLoading(false))
  }, [attack.attack_result_id, attack.conversation_id, loading, messages])

  return (
    <details className={styles.attack} onToggle={(event) => {
      if (event.currentTarget.open) loadMessages()
    }}>
      <summary className={styles.attackSummary}>
        <Badge appearance="tint" color={attack.outcome === 'success' ? 'success' : attack.outcome === 'error' ? 'danger' : 'informative'}>
          {attack.outcome}
        </Badge>
        <span className={styles.attackObjective}>{attack.objective}</span>
        <span className={styles.muted}>{attack.executed_turns} turns</span>
      </summary>
      <div className={styles.messages}>
        {loading && <Spinner size="tiny" label="Loading conversation..." />}
        {error && (
          <MessageBar intent="error">
            <MessageBarBody>{error}</MessageBarBody>
          </MessageBar>
        )}
        {messages?.length === 0 && <Text>No messages were recorded.</Text>}
        {messages?.map((message, index) => (
          <div
            className={styles.message}
            key={message.message_pieces[0]?.id ?? `${message.turn_number}-${message.role}-${index}`}
          >
            <span className={styles.messageRole}>{message.role}</span>
            <span>{messageText(message) || '(non-text content)'}</span>
          </div>
        ))}
      </div>
    </details>
  )
}

interface ScenarioRunItemProps {
  run: ScenarioRunSummary
}

function ScenarioRunItem({ run }: ScenarioRunItemProps) {
  const styles = useScenariosStyles()
  const [result, setResult] = useState<ScenarioResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadResult = useCallback(() => {
    if (run.status !== 'COMPLETED' || result || loading) return
    setLoading(true)
    scenariosApi.getResults(run.scenario_result_id)
      .then((response) => {
        setResult(response)
        setError(null)
      })
      .catch((err: unknown) => setError(toApiError(err).detail))
      .finally(() => setLoading(false))
  }, [loading, result, run.scenario_result_id, run.status])

  const groups = result ? Object.entries(result.attack_results) : []

  return (
    <details className={styles.run} onToggle={(event) => {
      if (event.currentTarget.open) loadResult()
    }}>
      <summary className={styles.summary}>
        <Badge appearance="filled" color={run.status === 'COMPLETED' ? 'success' : run.status === 'FAILED' ? 'danger' : 'informative'}>
          {run.status}
        </Badge>
        <span className={styles.summaryName}>{run.scenario_name}</span>
        <span className={styles.muted}>{new Date(run.created_at).toLocaleString()}</span>
      </summary>
      <div className={styles.details}>
        <div className={styles.metrics}>
          <Text>Attacks: {run.completed_attacks}/{run.total_attacks}</Text>
          <Text>Objective achieved: {run.objective_achieved_rate}%</Text>
          <Text>Retries: {run.total_retries}</Text>
        </div>
        {run.error && (
          <MessageBar intent="error">
            <MessageBarBody>{run.error}</MessageBarBody>
          </MessageBar>
        )}
        {loading && <Spinner size="small" label="Loading results..." />}
        {error && (
          <MessageBar intent="error">
            <MessageBarBody>{error}</MessageBarBody>
          </MessageBar>
        )}
        {run.status !== 'COMPLETED' && !run.error && (
          <Text className={styles.muted}>Detailed results are available when the run completes.</Text>
        )}
        {groups.map(([groupName, attacks]) => (
          <section className={styles.attackGroup} key={groupName}>
            <Text as="h3" weight="semibold">
              {result?.display_group_map[groupName] ?? groupName} ({attacks.length})
            </Text>
            {attacks.map((attack) => (
              <AttackResultItem attack={attack} key={attack.attack_result_id} />
            ))}
          </section>
        ))}
      </div>
    </details>
  )
}

export default function Scenarios({ activeTarget, labels }: ScenariosProps) {
  const styles = useScenariosStyles()
  const [catalog, setCatalog] = useState<RegisteredScenario[]>([])
  const [targets, setTargets] = useState<TargetInstance[]>([])
  const [runs, setRuns] = useState<ScenarioRunSummary[]>([])
  const [scenarioName, setScenarioName] = useState('')
  const [targetName, setTargetName] = useState(activeTarget?.target_registry_name ?? '')
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState(0)

  const hasActiveRuns = useMemo(
    () => runs.some((run) => !TERMINAL_STATES.has(run.status)),
    [runs],
  )

  useEffect(() => {
    let cancelled = false
    Promise.all([
      scenariosApi.listCatalog(),
      targetsApi.listTargets(200),
      scenariosApi.listRuns(),
    ]).then(([catalogResponse, targetResponse, runResponse]) => {
      if (cancelled) return
      setCatalog(catalogResponse.items)
      setTargets(targetResponse.items)
      setRuns(runResponse.items)
      setScenarioName((current) => current || catalogResponse.items[0]?.scenario_name || '')
      setTargetName((current) => current || targetResponse.items[0]?.target_registry_name || '')
      setError(null)
    }).catch((err: unknown) => {
      if (!cancelled) setError(toApiError(err).detail)
    }).finally(() => {
      if (!cancelled) setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [refreshToken])

  useEffect(() => {
    if (!hasActiveRuns) return
    const timer = window.setInterval(() => {
      scenariosApi.listRuns()
        .then((response) => setRuns(response.items))
        .catch(() => { /* The next poll or manual refresh can recover. */ })
    }, POLL_INTERVAL_MS)
    return () => window.clearInterval(timer)
  }, [hasActiveRuns])

  const startRun = useCallback(() => {
    if (!scenarioName || !targetName) return
    setStarting(true)
    setError(null)
    scenariosApi.startRun({
      scenario_name: scenarioName,
      target_name: targetName,
      labels,
    }).then((run) => {
      setRuns((current) => [run, ...current.filter((item) => item.scenario_result_id !== run.scenario_result_id)])
    }).catch((err: unknown) => {
      setError(toApiError(err).detail)
    }).finally(() => setStarting(false))
  }, [labels, scenarioName, targetName])

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <Text as="h1" size={500} weight="semibold">Scenarios</Text>
        <Button
          className={styles.touchTarget}
          appearance="subtle"
          icon={<ArrowSyncRegular />}
          disabled={loading}
          onClick={() => {
            setLoading(true)
            setRefreshToken((value) => value + 1)
          }}
        >
          Refresh
        </Button>
      </div>
      <div className={styles.content}>
        <div className={styles.form}>
          <Field className={styles.field} label="Scenario" required>
            <Dropdown
              value={catalog.find((scenario) => scenario.scenario_name === scenarioName)?.scenario_name ?? ''}
              selectedOptions={scenarioName ? [scenarioName] : []}
              onOptionSelect={(_, data) => setScenarioName(data.optionValue ?? '')}
            >
              {catalog.map((scenario) => (
                <Option key={scenario.scenario_name} value={scenario.scenario_name}>
                  {scenario.scenario_name}
                </Option>
              ))}
            </Dropdown>
          </Field>
          <Field className={styles.field} label="Target" required>
            <Dropdown
              value={targetName}
              selectedOptions={targetName ? [targetName] : []}
              onOptionSelect={(_, data) => setTargetName(data.optionValue ?? '')}
            >
              {targets.map((target) => (
                <Option key={target.target_registry_name} value={target.target_registry_name}>
                  {target.target_registry_name}
                </Option>
              ))}
            </Dropdown>
          </Field>
          <Button
            className={styles.touchTarget}
            appearance="primary"
            icon={<PlayRegular />}
            disabled={starting || loading || !scenarioName || !targetName}
            onClick={startRun}
          >
            {starting ? 'Starting...' : 'Start scenario'}
          </Button>
        </div>
        {error && (
          <MessageBar intent="error">
            <MessageBarBody>{error}</MessageBarBody>
          </MessageBar>
        )}
        {loading ? (
          <Spinner label="Loading scenarios..." />
        ) : runs.length === 0 ? (
          <div className={styles.empty}>No scenario runs yet.</div>
        ) : (
          <div className={styles.runList}>
            {runs.map((run) => <ScenarioRunItem key={run.scenario_result_id} run={run} />)}
          </div>
        )}
      </div>
    </div>
  )
}
