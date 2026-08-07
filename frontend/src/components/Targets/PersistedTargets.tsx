import { useEffect, useState } from 'react'

import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  Input,
  MessageBar,
  MessageBarBody,
  Select,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableHeaderCell,
  TableRow,
  Text,
  tokens,
} from '@fluentui/react-components'
import { AddRegular, ArrowSyncRegular, DeleteRegular } from '@fluentui/react-icons'

import { targetsApi } from '@/services/api'
import { toApiError } from '@/services/errors'
import type { CreatePersistedTargetRequest, PersistedTarget } from '@/types'

import { usePersistedTargetsStyles } from './PersistedTargets.styles'

const EMPTY_FORM: CreatePersistedTargetRequest = {
  display_name: '',
  endpoint: '',
  model_name: '',
  auth_mode: 'api_key',
  api_key: '',
}

export default function PersistedTargets() {
  const styles = usePersistedTargetsStyles()
  const [targets, setTargets] = useState<PersistedTarget[]>([])
  const [loading, setLoading] = useState(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [message, setMessage] = useState<{ intent: 'success' | 'error'; text: string } | null>(null)
  const [form, setForm] = useState<CreatePersistedTargetRequest>(EMPTY_FORM)
  const [refetchCount, setRefetchCount] = useState(0)

  useEffect(() => {
    let cancelled = false
    targetsApi.listPersistedTargets()
      .then((response) => {
        if (!cancelled) setTargets(response.items)
      })
      .catch((error) => {
        if (!cancelled) setMessage({ intent: 'error', text: toApiError(error).detail })
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [refetchCount])

  const refresh = (): void => {
    setLoading(true)
    setMessage(null)
    setRefetchCount((count) => count + 1)
  }

  const createTarget = async (): Promise<void> => {
    setSubmitting(true)
    setMessage(null)
    try {
      await targetsApi.createPersistedTarget({
        ...form,
        ...(form.auth_mode === 'identity' ? { api_key: undefined } : {}),
      })
      setDialogOpen(false)
      setForm(EMPTY_FORM)
      setMessage({ intent: 'success', text: 'Persisted target added.' })
      setRefetchCount((count) => count + 1)
    } catch (error) {
      setMessage({ intent: 'error', text: toApiError(error).detail })
    } finally {
      setSubmitting(false)
    }
  }

  const removeTarget = async (target: PersistedTarget): Promise<void> => {
    setDeletingId(target.id)
    setMessage(null)
    try {
      await targetsApi.deletePersistedTarget(target.id)
      setTargets((items) => items.filter((item) => item.id !== target.id))
      setMessage({ intent: 'success', text: `Removed ${target.display_name}.` })
    } catch (error) {
      setMessage({ intent: 'error', text: toApiError(error).detail })
    } finally {
      setDeletingId(null)
    }
  }

  const canSubmit = form.display_name.trim() !== ''
    && form.endpoint.trim() !== ''
    && form.model_name.trim() !== ''
    && (form.auth_mode === 'identity' || Boolean(form.api_key))

  return (
    <main className={styles.root}>
      <div className={styles.header}>
        <div className={styles.heading}>
          <Text as="h1" size={600} weight="semibold">Persisted Targets</Text>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3 }}>
            Manage OpenAI Responses target configurations restored when the backend starts.
          </Text>
        </div>
        <div className={styles.actions}>
          <Button appearance="subtle" icon={<ArrowSyncRegular />} onClick={refresh} disabled={loading}>
            Refresh
          </Button>
          <Button appearance="primary" icon={<AddRegular />} onClick={() => setDialogOpen(true)}>
            Add Target
          </Button>
        </div>
      </div>

      {message && (
        <MessageBar intent={message.intent} className={styles.message}>
          <MessageBarBody>{message.text}</MessageBarBody>
        </MessageBar>
      )}

      {loading ? (
        <div className={styles.state}><Spinner label="Loading persisted targets..." /></div>
      ) : targets.length === 0 ? (
        <div className={styles.state}>
          <Text size={500} weight="semibold">No Persisted Targets</Text>
          <Button appearance="primary" icon={<AddRegular />} onClick={() => setDialogOpen(true)}>
            Add Target
          </Button>
        </div>
      ) : (
        <div className={styles.tableWrap}>
          <Table aria-label="Persisted targets">
            <TableHeader>
              <TableRow>
                <TableHeaderCell>Display name</TableHeaderCell>
                <TableHeaderCell>Model</TableHeaderCell>
                <TableHeaderCell>Endpoint</TableHeaderCell>
                <TableHeaderCell>Authentication</TableHeaderCell>
                <TableHeaderCell>Actions</TableHeaderCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map((target) => (
                <TableRow key={target.id}>
                  <TableCell>{target.display_name}</TableCell>
                  <TableCell>{target.model_name}</TableCell>
                  <TableCell className={styles.endpoint}>{target.endpoint}</TableCell>
                  <TableCell>{target.auth_mode === 'identity' ? 'Microsoft Entra ID' : 'API key'}</TableCell>
                  <TableCell>
                    <Button
                      appearance="subtle"
                      icon={<DeleteRegular />}
                      aria-label={`Remove ${target.display_name}`}
                      title={`Remove ${target.display_name}`}
                      disabled={deletingId === target.id}
                      onClick={() => void removeTarget(target)}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={dialogOpen} onOpenChange={(_, data) => setDialogOpen(data.open)}>
        <DialogSurface>
          <DialogBody>
            <DialogTitle>Add Persisted Target</DialogTitle>
            <DialogContent>
              <form className={styles.dialogForm} onSubmit={(event) => { event.preventDefault(); void createTarget() }}>
                <Field label="Display name" required>
                  <Input aria-label="Display name" value={form.display_name} onChange={(_, data) => setForm({ ...form, display_name: data.value })} />
                </Field>
                <Field label="Endpoint" required>
                  <Input aria-label="Endpoint" value={form.endpoint} onChange={(_, data) => setForm({ ...form, endpoint: data.value })} />
                </Field>
                <Field label="Model name" required>
                  <Input aria-label="Model name" value={form.model_name} onChange={(_, data) => setForm({ ...form, model_name: data.value })} />
                </Field>
                <Field label="Authentication">
                  <Select
                    aria-label="Authentication"
                    value={form.auth_mode}
                    onChange={(event) => setForm({ ...form, auth_mode: event.target.value as 'api_key' | 'identity' })}
                  >
                    <option value="api_key">API key</option>
                    <option value="identity">Microsoft Entra ID</option>
                  </Select>
                </Field>
                {form.auth_mode === 'api_key' && (
                  <Field label="API key" required>
                    <Input aria-label="API key" type="password" value={form.api_key} onChange={(_, data) => setForm({ ...form, api_key: data.value })} />
                  </Field>
                )}
              </form>
            </DialogContent>
            <DialogActions>
              <Button appearance="secondary" onClick={() => setDialogOpen(false)}>Cancel</Button>
              <Button appearance="primary" disabled={!canSubmit || submitting} onClick={() => void createTarget()}>
                {submitting ? 'Adding...' : 'Add Target'}
              </Button>
            </DialogActions>
          </DialogBody>
        </DialogSurface>
      </Dialog>
    </main>
  )
}