import { useEffect, useRef } from 'react'
import {
  Accordion,
  AccordionHeader,
  AccordionItem,
  AccordionPanel,
  MessageBar,
  MessageBarBody,
  Spinner,
  Text,
} from '@fluentui/react-components'
import { WrenchRegular } from '@fluentui/react-icons'

import { formatStructuredMessage } from '@/components/Chat/messageViewModel'
import MarkdownContent from '@/components/Markdown/MarkdownContent'
import type { AgentTranscriptItem } from '@/types'

import { useAgentTranscriptStyles } from './AgentTranscript.styles'

interface AgentTranscriptProps {
  items: AgentTranscriptItem[]
  /** The message being sent, shown until the agent answers. */
  pendingText?: string
}

interface TranscriptRowProps {
  item: AgentTranscriptItem
}

function formatJson(text: string): string {
  return formatStructuredMessage(text) ?? text
}

function TranscriptRow({ item }: TranscriptRowProps) {
  const styles = useAgentTranscriptStyles()
  switch (item.kind) {
    case 'user':
      return <Text className={styles.user}>{item.text}</Text>
    case 'assistant':
      return <MarkdownContent content={item.text} className={styles.assistant} />
    case 'error':
      return (
        <MessageBar intent="error">
          <MessageBarBody>{item.text}</MessageBarBody>
        </MessageBar>
      )
    case 'tool':
      return (
        <Accordion collapsible className={styles.tool}>
          <AccordionItem value={item.id}>
            <AccordionHeader icon={<WrenchRegular />} size="small">{`Used ${item.name}`}</AccordionHeader>
            <AccordionPanel>
              <Text size={200} weight="semibold">Arguments</Text>
              <pre className={styles.code}>{formatJson(item.arguments)}</pre>
              <Text size={200} weight="semibold">Result</Text>
              <pre className={styles.code}>{item.output === undefined ? 'No result' : formatJson(item.output)}</pre>
            </AccordionPanel>
          </AccordionItem>
        </Accordion>
      )
  }
}

/** An agent conversation: messages, collapsed tool calls, and the message being answered. */
export default function AgentTranscript({ items, pendingText }: AgentTranscriptProps) {
  const styles = useAgentTranscriptStyles()
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' })
  }, [items, pendingText])

  return (
    <div className={styles.root} role="log" aria-label="Agent conversation">
      {items.map((item: AgentTranscriptItem) => <TranscriptRow key={item.id} item={item} />)}
      {pendingText !== undefined && (
        <>
          <Text className={styles.user}>{pendingText}</Text>
          <Spinner className={styles.pending} size="tiny" labelPosition="after" label="The agent is working…" />
        </>
      )}
      <div ref={endRef} />
    </div>
  )
}
