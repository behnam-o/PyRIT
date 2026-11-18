import { makeStyles, tokens } from '@fluentui/react-components'

import { NARROW_VIEWPORT_QUERY } from '@/styles/touchTargets'

export const useAgentTranscriptStyles = makeStyles({
  root: {
    flex: 1,
    minHeight: 0,
    overflowY: 'auto',
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
    padding: tokens.spacingHorizontalXL,
    [NARROW_VIEWPORT_QUERY]: { padding: tokens.spacingHorizontalM },
  },
  user: {
    alignSelf: 'flex-end',
    maxWidth: '75%',
    padding: `${tokens.spacingVerticalS} ${tokens.spacingHorizontalM}`,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorBrandBackground2,
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
  },
  assistant: {
    alignSelf: 'flex-start',
    maxWidth: '85%',
    minWidth: 0,
    overflowWrap: 'anywhere',
  },
  tool: {
    alignSelf: 'stretch',
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground3,
  },
  code: {
    margin: `${tokens.spacingVerticalXS} 0 ${tokens.spacingVerticalS}`,
    maxHeight: '240px',
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
  },
  pending: { alignSelf: 'flex-start' },
})
