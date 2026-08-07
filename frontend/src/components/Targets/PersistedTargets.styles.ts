import { makeStyles, tokens } from '@fluentui/react-components'

export const usePersistedTargetsStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    minWidth: 0,
    padding: tokens.spacingVerticalXXL,
    overflow: 'auto',
    backgroundColor: tokens.colorNeutralBackground2,
    '@media (max-width: 600px)': {
      padding: `${tokens.spacingVerticalL} ${tokens.spacingHorizontalM}`,
    },
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: tokens.spacingVerticalM,
    marginBottom: tokens.spacingVerticalXL,
  },
  heading: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXS,
  },
  actions: {
    display: 'flex',
    gap: tokens.spacingHorizontalS,
  },
  state: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: tokens.spacingVerticalM,
    padding: tokens.spacingVerticalXXXL,
  },
  tableWrap: {
    overflowX: 'auto',
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  endpoint: {
    overflowWrap: 'anywhere',
  },
  dialogForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
  },
  message: {
    marginBottom: tokens.spacingVerticalL,
  },
})