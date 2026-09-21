import { makeStyles, tokens } from '@fluentui/react-components'

import { mobileTouchTargetHeight } from '@/styles/touchTargets'

export const useDatasetLinksStyles = makeStyles({
  root: {
    display: 'inline-flex',
    flexWrap: 'wrap',
    alignItems: 'center',
    columnGap: tokens.spacingHorizontalXS,
    maxWidth: '100%',
  },
  link: {
    ...mobileTouchTargetHeight,
    display: 'inline-flex',
    alignItems: 'center',
    overflowWrap: 'anywhere',
    minWidth: 0,
    color: tokens.colorBrandForegroundLink,
    ':hover': {
      color: tokens.colorBrandForegroundLinkHover,
    },
  },
})
