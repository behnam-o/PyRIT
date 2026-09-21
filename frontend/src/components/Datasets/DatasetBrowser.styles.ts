import { makeStyles, tokens } from '@fluentui/react-components'

import {
  MINIMUM_TOUCH_TARGET_SIZE, mobileTouchTarget, mobileTouchTargetHeight, NARROW_VIEWPORT_QUERY,
} from '@/styles/touchTargets'

export const useDatasetBrowserStyles = makeStyles({
  root: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalL,
    height: '100%',
    minWidth: 0,
    minHeight: 0,
    overflow: 'hidden',
    padding: tokens.spacingVerticalXXL,
    backgroundColor: tokens.colorNeutralBackground2,
    [NARROW_VIEWPORT_QUERY]: {
      padding: tokens.spacingVerticalM,
    },
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalM,
    flexShrink: 0,
  },
  stack: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalS,
    minWidth: 0,
  },
  subtitle: {
    color: tokens.colorNeutralForeground3,
  },
  datasetName: {
    overflowWrap: 'anywhere',
    margin: 0,
  },
  layout: {
    display: 'grid',
    flex: 1,
    gridTemplateColumns: 'minmax(16rem, 22rem) minmax(0, 1fr)',
    gridTemplateRows: 'minmax(0, 1fr)',
    alignItems: 'stretch',
    gap: tokens.spacingHorizontalL,
    minHeight: 0,
    [NARROW_VIEWPORT_QUERY]: {
      gridTemplateColumns: 'minmax(0, 1fr)',
      gridTemplateRows: 'repeat(2, minmax(0, 1fr))',
    },
  },
  panel: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalM,
    minWidth: 0,
    minHeight: 0,
    overflow: 'auto',
    padding: tokens.spacingVerticalL,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusLarge,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  search: {
    ...mobileTouchTargetHeight,
    minWidth: 0,
    flexShrink: 0,
  },
  datasetList: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalXS,
    flex: 1,
    minHeight: MINIMUM_TOUCH_TARGET_SIZE,
    overflowY: 'auto',
  },
  datasetButton: {
    ...mobileTouchTargetHeight,
    justifyContent: 'flex-start',
    textAlign: 'left',
    overflowWrap: 'anywhere',
    flex: 1,
    minWidth: 0,
  },
  datasetRow: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalXS,
  },
  touchTarget: {
    ...mobileTouchTarget,
  },
  empty: {
    padding: tokens.spacingVerticalXXL,
    textAlign: 'center',
    color: tokens.colorNeutralForeground3,
    minHeight: 0,
    overflowY: 'auto',
  },
  seedPanel: {
    gap: tokens.spacingVerticalXS,
    padding: tokens.spacingVerticalM,
  },
  tableContainer: {
    flex: 1,
    minHeight: `calc(2 * ${MINIMUM_TOUCH_TARGET_SIZE})`,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    overflow: 'auto',
  },
  seedTable: {
    tableLayout: 'fixed',
    width: '100%',
  },
  tableHeader: {
    position: 'sticky',
    top: 0,
    zIndex: 1,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  typeColumn: {
    width: '9.5rem',
    [NARROW_VIEWPORT_QUERY]: {
      width: '45%',
    },
  },
  seedCell: {
    verticalAlign: 'middle',
    padding: `${tokens.spacingVerticalXXS} ${tokens.spacingHorizontalXS}`,
    borderBottom: `${tokens.strokeWidthThin} solid ${tokens.colorNeutralStroke2}`,
  },
  seedIdentity: {
    display: 'flex',
    alignItems: 'center',
    gap: tokens.spacingHorizontalXS,
  },
  seedTypes: {
    minWidth: 0,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  detailsCell: {
    padding: `${tokens.spacingVerticalS} ${tokens.spacingHorizontalM}`,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  seedDetails: {
    display: 'flex',
    flexDirection: 'column',
    gap: tokens.spacingVerticalS,
  },
  jsonValue: {
    whiteSpace: 'pre-wrap',
    overflowWrap: 'anywhere',
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    lineHeight: tokens.lineHeightBase300,
    margin: 0,
    padding: tokens.spacingVerticalS,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  valuePreview: {
    fontSize: tokens.fontSizeBase200,
    lineHeight: tokens.lineHeightBase200,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  copyActions: {
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: tokens.spacingHorizontalXS,
  },
})
