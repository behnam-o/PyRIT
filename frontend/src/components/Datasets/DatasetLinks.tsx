import { Fragment } from 'react'

import { Link } from 'react-router'

import { datasetRoutePath } from '@/utils/routeParams'

import { useDatasetLinksStyles } from './DatasetLinks.styles'

interface DatasetLinksProps {
  readonly names: readonly string[]
  readonly emptyText?: string
}

export default function DatasetLinks({ names, emptyText = 'No datasets declared' }: DatasetLinksProps) {
  const styles = useDatasetLinksStyles()
  const uniqueNames = [...new Set(names)]

  return (
    <span className={styles.root}>
      {uniqueNames.length === 0 ? emptyText : uniqueNames.map((name: string, index: number) => (
        <Fragment key={name}>
          {index > 0 && <span aria-hidden="true">, </span>}
          <Link className={styles.link} to={datasetRoutePath(name)}>{name}</Link>
        </Fragment>
      ))}
    </span>
  )
}
