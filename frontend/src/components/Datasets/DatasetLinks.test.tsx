import type { ReactNode } from 'react'

import { FluentProvider, webLightTheme } from '@fluentui/react-components'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useSearchParams } from 'react-router'

import DatasetLinks from './DatasetLinks'

function TestWrapper({ children }: { readonly children: ReactNode }) {
  return <FluentProvider theme={webLightTheme}><MemoryRouter>{children}</MemoryRouter></FluentProvider>
}

function DatasetDestination() {
  const [searchParams] = useSearchParams()
  return <h1>{searchParams.get('dataset')}</h1>
}

describe('DatasetLinks', () => {
  it('should link each unique dataset and preserve its exact name through navigation', async () => {
    const user = userEvent.setup()
    const name = 'local/example & 50%+#'
    render(
      <TestWrapper>
        <Routes>
          <Route path="/" element={<DatasetLinks names={[name, name, 'second']} />} />
          <Route path="/datasets" element={<DatasetDestination />} />
        </Routes>
      </TestWrapper>,
    )
    expect(screen.getAllByRole('link')).toHaveLength(2)
    expect(screen.getByRole('link', { name })).toHaveAttribute(
      'href', '/datasets?dataset=local%2Fexample+%26+50%25%2B%23',
    )
    await user.click(screen.getByRole('link', { name }))
    expect(screen.getByRole('heading', { name })).toBeInTheDocument()
  })

  it('should preserve the empty state without inventing a dataset link', () => {
    render(<TestWrapper><DatasetLinks names={[]} emptyText="Unavailable" /></TestWrapper>)
    expect(screen.getByText('Unavailable')).toBeInTheDocument()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })
})
