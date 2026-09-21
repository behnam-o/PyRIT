# PyRIT Frontend

Modern TypeScript + React frontend for PyRIT, built with Fluent UI.

## Development

```bash
# Install dependencies
npm install

# Start both backend and frontend (cross-platform)
python dev.py start
# OR use npm script
npm run start

# Start backend only (with airt initializer by default)
python dev.py backend

# Start frontend only (backend must be started separately)
python dev.py frontend
# OR
npm run dev

# Restart both servers
python dev.py restart
# OR
npm run restart

# Stop all servers
python dev.py stop
# OR
npm run stop

# Build for production
npm run build

# Preview production build
npm run preview
```

### Backend CLI

The backend uses `pyrit_backend` CLI which supports initializers:

```bash
# Start with default airt initializer (loads targets from env vars)
pyrit_backend --initializers airt

# Start without initializers
pyrit_backend

# Start with custom initialization script
pyrit_backend --initialization-scripts ./my_targets.py

# List available initializers
pyrit_backend --list-initializers

# Custom host/port
pyrit_backend --host 127.0.0.1 --port 8080
```

**Development Mode**: The `dev.py` script sets `PYRIT_DEV_MODE=true` so the backend expects the frontend to run separately on port 3000.

**Production Mode**: When installed from PyPI, the backend serves the bundled frontend and will exit if frontend files are missing.

## Dataset browser

Open **Datasets** in the sidebar to search available dataset names. Select a dataset
to browse its loaded seeds in pages of 25. A compact table shows seed/data type
beside a single-line content preview. Expand a row for the complete seed as
indented JSON, with type and content first, followed by its IDs and metadata.
Copy either the original value or the full JSON record. The selected dataset is
stored in the URL.

The two panels fill the remaining viewport height and scroll independently.
Headings and controls stay above the scrolling content; on very short screens,
the panel itself can also scroll so controls never become inaccessible.
On narrow screens the panels stack and share the available height.

Each dataset has one status/action element: a download button when not loaded,
a spinner while loading, and a check mark when its seeds are in memory.
Use the download button beside a dataset or **Load dataset** in the selected
panel to load it using its registered provider. Remote datasets
may require network access and provider credentials. Both panels show loading
state and errors, and update when loading finishes. Already-loaded datasets are
not loaded again; memory-only datasets without providers cannot be loaded here.

Browsing alone does not download anything. Seeds cannot be edited or deleted in
this view. Non-text values are shown as stored references, not opened as media.
Dataset names in the Scanner catalog, scan configuration/preview, and individual
Scanner History run configuration link directly to the dataset browser.

## Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Fluent UI v9** - Microsoft design system
- **Vite** - Fast build tool
- **Axios** - HTTP client

## Testing

```bash
# Unit & Integration Tests (Jest + React Testing Library)
npm test              # Run all tests
npm run test:watch    # Watch mode for development
npm run test:coverage # Run with coverage report (85%+ threshold)

# End-to-End Tests (Playwright)
npm run test:e2e          # Run headless (auto-starts frontend + backend via dev.py)
npm run test:e2e:headed   # Run with visible browser windows (requires display)
npm run test:e2e:ui       # Interactive UI mode (requires display)
```

### E2E Test Modes

E2E flow tests run in two modes controlled by Playwright projects and an environment variable:

- **Seeded** (`--project seeded`, default for CI): Messages are stored directly in the database with `send: false` using dummy credentials. No real API keys needed. Tests cover the full UI flow (display, branching, conversation switching, promoting) without calling any external service.

- **Live** (`--project live`, requires `E2E_LIVE_MODE=true`): Messages are sent to real OpenAI endpoints with `send: true`. Each target variant requires endpoint and model environment variables plus either an API key or an Azure endpoint accessible through the current Entra identity. Variants without a usable configuration are automatically skipped. Tests verify that real target responses render correctly.

```bash
# Seeded integration (no credentials needed)
npx playwright test --project seeded

# Live integration (uses API keys when present, otherwise Entra authentication)
E2E_LIVE_MODE=true npx playwright test --project live

# Run both
E2E_LIVE_MODE=true npx playwright test
```

The mock and seeded projects run in the **GitHub Actions** pull-request workflow. The live project is intended for a protected pipeline with an Entra identity or API keys.

E2E tests use `dev.py` to automatically start both frontend and backend servers. If servers are already running, they will be reused.

> **Note**: `test:e2e:ui` and `test:e2e:headed` require a graphical display and won't work in headless environments like devcontainers. Use `npm run test:e2e` for CI/headless testing.

## Configuration

The frontend proxies API requests to `http://localhost:8000` in development.
Configure this in `vite.config.ts` if needed.
