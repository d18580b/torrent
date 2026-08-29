import React from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from './App'
import './styles.css'

const client = new QueryClient({
  defaultOptions: {
    queries: {
      // The daemon pushes deltas over SSE; polling is the fallback for when
      // that stream is unavailable, so it can be slow.
      refetchInterval: 15_000,
      refetchOnWindowFocus: true,
      retry: (n, err) => !(err instanceof Error && err.message === 'authentication required') && n < 2,
      staleTime: 2_000,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>,
)
