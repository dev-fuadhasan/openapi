import { useState } from 'react'
import DomainInput from './components/DomainInput'
import ResultCard from './components/ResultCard'
import Loader from './components/Loader'

function App() {
  const [scanResults, setScanResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Replace with your Cloudflare Worker URL after deployment
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8787'

  const handleScan = async (domain) => {
    setLoading(true)
    setError(null)
    setScanResults(null)

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      setScanResults(data)
    } catch (err) {
      setError(err.message || 'An error occurred while scanning. Please try again.')
      console.error('Scan error:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-2">
            Open API Exposure Scanner
          </h1>
          <p className="text-gray-400 text-lg">
            Discover exposed API endpoints, sensitive files, and hidden URLs
          </p>
        </div>

        {/* Domain Input */}
        <DomainInput onScan={handleScan} disabled={loading} />

        {/* Error Message */}
        {error && (
          <div className="mt-4 max-w-2xl mx-auto">
            <div className="bg-red-500/10 border border-red-500 text-red-200 px-4 py-3 rounded-lg">
              <p className="font-semibold">Error:</p>
              <p>{error}</p>
            </div>
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div className="mt-8 flex justify-center">
            <Loader />
          </div>
        )}

        {/* Results */}
        {scanResults && !loading && (
          <div className="mt-8 space-y-6 max-w-6xl mx-auto">
            {/* Common Endpoints */}
            <ResultCard
              title="Common API Endpoints"
              items={scanResults.common_endpoints || []}
              renderItem={(item) => (
                <div className="border-l-4 border-blue-500 pl-4 py-2">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 break-all font-mono text-sm"
                    >
                      {item.url}
                    </a>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        item.open
                          ? 'bg-green-500/20 text-green-400 border border-green-500/50'
                          : item.status === 401 || item.status === 403
                          ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/50'
                          : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                      }`}
                    >
                      {item.status} {item.open ? 'OPEN' : ''}
                    </span>
                  </div>
                  {item.sample && (
                    <div className="mt-2 p-2 bg-gray-800/50 rounded text-xs text-gray-300 font-mono overflow-x-auto">
                      <pre className="whitespace-pre-wrap break-words">
                        {item.sample}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            />

            {/* Discovered Endpoints */}
            <ResultCard
              title="Discovered Endpoints"
              items={scanResults.discovered_endpoints || []}
              renderItem={(item) => (
                <div className="border-l-4 border-purple-500 pl-4 py-2">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 hover:text-purple-300 break-all font-mono text-sm"
                    >
                      {item.url}
                    </a>
                    <span className="px-2 py-1 bg-gray-700/50 text-gray-400 text-xs rounded">
                      {item.found_in}
                    </span>
                  </div>
                </div>
              )}
            />

            {/* Sensitive Files */}
            <ResultCard
              title="Sensitive Files"
              items={scanResults.sensitive_files || []}
              renderItem={(item) => (
                <div className="border-l-4 border-red-500 pl-4 py-2">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-red-400 hover:text-red-300 break-all font-mono text-sm"
                    >
                      {item.url}
                    </a>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        item.exposed
                          ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                          : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                      }`}
                    >
                      {item.status} {item.exposed ? 'EXPOSED' : ''}
                    </span>
                  </div>
                </div>
              )}
            />
          </div>
        )}

        {/* Footer */}
        <div className="mt-12 text-center text-gray-500 text-sm">
          <p>Use responsibly. Only scan domains you own or have permission to test.</p>
        </div>
      </div>
    </div>
  )
}

export default App

