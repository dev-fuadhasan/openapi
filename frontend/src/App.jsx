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
        {scanResults && !loading && (() => {
          const openAPIs = scanResults.open_apis || []
          const exposedFiles = scanResults.exposed_sensitive_files || []
          const sqlInjectionVulns = scanResults.sql_injection_vulnerabilities || []
          const totalOpen = openAPIs.length + exposedFiles.length + sqlInjectionVulns.length
          const summary = scanResults.scan_summary || {}

          return (
            <div className="mt-8 space-y-6 max-w-6xl mx-auto">
              {/* Summary Alert */}
              {totalOpen > 0 ? (
                <div className="bg-red-500/20 border-2 border-red-500 rounded-lg p-6">
                  <div className="flex items-start gap-4">
                    <div className="flex-shrink-0">
                      <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                    <div className="flex-1">
                      <h3 className="text-xl font-bold text-red-400 mb-2">
                        ⚠️ Security Alert: {totalOpen} Open/Exposed Endpoint{totalOpen > 1 ? 's' : ''} Found!
                      </h3>
                      <p className="text-red-200 mb-3">
                        The following endpoints are publicly accessible and may expose sensitive data:
                      </p>
                      <div className="space-y-2">
                        {openAPIs.length > 0 && (
                          <div className="text-red-200">
                            <span className="font-semibold">• {openAPIs.length} Open API Endpoint{openAPIs.length > 1 ? 's' : ''} Found:</span>
                            <ul className="ml-4 mt-1 space-y-1">
                              {openAPIs.slice(0, 3).map((ep, idx) => (
                                <li key={idx} className="text-sm font-mono">{ep.url}</li>
                              ))}
                              {openAPIs.length > 3 && (
                                <li className="text-sm">... and {openAPIs.length - 3} more</li>
                              )}
                            </ul>
                          </div>
                        )}
                        {exposedFiles.length > 0 && (
                          <div className="text-red-200">
                            <span className="font-semibold">• {exposedFiles.length} Exposed Sensitive File{exposedFiles.length > 1 ? 's' : ''}:</span>
                            <ul className="ml-4 mt-1 space-y-1">
                              {exposedFiles.slice(0, 3).map((file, idx) => (
                                <li key={idx} className="text-sm font-mono">{file.url}</li>
                              ))}
                              {exposedFiles.length > 3 && (
                                <li className="text-sm">... and {exposedFiles.length - 3} more</li>
                              )}
                            </ul>
                          </div>
                        )}
                        {sqlInjectionVulns.length > 0 && (
                          <div className="text-red-200">
                            <span className="font-semibold">• {sqlInjectionVulns.length} SQL Injection Vulnerabilit{sqlInjectionVulns.length > 1 ? 'ies' : 'y'} Found:</span>
                            <ul className="ml-4 mt-1 space-y-1">
                              {sqlInjectionVulns.slice(0, 3).map((vuln, idx) => (
                                <li key={idx} className="text-sm font-mono">{vuln.url}</li>
                              ))}
                              {sqlInjectionVulns.length > 3 && (
                                <li className="text-sm">... and {sqlInjectionVulns.length - 3} more</li>
                              )}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-green-500/20 border-2 border-green-500 rounded-lg p-6">
                  <div className="flex items-center gap-4">
                    <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                      <h3 className="text-xl font-bold text-green-400 mb-1">✅ No Open APIs Found</h3>
                      <p className="text-green-200">No publicly accessible endpoints or exposed sensitive files detected.</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Scan Summary */}
              {summary && (
                <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                  <h3 className="text-lg font-semibold text-white mb-3">Scan Summary</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <div className="text-gray-400">Open APIs Found</div>
                      <div className="text-2xl font-bold text-red-400">{summary.total_open_apis || 0}</div>
                    </div>
                    <div>
                      <div className="text-gray-400">Exposed Files</div>
                      <div className="text-2xl font-bold text-red-400">{summary.total_exposed_files || 0}</div>
                    </div>
                    <div>
                      <div className="text-gray-400">Endpoints Checked</div>
                      <div className="text-2xl font-bold text-blue-400">{summary.common_endpoints_checked || 0}</div>
                    </div>
                    <div>
                      <div className="text-gray-400">SQL Injection Vulns</div>
                      <div className="text-2xl font-bold text-red-400">{summary.total_sql_injection_vulns || 0}</div>
                    </div>
                  </div>
                </div>
              )}

              {/* SQL Injection Vulnerabilities */}
              {sqlInjectionVulns.length > 0 && (
                <ResultCard
                  title={`SQL Injection Vulnerabilities Found (${sqlInjectionVulns.length})`}
                  items={sqlInjectionVulns}
                  renderItem={(vuln) => (
                    <div className="border-l-4 border-red-600 pl-4 py-3 rounded-r bg-red-500/10">
                      <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
                        <a
                          href={vuln.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-red-400 hover:text-red-300 break-all font-mono text-sm font-semibold"
                        >
                          {vuln.url}
                        </a>
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-red-600 text-white animate-pulse">
                          🔴 HIGH SEVERITY
                        </span>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="text-red-300 text-sm font-semibold">
                          ⚠️ Vulnerable Parameters:
                        </div>
                        {vuln.vulnerable_params && vuln.vulnerable_params.map((param, idx) => (
                          <div key={idx} className="bg-gray-900/50 p-3 rounded border border-red-500/30">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-red-400 font-semibold text-xs">Parameter:</span>
                              <span className="text-yellow-300 font-mono text-xs">{param.parameter}</span>
                            </div>
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-red-400 font-semibold text-xs">Payload:</span>
                              <span className="text-gray-300 font-mono text-xs bg-gray-800 px-2 py-1 rounded">{param.payload}</span>
                            </div>
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-red-400 font-semibold text-xs">Evidence:</span>
                              <span className="text-red-300 text-xs">{param.evidence}</span>
                            </div>
                            {param.response_sample && (
                              <div className="mt-2">
                                <div className="text-gray-400 text-xs mb-1">Response Sample:</div>
                                <div className="bg-gray-800 p-2 rounded text-xs text-gray-300 font-mono overflow-x-auto max-h-40 overflow-y-auto">
                                  <pre className="whitespace-pre-wrap break-words">{param.response_sample}</pre>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                      
                      <div className="mt-3 p-2 bg-red-500/10 border border-red-500/30 rounded">
                        <p className="text-red-300 text-xs">
                          <strong>⚠️ Security Risk:</strong> This URL is vulnerable to SQL injection attacks. 
                          Attackers could potentially access, modify, or delete database records.
                        </p>
                      </div>
                    </div>
                  )}
                />
              )}

              {/* Open APIs */}
              <ResultCard
                title={`Open APIs Found (${openAPIs.length})`}
                items={openAPIs}
                renderItem={(item) => (
                  <div className={`border-l-4 pl-4 py-3 rounded-r ${item.open ? 'bg-red-500/10 border-red-500' : 'border-blue-500'}`}>
                    <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
                      <a
                        href={item.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300 break-all font-mono text-sm font-semibold"
                      >
                        {item.url}
                      </a>
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-bold ${
                          item.open
                            ? 'bg-red-500 text-white animate-pulse'
                            : item.status === 401 || item.status === 403
                            ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/50'
                            : item.status === 404
                            ? 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/50'
                        }`}
                      >
                        {item.status} {item.open ? '🔓 OPEN' : item.status === 401 ? '🔒 AUTH REQUIRED' : item.status === 403 ? '🚫 FORBIDDEN' : item.status === 404 ? '❌ NOT FOUND' : ''}
                      </span>
                    </div>
                    {item.open && (
                      <div className="mt-3 p-4 bg-red-500/5 border border-red-500/30 rounded">
                        <div className="flex items-center gap-2 mb-3">
                          <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                          <span className="text-red-400 font-semibold text-sm">⚠️ Exposed Data:</span>
                        </div>
                        
                        {/* Data Type and Info */}
                        <div className="mb-3 space-y-2">
                          {item.dataType && (
                            <div className="flex items-center gap-2 text-xs">
                              <span className="text-gray-400">Data Type:</span>
                              <span className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded font-mono">{item.dataType}</span>
                            </div>
                          )}
                          {item.contentType && (
                            <div className="flex items-center gap-2 text-xs">
                              <span className="text-gray-400">Content-Type:</span>
                              <span className="text-gray-300 font-mono">{item.contentType}</span>
                            </div>
                          )}
                          {item.contentLength && (
                            <div className="flex items-center gap-2 text-xs">
                              <span className="text-gray-400">Size:</span>
                              <span className="text-gray-300">{item.contentLength.toLocaleString()} bytes</span>
                            </div>
                          )}
                          {item.dataInfo && item.dataInfo.type === 'object' && (
                            <div className="mt-2 p-2 bg-gray-800/50 rounded text-xs">
                              <span className="text-gray-400">JSON Structure: </span>
                              <span className="text-gray-300">
                                Object with {item.dataInfo.totalKeys} key{item.dataInfo.totalKeys !== 1 ? 's' : ''}
                                {item.dataInfo.keys.length > 0 && (
                                  <span className="ml-2">
                                    ({item.dataInfo.keys.slice(0, 5).join(', ')}
                                    {item.dataInfo.keys.length > 5 && ` +${item.dataInfo.keys.length - 5} more`})
                                  </span>
                                )}
                              </span>
                            </div>
                          )}
                        </div>

                        {/* Sample Data */}
                        {item.sample ? (
                          <div className="bg-gray-900/50 p-3 rounded border border-gray-700">
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-gray-400 text-xs font-semibold">Response Data Preview:</span>
                              {item.sample.length > 1000 && (
                                <span className="text-yellow-400 text-xs">(Truncated)</span>
                              )}
                            </div>
                            <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words overflow-x-auto max-h-60 overflow-y-auto">
                              {item.sample}
                            </pre>
                          </div>
                        ) : (
                          <p className="text-gray-400 text-sm italic">No data sample available</p>
                        )}
                        
                        <div className="mt-3 flex items-center gap-3">
                          <a
                            href={item.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-red-400 hover:text-red-300 text-sm font-semibold"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                            </svg>
                            View Full Response
                          </a>
                          <span className="text-gray-500 text-xs">|</span>
                          <span className="text-gray-500 text-xs">This endpoint is publicly accessible without authentication</span>
                        </div>
                      </div>
                    )}
                    {!item.open && item.status !== 404 && item.status !== 0 && (
                      <p className="text-gray-500 text-xs mt-2">
                        Status: {item.status} - {item.status === 401 ? 'Authentication required' : item.status === 403 ? 'Access forbidden' : 'Not publicly accessible'}
                      </p>
                    )}
                  </div>
                )}
              />

            {/* Sensitive Files */}
            <ResultCard
              title={`Exposed Sensitive Files (${exposedFiles.length})`}
              items={exposedFiles}
              renderItem={(item) => (
                <div className={`border-l-4 pl-4 py-3 rounded-r ${item.exposed ? 'bg-red-500/10 border-red-500' : 'border-gray-600'}`}>
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-red-400 hover:text-red-300 break-all font-mono text-sm font-semibold"
                    >
                      {item.url}
                    </a>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-bold ${
                        item.exposed
                          ? 'bg-red-500 text-white animate-pulse'
                          : 'bg-gray-500/20 text-gray-400 border border-gray-500/50'
                      }`}
                    >
                      {item.status} {item.exposed ? '🔓 EXPOSED' : '✅ SECURE'}
                    </span>
                  </div>
                  {item.exposed && (
                    <div className="mt-3 p-3 bg-red-500/5 border border-red-500/30 rounded">
                      <div className="flex items-center gap-2 mb-2">
                        <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <span className="text-red-400 font-semibold text-sm">⚠️ This sensitive file is publicly accessible!</span>
                      </div>
                      <p className="text-gray-400 text-xs mb-2">
                        Sensitive files like .env, config.json, or .git/HEAD should never be publicly accessible as they may contain:
                      </p>
                      <ul className="text-gray-400 text-xs list-disc list-inside space-y-1 mb-2">
                        <li>API keys and secrets</li>
                        <li>Database credentials</li>
                        <li>Configuration data</li>
                        <li>Source code information</li>
                      </ul>
                      <a
                        href={item.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-2 inline-block text-red-400 hover:text-red-300 text-sm font-semibold"
                      >
                        → View File Content
                      </a>
                    </div>
                  )}
                </div>
              )}
            />
            </div>
          )
        })()}

        {/* Footer */}
        <div className="mt-12 text-center text-gray-500 text-sm">
          <p>Use responsibly. Only scan domains you own or have permission to test.</p>
        </div>
      </div>
    </div>
  )
}

export default App

