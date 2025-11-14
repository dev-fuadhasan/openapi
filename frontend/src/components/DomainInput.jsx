import { useState } from 'react'

function DomainInput({ onScan, disabled }) {
  const [domain, setDomain] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (domain.trim() && !disabled) {
      onScan(domain.trim())
    }
  }

  const normalizeDomain = (value) => {
    // Remove http://, https://, and trailing slashes
    return value
      .replace(/^https?:\/\//, '')
      .replace(/\/$/, '')
      .trim()
  }

  const handleChange = (e) => {
    setDomain(normalizeDomain(e.target.value))
  }

  return (
    <div className="max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={domain}
          onChange={handleChange}
          placeholder="Enter domain (e.g., example.com)"
          disabled={disabled}
          className="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <button
          type="submit"
          disabled={disabled || !domain.trim()}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors duration-200"
        >
          Scan Now
        </button>
      </form>
    </div>
  )
}

export default DomainInput

