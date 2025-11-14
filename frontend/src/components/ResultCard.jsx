import { useState } from 'react'

function ResultCard({ title, items, renderItem }) {
  const [isExpanded, setIsExpanded] = useState(true)

  if (!items || items.length === 0) {
    return (
      <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
        <h2 className="text-xl font-semibold text-white mb-4">{title}</h2>
        <p className="text-gray-400 text-sm">No items found.</p>
      </div>
    )
  }

  return (
    <div className="bg-gray-800/50 border border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-700/50 transition-colors"
      >
        <h2 className="text-xl font-semibold text-white">
          {title}
          <span className="ml-3 text-sm font-normal text-gray-400">
            ({items.length})
          </span>
        </h2>
        <svg
          className={`w-5 h-5 text-gray-400 transition-transform ${
            isExpanded ? 'transform rotate-180' : ''
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>
      {isExpanded && (
        <div className="px-6 py-4 space-y-3 max-h-96 overflow-y-auto">
          {items.map((item, index) => (
            <div key={index}>{renderItem(item)}</div>
          ))}
        </div>
      )}
    </div>
  )
}

export default ResultCard

