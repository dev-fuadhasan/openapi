/**
 * Open API Exposure Scanner - Cloudflare Worker
 * 
 * This worker scans domains for exposed API endpoints, sensitive files,
 * and discovers hidden URLs from HTML/JS files.
 */

// Common API endpoints to scan
const COMMON_ENDPOINTS = [
  '/api/',
  '/api/v1/',
  '/api/users',
  '/api/auth',
  '/api/admin',
  '/api-docs',
  '/api/v1/auth',
  '/graphql',
  '/swagger.json',
  '/openapi.json',
  '/wp-json/',
  '/config.json',
  '/settings.json',
  '/env',
  '/.env',
  '/.git/HEAD',
  '/debug',
  '/phpinfo.php',
]

// Sensitive files to check
const SENSITIVE_FILES = [
  '/.env',
  '/env',
  '/config.json',
  '/config.js',
  '/settings.json',
  '/.git/HEAD',
  '/phpinfo.php',
]

// Timeout for fetch requests (in milliseconds)
const FETCH_TIMEOUT = 10000

/**
 * Normalize domain - remove protocol and trailing slashes
 */
function normalizeDomain(domain) {
  return domain
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .trim()
}

/**
 * Validate domain format
 */
function isValidDomain(domain) {
  const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i
  return domainRegex.test(domain)
}

/**
 * Fetch with timeout
 */
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT)

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ...options.headers,
      },
    })
    clearTimeout(timeoutId)
    return response
  } catch (error) {
    clearTimeout(timeoutId)
    if (error.name === 'AbortError') {
      throw new Error('Request timeout')
    }
    throw error
  }
}

/**
 * Check if URL is valid and absolute
 */
function isValidUrl(url) {
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * Extract URLs from HTML content
 */
function extractUrlsFromHTML(html, baseUrl) {
  const urls = new Set()
  const base = new URL(baseUrl)

  // Extract from href attributes
  const hrefRegex = /href=["']([^"']+)["']/gi
  let match
  while ((match = hrefRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from src attributes
  const srcRegex = /src=["']([^"']+)["']/gi
  while ((match = srcRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from fetch() calls
  const fetchRegex = /fetch\s*\(\s*["']([^"']+)["']/gi
  while ((match = fetchRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from axios.get() calls
  const axiosRegex = /axios\.(get|post|put|delete)\s*\(\s*["']([^"']+)["']/gi
  while ((match = axiosRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[2], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from $.ajax() calls
  const ajaxRegex = /\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']/gi
  while ((match = ajaxRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return Array.from(urls)
}

/**
 * Extract URLs from JavaScript content
 */
function extractUrlsFromJS(jsContent, baseUrl) {
  const urls = new Set()
  const base = new URL(baseUrl)

  // Extract from fetch() calls
  const fetchRegex = /fetch\s*\(\s*["']([^"']+)["']/gi
  let match
  while ((match = fetchRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from axios calls
  const axiosRegex = /axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/gi
  while ((match = axiosRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[2], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from XMLHttpRequest
  const xhrRegex = /\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE)["']\s*,\s*["']([^"']+)["']/gi
  while ((match = xhrRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from URL strings that look like API endpoints
  const apiUrlRegex = /["']([^"']*(?:\/api\/|\/graphql|\.json)[^"']*)["']/gi
  while ((match = apiUrlRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url)) {
        urls.add(url)
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return Array.from(urls)
}

/**
 * Check if a URL is API-like
 */
function isApiLikeUrl(url) {
  const apiPatterns = [
    /\/api\//i,
    /\/graphql/i,
    /\.json$/i,
    /\/v\d+\//i,
    /\/endpoint/i,
    /\/rest/i,
  ]
  return apiPatterns.some(pattern => pattern.test(url))
}

/**
 * Scan a single endpoint
 */
async function scanEndpoint(url) {
  try {
    const response = await fetchWithTimeout(url, { method: 'GET' })
    const status = response.status
    const contentType = response.headers.get('content-type') || ''

    let sample = null
    if (status === 200 && contentType.includes('application/json')) {
      try {
        const text = await response.text()
        sample = text.substring(0, 200)
      } catch {
        // Failed to read body, ignore
      }
    }

    return {
      url,
      status,
      open: status === 200,
      sample,
    }
  } catch (error) {
    return {
      url,
      status: 0,
      open: false,
      error: error.message,
    }
  }
}

/**
 * Scan common API endpoints
 */
async function scanCommonEndpoints(domain) {
  const baseUrl = `https://${domain}`
  const results = []

  // Scan endpoints in parallel with limited concurrency
  const batchSize = 5
  for (let i = 0; i < COMMON_ENDPOINTS.length; i += batchSize) {
    const batch = COMMON_ENDPOINTS.slice(i, i + batchSize)
    const batchResults = await Promise.all(
      batch.map(endpoint => scanEndpoint(`${baseUrl}${endpoint}`))
    )
    results.push(...batchResults)
  }

  return results
}

/**
 * Crawl homepage and extract URLs
 */
async function crawlHomepage(domain) {
  const baseUrl = `https://${domain}`
  const discoveredEndpoints = []
  const seenUrls = new Set()

  try {
    // Fetch homepage
    const response = await fetchWithTimeout(baseUrl, { method: 'GET' })
    if (!response.ok) {
      return discoveredEndpoints
    }

    const html = await response.text()

    // Extract URLs from HTML
    const htmlUrls = extractUrlsFromHTML(html, baseUrl)
    for (const url of htmlUrls) {
      if (!seenUrls.has(url)) {
        seenUrls.add(url)
        if (isApiLikeUrl(url)) {
          discoveredEndpoints.push({
            url,
            found_in: 'homepage_html',
          })
        }
      }
    }

    // Find and fetch JS files
    const jsFileRegex = /<script[^>]*src=["']([^"']+\.js[^"']*)["']/gi
    let match
    const jsFiles = []
    while ((match = jsFileRegex.exec(html)) !== null) {
      try {
        const jsUrl = new URL(match[1], baseUrl).href
        if (isValidUrl(jsUrl) && !seenUrls.has(jsUrl)) {
          jsFiles.push(jsUrl)
          seenUrls.add(jsUrl)
        }
      } catch {
        // Invalid URL, skip
      }
    }

    // Fetch and analyze JS files (limit to first 10 to avoid timeout)
    const jsFilesToFetch = jsFiles.slice(0, 10)
    for (const jsUrl of jsFilesToFetch) {
      try {
        const jsResponse = await fetchWithTimeout(jsUrl, { method: 'GET' })
        if (jsResponse.ok) {
          const jsContent = await jsResponse.text()
          const jsUrls = extractUrlsFromJS(jsContent, baseUrl)

          for (const url of jsUrls) {
            if (!seenUrls.has(url)) {
              seenUrls.add(url)
              if (isApiLikeUrl(url)) {
                discoveredEndpoints.push({
                  url,
                  found_in: `js_file:${jsUrl.split('/').pop()}`,
                })
              }
            }
          }
        }
      } catch {
        // Failed to fetch JS file, skip
      }
    }
  } catch (error) {
    console.error('Error crawling homepage:', error)
  }

  return discoveredEndpoints
}

/**
 * Check sensitive files
 */
async function checkSensitiveFiles(domain) {
  const baseUrl = `https://${domain}`
  const results = []

  // Check files in parallel with limited concurrency
  const batchSize = 5
  for (let i = 0; i < SENSITIVE_FILES.length; i += batchSize) {
    const batch = SENSITIVE_FILES.slice(i, i + batchSize)
    const batchResults = await Promise.all(
      batch.map(async (file) => {
        try {
          const url = `${baseUrl}${file}`
          const response = await fetchWithTimeout(url, { method: 'GET' })
          return {
            url,
            status: response.status,
            exposed: response.status === 200,
          }
        } catch {
          return {
            url: `${baseUrl}${file}`,
            status: 0,
            exposed: false,
          }
        }
      })
    )
    results.push(...batchResults)
  }

  return results
}

/**
 * Handle CORS preflight
 */
function handleCors(request) {
  const origin = request.headers.get('Origin')
  const headers = {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  }
  return new Response(null, { status: 204, headers })
}

/**
 * Main request handler
 */
export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCors(request)
    }

    // Only allow POST requests to /scan
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/scan') {
      return new Response(
        JSON.stringify({ error: 'Not found. Use POST /scan' }),
        {
          status: 404,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }

    try {
      // Parse request body
      const body = await request.json()
      const { domain } = body

      if (!domain || typeof domain !== 'string') {
        return new Response(
          JSON.stringify({ error: 'Domain is required' }),
          {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          }
        )
      }

      // Normalize and validate domain
      const normalizedDomain = normalizeDomain(domain)
      if (!isValidDomain(normalizedDomain)) {
        return new Response(
          JSON.stringify({ error: 'Invalid domain format' }),
          {
            status: 400,
            headers: {
              'Content-Type': 'application/json',
              'Access-Control-Allow-Origin': '*',
            },
          }
        )
      }

      // Perform scans in parallel
      const [commonEndpoints, discoveredEndpoints, sensitiveFiles] = await Promise.all([
        scanCommonEndpoints(normalizedDomain),
        crawlHomepage(normalizedDomain),
        checkSensitiveFiles(normalizedDomain),
      ])

      // Return results
      const results = {
        domain: normalizedDomain,
        common_endpoints: commonEndpoints,
        discovered_endpoints: discoveredEndpoints,
        sensitive_files: sensitiveFiles,
      }

      return new Response(JSON.stringify(results), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      })
    } catch (error) {
      console.error('Error processing request:', error)
      return new Response(
        JSON.stringify({ error: 'Internal server error', message: error.message }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        }
      )
    }
  },
}

