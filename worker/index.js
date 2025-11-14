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

// Crawling configuration
const MAX_CRAWL_DEPTH = 3
const MAX_PAGES_TO_CRAWL = 50
const MAX_URLS_TO_CHECK = 200

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
 * Extract ALL URLs from HTML content (enhanced)
 */
function extractUrlsFromHTML(html, baseUrl, baseDomain) {
  const urls = new Set()
  const base = new URL(baseUrl)

  // Extract from href attributes (all links)
  const hrefRegex = /href=["']([^"']+)["']/gi
  let match
  while ((match = hrefRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
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
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from data attributes
  const dataUrlRegex = /data-[\w-]*url=["']([^"']+)["']/gi
  while ((match = dataUrlRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from action attributes (forms)
  const actionRegex = /action=["']([^"']+)["']/gi
  while ((match = actionRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
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
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from axios calls
  const axiosRegex = /axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/gi
  while ((match = axiosRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[2], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
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
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from window.location
  const locationRegex = /window\.location\s*=\s*["']([^"']+)["']/gi
  while ((match = locationRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from URL strings in general
  const urlStringRegex = /(?:url|endpoint|api|path)\s*[:=]\s*["']([^"']+)["']/gi
  while ((match = urlStringRegex.exec(html)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return Array.from(urls)
}

/**
 * Extract ALL URLs from JavaScript content (enhanced)
 */
function extractUrlsFromJS(jsContent, baseUrl, baseDomain) {
  const urls = new Set()
  const base = new URL(baseUrl)

  // Extract from fetch() calls
  const fetchRegex = /fetch\s*\(\s*["']([^"']+)["']/gi
  let match
  while ((match = fetchRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
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
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from XMLHttpRequest
  const xhrRegex = /\.open\s*\(\s*["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']/gi
  while ((match = xhrRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from URL strings that look like API endpoints
  const apiUrlRegex = /["']([^"']*(?:\/api\/|\/graphql|\.json|\/v\d+\/)[^"']*)["']/gi
  while ((match = apiUrlRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from baseURL, apiUrl, endpoint variables
  const varUrlRegex = /(?:baseURL|apiUrl|endpoint|api|url)\s*[:=]\s*["']([^"']+)["']/gi
  while ((match = varUrlRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
      }
    } catch {
      // Invalid URL, skip
    }
  }

  // Extract from template literals
  const templateRegex = /`([^`]*(?:\/api\/|\/graphql|\.json)[^`]*)`/gi
  while ((match = templateRegex.exec(jsContent)) !== null) {
    try {
      const url = new URL(match[1], base).href
      if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
        urls.add(normalizeUrl(url))
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
    /\/swagger/i,
    /\/openapi/i,
    /\/webhook/i,
    /\/callback/i,
    /\/oauth/i,
    /\/auth/i,
    /\/token/i,
    /\/user/i,
    /\/admin/i,
    /\/dashboard/i,
    /\/data/i,
    /\/query/i,
  ]
  return apiPatterns.some(pattern => pattern.test(url))
}

/**
 * Check if URL belongs to the same domain (including subdomains)
 */
function isSameDomain(url, baseDomain) {
  try {
    const urlObj = new URL(url)
    const urlHost = urlObj.hostname.toLowerCase()
    const baseHost = baseDomain.toLowerCase()
    
    // Exact match
    if (urlHost === baseHost) return true
    
    // Subdomain match (e.g., api.example.com matches example.com)
    if (urlHost.endsWith('.' + baseHost)) return true
    
    return false
  } catch {
    return false
  }
}

/**
 * Normalize URL - remove fragments, query params for deduplication
 */
function normalizeUrl(url) {
  try {
    const urlObj = new URL(url)
    urlObj.hash = ''
    // Keep query params for APIs as they might be different endpoints
    return urlObj.href
  } catch {
    return url
  }
}

/**
 * Extract URLs from sitemap.xml
 */
async function extractUrlsFromSitemap(sitemapUrl, baseDomain) {
  const urls = new Set()
  try {
    const response = await fetchWithTimeout(sitemapUrl, { method: 'GET' })
    if (!response.ok) return Array.from(urls)
    
    const text = await response.text()
    
    // Extract URLs from sitemap
    const urlRegex = /<loc[^>]*>([^<]+)<\/loc>/gi
    let match
    while ((match = urlRegex.exec(text)) !== null) {
      try {
        const url = match[1].trim()
        if (isValidUrl(url) && isSameDomain(url, baseDomain)) {
          urls.add(normalizeUrl(url))
        }
      } catch {
        // Invalid URL, skip
      }
    }
    
    // Also check for sitemap index files
    const sitemapIndexRegex = /<sitemap[^>]*>[\s\S]*?<loc[^>]*>([^<]+)<\/loc>/gi
    while ((match = sitemapIndexRegex.exec(text)) !== null) {
      try {
        const sitemapUrl = match[1].trim()
        if (isValidUrl(sitemapUrl)) {
          const nestedUrls = await extractUrlsFromSitemap(sitemapUrl, baseDomain)
          nestedUrls.forEach(u => urls.add(u))
        }
      } catch {
        // Skip nested sitemap
      }
    }
  } catch {
    // Failed to fetch sitemap
  }
  
  return Array.from(urls)
}

/**
 * Extract URLs from robots.txt
 */
async function extractUrlsFromRobots(robotsUrl, baseDomain) {
  const urls = new Set()
  try {
    const response = await fetchWithTimeout(robotsUrl, { method: 'GET' })
    if (!response.ok) return Array.from(urls)
    
    const text = await response.text()
    const base = new URL(robotsUrl)
    
    // Extract sitemap URLs
    const sitemapRegex = /Sitemap:\s*([^\s]+)/gi
    let match
    while ((match = sitemapRegex.exec(text)) !== null) {
      try {
        const sitemapUrl = new URL(match[1].trim(), base).href
        if (isValidUrl(sitemapUrl)) {
          const sitemapUrls = await extractUrlsFromSitemap(sitemapUrl, baseDomain)
          sitemapUrls.forEach(u => urls.add(u))
        }
      } catch {
        // Skip
      }
    }
  } catch {
    // Failed to fetch robots.txt
  }
  
  return Array.from(urls)
}

/**
 * Scan a single endpoint
 */
async function scanEndpoint(url) {
  try {
    const response = await fetchWithTimeout(url, { method: 'GET' })
    const status = response.status
    const contentType = response.headers.get('content-type') || ''
    const contentLength = response.headers.get('content-length')

    let sample = null
    let dataType = null
    let dataInfo = null

    if (status === 200) {
      try {
        const text = await response.text()
        const textLength = text.length

        // Get more data for open endpoints (up to 1000 chars)
        if (contentType.includes('application/json')) {
          dataType = 'JSON'
          try {
            const parsed = JSON.parse(text)
            // Get first 1000 chars of formatted JSON
            sample = JSON.stringify(parsed, null, 2).substring(0, 1000)
            
            // Analyze JSON structure
            if (typeof parsed === 'object') {
              const keys = Object.keys(parsed)
              dataInfo = {
                type: 'object',
                keys: keys.slice(0, 10), // First 10 keys
                totalKeys: keys.length,
                size: textLength,
              }
            }
          } catch {
            // Not valid JSON, use raw text
            sample = text.substring(0, 1000)
            dataType = 'Text (JSON-like)'
          }
        } else if (contentType.includes('text/html')) {
          dataType = 'HTML'
          // Extract title or first meaningful content
          const titleMatch = text.match(/<title[^>]*>([^<]+)<\/title>/i)
          if (titleMatch) {
            sample = `HTML Page - Title: ${titleMatch[1]}\n\nFirst 500 chars:\n${text.substring(0, 500)}`
          } else {
            sample = text.substring(0, 1000)
          }
        } else if (contentType.includes('text/plain') || contentType.includes('text/')) {
          dataType = 'Text'
          sample = text.substring(0, 1000)
        } else if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
          dataType = 'XML'
          sample = text.substring(0, 1000)
        } else {
          dataType = contentType.split(';')[0] || 'Unknown'
          sample = text.substring(0, 1000)
        }

        // Add truncation notice if content is longer
        if (textLength > 1000) {
          sample += `\n\n... (truncated, total length: ${textLength} characters)`
        }
      } catch {
        // Failed to read body, ignore
      }
    }

    return {
      url,
      status,
      open: status === 200,
      sample,
      dataType,
      dataInfo,
      contentType,
      contentLength: contentLength ? parseInt(contentLength) : null,
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
 * Deep crawl website and discover all URLs, then check for open APIs
 */
async function deepCrawlAndFindOpenAPIs(domain) {
  const baseUrl = `https://${domain}`
  const baseDomain = domain
  const seenUrls = new Set()
  const urlsToCrawl = []
  const crawledUrls = new Set()
  const allDiscoveredUrls = new Set()
  const openAPIs = []

  // Step 1: Check sitemap.xml and robots.txt
  try {
    const sitemapUrls = await extractUrlsFromSitemap(`${baseUrl}/sitemap.xml`, baseDomain)
    sitemapUrls.forEach(url => {
      if (!seenUrls.has(url)) {
        seenUrls.add(url)
        allDiscoveredUrls.add(url)
        urlsToCrawl.push(url)
      }
    })

    const robotsUrls = await extractUrlsFromRobots(`${baseUrl}/robots.txt`, baseDomain)
    robotsUrls.forEach(url => {
      if (!seenUrls.has(url)) {
        seenUrls.add(url)
        allDiscoveredUrls.add(url)
        urlsToCrawl.push(url)
      }
    })
  } catch {
    // Continue if sitemap/robots not available
  }

  // Step 2: Start with homepage
  if (!seenUrls.has(baseUrl)) {
    seenUrls.add(baseUrl)
    urlsToCrawl.push(baseUrl)
  }

  // Step 3: Deep crawl pages (limited depth and count)
  let crawlDepth = 0
  const maxDepth = MAX_CRAWL_DEPTH
  const maxPages = MAX_PAGES_TO_CRAWL

  while (urlsToCrawl.length > 0 && crawledUrls.size < maxPages && crawlDepth < maxDepth) {
    const currentBatch = urlsToCrawl.splice(0, Math.min(10, urlsToCrawl.length))
    
    await Promise.all(
      currentBatch.map(async (url) => {
        if (crawledUrls.has(url)) return
        crawledUrls.add(url)

        try {
          const response = await fetchWithTimeout(url, { method: 'GET' })
          if (!response.ok) return

          const contentType = response.headers.get('content-type') || ''
          
          if (contentType.includes('text/html')) {
            const html = await response.text()
            
            // Extract all URLs from HTML
            const htmlUrls = extractUrlsFromHTML(html, url, baseDomain)
            htmlUrls.forEach(newUrl => {
              if (!seenUrls.has(newUrl)) {
                seenUrls.add(newUrl)
                allDiscoveredUrls.add(newUrl)
                // Add to crawl queue if same domain and not too deep
                if (crawlDepth < maxDepth - 1) {
                  urlsToCrawl.push(newUrl)
                }
              }
            })

            // Extract and analyze JS files
            const jsFileRegex = /<script[^>]*src=["']([^"']+\.js[^"']*)["']/gi
            let match
            const jsFiles = []
            while ((match = jsFileRegex.exec(html)) !== null && jsFiles.length < 20) {
              try {
                const jsUrl = new URL(match[1], url).href
                if (isValidUrl(jsUrl) && isSameDomain(jsUrl, baseDomain) && !seenUrls.has(jsUrl)) {
                  jsFiles.push(jsUrl)
                  seenUrls.add(jsUrl)
                }
              } catch {
                // Skip
              }
            }

            // Fetch and analyze JS files
            for (const jsUrl of jsFiles.slice(0, 15)) {
              try {
                const jsResponse = await fetchWithTimeout(jsUrl, { method: 'GET' })
                if (jsResponse.ok) {
                  const jsContent = await jsResponse.text()
                  const jsUrls = extractUrlsFromJS(jsContent, url, baseDomain)
                  jsUrls.forEach(newUrl => {
                    if (!seenUrls.has(newUrl)) {
                      seenUrls.add(newUrl)
                      allDiscoveredUrls.add(newUrl)
                    }
                  })
                }
              } catch {
                // Skip failed JS files
              }
            }
          }
        } catch {
          // Skip failed requests
        }
      })
    )

    crawlDepth++
  }

  // Step 4: Check all discovered URLs for open APIs
  const urlsToCheck = Array.from(allDiscoveredUrls)
    .filter(url => isApiLikeUrl(url) || url.includes('/api') || url.endsWith('.json'))
    .slice(0, MAX_URLS_TO_CHECK)

  // Check URLs in batches
  const batchSize = 10
  for (let i = 0; i < urlsToCheck.length; i += batchSize) {
    const batch = urlsToCheck.slice(i, i + batchSize)
    const results = await Promise.all(
      batch.map(async (url) => {
        const result = await scanEndpoint(url)
        if (result.open && result.status === 200) {
          return {
            url: result.url,
            status: result.status,
            open: true,
            sample: result.sample,
            dataType: result.dataType,
            dataInfo: result.dataInfo,
            contentType: result.contentType,
            contentLength: result.contentLength,
            found_in: 'deep_crawl',
          }
        }
        return null
      })
    )
    
    results.forEach(result => {
      if (result) {
        openAPIs.push(result)
      }
    })
  }

  return openAPIs
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

      // Perform scans - deep crawl will find all open APIs
      const [commonEndpoints, deepCrawlOpenAPIs, sensitiveFiles] = await Promise.all([
        scanCommonEndpoints(normalizedDomain),
        deepCrawlAndFindOpenAPIs(normalizedDomain),
        checkSensitiveFiles(normalizedDomain),
      ])

      // Filter common endpoints to only show open ones
      const openCommonEndpoints = commonEndpoints.filter(e => e.open)
      
      // Filter sensitive files to only show exposed ones
      const exposedSensitiveFiles = sensitiveFiles.filter(f => f.exposed)

      // Combine all open APIs (remove duplicates)
      const allOpenAPIs = []
      const seenApiUrls = new Set()
      
      // Add common open endpoints
      openCommonEndpoints.forEach(ep => {
        if (!seenApiUrls.has(ep.url)) {
          seenApiUrls.add(ep.url)
          allOpenAPIs.push(ep)
        }
      })
      
      // Add deep crawl open APIs
      deepCrawlOpenAPIs.forEach(api => {
        if (!seenApiUrls.has(api.url)) {
          seenApiUrls.add(api.url)
          allOpenAPIs.push(api)
        }
      })

      // Return results - ONLY open APIs and exposed files
      const results = {
        domain: normalizedDomain,
        open_apis: allOpenAPIs,
        exposed_sensitive_files: exposedSensitiveFiles,
        scan_summary: {
          total_open_apis: allOpenAPIs.length,
          total_exposed_files: exposedSensitiveFiles.length,
          common_endpoints_checked: commonEndpoints.length,
          common_endpoints_open: openCommonEndpoints.length,
        },
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

