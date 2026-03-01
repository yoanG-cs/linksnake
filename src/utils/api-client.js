const WORKER_URL = 'https://linksnake.john-gergiev.workers.dev'
const REQUEST_TIMEOUT_MS = 8000

export async function checkUrl(url) {
  try {
    const response = await fetchWithTimeout(`${WORKER_URL}/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl: url })
    })

    if (!response.ok) {
      console.warn('[API] /check-url returned', response.status)
      return null
    }

    const data = await response.json()
    const matches = data.matches ?? []
    const threats = matches.map(m => m.threatType).filter(Boolean)
    const malicious = matches.length > 0

    if (malicious) {
      console.warn('[API] Safe Browsing flagged URL:', threats)
    }

    return { malicious, threats }
  } catch (error) {
    console.error('[API] checkUrl error:', error)
    return null
  }
}

export async function checkHash(sha256Hex) {
  try {
    const response = await fetchWithTimeout(`${WORKER_URL}/check-hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: sha256Hex })
    })

    if (!response.ok) {
      console.warn('[API] /check-hash returned', response.status)
      return null
    }

    const data = await response.json()
    if (!data || !data.query_status) return null

    if (data.query_status === 'hash_not_found') {
      return { malicious: false, info: null }
    }

    if (data.query_status === 'ok' && Array.isArray(data.data) && data.data.length > 0) {
      const entry = data.data[0]
      console.warn('[API] MalwareBazaar match:', entry.file_name, entry.tags)
      return {
        malicious: true,
        info: {
          fileName: entry.file_name,
          fileType: entry.file_type,
          tags: entry.tags ?? [],
          signature: entry.signature ?? null,
          firstSeen: entry.first_seen ?? null
        }
      }
    }

    return { malicious: false, info: null }
  } catch (error) {
    console.error('[API] checkHash error:', error)
    return null
  }
}

function fetchWithTimeout(url, options) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timer))
}