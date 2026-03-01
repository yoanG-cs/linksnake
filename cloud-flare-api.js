const corsHeaders = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url)
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders })
        }
        if (url.pathname === '/check-url' && request.method === 'POST') {
            return await handleCheckUrl(request, env)
        }
        if (url.pathname === '/check-hash' && request.method === 'POST') {
            return await handleCheckHash(request, env, ctx)
        }

        return new Response('LinkSnake API — path not found', { status: 404, headers: corsHeaders })
    }
}


async function handleCheckUrl(request, env) {
    try {
        const body = await request.json().catch(() => null)

        if (!body || typeof body.targetUrl !== 'string' || !body.targetUrl.startsWith('http')) {
            return errorResponse(400, 'Missing or invalid targetUrl')
        }

        const googleApiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${env.GOOGLE_API_KEY}`

        const payload = {
            client: { clientId: 'linksnake', clientVersion: '1.1' },
            threatInfo: {
                threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes:    ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries:    [{ url: body.targetUrl }]
            }
        }

        const gsb = await fetch(googleApiUrl, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload)
        })

        if (!gsb.ok) {
            return errorResponse(502, `Google Safe Browsing returned ${gsb.status}`)
        }

        const data = await gsb.json()
        const result = { matches: data.matches ?? [] }

        return jsonResponse(result)
    } catch (err) {
        return errorResponse(500, `check-url error: ${err.message}`)
    }
}

async function handleCheckHash(request, env, ctx) {
    try {
        const body = await request.json().catch(() => null)

        if (!body || typeof body.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(body.hash)) {
            return errorResponse(400, 'Missing or invalid hash — must be 64-char SHA-256 hex')
        }

        const hash = body.hash.toLowerCase()
        
        const cache = caches.default
        const cacheUrl = `https://linksnake-cache.internal/hash/${hash}`
        const cached = await cache.match(cacheUrl)
        
        if (cached) {
            return addCorsHeaders(cached)
        }

        const formData = new URLSearchParams()
        formData.append('query', 'get_info')
        formData.append('hash',  hash)

        const mbResponse = await fetch('https://mb-api.abuse.ch/api/v1/', {
            method:  'POST',
            headers: {
                'Auth-Key': env.MB_API_KEY,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData.toString()
        })
        if (!mbResponse.ok) {
            return errorResponse(502, `MalwareBazaar returned ${mbResponse.status}`)
        }

        const data = await mbResponse.json()
        const response = new Response(JSON.stringify(data), {
            headers: {
                ...corsHeaders,
                'Content-Type': 'application/json',
                'Cache-Control': 's-maxage=86400'
            }
        })
        
        ctx.waitUntil(cache.put(cacheUrl, response.clone()))
        
        return response
    } catch (err) {
        return errorResponse(500, `check-hash error: ${err.message}`)
    }
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
}

function errorResponse(status, message) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
}

function addCorsHeaders(response) {
    const newHeaders = new Headers(response.headers)
    newHeaders.set('Access-Control-Allow-Origin', '*')
    
    return new Response(response.body, {
        status:     response.status,
        statusText: response.statusText,
        headers:    newHeaders
    })
}