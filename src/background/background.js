import { parseURL, checkTLD, checkDomain, checkPath, checkFilename, checkHostname } from "../utils/download-url-analyzer.js"
import { loadRules, getPatterns, getTranco } from "../utils/loader.js"
import { buildHashTable } from "../utils/tranco-hash.js"
import { checkUrl, checkHash } from "../utils/api-client.js"
import { checkMagicNumber } from "../utils/magicnumber-checker.js"
import { calculateHash, calculateEntropy } from "../utils/file-hash-worker.js"

const downloads = new Map()
const navigationTracker = {};
let patterns = null;
let trancoTable = null;

let cachedSettings = {};
let cachedUserWhitelist = [];
const cancelledDownloads = new Set()

const stats = {
    scanned: 0,
    blocked: 0,
    warned: 0
};

async function initialize() {
    console.log('[Init] Loading patterns...')
    await loadRules()
    patterns = getPatterns()
    const trancoArray = getTranco()
    trancoTable = buildHashTable(trancoArray)
    console.log('[Init] Tranco table built with', trancoArray.length, 'domains')
    const storedStats = await chrome.storage.local.get(['stats'])
    if (storedStats.stats) {
        Object.assign(stats, storedStats.stats)
    }
    await refreshSettingsCache()
    await refreshWhitelistCache()
    console.log('[Init] Ready')
}
let initPromise = null

function ensureInitialized() {
    if (!initPromise) {
        initPromise = initialize().catch(err => {
            console.error('[Init] Failed:', err)
            initPromise = null
        })
    }
    return initPromise
}

function saveStats() {
    chrome.storage.local.set({ stats })
}

function saveLastBlockedFile(data) {
    chrome.storage.local.set({ lastBlockedFile: data })
}

function getSettings() {
    return cachedSettings || {}
}

async function refreshSettingsCache() {
    cachedSettings = await chrome.storage.local.get(
        ['parameter-removal', 'stop-url-redirecting', 'file-scanning', 'notifications']
    )
}

async function refreshWhitelistCache() {
    const result = await chrome.storage.local.get(['userWhitelist'])
    cachedUserWhitelist = result.userWhitelist || []
}

chrome.runtime.onStartup.addListener(async () => {
    await ensureInitialized()
    await syncDNRWhitelist()
    syncRuleset(getSettings()['parameter-removal'] || false)
})

chrome.runtime.onInstalled.addListener(async (details) => {
    await ensureInitialized()
    await syncDNRWhitelist()
    if (details.reason === "install") {
        await chrome.storage.local.set({
            'parameter-removal': true,
            'stop-url-redirecting': true,
            'file-scanning': true
        })
        await refreshSettingsCache()
    }
    syncRuleset(getSettings()['parameter-removal'] || false)
})

function syncRuleset(enabled) {
    chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: enabled ? ['ruleset_1'] : [],
        disableRulesetIds: enabled ? [] : ['ruleset_1']
    })
}

chrome.storage.onChanged.addListener((changes) => {
    if (changes['parameter-removal'] !== undefined) {
        cachedSettings['parameter-removal'] = changes['parameter-removal'].newValue || false
        syncRuleset(cachedSettings['parameter-removal'])
    }
    if (changes['stop-url-redirecting'] !== undefined) {
        cachedSettings['stop-url-redirecting'] = changes['stop-url-redirecting'].newValue || false
    }
    if (changes['file-scanning'] !== undefined) {
        cachedSettings['file-scanning'] = changes['file-scanning'].newValue || false
    }
    if (changes['notifications'] !== undefined) {
        cachedSettings['notifications'] = changes['notifications'].newValue
    }
    if (changes['userWhitelist']) {
        cachedUserWhitelist = changes['userWhitelist'].newValue || []
        syncDNRWhitelist()
    }
})

console.log("background: started")


const redirectDomains = [
    "l.facebook.com",
    "lm.facebook.com",
    "t.co",
    "l.instagram.com",
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "out.reddit.com",
    "youtube.com",
    "lnkd.in",
    "linkedin.com",
    "l.messenger.com",
    "slack-redir.net",
    "steamcommunity.com",
    "substack.com",
    "link.medium.com",
    "vk.com",
    "click.discord.com",
    "safelinks.protection.outlook.com",
    "urldefense.proofpoint.com",
    "linkprotect.cudasvc.com"
]

const redirectPathHints = {
    "google.com": "/url",
    "bing.com": "/ck/a",
    "duckduckgo.com": "/l",
    "youtube.com": "/redirect",
    "linkedin.com": "/redir",
    "slack-redir.net": "/link",
    "steamcommunity.com": "/linkfilter",
    "substack.com": "/redirect",
    "vk.com": "/away.php"
}

const whitelistDomains = [
    "web.archive.org",
    "archive.org",
    "translate.google.com",
    "translate.googleusercontent.com",
    "webcache.googleusercontent.com",
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "github.com",
    "oauth.reddit.com",
    "paypal.com",
    "checkout.stripe.com",
    "stripe.com",
    "drive.google.com",
    "docs.google.com",
    "sheets.google.com",
    "onedrive.live.com"
]

function isWhiteListed(url) {
    try {
        const hostname = new URL(url).hostname
        return (
            whitelistDomains.some(d => hostname === d || hostname.endsWith("." + d)) ||
            cachedUserWhitelist.some(d => hostname === d || hostname.endsWith("." + d))
        )
    } catch {
        return false
    }
}

async function syncDNRWhitelist() {
    const existing = await chrome.declarativeNetRequest.getDynamicRules()
    const removeIds = existing.map(r => r.id)
    const newRules = cachedUserWhitelist.map((hostname, i) => ({
        id: i + 1,
        priority: 2,
        action: { type: 'allow' },
        condition: {
            urlFilter: `||${hostname}`,
            resourceTypes: ['main_frame']
        }
    }))
    await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: removeIds,
        addRules: newRules
    })
}

function isKnownRedirectDomain(url) {
    try {
        const parsed = new URL(url)
        const hostname = parsed.hostname.toLowerCase()
        const pathname = parsed.pathname.toLowerCase()
        return redirectDomains.some(domain => {
            const isHostMatch = hostname === domain || hostname.endsWith('.' + domain)
            if (!isHostMatch) return false
            const requiredPath = redirectPathHints[domain]
            if (requiredPath) return pathname.startsWith(requiredPath)
            return true
        })
    } catch {
        return false
    }
}

function hasRedirectPattern(url) {
    try {
        const params = new URL(url).searchParams
        for (const [, value] of params) {
            if (!value) continue
            if (value.startsWith("http://") || value.startsWith("https://") ||
                value.startsWith("http%") || value.startsWith("https%")) {
                return true
            }
        }
        return false
    } catch {
        return false
    }
}

function extractDestination(url) {
    try {
        const params = new URL(url).searchParams
        for (const [, value] of params) {
            if (!value) continue
            if (value.startsWith("http://") || value.startsWith("https://") ||
                value.startsWith("http%") || value.startsWith("https%")) {
                let decoded = value
                for (let i = 0; i < 10; i++) {
                    try {
                        const next = decodeURIComponent(decoded)
                        if (next === decoded) break
                        decoded = next
                    } catch { break }
                }
                if (decoded.startsWith("http://") || decoded.startsWith("https://")) {
                    return decoded
                }
            }
        }
        return null
    } catch {
        return null
    }
}

function incrementCounter(key) {
    return new Promise((resolve) => {
        chrome.storage.local.get([key], (result) => {
            const current = result[key] || 0
            chrome.storage.local.set({ [key]: current + 1 }, resolve)
        })
    })
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        navigationTracker[details.tabId] = details.url
    }
})

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return
    const url = details.url

    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return
    if (isWhiteListed(url)) return

    await ensureInitialized()
    const settings = getSettings()

    if (settings['stop-url-redirecting']) {
        const isKnown = isKnownRedirectDomain(url)
        const hasPattern = !isKnown && hasRedirectPattern(url)

        if (isKnown || hasPattern) {
            const destination = extractDestination(url)
            if (destination) {
                await incrementCounter('totalUrlsCleaned')
                await incrementCounter('totalRedirectsCleaned')
                chrome.storage.local.set({
                    [`stats_${details.tabId}`]: { before: url, after: destination, timestamp: Date.now() }
                })
                chrome.tabs.update(details.tabId, { url: destination })
                return
            }
        }
    }
    navigationTracker[details.tabId] = url
})

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return
    const url = details.url
    const originalUrl = navigationTracker[details.tabId]

    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
        url.startsWith("devtools://") || url.startsWith("about:")) return
    if (isWhiteListed(url)) {
        delete navigationTracker[details.tabId]
        return
    }

    const settings = getSettings()
    if (settings['parameter-removal']) {
        if (originalUrl && originalUrl !== url) {
            let hadParams = false
            try { hadParams = new URL(originalUrl).searchParams.toString().length > 0 } catch { }
            if (hadParams) {
                await incrementCounter('totalUrlsCleaned')
                chrome.storage.local.set({
                    [`stats_${details.tabId}`]: { before: originalUrl, after: url, timestamp: Date.now() }
                })
            }
        }
    }

    delete navigationTracker[details.tabId]
})

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId !== 0) return
    const url = details.url
    const originalUrl = navigationTracker[details.tabId]

    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
        url.startsWith("devtools://") || url.startsWith("about:")) return
    if (isWhiteListed(url)) {
        delete navigationTracker[details.tabId]
        return
    }

    const settings = getSettings()
    if (settings['parameter-removal']) {
        if (originalUrl && originalUrl !== url) {
            let hadParams = false
            try { hadParams = new URL(originalUrl).searchParams.toString().length > 0 } catch { }
            if (hadParams) {
                await incrementCounter('totalUrlsCleaned')
                chrome.storage.local.set({
                    [`stats_${details.tabId}`]: { before: originalUrl, after: url, timestamp: Date.now() }
                })
            }
        }
    }

    delete navigationTracker[details.tabId]
})

function notify(options) {
    if (getSettings()['notifications'] === false) return
    const id = `linksnake-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    chrome.notifications.create(id, options)
}

function cancelAndNotify(item, reason, score, reasons) {
    cancelledDownloads.add(item.id)
    chrome.downloads.cancel(item.id, () => { /* silent */ })
    chrome.downloads.erase({ id: item.id })
    stats.blocked++
    saveStats()

    saveLastBlockedFile({
        name: item.filename.split(/[\\/]/).pop(),
        origin: item.referrer || item.url,
        type: item.mime || '—',
        size: item.totalBytes ?? 0,
        riskScore: Math.min(score ?? 100, 100),
        entropy: null,
        reasons: reasons ?? [reason]
    })

    notify({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon.png'),
        title: 'Свалянето е блокирано',
        message: `"${item.filename}" блокирано: ${reason}`,
        priority: 2
    })
}

async function deleteAndNotify(item, reason, entropy) {
    cancelledDownloads.add(item.id)
    chrome.downloads.cancel(item.id, () => { /* silent */ })

    await new Promise((resolve) => {
        chrome.downloads.removeFile(item.id, () => {
            if (chrome.runtime.lastError) {
                console.warn(`[Security] removeFile: ${chrome.runtime.lastError.message}`)
            } else {
                console.log(`[Security] Deleted from disk: ${item.filename}`)
            }
            resolve()
        })
    })

    chrome.downloads.erase({ id: item.id })

    stats.blocked++
    saveStats()

    saveLastBlockedFile({
        name: item.filename.split(/[\\/]/).pop(),
        origin: item.referrer || item.url,
        type: item.mime || '—',
        size: item.totalBytes ?? 0,
        riskScore: 100,
        entropy: entropy ?? null,
        reasons: [reason]
    })

    notify({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon.png'),
        title: 'Злонамерен файл е изтрит',
        message: `"${item.filename.split(/[\\/]/).pop()}" изтрит: ${reason}`,
        priority: 2
    })
}

async function analyseBuffer(arrayBuffer, extension) {
    const hash = await calculateHash(arrayBuffer)
    const entropy = calculateEntropy(arrayBuffer)
    console.log(`[Deep Scan] Hash: ${hash} | Entropy: ${entropy.toFixed(2)}`)

    const magicResult = await checkMagicNumber(arrayBuffer, extension, patterns)
    if (magicResult.mismatch) {
        const normalizedClaimed = magicResult.claimedType.toLowerCase().replace(/^\./, '')
        const sameType = normalizedClaimed === magicResult.actualType.toLowerCase()
        const reason = sameType
            ? magicResult.description
            : `маскиран като ${magicResult.claimedType}, но всъщност ${magicResult.actualType}`
        return { block: true, entropy, reason }
    }

    const mbResult = await checkHash(hash)
    if (mbResult && mbResult.malicious) {
        return { block: true, entropy, reason: `съвпадение с малуер сигнатура: ${mbResult.info?.signature ?? 'неизвестна'}` }
    }

    const ext = extension.toLowerCase().replace('.', '')
    const ENTROPY_THRESHOLDS = {
        exe: 7.0, dll: 7.0, scr: 7.0, sys: 7.0, com: 7.0,
        msi: 7.0, bin: 7.0, elf: 7.0, run: 7.0, deb: 7.0, rpm: 7.0,
        dmg: 7.0, pkg: 7.0, apk: 7.0, jar: 7.0, appimage: 7.0,
        bat: 6.5, cmd: 6.5, pif: 7.0, hta: 6.5, cpl: 7.0,
        lnk: 7.0, url: 6.5, inf: 6.5, gadget: 7.0,
        msp: 7.0, mst: 7.0,
        ps1: 6.5, ps2: 6.5, vbs: 6.5, vbe: 6.5, wsf: 6.5,
        js: 6.5, py: 6.5, rb: 6.5, pl: 6.5, sh: 6.5,
        bash: 6.5, zsh: 6.5, lua: 6.5, tcl: 6.5, php: 6.5,
        asp: 6.5, aspx: 6.5, jsp: 6.5, wsc: 6.5, ws: 6.5,
        docm: 7.9, xlsm: 7.9, pptm: 7.9, ppam: 7.9,
        xltm: 7.9, dotm: 7.9, xlam: 7.9, sldm: 7.9,
        '': 7.5
    }
    const threshold = ENTROPY_THRESHOLDS[ext] ?? null
    if (threshold !== null && entropy > threshold) {
        return { block: false, warn: true, entropy, reason: `опакован/криптиран файл (ентропия ${entropy.toFixed(2)}, праг ${threshold} за .${ext || 'неизвестен'})` }
    }

    return { block: false, clean: true, entropy }
}

async function performDeepScan(downloadItem, urlInfo) {
    try {
        console.log(`[Deep Scan] Starting for: ${urlInfo.filename}`)
        const fetchUrl = downloadItem.finalUrl || downloadItem.url
        const response = await fetch(fetchUrl)
        if (!response.ok) throw new Error(`Fetch failed: ${response.status}`)
        const arrayBuffer = await response.arrayBuffer()

        const result = await analyseBuffer(arrayBuffer, urlInfo.extension)

        if (result.block) {
            await deleteAndNotify(downloadItem, result.reason, result.entropy)
        } else if (result.warn) {
            notify({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon.png'),
                title: 'Предупреждение за подозрителен файл',
                message: `"${urlInfo.filename}" е опакован/криптиран. Продължете с повишено внимание.`,
                priority: 1
            })
        } else {
            console.log(`[Deep Scan] Clean: "${urlInfo.filename}" passed all checks.`)
            notify({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon.png'),
                title: 'Сканирането е приключено',
                message: `"${urlInfo.filename}" — няма открити заплахи.`,
                priority: 0
            })
        }
    } catch (err) {
        console.error('[Deep Scan] Failed:', err.message)
        notify({
            type: 'basic',
            iconUrl: chrome.runtime.getURL('icons/icon.png'),
            title: 'Грешка при сканиране',
            message: `Не може да се провери "${urlInfo.filename}": ${err.message}`,
            priority: 1
        })
    }
}

chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    if (cancelledDownloads.has(downloadItem.id)) { suggest(); return; }

    ensureInitialized().then(() => {
        const settings = getSettings();
        if (!settings || !settings['file-scanning']) {
            suggest();
            return;
        }

        return processDownloadSecurity(downloadItem).then((action) => {
            if (action && action.block) {
                cancelAndNotify(downloadItem, action.reason, action.score, action.reasons);
            }
            suggest();
        }).catch(err => {
            console.error("Security check failed:", err);
            suggest();
        });
    }).catch(err => {
        console.error("Init failed during download check:", err);
        suggest();
    });

    return true;
});

function checkDGA(domain) {
    const parts = domain.split('.')
    if (parts.length < 2) return { isDGA: false, score: 0, reasons: [] }

    const label = parts[parts.length - 2]
    if (label.length < 7) return { isDGA: false, score: 0, reasons: [] }

    const alpha = label.replace(/[^a-z]/gi, '').toLowerCase()
    if (alpha.length < 5) return { isDGA: false, score: 0, reasons: [] }

    const vowelCount = (alpha.match(/[aeiou]/g) || []).length
    const vowelRatio = vowelCount / alpha.length
    const digitCount = (label.match(/[0-9]/g) || []).length
    const digitRatio = digitCount / label.length
    const maxConsonantRun = (alpha.match(/[^aeiou]+/g) || [])
        .reduce((max, run) => Math.max(max, run.length), 0)

    let dgaScore = 0
    const dgaReasons = []

    if (vowelRatio < 0.15 && alpha.length >= 8) {
        dgaScore += 35
        dgaReasons.push(`very low vowel ratio in domain label "${label}" (${(vowelRatio * 100).toFixed(0)}%)`)
    } else if (vowelRatio < 0.25 && alpha.length >= 12) {
        dgaScore += 20
        dgaReasons.push(`low vowel ratio in domain label "${label}" (${(vowelRatio * 100).toFixed(0)}%)`)
    }
    if (digitRatio > 0.4 && label.length >= 8) {
        dgaScore += 15
        dgaReasons.push(`high digit ratio in domain label "${label}" (${(digitRatio * 100).toFixed(0)}%)`)
    }
    if (maxConsonantRun >= 5) {
        dgaScore += 15
        dgaReasons.push(`${maxConsonantRun} consecutive consonants in label "${label}"`)
    }
    if (label.length >= 16 && digitRatio > 0.2) {
        dgaScore += 10
        dgaReasons.push(`long mixed-alphanumeric label "${label}" (${label.length} chars, ${(digitRatio * 100).toFixed(0)}% digits)`)
    }

    return { isDGA: dgaScore >= 20, score: dgaScore, reasons: dgaReasons, label }
}

function levenshtein(a, b) {
    const m = a.length, n = b.length
    let prev = Array.from({ length: n + 1 }, (_, i) => i)
    const curr = new Array(n + 1)
    for (let i = 1; i <= m; i++) {
        curr[0] = i
        for (let j = 1; j <= n; j++) {
            curr[j] = a[i - 1] === b[j - 1]
                ? prev[j - 1]
                : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1])
        }
        prev = curr.slice()
    }
    return prev[n]
}

function checkImpersonation(domain) {
    const parts = domain.split('.')
    if (parts.length < 2) return { match: false }
    const label = parts[parts.length - 2].toLowerCase()

    const BRANDS = [
        'paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple',
        'netflix', 'spotify', 'steam', 'discord', 'roblox', 'minecraft',
        'adobe', 'dropbox', 'github', 'twitter', 'instagram', 'whatsapp',
        'telegram', 'coinbase', 'binance', 'kraken', 'chase', 'wellsfargo',
        'bankofamerica', 'linkedin', 'youtube', 'twitch', 'reddit', 'yahoo',
        'outlook', 'onedrive', 'icloud', 'gmail', 'trustwallet', 'metamask'
    ]

    const normalize = s => s
        .replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e')
        .replace(/4/g, 'a').replace(/5/g, 's').replace(/6/g, 'g')
        .replace(/7/g, 't').replace(/8/g, 'b').replace(/@/g, 'a')
        .replace(/vv/g, 'w').replace(/-/g, '')

    const normalized = normalize(label)

    for (const brand of BRANDS) {
        if (normalized === brand && label !== brand) {
            return {
                match: true, brand,
                reason: `leet-speak имитация на "${brand}" (етикет "${label}")`
            }
        }
    }
    for (const brand of BRANDS) {
        if (brand.length >= 5 && Math.abs(label.length - brand.length) <= 1) {
            if (levenshtein(label, brand) === 1) {
                return {
                    match: true, brand,
                    reason: `тайпосквотинг на "${brand}" — вариант с 1 символ (етикет "${label}")`
                }
            }
        }
    }

    return { match: false }
}

async function processDownloadSecurity(downloadItem) {
    if (!patterns || !trancoTable) await ensureInitialized()

    const urlInfo = parseURL(downloadItem.url)
    if (!urlInfo) return { block: false }

    if (cachedUserWhitelist.some(entry => urlInfo.domain === entry || urlInfo.domain.endsWith('.' + entry))) {
        return { block: false }
    }

    stats.scanned++
    saveStats()

    const tldRisk = checkTLD(urlInfo.domain, patterns)
    const domainChecks = checkDomain(urlInfo.domain, patterns, trancoTable)
    const pathCheck = checkPath(urlInfo.path, patterns)
    const fileChecks = checkFilename(urlInfo.filename, patterns)
    const hostChecks = checkHostname(urlInfo.domain, patterns)

    let score = 0
    const reasons = []

    if (tldRisk === 'critical') { score += 50; reasons.push("Критично рискова TLD") }
    else if (tldRisk === 'risk') { score += 35; reasons.push("Високорискова TLD") }
    else if (tldRisk === 'suspicious') { score += 15; reasons.push("Подозрителна TLD") }
    else if (tldRisk === 'grey_area') { score += 5; reasons.push("Гранична TLD") }

    if (domainChecks.isTrancoSafe) {
        const isHighRiskFileType = fileChecks.isDoubleExtension ||
            fileChecks.detectedType === 'executable' ||
            fileChecks.detectedType === 'script' ||
            fileChecks.detectedType === 'macro'
        const trancoPenalty = isHighRiskFileType ? -10 : -20
        score += trancoPenalty
        reasons.push(`Популярен домейн (Tranco Top 50k, ${isHighRiskFileType ? 'частично доверие — рисков тип файл' : 'пълно доверие'})`)
    }
    if (domainChecks.isHighRiskShortener) { score += 30; reasons.push("Високорисков съкращател на URL") }
    else if (domainChecks.isShortener) { score += 15; reasons.push("Съкращател на URL") }

    if (hostChecks.isRawIP) { score += 25; reasons.push("URL с открит IP адрес") }
    if (hostChecks.isPunycode) { score += 30; reasons.push("Punycode домейн (хомографска атака)") }

    const subdomainDepth = urlInfo.domain.split('.').length - 2
    if (subdomainDepth >= 3) { score += 30; reasons.push("Прекомерна дълбочина на поддомейн") }

    const hasNumbersAndHyphens = /(?:[0-9].*-|-.*[0-9])/.test(urlInfo.domain)
    if (hasNumbersAndHyphens && tldRisk !== 'neutral') { score += 15; reasons.push("Цифри и тирета в рисков TLD") }

    const impersonationResult = checkImpersonation(urlInfo.domain)
    if (impersonationResult.match) {
        score += 50
        reasons.push(`Имитация на марка: ${impersonationResult.reason}`)
    }

    if (!domainChecks.isTrancoSafe) {
        const dgaResult = checkDGA(urlInfo.domain)
        if (dgaResult.isDGA) {
            const dgaContribution = Math.min(dgaResult.score, 40)
            score += dgaContribution
            dgaResult.reasons.forEach(r => reasons.push(`DGA сигнал: ${r}`))
            console.log(`[Layer 1] DGA signal on "${urlInfo.domain}": score +${dgaContribution}`, dgaResult.reasons)
        }
    }

    const CONTEXT_DEPENDENT_CATEGORIES = new Set([
        'Social Engineering Keywords',
        'Suspicious Directory Patterns'
    ])
    const scoreBeforePaths = score
    pathCheck.matchedRules.forEach(rule => {
        const needsContext = CONTEXT_DEPENDENT_CATEGORIES.has(rule.category)
        if (needsContext && scoreBeforePaths === 0) {
            console.log(`[Layer 1] Suppressed low-signal path rule "${rule.category}" (no other risk context)`)
            return
        }
        if (rule.severity === 'critical') { score += 50; reasons.push(`Критичен: ${rule.category}`) }
        else if (rule.severity === 'high') { score += 30; reasons.push(`Висок риск: ${rule.category}`) }
        else if (rule.severity === 'medium') { score += 15; reasons.push(`Среден риск: ${rule.category}`) }
        else if (rule.severity === 'low') { score += 5; reasons.push(`Нисък риск: ${rule.category}`) }
    })

    if (fileChecks.isDoubleExtension) { score += 85; reasons.push("Двойно разширение") }
    else if (fileChecks.detectedType === 'executable') { score += 40; reasons.push("Изпълним файл") }
    else if (fileChecks.detectedType === 'macro') { score += 35; reasons.push("Файл с макроси") }
    else if (fileChecks.detectedType === 'script') { score += 25; reasons.push("Скрипт файл") }

    if (urlInfo.protocol === 'http') { score += 20; reasons.push("Незащитен HTTP") }

    if (downloadItem.finalUrl && downloadItem.finalUrl !== downloadItem.url) {
        try {
            const originalDomain = new URL(downloadItem.url).hostname.toLowerCase()
            const finalDomain = new URL(downloadItem.finalUrl).hostname.toLowerCase()
            if (originalDomain !== finalDomain) {
                score += 15
                reasons.push(`Пренасочване между домейни (${originalDomain} → ${finalDomain})`)
                console.log(`[Layer 1] Redirect: ${originalDomain} → ${finalDomain}`)
            }
        } catch { /* malformed URL — ignore */ }
    }

    const totalBytes = downloadItem.totalBytes ?? -1
    if (totalBytes > 0) {
        const isExecutableType = fileChecks.detectedType === 'executable' ||
            fileChecks.detectedType === 'macro' ||
            fileChecks.isDoubleExtension

        if (isExecutableType && totalBytes < 5_120) {
            score += 25
            reasons.push(`Подозрително малък изпълним файл (${totalBytes} байта)`)
        } else if (totalBytes > 524_288_000) {
            score += 10
            reasons.push(`Необичайно голям файл (${(totalBytes / 1_048_576).toFixed(0)} МБ)`)
        }
    }

    score = Math.max(0, score)
    console.log(`[Layer 1] Score for "${urlInfo.filename}": ${score}`, reasons)

    const isHighRiskFileType = fileChecks.isDoubleExtension ||
        fileChecks.detectedType === 'executable' ||
        fileChecks.detectedType === 'script' ||
        fileChecks.detectedType === 'macro'

    if (score >= 70) {
        const apiResult = await checkUrl(downloadItem.url)
        if (apiResult && apiResult.malicious) {
            return { block: true, score, reasons, reason: `Safe Browsing: ${(apiResult.threats || []).join(', ') || 'malicious'}` }
        }
        return { block: true, score, reasons, reason: reasons[0] || "Изключително рискован URL" }
    } else if (score >= 40 || isHighRiskFileType) {
        const apiResult = await checkUrl(downloadItem.url)
        if (apiResult && apiResult.malicious) {
            return { block: true, score, reasons, reason: `Safe Browsing: ${(apiResult.threats || []).join(', ') || 'malicious'}` }
        }
    }

    return { block: false }
}

chrome.downloads.onChanged.addListener(async (delta) => {

    if (delta.state?.current !== 'complete') return
    if (cancelledDownloads.has(delta.id)) {
        cancelledDownloads.delete(delta.id)
        return
    }

    const settings = getSettings()
    if (!settings['file-scanning']) return

    const [item] = await chrome.downloads.search({ id: delta.id })
    if (!item) return

    const urlInfo = parseURL(item.url)
    if (!urlInfo) return

    if (urlInfo.protocol === 'blob' || urlInfo.protocol === 'data') {
        console.log(`[Deep Scan] Skipped "${item.filename}" — blob/data URLs are scanned pre-download by the content script`)
        return
    }

    await performDeepScan(item, urlInfo)

});


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== 'SCAN_BLOB') return false

    const settings = getSettings()
    if (!settings['file-scanning']) {
        sendResponse({ block: false })
        return true
    }

    const filename = message.filename || 'unknown'
    const extension = filename.includes('.')
        ? '.' + filename.split('.').pop().toLowerCase()
        : ''

    const arrayBuffer = new Uint8Array(message.bytes).buffer

    console.log(`[Deep Scan] Blob scan starting for: "${filename}"`)

    analyseBuffer(arrayBuffer, filename, extension).then(result => {
        if (result.block) {
            console.warn(`[Deep Scan] Blob BLOCKED: "${filename}" — ${result.reason}`)

            saveLastBlockedFile({
                name: filename,
                origin: sender.tab?.url || '—',
                type: message.mime || extension || '—',
                size: message.bytes?.length ?? 0,
                riskScore: 100,
                entropy: result.entropy ?? null,
                reasons: [result.reason]
            })

            notify({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon.png'),
                title: 'Свалянето e блокирано',
                message: `"${filename}" блокирано: ${result.reason}`,
                priority: 2
            })
        } else if (result.warn) {
            console.warn(`[Deep Scan] Blob WARNING: "${filename}" — ${result.reason}`)
            notify({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon.png'),
                title: 'Предупреждение за подозрителен файл',
                message: `"${filename}" е опакован/криптиран. Продължете с повишено внимание.`,
                priority: 1
            })
        } else {
            console.log(`[Deep Scan] Blob CLEAN: "${filename}" passed all checks.`)
            notify({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icons/icon.png'),
                title: 'Сканирането е приключено',
                message: `"${filename}" — няма открити заплахи.`,
                priority: 0
            })
        }
        sendResponse(result)
    }).catch(err => {
        console.error('[Deep Scan] Blob scan error:', err)
        sendResponse({ block: false, error: err.message })
    })

    return true
})

console.log("background: active")