document.addEventListener('DOMContentLoaded', function () {

    const btn = document.getElementById("close-btn")
    btn.addEventListener("click", function () {
        window.close()
    })

    const buttons = document.querySelectorAll(".segment-btn")
    const contents = document.querySelectorAll(".tab-content")

    buttons.forEach(button => {
        button.addEventListener('click', function () {
            const targetTab = this.getAttribute('data-tab')
            contents.forEach(c => { c.style.display = "none" })
            buttons.forEach(b => { b.classList.remove('active') })
            document.getElementById(targetTab).style.display = 'block'
            this.classList.add('active')
        })
    })

    const allSwitches = document.querySelectorAll('.settings-toggle')
    const defaultSettings = {
        'parameter-removal': true,
        'stop-url-redirecting': true,
        'file-scanning': true,
        'notifications': true
    }
    allSwitches.forEach(toggle => {
        const key = toggle.getAttribute('data-save')
        chrome.storage.local.get([key]).then((result) => {
            if (result[key] !== undefined) {
                toggle.checked = result[key]
            } else {
                toggle.checked = defaultSettings[key] || false
            }
        })
        toggle.addEventListener('change', () => {
            chrome.storage.local.set({ [key]: toggle.checked })
        })
    })

    updateCleanedNumUrl()
    updateBlockedFilesNum()
    renderWhitelist()
    updateRedirectNum()
    refreshTabData()
    updateLastBlockedUI()

    document.getElementById('whitelist-btn').addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        const hostname = new URL(tab.url).hostname

        chrome.storage.local.get(['userWhitelist'], (result) => {
            const list = result.userWhitelist || []
            if (!list.includes(hostname)) {
                list.unshift(hostname)
                chrome.storage.local.set({ userWhitelist: list }, renderWhitelist)
            }
        })
    })

    chrome.storage.onChanged.addListener((changes) => {
        if (changes.totalUrlsCleaned) {
            const statCardNum = document.getElementById('cleanedUrlsNum')
            if (statCardNum) statCardNum.textContent = changes.totalUrlsCleaned.newValue || 0
        }
        if (changes.totalRedirectsCleaned) {
            const badge = document.getElementById('redirectsBadge')
            if (badge) badge.textContent = changes.totalRedirectsCleaned.newValue || 0
        }
        if (changes.stats) {
            const el = document.getElementById('blockedFilesNum')
            if (el) el.textContent = changes.stats.newValue?.scanned ?? 0
        }
        if (changes.lastBlockedFile) {
            updateLastBlockedUI()
        }
        const tabStatsKey = Object.keys(changes).find(k => k.startsWith('stats_'))
        if (tabStatsKey) {
            refreshTabData()
        }
    })
})

function updateCleanedNumUrl() {
    chrome.storage.local.get(['totalUrlsCleaned'], (result) => {
        const count = result.totalUrlsCleaned || 0
        const statCardNum = document.getElementById('cleanedUrlsNum')
        if (statCardNum) statCardNum.textContent = count
    })
}

function updateBlockedFilesNum() {
    chrome.storage.local.get(['stats'], (result) => {
        const count = result.stats?.scanned || 0
        const el = document.getElementById('blockedFilesNum')
        if (el) el.textContent = count
    })
}

function updateRedirectNum() {
    chrome.storage.local.get(['totalRedirectsCleaned'], (result) => {
        const count = result.totalRedirectsCleaned || 0
        const badge = document.getElementById('redirectsBadge')
        if (badge) badge.textContent = count
    })
}

async function refreshTabData() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab) return

    const uncleanedUrl = document.querySelector('.uncleaned-url')
    const cleanedUrl = document.querySelector('.cleaned-url')

    chrome.storage.local.get([`stats_${tab.id}`], (result) => {
        const data = result[`stats_${tab.id}`]
        if (data) {
            uncleanedUrl.textContent = data.before
            cleanedUrl.textContent = data.after
            cleanedUrl.parentElement.classList.add('is-cleaned')
        } else {
            uncleanedUrl.textContent = "Никакви параметри и пренасочвания намерени."
            cleanedUrl.textContent = tab.url
            cleanedUrl.parentElement.classList.remove('is-cleaned')
        }
    })
}

function renderWhitelist() {
    chrome.storage.local.get(['userWhitelist'], (result) => {
        const list = result.userWhitelist || []
        const container = document.getElementById('whitelist-list')
        container.innerHTML = ''
        list.forEach(hostname => {
            const row = document.createElement('div')
            row.className = 'setting-item'
            row.innerHTML =
                `<span class=userWhitelist-element>${hostname}</span>
    <button data-host="${hostname}" class="rm-whitelist-btn whitelist-remove-x"><div id="wl-rm-x">&times;</div></button>`
            container.appendChild(row)
        })

        container.querySelectorAll('.rm-whitelist-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const host = btn.getAttribute('data-host')
                chrome.storage.local.get(['userWhitelist'], (r) => {
                    const updated = (r.userWhitelist || []).filter(h => h !== host)
                    chrome.storage.local.set({ userWhitelist: updated }, renderWhitelist)
                })
            })
        })
    })
}

function formatBytes(bytes) {
    if (!bytes || isNaN(bytes)) return '—'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function riskClass(score) {
    if (score >= 70) return 'risk-high'
    if (score >= 40) return 'risk-medium'
    return 'risk-low'
}


function riskLabel(score) {
    if (score >= 70) return `⚠ Висок ${score}/100`
    if (score >= 40) return `~ Среден ${score}/100`
    return `✓ Нисък ${score}/100`
}

async function updateLastBlockedUI() {
    chrome.storage.local.get(['lastBlockedFile'], (result) => {
        const file = result.lastBlockedFile

        const card = document.getElementById('lastBlockedCard')
        const strip = document.getElementById('fileHeaderStrip')
        const nameEl = document.getElementById('fileName')
        const riskEl = document.getElementById('riskScore')
        const originEl = document.getElementById('fileOrigin')
        const typeEl = document.getElementById('fileType')
        const sizeEl = document.getElementById('fileSize')
        const entropyVal = document.getElementById('entropyValue')
        const entropyBar = document.getElementById('entropyBar')
        const reasonsSec = document.getElementById('fileReasonsSection')
        const reasonsList = document.getElementById('blockReasons')

        const emptyState = document.getElementById('fileEmptyState')

        if (!file) {
            emptyState.style.display = 'flex'
            strip.style.display = 'none'
            document.getElementById('fileInfoTable').style.display = 'none'
            reasonsSec.style.display = 'none'
            return
        }

        emptyState.style.display = 'none'
        strip.style.display = 'flex'
        document.getElementById('fileInfoTable').style.display = 'table'

        const rc = riskClass(file.riskScore ?? 0)
        strip.className = `file-header-strip ${rc}`
        riskEl.className = `file-risk-badge ${rc}`

        nameEl.textContent = file.name || 'Неизвестен файл'
        riskEl.textContent = riskLabel(file.riskScore ?? 0)
        originEl.textContent = file.origin || '—'
        typeEl.textContent = file.type || '—'
        sizeEl.textContent = formatBytes(file.size)

        const entropy = file.entropy ?? 0
        entropyVal.textContent = entropy.toFixed(2)
        entropyBar.style.width = `${Math.min((entropy / 8) * 100, 100)}%`

        const reasons = file.reasons || []
        if (reasons.length > 0) {
            reasonsSec.style.display = 'block'
            reasonsList.innerHTML = ''
            reasons.forEach(reason => {
                const tag = document.createElement('div')
                tag.className = 'reason-tag'
                tag.textContent = reason
                reasonsList.appendChild(tag)
            })
        } else {
            reasonsSec.style.display = 'none'
        }
    })
}