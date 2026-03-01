;(function () {
    'use strict'

    let interceptorActive = true

    const nativeClick = HTMLElement.prototype.click

    async function scanAndDecide(blobUrl, filename) {
        try {
            const response = await fetch(blobUrl)
            if (!response.ok) throw new Error(`Blob fetch failed: ${response.status}`)
            const buffer = await response.arrayBuffer()
            const bytes = Array.from(new Uint8Array(buffer))

            const result = await chrome.runtime.sendMessage({
                type: 'SCAN_BLOB',
                filename: filename || 'unknown',
                bytes
            })

            return result
        } catch (err) {
            console.error('[LinkSnake] Blob scan error:', err)
            return { block: false, error: err.message }
        }
    }

    function getFilenameFromAnchor(anchor) {
        if (anchor.download && anchor.download.trim()) return anchor.download.trim()
        try {
            const url = new URL(anchor.href)
            const parts = url.pathname.split('/')
            const last = parts[parts.length - 1]
            if (last) return decodeURIComponent(last)
        } catch { /* ignore */ }
        return 'downloaded-file'
    }

    document.addEventListener('click', async function (e) {
        if (!interceptorActive) return

        const anchor = e.target.closest('a')
        if (!anchor) return

        const href = anchor.href || ''
        if (!href.startsWith('blob:') && !href.startsWith('data:')) return

        e.preventDefault()
        e.stopImmediatePropagation()

        const filename = getFilenameFromAnchor(anchor)
        console.log(`[LinkSnake] Intercepted download: "${filename}"`)

        const result = await scanAndDecide(href, filename)

        if (result && result.block) {
            console.warn(`[LinkSnake] Blocked: "${filename}" — ${result.reason}`)
        } else {
            console.log(`[LinkSnake] Allowed: "${filename}"`)
            interceptorActive = false
            nativeClick.call(anchor)
            interceptorActive = true
        }
    }, true)

    function patchAnchorClick(anchor) {
        if (anchor._linksnakePatched) return
        anchor._linksnakePatched = true
        const originalElClick = anchor.click.bind(anchor)
        anchor.click = async function () {
            if (!interceptorActive || (!anchor.href?.startsWith('blob:') && !anchor.href?.startsWith('data:'))) {
                return originalElClick()
            }
            const filename = getFilenameFromAnchor(anchor)
            console.log(`[LinkSnake] Intercepted programmatic download: "${filename}"`)
            const result = await scanAndDecide(anchor.href, filename)
            if (result && result.block) {
                console.warn(`[LinkSnake] Blocked programmatic: "${filename}" — ${result.reason}`)
            } else {
                console.log(`[LinkSnake] Allowed programmatic: "${filename}"`)
                interceptorActive = false
                originalElClick()
                interceptorActive = true
            }
        }
    }

    const anchorObserver = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue
                if (node.tagName === 'A') patchAnchorClick(node)
                node.querySelectorAll?.('a').forEach(patchAnchorClick)
            }
        }
    })
    anchorObserver.observe(document.documentElement, { childList: true, subtree: true })

    const originalCreateElement = document.createElement.bind(document)
    document.createElement = function (tag, options) {
        const el = originalCreateElement(tag, options)
        if (tag.toLowerCase() === 'a') patchAnchorClick(el)
        return el
    }

    console.log('[LinkSnake] Download interceptor active')
})()