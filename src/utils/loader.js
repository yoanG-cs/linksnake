const PATTERNS_CACHE_KEY = 'patterns-key';
const TRANCO_CACHE_KEY = 'tranco-key';

let patterns = null;
let trancoDomains = null;

export async function loadRules() {
    const storage = await chrome.storage.local.get([
        PATTERNS_CACHE_KEY,
        TRANCO_CACHE_KEY
    ]);


    if (storage[PATTERNS_CACHE_KEY]) {
        patterns = storage[PATTERNS_CACHE_KEY];
    } else {
        const url = chrome.runtime.getURL('data/patterns.json');
        const response = await fetch(url);
        patterns = await response.json();
        await chrome.storage.local.set({ [PATTERNS_CACHE_KEY]: patterns });
    }


    if (storage[TRANCO_CACHE_KEY]) {
        trancoDomains = storage[TRANCO_CACHE_KEY];
    } else {
        const url = chrome.runtime.getURL('data/tranco-top50k.json');
        const response = await fetch(url);
        trancoDomains = await response.json();
        await chrome.storage.local.set({ [TRANCO_CACHE_KEY]: trancoDomains });
    }
}

export function getPatterns() {
    return patterns;
}

export function getTranco() {
    return trancoDomains;
}