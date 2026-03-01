function hashString(str, tableSize) {
    let hash = 2166136261
    for (let i = 0; i < str.length; i++) {
        hash = hash ^ str.charCodeAt(i)
        hash = hash * 16777619
        hash = hash >>> 0
    }
    return hash % tableSize
}

function findEmptySlot(table, domain, tableSize) {
    let index = hashString(domain, tableSize)
    let attempts = 0

    while (table[index] !== undefined) {
        if (table[index] === domain) {
            return -1
        }

        index = (index + 1) % tableSize
        attempts++

        if (attempts > tableSize) {
            console.error('Table: full')
            return -1
        }
    }
    return index
}

export function buildHashTable(domains) {
    const tableSize = 100003
    const table = new Array(tableSize)
    let insertedCount = 0

    for (let i = 0; i < domains.length; i++) {
        const domain = domains[i]
        if (!domain || typeof domain !== 'string') {
            continue
        }
        const lowerDomain = domain.toLowerCase().trim()
        const index = findEmptySlot(table, lowerDomain, tableSize)
        if (index !== -1) {
            table[index] = lowerDomain
            insertedCount++
        }
    }
    const loadFactor = (insertedCount / tableSize).toFixed(2)
    console.log(`[Tranco] Built hash table: ${insertedCount} domains, load factor ${loadFactor}`)

    return {
        table: table,
        size: tableSize,
        count: insertedCount
    }
}

export function lookupDomain(tableObj, domain) {
    const { table, size } = tableObj
    const lowerDomain = domain.toLowerCase()

    let index = hashString(lowerDomain, size)
    let attempts = 0

    while (table[index] !== undefined) {
        if (table[index] === lowerDomain) {
            return true
        }
        index = (index + 1) % size
        attempts++
        if (attempts > size) {
            break
        }
    }
    return false
}

export function isTrancoSafe(tableObj, domain) {
    const lowerDomain = domain.toLowerCase();

    if (lookupDomain(tableObj, lowerDomain)) {
        return true;
    }

    const parts = lowerDomain.split('.');

    for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join('.');

        if (lookupDomain(tableObj, parent)) {
            return true;
        }
    }

    return false;
}