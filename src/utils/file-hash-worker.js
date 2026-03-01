export async function calculateHash(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(byte => byte.toString(16).padStart(2, "0")).join('')
}

export function calculateEntropy(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer)
    const sampleSize = Math.min(bytes.length, 10000)
    const sample = bytes.slice(0, sampleSize)
    const frequencies = new Array(256).fill(0)

    for (let i = 0; i < sample.length; i++) {
        frequencies[sample[i]]++
    }

    let entropy = 0
    for (let i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            const probability = frequencies[i] / sample.length
            entropy -= probability * Math.log2(probability)
        }
    }

    return entropy
}