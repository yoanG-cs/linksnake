
const HEADER_BYTES = 32

export async function checkMagicNumber(arrayBuffer, claimedExtension, patterns) {
    try {
        if (!arrayBuffer || arrayBuffer.byteLength < 4) {
            return { match: true, mismatch: false, description: 'Empty or small buffer' }
        }

        const hexString = bytesToHex(arrayBuffer, HEADER_BYTES)
        const signature  = lookupMagicNumbers(hexString, patterns)

        if (!signature) {
            return {
                match: true,
                actualType: null,
                claimedType: claimedExtension,
                mismatch: false,
                description: 'Unknown file type'
            }
        }
        const resolvedType = resolveRiffSubtype(signature.type, arrayBuffer) ?? signature.type
        if (resolvedType === 'html' && claimedExtension.toLowerCase() === '.hta') {
            return {
                match: false,
                actualType: 'html',
                claimedType: '.hta',
                mismatch: true,
                description: 'HTA (HTML Application) — executes as a program, not a document'
            }
        }

        const match = compareTypes(resolvedType, claimedExtension)

        if (match && resolvedType === 'zip') {
            const embedded = findEmbeddedExecutable(arrayBuffer)
            if (embedded) {
                return {
                    match: false,
                    actualType: 'zip',
                    claimedType: claimedExtension,
                    mismatch: true,
                    description: `ZIP/Office архив съдържа вграден изпълним файл: ${embedded}`
                }
            }
        }

        return {
            match,
            actualType: resolvedType,
            claimedType: claimedExtension,
            mismatch: !match,
            description: signature.description
        }
    } catch (error) {
        return { match: true, mismatch: false, description: 'Check failed' }
    }
}


function bytesToHex(arrayBuffer, count) {
    const bytes = new Uint8Array(arrayBuffer)
    const end   = Math.min(count, bytes.length)
    const parts = []
    for (let i = 0; i < end; i++) {
        parts.push(bytes[i].toString(16).padStart(2, '0').toUpperCase())
    }
    return parts.join('')
}

function lookupMagicNumbers(hexString, patterns) {
    const signatures = patterns.fileSignatures.signatures

    for (let len = hexString.length; len >= 4; len -= 2) {
        const sig = signatures[hexString.substring(0, len)]
        if (sig) return sig
    }
    return null
}

function resolveRiffSubtype(type, arrayBuffer) {
    if (type !== 'riff') return null
    const bytes = new Uint8Array(arrayBuffer)
    if (bytes.length < 12) return 'riff'
    const subtype = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11])
    if (subtype === 'WEBP') return 'webp'
    if (subtype === 'AVI ') return 'avi'
    if (subtype === 'WAVE') return 'wav'
    return 'riff'
}


function findEmbeddedExecutable(arrayBuffer) {
    const DANGEROUS_EXTENSIONS = new Set([
        'exe', 'dll', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'ps2',
        'vbs', 'vbe', 'wsf', 'wsc', 'hta', 'lnk', 'msi', 'msp', 'cpl',
        'inf', 'reg', 'elf', 'sh', 'bash', 'zsh', 'run', 'apk', 'jar'
    ])

    const bytes  = new Uint8Array(arrayBuffer)
    const LFH_SIG = 0x04034B50 
    let offset = 0

    while (offset + 30 < bytes.length) {

        const sig =  bytes[offset]         |
                    (bytes[offset + 1] << 8)  |
                    (bytes[offset + 2] << 16) |
                    (bytes[offset + 3] << 24)

        if ((sig >>> 0) !== LFH_SIG) {
            offset++
            continue
        }

        const compressedSize   = (bytes[offset + 18]        |
                                  bytes[offset + 19] << 8   |
                                  bytes[offset + 20] << 16  |
                                  bytes[offset + 21] << 24) >>> 0
        const filenameLength   =  bytes[offset + 26] | (bytes[offset + 27] << 8)
        const extraFieldLength =  bytes[offset + 28] | (bytes[offset + 29] << 8)

        if (filenameLength > 0 && offset + 30 + filenameLength <= bytes.length) {
            const nameBytes = bytes.slice(offset + 30, offset + 30 + filenameLength)
            const name      = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes).toLowerCase()
            const ext       = name.split('.').pop()
            if (DANGEROUS_EXTENSIONS.has(ext)) {
                return name
            }
        }

        const advance = 30 + filenameLength + extraFieldLength + compressedSize
        offset += advance > 0 ? advance : 1
    }

    return null
}

function compareTypes(actualType, claimedExtension) {
    const actual  = actualType.toLowerCase()
    const claimed = claimedExtension.toLowerCase().replace(/^\./, '')

    if (actual === claimed) return true

    const families = {
        zip: [
            'zip', 'docx', 'xlsx', 'pptx', 'dotx', 'xltx', 'potx',
            'jar', 'apk', 'odt', 'ods', 'odp', 'odg', 'epub',
            'xpi', 'aar', 'war', 'ear'
        ],

        xml: [
            'xml', 'svg', 'xhtml', 'htm', 'html', 'rss', 'atom',
            'xsl', 'xslt', 'plist', 'gpx', 'kml', 'xaml', 'resx'
        ],
        jpeg: ['jpeg', 'jpg', 'jfif', 'jpe'],
        ole:  ['doc', 'xls', 'ppt', 'dot', 'xlt', 'pot', 'msg', 'pub', 'vsd'],
        macho: ['macho', 'dylib', 'o', 'app', 'bin', 'dmg'],
        elf:  ['elf', 'so', 'bin', 'axf', 'o', 'ko', 'out', 'run'],
        riff: ['riff', 'wav', 'avi', 'webp'],
        webp: ['webp'],
        wav:  ['wav'],
        avi:  ['avi'],
        gz:   ['gz', 'tgz', 'tar'],
        bz2:  ['bz2', 'tbz', 'tbz2'],
        xz:   ['xz', 'txz'],
        html: ['html', 'htm'],
        rtf:  ['rtf'],
        lnk:  ['lnk'],
        cab:  ['cab'],
        deb:  ['deb'],
        '7z': ['7z'],
        rar:  ['rar'],
        class:['class'],
        exe:  ['exe', 'scr', 'com', 'pif', 'cpl', 'dll', 'sys'],
    }

    return families[actual]?.includes(claimed) ?? false
}