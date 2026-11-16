// ============================================================
// SSH GATEWAY - Gabungan ws-proxy.js (8880) + mux.js (8881)
// Satu proses, dua pintu:
//   - Port 8880 : WS-Proxy langsung ke Dropbear (dari ws-proxy.js)
//   - Port 8881 : Mux splitter (dari mux.js)
//                 byte pertama 0x16 (TLS) -> Stunnel 2443
//                 selain itu              -> WS-Proxy 8880
// Plus REGISTRY KONEKSI: semua koneksi SSH yang beneran aktif
// dicatat ke /tmp/ssh_conns.json supaya panel bisa nampilin
// "SSH Online" yang akurat (IP asli dari header cf-connecting-ip).
// ============================================================
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

const WS_PORT = process.env.WS_PORT || '8880';
const MUX_PORT = parseInt(process.env.MUX_PORT || process.env.PUBLIC_PORT || '8881');
const SSL_TARGET = parseInt(process.env.SSL_TARGET_PORT || '2443');
const WS_TARGET = parseInt(process.env.WS_TARGET_PORT || '8880');
const SSH_TARGET_HOST = '127.0.0.1';
const WSMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PROXY_CONFIG_FILE = "/tmp/ws_proxy_config.json";
const CONNS_FILE = "/tmp/ssh_conns.json";

// ============================================================
// REGISTRY KONEKSI AKTIF
// - Koneksi WS: dicatat pas SSH banner ketemu (beneran SSH,
//   bukan scanner nyasar), IP asli dari cf-connecting-ip.
// - Koneksi SSL (lewat Mux -> Stunnel): cuma kehitung jumlahnya,
//   isinya terenkripsi TLS jadi IP/username nggak kelihatan di sini.
// ============================================================
const activeWsConns = new Map(); // id -> { ip, since }
let sslActiveCount = 0;
let connSeq = 0;

function writeRegistry() {
    try {
        const list = [];
        for (const c of activeWsConns.values()) {
            list.push({ ip: c.ip || 'Unknown', since: c.since, via: 'WS' });
        }
        const data = {
            updated: Date.now(),
            total: list.length + sslActiveCount,
            ws_active: list.length,
            ssl_active: sslActiveCount,
            list: list
        };
        fs.writeFileSync(CONNS_FILE, JSON.stringify(data));
    } catch (e) {}
}
setInterval(writeRegistry, 5000);
writeRegistry();

// 🔍 FUNGSI BACA CONFIG DINAMIS DARI BACKEND UI
function getProxyConfig() {
    try {
        if (fs.existsSync(PROXY_CONFIG_FILE)) {
            return JSON.parse(fs.readFileSync(PROXY_CONFIG_FILE, 'utf8'));
        }
    } catch (e) {}
    return {
        sshPort: parseInt(process.env.SSH_TARGET_PORT || '22'),
        keepAlive: 15000,
        maxBuffer: 32 * 1024
    };
}

function parseHeaders(rawText) {
    const headers = {};
    const lines = rawText.split("\r\n");
    for (let i = 1; i < lines.length; i++) {
        let line = lines[i];
        if (line.includes(":")) {
            let parts = line.split(":");
            let k = parts[0].trim().toLowerCase();
            let v = parts.slice(1).join(":").trim();
            headers[k] = v;
        }
    }
    return headers;
}

// ============================================================
// BAGIAN 1: WS-PROXY (PORT 8880) - dari ws-proxy.js
// ============================================================
const wsServer = net.createServer((clientConn) => {
    // Ambil settingan terbaru tiap ada client konek
    const cfg = getProxyConfig();
    const targetSshPort = cfg.sshPort || 22;
    const keepAliveMs = cfg.keepAlive || 15000;
    const maxBufferLimit = cfg.maxBuffer || (32 * 1024);

    // 📝 Tracking koneksi ini
    const connId = ++connSeq;
    const connInfo = { ip: null, since: Date.now() };
    let registered = false;
    clientConn.on('close', () => {
        if (registered) {
            activeWsConns.delete(connId);
            writeRegistry();
        }
    });

    clientConn.setNoDelay(true);
    clientConn.setKeepAlive(true, keepAliveMs); // ⚡ Ping KeepAlive Dinamis
    clientConn.readableHighWaterMark = 64 * 1024;
    clientConn.writableHighWaterMark = 64 * 1024;

    clientConn.once('data', (rawHeaders) => {
        if (!rawHeaders || rawHeaders.length === 0) {
            clientConn.destroy();
            return;
        }

        const rawText = rawHeaders.toString('utf8');
        const rawTextLower = rawText.toLowerCase();
        const headers = parseHeaders(rawText);

        // IP asli user: koneksi datang lewat cloudflared (127.0.0.1),
        // IP aslinya nempel di header ini.
        connInfo.ip = headers['cf-connecting-ip']
            || (headers['x-forwarded-for'] ? headers['x-forwarded-for'].split(',')[0].trim() : null)
            || clientConn.remoteAddress
            || null;

        const isWsUpgrade = rawTextLower.includes('upgrade: websocket') || headers['upgrade'] === 'websocket';

        if (isWsUpgrade) {
            let wsKey = headers['sec-websocket-key'];
            if (!wsKey && rawTextLower.includes('sec-websocket-key:')) {
                const lines = rawText.split("\r\n");
                for (let line of lines) {
                    if (line.toLowerCase().startsWith('sec-websocket-key:')) {
                        wsKey = line.split(":")[1].trim();
                        break;
                    }
                }
            }

            if (!wsKey) {
                wsKey = crypto.randomBytes(16).toString('base64');
            }

            const shasum = crypto.createHash('sha1');
            shasum.update(wsKey + WSMagic);
            const acceptKey = shasum.digest('base64');

            let response = "HTTP/1.1 101 Switching Protocols\r\n" +
                             "Upgrade: websocket\r\n" +
                             "Connection: Upgrade\r\n" +
                             `Sec-WebSocket-Accept: ${acceptKey}\r\n`;

            if (headers['sec-websocket-protocol']) {
                response += `Sec-WebSocket-Protocol: ${headers['sec-websocket-protocol']}\r\n`;
            }
            response += "\r\n";

            clientConn.write(response);
        } else {
            const defaultResp = process.env.WS_RESPONSE || "HTTP/1.1 101 Switching Protocols\r\n\r\n";
            clientConn.write(defaultResp);
        }

        // =========================================================
        // KONEKSI DINAMIS KE DROPBEAR / OPENSSH
        // Handler data client dipasang LANGSUNG (chunk awal ditampung
        // dulu) supaya banner SSH yang datang super cepat nggak
        // kelewat sebelum koneksi ke dropbear siap.
        // =========================================================
        const sshConn = net.createConnection({ port: targetSshPort, host: SSH_TARGET_HOST });

        let sshReady = false;
        let sshHandshakeDone = false;
        let pendingBuffer = Buffer.alloc(0);
        const earlyChunks = [];

        const processClientChunk = (chunk) => {
            if (sshHandshakeDone) {
                if (sshConn.writable) {
                    const flush = sshConn.write(chunk);
                    if (!flush) clientConn.pause();
                }
                return;
            }

            pendingBuffer = Buffer.concat([pendingBuffer, chunk]);
            const sshIndex = pendingBuffer.indexOf(Buffer.from('SSH-'));

            if (sshIndex !== -1) {
                const cleanSshData = pendingBuffer.subarray(sshIndex);
                sshHandshakeDone = true;

                // 📝 Banner SSH ketemu = koneksi ini beneran SSH aktif
                if (!registered) {
                    registered = true;
                    activeWsConns.set(connId, connInfo);
                    writeRegistry();
                }

                if (sshConn.writable) {
                    const flush = sshConn.write(cleanSshData);
                    if (!flush) clientConn.pause();
                }
                pendingBuffer = null;
            } else {
                // Batas penyaringan buffer dinamis
                if (pendingBuffer.length > maxBufferLimit) {
                    clientConn.destroy();
                    sshConn.destroy();
                }
            }
        };

        clientConn.on('data', (chunk) => {
            if (!sshReady) { earlyChunks.push(chunk); return; }
            processClientChunk(chunk);
        });

        sshConn.on('connect', () => {
            sshConn.setNoDelay(true);
            sshConn.setKeepAlive(true, keepAliveMs);
            sshReady = true;
            while (earlyChunks.length > 0) {
                processClientChunk(earlyChunks.shift());
            }
        });

        sshConn.on('data', (data) => {
            if (clientConn.writable) {
                const flush = clientConn.write(data);
                if (!flush) sshConn.pause();
            }
        });

        sshConn.on('drain', () => clientConn.resume());
        clientConn.on('drain', () => sshConn.resume());

        sshConn.on('error', () => clientConn.destroy());
        clientConn.on('error', () => sshConn.destroy());
        sshConn.on('close', () => clientConn.destroy());
        clientConn.on('close', () => sshConn.destroy());
    });
});

wsServer.listen(WS_PORT, '0.0.0.0', () => {
    console.log(`[WS Engine JS] Dynamic Proxy Active on Port ${WS_PORT}`);
});

// ============================================================
// BAGIAN 2: MUX SPLITTER (PORT 8881) - dari mux.js
// ============================================================
const muxServer = net.createServer((clientConn) => {
    clientConn.setNoDelay(true);
    clientConn.setKeepAlive(true, 15000); // Anti silent disconnect
    clientConn.readableHighWaterMark = 64 * 1024;
    clientConn.writableHighWaterMark = 64 * 1024;

    let backendConn = null;
    let isConnected = false;
    let countedAsSsl = false;
    const earlyBuffer = [];

    clientConn.on('close', () => {
        if (countedAsSsl) {
            sslActiveCount = Math.max(0, sslActiveCount - 1);
            writeRegistry();
        }
    });

    const handleInitialData = (buffer) => {
        if (!buffer || buffer.length === 0) return;

        clientConn.removeListener('data', handleInitialData);

        // ⚡ PEMISAH LALU LINTAS MURNI:
        // Cuma cek Byte Pertama: 0x16 = Handshake TLS/SSL -> Stunnel (2443)
        // Selain itu (HTTP/WS/Inject Payload) -> WS-Proxy (8880)
        const targetPort = (buffer[0] === 0x16) ? SSL_TARGET : WS_TARGET;

        // 📝 Jalur TLS = koneksi SSH-SSL: hitung di sini
        // (yang jalur WS dihitung di ws-proxy setelah banner SSH)
        if (targetPort === SSL_TARGET && !countedAsSsl) {
            countedAsSsl = true;
            sslActiveCount++;
            writeRegistry();
        }

        backendConn = net.createConnection({ port: targetPort, host: '127.0.0.1' }, () => {
            isConnected = true;
            backendConn.setNoDelay(true);
            backendConn.setKeepAlive(true, 15000);

            backendConn.write(buffer);

            while (earlyBuffer.length > 0) {
                const chunk = earlyBuffer.shift();
                backendConn.write(chunk);
            }
        });

        clientConn.on('data', (data) => {
            if (isConnected && backendConn && backendConn.writable) {
                const flush = backendConn.write(data);
                if (!flush) clientConn.pause();
            } else {
                earlyBuffer.push(data);
            }
        });

        backendConn.on('data', (data) => {
            if (clientConn.writable) {
                const flush = clientConn.write(data);
                if (!flush) backendConn.pause();
            }
        });

        backendConn.on('drain', () => clientConn.resume());
        clientConn.on('drain', () => backendConn.resume());

        backendConn.on('error', () => clientConn.destroy());
        clientConn.on('error', () => backendConn ? backendConn.destroy() : null);
        backendConn.on('close', () => clientConn.destroy());
        clientConn.on('close', () => backendConn ? backendConn.destroy() : null);
    };

    clientConn.on('data', handleInitialData);
});

muxServer.listen(MUX_PORT, '0.0.0.0', () => {
    console.log(`[Mux JS] Pure Traffic Splitter Active on Port ${MUX_PORT}`);
});
