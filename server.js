'use strict';
/* MR.ADAM server: SQLite database + video storage. No dependencies (Node >= 22.5). */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TEACHER_USER = String(process.env.TEACHER_USER || '1').toLowerCase();
const ASSISTANT_USER = String(process.env.ASSISTANT_USER || '2').toLowerCase();
const VIDEO_DIR = path.join(DATA_DIR, 'videos');
fs.mkdirSync(VIDEO_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'app.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, ver INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);`);
const q = {
  getAll: db.prepare('SELECT k,v,ver FROM kv WHERE ver>?'),
  get: db.prepare('SELECT v,ver FROM kv WHERE k=?'),
  put: db.prepare('INSERT INTO kv(k,v,ver) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v,ver=excluded.ver'),
  metaGet: db.prepare('SELECT v FROM meta WHERE k=?'),
  metaPut: db.prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v'),
  maxVer: db.prepare('SELECT COALESCE(MAX(ver),0) AS m FROM kv'),
};
let SECRET = q.metaGet.get('secret')?.v;
if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); q.metaPut.run('secret', SECRET); }
let VER = q.maxVer.get().m;

/* ---------- auth (signed stateless tokens) ---------- */
const b64 = (s) => Buffer.from(s).toString('base64url');
const sign = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function makeToken(me) { const p = b64(JSON.stringify({ ...me, exp: Date.now() + 90 * 864e5 })); return p + '.' + sign(p); }
function readToken(t) {
  if (!t || typeof t !== 'string') return null;
  const [p, s] = t.split('.');
  if (!p || !s) return null;
  const e = sign(p);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch { return null; }
}
function authOf(req, url) {
  const h = req.headers.authorization || '';
  return readToken(h.startsWith('Bearer ') ? h.slice(7) : url.searchParams.get('t'));
}
const staff = (a) => a && (a.role === 'teacher' || a.role === 'assistant');

const tries = new Map();
function limited(ip) {
  const now = Date.now(); const a = (tries.get(ip) || []).filter((t) => now - t < 60000);
  a.push(now); tries.set(ip, a); return a.length > 12;
}

/* ---------- merge (3-way, by item identity) ---------- */
const IDK = {
  att: (x) => x.sid + '|' + x.date, hwSub: (x) => x.sid + '|' + x.hid, examScores: (x) => x.sid + '|' + x.eid,
  quizRes: (x) => [x.sid, x.qid, x.date, x.pct].join('|'), ratings: (x) => x.sid + '|' + x.lid,
  log: (x) => [x.date, x.time, x.sid, x.by, x.action].join('|'),
};
const idOf = (k, x) => (IDK[k] ? IDK[k](x) : x && x.id);
function merge(k, base, mine, cur) {
  if (![base, mine, cur].every(Array.isArray)) return mine;
  const B = new Map(base.map((x) => [idOf(k, x), JSON.stringify(x)]));
  const M = new Map(mine.map((x) => [idOf(k, x), x]));
  const out = new Map(cur.map((x) => [idOf(k, x), x]));
  for (const [id, x] of M) if (!B.has(id) || B.get(id) !== JSON.stringify(x)) out.set(id, x);
  for (const id of B.keys()) if (!M.has(id)) out.delete(id);
  return [...out.values()];
}
const STUDENT_KEYS = new Set(['quizRes', 'ratings', 'msgs', 'notifs']);

/* ---------- helpers ---------- */
const send = (res, code, obj) => { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(b); };
function body(req, max = 300 * 1024 * 1024) {
  return new Promise((ok, no) => {
    const c = []; let n = 0;
    req.on('data', (d) => { n += d.length; if (n > max) { no(new Error('big')); req.destroy(); } else c.push(d); });
    req.on('end', () => ok(Buffer.concat(c)));
    req.on('error', no);
  });
}
const vpath = (id) => (/^[A-Za-z0-9_-]{1,80}$/.test(id) ? path.join(VIDEO_DIR, id) : null);
const MIME = { '.html': 'text/html; charset=utf-8' };

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      const f = path.join(__dirname, 'public', 'index.html');
      res.writeHead(200, { 'Content-Type': MIME['.html'], 'Cache-Control': 'no-cache' });
      return fs.createReadStream(f).pipe(res);
    }

    if (p === '/api/login' && req.method === 'POST') {
      if (limited(req.socket.remoteAddress)) return send(res, 429, { error: 'rate' });
      const { role, user } = JSON.parse((await body(req, 1e5)).toString() || '{}');
      const v = String(user || '').trim().toLowerCase();
      if (!v) return send(res, 401, { error: 'bad' });
      let me = null;
      if (v === TEACHER_USER) me = { role: 'teacher' };
      else if (v === ASSISTANT_USER) me = { role: 'assistant' };
      else {
        const row = q.get.get('students');
        const list = row ? JSON.parse(row.v) : [];
        if (role === 'parent') { const s = list.find((x) => String(x.puser || 'p' + x.code).toLowerCase() === v); if (s) me = { role: 'parent', sid: s.id }; }
        else { const s = list.find((x) => String(x.user || x.code).toLowerCase() === v); if (s) me = { role: 'student', sid: s.id }; }
      }
      if (!me) return send(res, 401, { error: 'bad' });
      return send(res, 200, { token: makeToken(me), me });
    }

    if (p === '/api/state') {
      const a = authOf(req, url);
      if (!a) return send(res, 401, { error: 'auth' });
      if (req.method === 'GET') {
        const since = +url.searchParams.get('since') || 0;
        const data = {};
        for (const r of q.getAll.all(since)) data[r.k] = JSON.parse(r.v);
        return send(res, 200, { ver: VER, data });
      }
      if (req.method === 'PUT') {
        const { changes } = JSON.parse((await body(req)).toString() || '{}');
        const keys = Object.keys(changes || {});
        if (!staff(a) && keys.some((k) => !STUDENT_KEYS.has(k))) return send(res, 403, { error: 'forbidden' });
        const out = {};
        db.exec('BEGIN');
        try {
          for (const k of keys) {
            if (!/^[A-Za-z0-9_]{1,40}$/.test(k)) continue;
            const { value, base } = changes[k];
            const row = q.get.get(k);
            const merged = row && base !== undefined && base !== null ? merge(k, base, value, JSON.parse(row.v)) : value;
            q.put.run(k, JSON.stringify(merged), ++VER);
            out[k] = merged;
          }
          db.exec('COMMIT');
        } catch (e) { db.exec('ROLLBACK'); throw e; }
        return send(res, 200, { ver: VER, data: out });
      }
    }

    if (p.startsWith('/api/video/')) {
      const a = authOf(req, url);
      if (!a) return send(res, 401, { error: 'auth' });
      const f = vpath(decodeURIComponent(p.slice(11)));
      if (!f) return send(res, 400, { error: 'id' });
      if (req.method === 'PUT') {
        if (!staff(a)) return send(res, 403, { error: 'forbidden' });
        const tmp = f + '.part';
        const ws = fs.createWriteStream(tmp);
        req.pipe(ws);
        ws.on('finish', () => { fs.renameSync(tmp, f); send(res, 200, { ok: true }); });
        ws.on('error', () => send(res, 500, { error: 'write' }));
        req.on('error', () => { ws.destroy(); fs.rmSync(tmp, { force: true }); });
        return;
      }
      if (req.method === 'DELETE') {
        if (!staff(a)) return send(res, 403, { error: 'forbidden' });
        fs.rmSync(f, { force: true }); return send(res, 200, { ok: true });
      }
      if (req.method === 'GET') {
        if (!fs.existsSync(f)) return send(res, 404, { error: 'none' });
        const size = fs.statSync(f).size;
        const m = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
        const type = 'video/mp4';
        if (m) {
          let s = m[1] ? +m[1] : 0, e = m[2] ? +m[2] : size - 1;
          if (!m[1] && m[2]) { s = size - +m[2]; e = size - 1; }
          if (s >= size || e >= size || s > e) { res.writeHead(416, { 'Content-Range': 'bytes */' + size }); return res.end(); }
          res.writeHead(206, { 'Content-Range': `bytes ${s}-${e}/${size}`, 'Accept-Ranges': 'bytes', 'Content-Length': e - s + 1, 'Content-Type': type, 'Cache-Control': 'private, no-store' });
          return fs.createReadStream(f, { start: s, end: e }).pipe(res);
        }
        res.writeHead(200, { 'Accept-Ranges': 'bytes', 'Content-Length': size, 'Content-Type': type, 'Cache-Control': 'private, no-store' });
        return fs.createReadStream(f).pipe(res);
      }
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'server' });
  }
});
server.requestTimeout = 0; // long video uploads
server.listen(PORT, () => {
  console.log(`MR.ADAM server on http://localhost:${PORT}  (data: ${DATA_DIR})`);
  if (TEACHER_USER === '1') console.log('WARNING: set TEACHER_USER and ASSISTANT_USER environment variables to private usernames before publishing.');
});
