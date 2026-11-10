#!/usr/bin/env node
// hosterd: the only holder of the Dokploy token.
//
// Design rules, from docs/host-now-security.md:
//   * the Dokploy token never leaves this process
//   * every request is attributed to a key id and recorded in the audit log
//   * scopes are checked per verb; delete is a separate scope from write
//   * secrets are printed once, never stored in plaintext, never logged
//   * a request with no live credentials produces a plan, not a mutation
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import pg from 'pg';
import { join } from 'node:path';
import { homedir } from 'node:os';

const PORT = Number(process.env.PORT ?? process.env.HOSTERD_PORT ?? 8799);
const MASTER = process.env.HOSTERD_MASTER_KEY ?? '';
const HOME = process.env.HOSTERD_HOME ?? join(homedir(), '.hosterd');
const DB = join(HOME, 'hosterd.json');
const ADMIN = process.env.HOSTERD_ADMIN_KEY ?? '';
const LIVE = process.env.HOSTERD_LIVE === '1' && Boolean(process.env.DOKPLOY_TOKEN);

const SCOPES = new Set(['sites:read', 'sites:write', 'sites:delete', 'db:read', 'db:write', 'keys:admin', 'log:read', 'static:write']);
const ANON_ON = process.env.HOSTERD_ANON === '1';
const anonHits = new Map(); // ip -> [timestamps]

// ---- store ---------------------------------------------------------------
function blank() { return { version: 1, tenants: [], keys: [], sites: [], audit: [] }; }
if (!process.env.DATABASE_URL) { console.error('FATAL: DATABASE_URL is required'); process.exit(1); }
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
await pool.query('CREATE TABLE IF NOT EXISTS host_now_state (id int primary key, doc jsonb not null)');
await pool.query("CREATE TABLE IF NOT EXISTS host_now_audit (at timestamptz not null default now(), row jsonb not null)");

let store = blank();
{
  const { rows } = await pool.query('SELECT doc FROM host_now_state WHERE id = 1');
  if (rows[0]?.doc) store = { ...blank(), ...rows[0].doc };
}
mkdirSync(join(HOME, 'sites'), { recursive: true });

let chain = Promise.resolve();
const persist = () => {
  const snapshot = JSON.stringify({ tenants: store.tenants, keys: store.keys, sites: store.sites });
  chain = chain
    .then(() => pool.query('INSERT INTO host_now_state (id, doc) VALUES (1, $1::jsonb) ON CONFLICT (id) DO UPDATE SET doc = $1::jsonb', [snapshot]))
    .catch((err) => console.error('persist failed:', err.message));
  return chain;
};

const hash = (secret) => createHash('sha256').update(secret).digest('hex');
const id = (p) => `${p}_${randomBytes(6).toString('hex')}`;
const now = () => new Date().toISOString();

function audit(actor, action, target, result, detail) {
  const row = { at: now(), actor, action, target, result, detail: detail ?? null };
  store.audit.push(row);
  if (store.audit.length > 1000) store.audit = store.audit.slice(-800);
  pool.query('INSERT INTO host_now_audit (row) VALUES ($1::jsonb)', [JSON.stringify(row)])
    .catch((err) => console.error('audit write failed:', err.message));
  persist();
}

// ---- keys ----------------------------------------------------------------
function mintKey({ label, tenant, scopes, ttlSeconds, kind }) {
  const secret = 'hn_live_' + randomBytes(24).toString('hex');
  const rec = {
    id: id('key'),
    label: label ?? 'unnamed',
    tenant,
    kind: kind ?? 'registered',
    hash: hash(secret),
    prefix: secret.slice(0, 14),
    scopes: [...new Set(scopes)].filter((s) => SCOPES.has(s)),
    expiresAt: new Date(Date.now() + (ttlSeconds ?? 3600) * 1000).toISOString(),
    revokedAt: null,
    lastUsedAt: null,
    createdAt: now(),
  };
  store.keys.push(rec);
  persist();
  return { secret, rec };
}

function resolveKey(secret) {
  if (!secret) return null;
  const h = hash(secret);
  const rec = store.keys.find((k) => k.hash === h);
  if (!rec || rec.revokedAt) return null;
  if (new Date(rec.expiresAt) < new Date()) return null;
  return rec;
}

const can = (key, scope) => key.scopes.includes(scope) || key.scopes.includes('keys:admin');

// ---- http helpers --------------------------------------------------------
const json = (res, code, body) => {
  const s = JSON.stringify(body);
  res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(s) });
  res.end(s);
};
const fail = (res, code, name, message, next) => json(res, code, { code: name, message, next: next ?? null });
const read = async (req) => {
  let b = '';
  for await (const c of req) b += c;
  return b ? JSON.parse(b) : {};
};
const bearer = (req) => (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');

// ---- validation ----------------------------------------------------------
const NAME = /^[a-z0-9]([a-z0-9-]{1,28})[a-z0-9]$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORDS = ['swift', 'quiet', 'amber', 'brave', 'calm', 'clever', 'noble', 'rapid', 'solid'];
const NOUNS = ['otter', 'harbour', 'falcon', 'meadow', 'summit', 'willow', 'ember', 'cobalt'];
const generated = () => `${WORDS[Math.floor(Math.random() * WORDS.length)]}-${NOUNS[Math.floor(Math.random() * NOUNS.length)]}`;

// ---- the site plan -------------------------------------------------------
// This is the sequence proven by hand on 2026-10-28. In dry-run it is a plan;
// with HOSTERD_LIVE=1 each step becomes the real call in dokploy.mjs.
function planFor(site) {
  const slug = site.name;
  if (site.kind === 'static') {
    return {
      slug, url: `https://${slug}.host.abslm.nl`, live: LIVE, kind: 'static',
      steps: [
        { call: 'files.scan', body: { note: 'size, mime, and reject password forms or <?php' } },
        { call: 'files.store', body: { root: `sites/${slug}` } },
        { call: 'static.serve', body: { host: `${slug}.host.abslm.nl`, shared: true, executes: false } },
        { call: 'dns.inherit', body: { note: 'covered by the *.host.abslm.nl wildcard, no record created' } },
      ],
    };
  }
  const steps = [
    { call: 'project.create', body: { name: `host-${slug}` } },
    { call: 'postgres.create', body: { name: `host-${slug}-db`, databaseName: slug.replace(/-/g, '_'), databaseUser: 'app' } },
    { call: 'postgres.deploy' },
    { call: 'network.isolate', body: { network: `host-${slug}-net`, attachDokployNetwork: false, note: 'measured cross-tenant reachability on dokploy-network; a site must not join it' } },
    { call: 'application.create', body: { name: `host-${slug}` } },
    ...(site.repo
      ? [{ call: 'application.saveGithubProvider', body: { owner: site.repo.split('/')[0], repository: site.repo.split('/')[1], branch: site.branch ?? 'main' } }]
      : [{ call: 'source.snapshot', body: { note: 'no repo: the working tree is the deploy unit, pushed to a private repo first' } }]),
    { call: 'application.saveBuildType', body: { buildType: 'dockerfile' } },
    { call: 'application.saveEnvironment', body: { env: 'DATABASE_URL=<injected at runtime>', buildArgs: '', buildSecrets: '', createEnvFile: true } },
    { call: 'domain.create', body: { host: `${slug}.host.abslm.nl`, port: site.port ?? 3000, https: true, certificateType: 'letsencrypt', domainType: 'application' } },
    { call: 'application.deploy' },
    { call: 'deployment.poll', body: { until: 'done', timeoutSeconds: 900 } },
  ];
  return { slug, url: `https://${slug}.host.abslm.nl`, steps, live: LIVE };
}


// ---- static files: scanned, stored, served, never executed ----------------
const EXT = new Set(['.html','.htm','.css','.js','.mjs','.json','.svg','.png','.jpg','.jpeg','.webp','.gif','.ico','.woff','.woff2','.ttf','.txt','.md','.map','.webmanifest']);
const TEXT = new Set(['.html','.htm','.css','.js','.mjs','.json','.svg','.txt','.md','.webmanifest']);
const MIME = { '.html':'text/html; charset=utf-8','.htm':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.json':'application/json','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.gif':'image/gif','.ico':'image/x-icon','.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.txt':'text/plain; charset=utf-8','.md':'text/markdown; charset=utf-8','.map':'application/json','.webmanifest':'application/manifest+json' };
const MAX_BYTES = 50 * 1024 * 1024, MAX_FILE = 8 * 1024 * 1024;
const SITES_DIR = () => join(HOME, 'sites');
const extOf = (p) => { const i = p.lastIndexOf('.'); return i < 0 ? '' : p.slice(i).toLowerCase(); };

function checkPath(rel) {
  if (typeof rel !== 'string' || !rel) return 'empty path';
  if (rel.includes('\0')) return 'null byte in path';
  if (rel.startsWith('/') || /^[A-Za-z]:/.test(rel)) return `absolute path: ${rel}`;
  const parts = rel.split('/');
  if (parts.some((x) => x === '..' || x === '.' || x === '')) return `illegal segment in ${rel}`;
  const ext = extOf(rel);
  if (!EXT.has(ext)) return `extension not allowed: ${ext || '(none)'} in ${rel}`;
  return null;
}

// the phishing shapes we refuse at upload, because a stranger can reach this
function scanText(rel, text) {
  const low = text.toLowerCase();
  if (/<\?php/.test(low)) return `${rel}: server-side code is not served`;
  if (/type\s*=\s*["']?password/.test(low) && /<form/i.test(low)) return `${rel}: a form with a password field is not allowed on an anonymous site`;
  if (/type\s*=\s*["']?password/.test(low) && /<input/i.test(low)) return `${rel}: a password field is not allowed on an anonymous site`;
  if (/(cgi-bin|\.php\b)/.test(low) && /<form/i.test(low)) return `${rel}: form posting to a server script`;
  return null;
}

const banned = (name) => store.audit.some((r) => r.action === 'site.ban' && r.target === name);

function storeFiles(name, files) {
  const dir = join(SITES_DIR(), name);
  let total = 0;
  const written = [];
  for (const f of files) {
    const bad = checkPath(f.path);
    if (bad) return { error: bad };
    const buf = Buffer.from(f.data ?? '', 'base64');
    if (buf.length > MAX_FILE) return { error: `${f.path} is larger than 8 MB` };
    total += buf.length;
    if (total > MAX_BYTES) return { error: 'site is larger than 50 MB' };
    if (TEXT.has(extOf(f.path))) {
      const reason = scanText(f.path, buf.toString('utf8'));
      if (reason) return { error: reason };
    }
    const target = join(dir, ...f.path.split('/'));
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, buf);
    written.push({ path: f.path, bytes: buf.length });
  }
  return { written, total };
}


// ---- live: make a hostname exist on the origin (the one Dokploy call we need) ----
async function ensureDomain(name) {
  const token = process.env.HOSTERD_DOKPLOY_TOKEN;
  const appId = process.env.HOSTERD_STATIC_APP_ID;
  if (!token || !appId) return { ok: false, reason: 'no dokploy credentials configured' };
  const base = process.env.HOSTERD_DOKPLOY_API ?? 'https://dp.abslm.nl/api';
  const callApi = async (path, body) => {
    const res = await fetch(base + path, {
      method: body ? 'POST' : 'GET',
      headers: { 'x-api-key': token, 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return res.json().catch(() => ({}));
  };
  const host = `${name}.host.abslm.nl`;
  try {
    const existing = await callApi(`/domain.byApplicationId?applicationId=${appId}`);
    if (Array.isArray(existing) && existing.some((d) => d.host === host)) return { ok: true, host, created: false };
    const made = await callApi('/domain.create', {
      applicationId: appId, host, port: 3000, https: true,
      certificateType: 'letsencrypt', domainType: 'application', path: '/',
    });
    if (made.domainId) return { ok: true, host, created: true, domainId: made.domainId };
    return { ok: false, reason: String(made.message ?? 'domain.create failed').slice(0, 120) };
  } catch (err) {
    return { ok: false, reason: String(err.message ?? err).slice(0, 120) };
  }
}

// ---- routes --------------------------------------------------------------
const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://hosterd');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  const presented = req.headers['x-hosterd-master'] ?? bearer(req);
  const masterOk = MASTER.length > 0 && presented === MASTER;
  // Operator surfaces need the master key. Tenant routes authenticate with the key itself, which is
  // what lets somebody's own CI deploy without ever holding the operator secret.
  const OPERATOR = new Set(['/anon', '/keys', '/keys/revoke', '/keys/verify', '/log', '/health', '/republish']);
  const strict = process.env.HOSTERD_STRICT_MASTER === '1';
  const needsMaster = strict || OPERATOR.has(path) || /^\/sites\/[a-z0-9-]+\/ban$/.test(path);
  if (needsMaster) {
    if (!MASTER) return fail(res, 503, 'no_master', 'HOSTERD_MASTER_KEY is not set on the server', 'set it in the environment');
    if (!masterOk) return fail(res, 401, 'master_required', 'this route requires the master key', 'send x-hosterd-master: $HOSTERD_MASTER_KEY');
  }

  if (method === 'GET' && path === '/health') return json(res, 200, { ok: true, live: LIVE, sites: store.sites.length });

  // public serving: a site is a website, so this needs no key
  if (method === 'GET' && path.startsWith('/s/')) {
    const [name, ...rest] = path.slice(3).split('/');
    if (!NAME.test(name)) return fail(res, 404, 'no_site', 'unknown site');
    if (banned(name)) return fail(res, 451, 'banned', 'this site has been removed');
    const rel = rest.join('/') || 'index.html';
    if (checkPath(rel)) return fail(res, 404, 'no_file', 'unknown file');
    const file = join(SITES_DIR(), name, ...rel.split('/'));
    if (!existsSync(file)) return fail(res, 404, 'no_file', 'not found', 'publish a folder first');
    const body = readFileSync(file);
    res.writeHead(200, { 'content-type': MIME[extOf(rel)] ?? 'application/octet-stream', 'content-length': body.length, 'x-content-type-options': 'nosniff' });
    return res.end(body);
  }

  // anonymous self-serve minting: no credentials, rate limited, static only
  if (method === 'POST' && path === '/anon') {
    if (!ANON_ON) return fail(res, 403, 'anon_off', 'anonymous keys are disabled on this instance', 'set HOSTERD_ANON=1');
    const ip = (req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? 'unknown').toString().split(',')[0].trim();
    const t = Date.now(); const hits = (anonHits.get(ip) ?? []).filter((x) => t - x < 3600_000);
    if (hits.length >= 5) return fail(res, 429, 'rate_limited', 'five anonymous keys per hour per address', 'try later, or connect a GitHub identity');
    hits.push(t); anonHits.set(ip, hits);
    const tenant = 'anon-' + randomBytes(4).toString('hex');
    const { secret, rec } = mintKey({ label: 'anon-' + ip.slice(0, 8), tenant, kind: 'anon', scopes: ['sites:read', 'static:write'], ttlSeconds: 86400 });
    audit(rec.id, 'key.anon', rec.id, 'ok', { ip, tenant });
    return json(res, 201, { secret, tenant, scopes: rec.scopes, expiresAt: rec.expiresAt, limits: { sites: 1, static: true, bytes: 52428800 } });
  }

  // admin surface: mint and inspect keys
  const isAdmin = ADMIN && req.headers['x-hosterd-admin'] === ADMIN;
  if (method === 'POST' && path === '/keys') {
    if (!isAdmin) return fail(res, 401, 'admin_required', 'admin key required', 'set HOSTERD_ADMIN_KEY and send x-hosterd-admin');
    const body = await read(req);
    if (!body.scopes?.length) return fail(res, 400, 'bad_request', 'scopes are required', 'e.g. ["sites:read","sites:write"]');
    const bad = body.scopes.filter((s) => !SCOPES.has(s));
    if (bad.length) return fail(res, 400, 'bad_request', `unknown scope: ${bad.join(", ")}`, `known: ${[...SCOPES].join(", ")}`);
    const tenant = body.tenant ?? 'team-' + (body.label ?? 'default').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const { secret, rec } = mintKey({ ...body, tenant });
    audit(rec.id, 'key.create', rec.id, 'ok', { label: rec.label, scopes: rec.scopes, tenant, expiresAt: rec.expiresAt });
    // the only time the secret is ever emitted
    return json(res, 201, { id: rec.id, secret, tenant, scopes: rec.scopes, expiresAt: rec.expiresAt });
  }
  if (method === 'GET' && path === '/keys') {
    if (!isAdmin) return fail(res, 401, 'admin_required', 'admin key required');
    return json(res, 200, store.keys.map(({ hash: _h, ...k }) => k));
  }
  if (method === 'POST' && path === '/keys/revoke') {
    if (!isAdmin) return fail(res, 401, 'admin_required', 'admin key required');
    const body = await read(req);
    const rec = store.keys.find((k) => k.id === body.id);
    if (!rec) return fail(res, 404, 'no_key', 'unknown key id');
    rec.revokedAt = now();
    persist();
    audit(body.id, 'key.revoke', rec.id, 'ok');
    return json(res, 200, { id: rec.id, revokedAt: rec.revokedAt });
  }

  // verify is unauthenticated by design: it is how a client checks its own key
  if (method === 'POST' && path === '/keys/verify') {
    const body = await read(req);
    const rec = resolveKey(body.secret ?? body.key);
    if (!rec) return fail(res, 401, 'key_rejected', 'unknown, expired or revoked key');
    return json(res, 200, { tenant: rec.tenant, scopes: rec.scopes, expiresAt: rec.expiresAt, id: rec.id });
  }

  // everything below needs a tenant key, or the admin header (which reads everything)
  const adminActor = isAdmin ? { id: 'admin', tenant: '*', scopes: [...SCOPES], expiresAt: null } : null;
  const key = adminActor ?? resolveKey(bearer(req));
  if (!key) return fail(res, 401, 'key_rejected', 'unknown, expired or revoked key', 'host-now connect <key>');
  if (!adminActor) key.lastUsedAt = now();

  if (method === 'GET' && path === '/me') {
    return json(res, 200, {
      tenant: key.tenant, kind: key.kind, scopes: key.scopes, expiresAt: key.expiresAt, id: key.id,
      sites: store.sites.filter((s) => s.tenant === key.tenant).length,
    });
  }

  if (method === 'POST' && path === '/sites') {
    const staticOnly = !can(key, 'sites:write') && key.scopes.includes('static:write');
    const wantsStatic = staticOnly || body.kind === 'static';
    if (!can(key, 'sites:write') && !staticOnly) return fail(res, 403, 'scope', 'this key cannot create sites', 'ask for sites:write');
    const body = await read(req);
    const name = body.name ?? generated();
    if (!NAME.test(name)) return fail(res, 400, 'bad_request', 'name must be 3-30 chars of a-z, 0-9 and hyphens');
    if (body.repo && !REPO.test(body.repo)) return fail(res, 400, 'bad_request', 'repo must look like owner/name');
    if (body.db && key.kind !== 'registered')
      return fail(res, 403, 'db_needs_identity', 'a database needs a registered key, not an anonymous one', 'connect a GitHub identity to get databases');
    if (body.kind !== undefined && body.kind !== 'static' && body.kind !== 'server')
      return fail(res, 400, 'bad_request', "kind must be 'static' or 'server'");
    if (wantsStatic && (body.repo || body.db || body.build))
      return fail(res, 403, 'static_only', 'an anonymous key cannot build, run a server, or create a database', 'connect a GitHub identity for that');
    if (store.sites.some((s) => s.name === name)) return fail(res, 409, 'name_taken', `site ${name} already exists`);
    const owned = store.sites.filter((s) => s.tenant === key.tenant);
    const cap = staticOnly ? 1 : 3;
    if (owned.length >= cap && !can(key, 'keys:admin'))
      return fail(res, 429, 'quota', staticOnly ? 'one anonymous site per key' : 'three sites per tenant at this stage', 'host-now down <name> first');

    const site = {
      name, tenant: key.tenant, kind: wantsStatic ? 'static' : 'server',
      repo: wantsStatic ? null : (body.repo ?? null), branch: body.branch ?? 'main',
      port: wantsStatic ? null : Number(body.port ?? 3000),
      // A database must be asked for. Defaulting to true provisioned Postgres for
      // every site, including ones that only ever serve files.
      db: wantsStatic ? false : Boolean(body.db ?? false),
      url: `https://${name}.host.abslm.nl`, state: 'planned', createdAt: now(),
    };
    const plan = planFor(site);
    if (!LIVE) {
      store.sites.push(site);
      audit(key.id, 'site.plan', name, 'ok', { steps: plan.steps.length });
      return json(res, 201, { site, plan });
    }
    return fail(res, 501, 'not_wired', 'live deploys are not wired yet; unset HOSTERD_LIVE to get a plan', 'hosterd live adapter is the next commit');
  }

  if (method === 'POST' && path === '/republish') {
    const origin = process.env.HOSTERD_STATIC_ORIGIN, originToken = process.env.HOSTERD_STATIC_TOKEN;
    if (!origin || !originToken) return fail(res, 501, 'no_origin', 'no static origin configured');
    if (!key.scopes.includes('static:write') && !can(key, 'sites:write')) return fail(res, 403, 'scope', 'this key cannot publish');
    const mine = key.tenant === '*' ? store.sites : store.sites.filter((s) => s.tenant === key.tenant);
    let sites = 0, files = 0;
    for (const site of mine) {
      if (site.kind !== 'static' || site.state === 'banned') continue;
      const dir = join(SITES_DIR(), site.name);
      if (!existsSync(dir)) continue;
      const payload = [];
      const walk = (d, prefix = '') => {
        for (const e of readdirSync(d, { withFileTypes: true })) {
          const rel = prefix ? `${prefix}/${e.name}` : e.name;
          if (e.isDirectory()) walk(join(d, e.name), rel);
          else if (e.isFile()) payload.push({ path: rel, data: readFileSync(join(d, e.name)).toString('base64') });
        }
      };
      walk(dir);
      const r = await fetch(origin.replace(/\/$/, '') + '/_upload', {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-static-token': originToken },
        body: JSON.stringify({ site: site.name, files: payload }),
      }).catch(() => null);
      if (r?.ok) { sites++; files += payload.length; }
    }
    audit(key.id, 'sites.republish', `${sites} sites`, 'ok', { files });
    return json(res, 200, { sites, files });
  }

  const banRoute = path.match(/^\/sites\/([a-z0-9-]+)\/ban$/);
  if (method === 'POST' && banRoute) {
    if (!isAdmin) return fail(res, 401, 'admin_required', 'banning needs the operator key');
    const body = await read(req);
    const name = banRoute[1];
    if (!body.reason) return fail(res, 400, 'bad_request', 'a ban needs a reason', 'host-now ban <site> --reason "...');
    const site = store.sites.find((s) => s.name === name);
    if (site) { site.state = 'banned'; persist(); }
    audit('admin', 'site.ban', name, 'ok', { reason: String(body.reason).slice(0, 200) });
    return json(res, 200, { site: name, state: 'banned', reason: body.reason });
  }

  if (method === 'GET' && path === '/sites') {
    if (!can(key, 'sites:read')) return fail(res, 403, 'scope', 'this key cannot read sites');
    const own = key.tenant === '*' ? store.sites : store.sites.filter((s) => s.tenant === key.tenant);
    return json(res, 200, own);
  }

  const one = path.match(/^\/sites\/([a-z0-9-]+)$/);
  if (method === 'GET' && one) {
    if (!can(key, 'sites:read')) return fail(res, 403, 'scope', 'this key cannot read sites');
    const site = store.sites.find((s) => s.name === one[1] && (can(key, 'keys:admin') || s.tenant === key.tenant));
    if (!site) return fail(res, 404, 'no_site', 'unknown site', 'host-now status');
    return json(res, 200, site);
  }

  const files = path.match(/^\/sites\/([a-z0-9-]+)\/files$/);
  if (method === 'POST' && files) {
    if (!can(key, 'sites:write') && !key.scopes.includes('static:write'))
      return fail(res, 403, 'scope', 'this key cannot publish files');
    const fixed = process.env.HOSTERD_FIXED_SITE;
    const target = fixed ?? files[1];
    let site = fixed && target === fixed
      ? store.sites.find((s) => s.name === fixed)
      : store.sites.find((s) => s.name === target && (key.tenant === '*' || s.tenant === key.tenant));
    if (!site && fixed && target === fixed) {
      site = { name: fixed, tenant: 'shared', kind: 'static', repo: null, branch: 'main', port: null, db: false,
               url: `https://${fixed}.host.abslm.nl`, state: 'live', createdAt: now() };
      store.sites.push(site);
    }
    if (!site) return fail(res, 404, 'no_site', 'unknown site', 'create it first with POST /sites');
    if (site.kind !== 'static') return fail(res, 400, 'not_static', 'this site is not a static site');
    const body = await read(req);
    if (!Array.isArray(body.files) || !body.files.length) return fail(res, 400, 'bad_request', 'send {files:[{path,data}]}');
    const result = storeFiles(site.name, body.files);
    if (result.error) { audit(key.id, 'files.reject', site.name, 'rejected', { reason: result.error }); return fail(res, 400, 'rejected', result.error); }
    // push to the public origin when one is configured; say so honestly when it is not
    const origin = process.env.HOSTERD_STATIC_ORIGIN;
    const originToken = process.env.HOSTERD_STATIC_TOKEN;
    let publicServing = false;
    let publicError = null;
    if (origin && originToken) {
      try {
        const r = await fetch(origin.replace(/\/$/, '') + '/_upload', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-static-token': originToken },
          body: JSON.stringify({ site: site.name, files: body.files }),
        });
        publicServing = r.ok;
        if (!r.ok) publicError = `origin said ${r.status}`;
      } catch (err) { publicError = String(err.message ?? err); }
      audit(key.id, 'files.publish', site.name, publicServing ? 'ok' : 'failed', { publicError });
    }
    let domain = { ok: false, reason: 'skipped' };
    if (publicServing && !process.env.HOSTERD_FIXED_SITE) {
      domain = await ensureDomain(site.name);
      audit(key.id, 'domain.ensure', site.name, domain.ok ? 'ok' : 'failed', domain);
    }
    site.publicServing = publicServing;
    site.domain = domain;
    site.bytes = result.total;
    site.publishedAt = now();
    site.state = 'live';
    persist();
    audit(key.id, 'files.store', site.name, 'ok', { files: result.written.length, bytes: result.total });
    return json(res, 200, { site, files: result.written.length, bytes: result.total, url: site.url, publicServing, publicError, domain, preview: `/s/${site.name}/` });
  }

  const stop = path.match(/^\/sites\/([a-z0-9-]+)\/stop$/);
  if (method === 'POST' && stop) {
    if (!can(key, 'sites:write')) return fail(res, 403, 'scope', 'this key cannot stop sites');
    const site = store.sites.find((s) => s.name === stop[1] && (can(key, 'keys:admin') || s.tenant === key.tenant));
    if (!site) return fail(res, 404, 'no_site', 'unknown site');
    site.state = 'stopped';
    persist();
    audit(key.id, 'site.stop', site.name, 'ok');
    return json(res, 200, site);
  }

  // delete is a separate scope, deliberately not implied by write
  if (method === 'DELETE' && one) {
    if (!can(key, 'sites:delete') && !can(key, 'keys:admin')) return fail(res, 403, 'scope', 'deleting a site needs sites:delete', 'host-now key create --allow delete');
    const i = store.sites.findIndex((s) => s.name === one[1] && (can(key, 'keys:admin') || s.tenant === key.tenant));
    if (i < 0) return fail(res, 404, 'no_site', 'unknown site');
    const [gone] = store.sites.splice(i, 1);
    persist();
    audit(key.id, 'site.delete', gone.name, 'ok');
    return json(res, 200, gone);
  }

  if (method === 'GET' && path === '/log') {
    if (!can(key, 'log:read') && !can(key, 'keys:admin')) return fail(res, 403, 'scope', 'this key cannot read the log');
    const limit = Math.min(Number(url.searchParams.get('limit') ?? 50), 500);
    const rows = key.tenant === '*'
      ? store.audit.slice(-limit)
      : store.audit.filter((r) => store.keys.find((k) => k.id === r.actor)?.tenant === key.tenant).slice(-limit);
    return json(res, 200, rows);
  }

  return fail(res, 404, 'no_route', `${method} ${path}`, 'see docs/host-now-cli-spec.md');
});

server.on('request', (req, res) => { /* handler errors are caught below */ });
process.on('uncaughtException', (err) => { console.error('uncaught:', err.message); });
process.on('unhandledRejection', (err) => { console.error('unhandled:', err?.message ?? err); });

server.listen(PORT, '0.0.0.0', () => {
  console.log(`hosterd on http://127.0.0.1:${PORT}  live=${LIVE}  store=${DB}`);
  if (!ADMIN) console.log('  no HOSTERD_ADMIN_KEY set: key minting disabled');
});
