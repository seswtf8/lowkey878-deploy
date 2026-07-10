export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path.startsWith('/api/')) return handleAPI(request, env, ctx);
    if (path.startsWith('/sub/')) return handleSub(request, env, path.split('/')[2]);
    if (path === '/' || path === '/panel') return getPanelHTML(env);
    if (request.headers.get('Upgrade') !== 'websocket') return new Response('<!DOCTYPE html><html><head><title>404</title></head><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;color:#333;background:#fff"><h1>404 Not Found</h1></body></html>', { headers: { 'Content-Type': 'text/html' } });
    const segments = path.split('/').filter(Boolean);
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (segments.length > 0 && uuidRegex.test(segments[0])) return handleVLESS(request, env, segments[0], ctx);
    const customPathUser = await env.DB.prepare('SELECT uuid FROM users WHERE custom_path = ? AND enabled = 1').bind(segments[0]).first();
    if (customPathUser) return handleVLESS(request, env, customPathUser.uuid, ctx);
    return new Response('404', { status: 404 });
  },
  async scheduled(event, env, ctx) {
    const { keys } = await env.KV.list({ prefix: 'conn_' });
    const now = Math.floor(Date.now() / 1000);
    for (const key of keys) { if (parseInt(await env.KV.get(key) || '0') > 0) { await env.KV.put(key, '0'); } }
    await env.DB.prepare('UPDATE users SET enabled = 0 WHERE enabled = 1 AND expiry_time > 0 AND expiry_time < ?').bind(now).run();
  }
};

async function handleSub(request, env, token) {
  if (!token) return new Response('Forbidden', { status: 403 });
  const user = await env.DB.prepare('SELECT * FROM users WHERE sub_token = ? AND enabled = 1').bind(token).first();
  if (!user || (user.expiry_time > 0 && user.expiry_time < Math.floor(Date.now() / 1000)) || (user.data_limit > 0 && user.data_used >= user.data_limit)) return new Response('Expired', { status: 403 });
  const s = await getSettings(env); const a = user.target_ip || request.headers.get('Host'); const ua = (request.headers.get('User-Agent') || '').toLowerCase(); const p = user.custom_path || user.uuid; const n = `${s.remark}-${user.name}`;
  if (ua.includes('clash')) { const c = { proxies: [{ name: n, type: "vless", server: a, port: user.port || 443, uuid: user.uuid, network: "ws", tls: true, udp: true, "client-fingerprint": s.fp, servername: s.sni, "ws-opts": { path: `/${p}`, headers: { Host: s.sni } } }] }; return new Response(JSON.stringify(c, null, 2), { headers: { 'Content-Type': 'text/yaml' } }); }
  if (ua.includes('sing-box')) { const c = { outbounds: [{ type: "vless", tag: n, server: a, server_port: user.port || 443, uuid: user.uuid, tls: { enabled: true, server_name: s.sni, utls: { enabled: true, fingerprint: s.fp } }, transport: { type: "ws", path: `/${p}`, headers: { Host: s.sni } } }] }; return new Response(JSON.stringify(c, null, 2), { headers: { 'Content-Type': 'application/json' } }); }
  return new Response(btoa(`vless://${user.uuid}@${a}:${user.port || 443}?type=ws&security=tls&sni=${s.sni}&fp=${s.fp}&path=%2F${p}&host=${s.sni}#${n}`), { headers: { 'Content-Type': 'text/plain' } });
}

async function handleVLESS(request, env, uuid, ctx) {
  const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ? AND enabled = 1').bind(uuid).first();
  const ip = request.headers.get('CF-Connecting-IP') || 'Unknown'; const ua = request.headers.get('User-Agent') || 'Unknown';
  if (!user) return new Response('403', { status: 403 });
  if (user.expiry_time > 0 && user.expiry_time < Math.floor(Date.now() / 1000)) return new Response('Exp', { status: 403 });
  if (user.data_limit > 0 && user.data_used >= user.data_limit) return new Response('Lim', { status: 403 });
  const cur = parseInt(await env.KV.get(`conn_${uuid}`) || '0');
  if (user.conn_limit > 0 && cur >= user.conn_limit) return new Response('429', { status: 429 });
  const [client, server] = Object.values(new WebSocketPair()); server.accept();
  await env.KV.put(`conn_${uuid}`, (cur + 1).toString());
  ctx.waitUntil(env.DB.prepare('INSERT INTO logs (uuid, ip, action, ua, created_at) VALUES (?, ?, ?, ?, ?)').bind(uuid, ip, 'Connected', ua, Math.floor(Date.now() / 1000)).run());
  ctx.waitUntil(env.DB.prepare('UPDATE users SET last_ip = ?, last_seen = ? WHERE uuid = ?').bind(ip, Math.floor(Date.now() / 1000), uuid).run());
  let remote; const s = await getSettings(env); const mul = parseFloat(s.dl_multiplier || '1');
  server.addEventListener('message', async e => { try { const p = new VLESSParser(e.data); await p.parse(); remote = connect({ hostname: p.address, port: p.port }); const w = remote.writable.getWriter(); await w.write(p.payload); w.releaseLock(); remote.readable.pipeTo(new WritableStream({ write(c) { if (server.readyState === 1) server.send(c) } })).catch(() => { }); ctx.waitUntil(env.DB.prepare('UPDATE users SET data_used = data_used + ? WHERE uuid = ?').bind(p.payload.byteLength + Math.floor(p.payload.byteLength * mul), uuid).run()); } catch (e) { server.close() } });
  const clean = async () => { await env.KV.put(`conn_${uuid}`, '0'); ctx.waitUntil(env.DB.prepare('INSERT INTO logs (uuid, ip, action, ua, created_at) VALUES (?, ?, ?, ?, ?)').bind(uuid, ip, 'Disconnected', ua, Math.floor(Date.now() / 1000)).run()); if (remote) remote.close(); };
  server.addEventListener('close', clean); server.addEventListener('error', clean);
  return new Response(null, { status: 101, webSocket: client });
}

class VLESSParser { constructor(b) { this.buffer = b; this.address = ''; this.port = 0; this.payload = null } async parse() { if (this.buffer instanceof ArrayBuffer) { const v = new DataView(this.buffer); let o = 0; o += 1 + v.getUint8(1) + 1 + v.getUint8(o + 2) + 1; const t = v.getUint8(o); o += 1; if (t === 1) { this.address = `${v.getUint8(o)}.${v.getUint8(o + 1)}.${v.getUint8(o + 2)}.${v.getUint8(o + 3)}`; o += 4 } else if (t === 2) { const d = v.getUint8(o); o += 1; this.address = new TextDecoder().decode(this.buffer.slice(o, o + d)); o += d } else if (t === 3) { this.address = Array.from(new Uint8Array(this.buffer, o, 16)).map(b => b.toString(16).padStart(2, '0')).join(':'); o += 16 } this.port = v.getUint16(o); o += 2; this.payload = this.buffer.slice(o) } } }
const CF_IPS = { 'AUTO': { name: 'خودکار', flag: '🌐', ips: [] }, 'DE': { name: 'آلمان', flag: '🇩🇪', ips: ['162.159.192.1'] }, 'NL': { name: 'هلند', flag: '🇳🇱', ips: ['104.18.0.1'] }, 'US': { name: 'آمریکا', flag: '🇺🇸', ips: ['172.64.0.1'] } };
async function getSettings(env) { const s = await env.KV.get('SETTINGS') || '{}'; return { panel_pass: 'admin', sni: env.HOST || 'example.com', fp: 'chrome', remark: 'Lowkey', dl_multiplier: '2', theme_color: '#ffd86f', panel_name: 'LOWKEY', logo_url: '', ...JSON.parse(s) }; }

async function handleAPI(request, env, ctx) {
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  if (request.method === 'OPTIONS') return new Response(null, { headers });
  const path = new URL(request.url).pathname; const body = request.method !== 'GET' ? await request.json() : {};

  if (path === '/api/init') {
    await env.DB.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL, name TEXT, sub_token TEXT UNIQUE, enabled INTEGER DEFAULT 1, data_limit INTEGER DEFAULT 0, data_used INTEGER DEFAULT 0, expiry_time INTEGER DEFAULT 0, country_code TEXT DEFAULT 'AUTO', target_ip TEXT DEFAULT '', port INTEGER DEFAULT 443, conn_limit INTEGER DEFAULT 0, last_ip TEXT DEFAULT '', last_seen INTEGER DEFAULT 0, note TEXT DEFAULT '', custom_path TEXT DEFAULT '', created_at INTEGER DEFAULT (strftime('%s', 'now'))); CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT, ip TEXT, action TEXT, ua TEXT, created_at INTEGER);`);
    if (!(await env.KV.get('SETTINGS'))) await env.KV.put('SETTINGS', JSON.stringify({ panel_pass: 'admin' }));
    return new Response(JSON.stringify({ status: 'ok' }), { headers });
  }
  if (path === '/api/login') { const s = await getSettings(env); return body.password === s.panel_pass ? new Response(JSON.stringify({ success: true }), { headers }) : new Response(JSON.stringify({ success: false }), { status: 401, headers }); }
  if (path === '/api/settings' && request.method === 'GET') return new Response(JSON.stringify(await getSettings(env)), { headers });
  if (path === '/api/settings' && request.method === 'POST') { await env.KV.put('SETTINGS', JSON.stringify(body)); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/ips') return new Response(JSON.stringify(CF_IPS), { headers });

  if (path === '/api/stats') {
    const t = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    const a = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE enabled = 1').first();
    const tr = await env.DB.prepare('SELECT SUM(data_used) as c FROM users').first();
    const exp = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE enabled = 0 AND expiry_time > 0 AND expiry_time < ?').bind(Math.floor(Date.now() / 1000)).first();
    const lim = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE enabled = 1 AND data_limit > 0 AND data_used >= data_limit').first();
    // محاسبه آنلاین از لاگ‌های 3 دقیقه اخیر
    const onl = await env.DB.prepare("SELECT COUNT(DISTINCT uuid) as c FROM logs WHERE action = 'Connected' AND created_at > ?").bind(Math.floor(Date.now() / 1000) - 180).first();
    return new Response(JSON.stringify({ total: t.c, active: a.c, traffic: tr.c || 0, expired: exp.c, limited: lim.c, online: onl.c }), { headers });
  }

  if (path === '/api/users' && request.method === 'GET') {
    let q = 'SELECT * FROM users';
    if (body.filter === 'active') q += ' WHERE enabled = 1 AND (expiry_time = 0 OR expiry_time > ?) AND (data_limit = 0 OR data_used < data_limit)'.replace('?', Math.floor(Date.now() / 1000));
    else if (body.filter === 'expired') q += ' WHERE enabled = 0 AND expiry_time > 0 AND expiry_time < ?'.replace('?', Math.floor(Date.now() / 1000));
    else if (body.filter === 'limited') q += ' WHERE enabled = 1 AND data_limit > 0 AND data_used >= data_limit';
    else if (body.filter === 'online') q += ` WHERE uuid IN (SELECT DISTINCT uuid FROM logs WHERE action='Connected' AND created_at > ${Math.floor(Date.now() / 1000) - 180})`;
    if (body.search) q += (body.filter ? ' AND' : ' WHERE') + ` name LIKE '%${body.search}%'`;
    q += ' ORDER BY id DESC';
    const results = (await env.DB.prepare(q).all()).results;
    const users = await Promise.all(results.map(async u => { u.current_conns = parseInt(await env.KV.get(`conn_${u.uuid}`) || '0'); return u; }));
    return new Response(JSON.stringify(users), { headers });
  }

  if (path === '/api/user/add' && request.method === 'POST') { const uuid = crypto.randomUUID(); const sub = crypto.randomUUID().replace(/-/g, ''); const exp = body.expiry_days > 0 ? Math.floor(Date.now() / 1000) + (body.expiry_days * 86400) : 0; await env.DB.prepare('INSERT INTO users (uuid,name,sub_token,data_limit,expiry_time,country_code,target_ip,port,conn_limit,note,custom_path) VALUES (?,?,?,?,?,?,?,?,?,?,?)').bind(uuid, body.name, sub, body.data_limit * 1073741824, exp, body.country_code, body.target_ip, body.port || 443, body.conn_limit, body.note || '', body.custom_path || '').run(); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/user/edit' && request.method === 'POST') { const exp = body.expiry_days > 0 ? Math.floor(Date.now() / 1000) + (body.expiry_days * 86400) : 0; await env.DB.prepare('UPDATE users SET name=?,data_limit=?,expiry_time=?,country_code=?,target_ip=?,port=?,conn_limit=?,note=?,custom_path=? WHERE id=?').bind(body.name, body.data_limit * 1073741824, exp, body.country_code, body.target_ip, body.port || 443, body.conn_limit, body.note, body.custom_path, body.id).run(); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/users/bulk' && request.method === 'POST') { for (const id of body.ids) { if (body.action === 'delete') await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run(); else if (body.action === 'extend') await env.DB.prepare('UPDATE users SET expiry_time = expiry_time + ? WHERE id=?').bind(body.days * 86400, id).run(); } return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/user/force-disconnect' && request.method === 'POST') { await env.KV.put(`conn_${body.uuid}`, '0'); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path.startsWith('/api/user/reset/')) { await env.DB.prepare('UPDATE users SET data_used = 0 WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path.startsWith('/api/user/toggle/')) { await env.DB.prepare('UPDATE users SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path.startsWith('/api/user/delete/')) { await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/logs') { const search = new URL(request.url).searchParams.get('q') || ''; const time = new URL(request.url).searchParams.get('t') || 'all'; let q = 'SELECT * FROM logs'; let w = []; if (search) w.push(`(uuid LIKE '%${search}%' OR ip LIKE '%${search}%')`); if (time !== 'all') { const ts = Math.floor(Date.now() / 1000) - parseInt(time); w.push(`created_at > ${ts}`); } if (w.length) q += ' WHERE ' + w.join(' AND '); q += ' ORDER BY id DESC LIMIT 100'; return new Response(JSON.stringify((await env.DB.prepare(q).all()).results), { headers }); }
  return new Response('Not Found', { status: 404 });
}

// ==================== فرانت‌اند ایترا (Ultra UI) ====================
function getPanelHTML(env) {
  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Panel</title>
  <style>
    :root { --primary: #ffd86f; --primary-dark: #c89c2b; --bg-main: #050505; --bg-card: rgba(15,15,15,0.95); --text-main: #f9f6ee; --text-muted: #aaa39a; --danger: #ff4f4f; --success: #24ff8d; --accent: #40c9ff; }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
    body { background: var(--bg-main); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
    
    /* Splash Screen */
    #splash { position: fixed; inset: 0; background: var(--bg-main); z-index: 9999; display: flex; flex-direction: column; align-items: center; justify-content: center; transition: opacity 0.5s; }
    #splash.hide { opacity: 0; pointer-events: none; }
    .loader { width: 40px; height: 40px; border: 4px solid rgba(255,255,255,0.1); border-top-color: var(--primary); border-radius: 50%; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Layout */
    #login-screen { position: fixed; inset: 0; background: var(--bg-main); z-index: 100; display: none; align-items: center; justify-content: center; }
    #app-container { display: none; width: 100%; height: 100%; }
    
    /* Sidebar */
    .sidebar { width: 260px; height: 100%; background: rgba(10,10,10,0.95); border-left: 1px solid rgba(255,255,255,0.05); backdrop-filter: blur(20px); display: flex; flex-direction: column; position: fixed; right: 0; top: 0; z-index: 50; transition: transform 0.3s; }
    .sidebar-header { padding: 24px; border-bottom: 1px solid rgba(255,255,255,0.05); text-align: center; }
    .sidebar-logo { width: 50px; height: 50px; border-radius: 50%; margin: 0 auto 10px; background: var(--primary); display: flex; align-items: center; justify-content: center; font-weight: 900; color: #000; font-size: 24px; box-shadow: 0 0 20px var(--primary); }
    .sidebar-menu { flex: 1; padding: 20px 0; overflow-y: auto; }
    .menu-item { padding: 12px 24px; display: flex; align-items: center; gap: 12px; cursor: pointer; color: var(--text-muted); transition: 0.2s; border-right: 3px solid transparent; }
    .menu-item:hover, .menu-item.active { background: rgba(255,255,255,0.03); color: var(--primary); border-right-color: var(--primary); }
    
    /* Main Content */
    .main-content { flex: 1; margin-right: 260px; height: 100vh; overflow-y: auto; padding: 30px; background: radial-gradient(circle at 10% 0%, #1a1408 0, transparent 40%), var(--bg-main); }
    .page { display: none; animation: fadeIn 0.3s ease; }
    .page.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* Cards & Grids */
    .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .stat-card { background: var(--bg-card); border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 20px; position: relative; overflow: hidden; }
    .stat-card::before { content: ''; position: absolute; top: 0; right: 0; width: 60px; height: 60px; background: var(--primary); filter: blur(40px); opacity: 0.2; }
    .stat-card h3 { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .stat-card .value { font-size: 28px; font-weight: 700; color: var(--primary); }
    
    /* CSS Chart */
    .chart-container { display: flex; align-items: flex-end; gap: 8px; height: 100px; margin-top: 15px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); }
    .bar { flex: 1; background: linear-gradient(to top, var(--primary), transparent); border-radius: 4px 4px 0 0; min-height: 5px; opacity: 0.7; transition: 0.3s; }
    .bar:hover { opacity: 1; }

    /* User Cards Grid */
    .users-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }
    .user-card { background: var(--bg-card); border: 1px solid rgba(255,255,255,0.05); border-radius: 16px; padding: 20px; position: relative; transition: 0.3s; cursor: pointer; }
    .user-card:hover { border-color: var(--primary); transform: translateY(-5px); box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    .user-card.selected { border-color: var(--accent); background: rgba(64,201,255,0.05); }
    .user-header { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
    .avatar { width: 45px; height: 45px; border-radius: 50%; border: 2px solid var(--primary); }
    .user-info h4 { font-size: 15px; margin-bottom: 2px; }
    .user-meta { display: flex; flex-wrap: wrap; gap: 8px; font-size: 11px; color: var(--text-muted); margin-bottom: 15px; }
    .badge-sm { padding: 2px 8px; border-radius: 20px; background: rgba(255,255,255,0.05); }
    .badge-sm.online { background: rgba(36,255,141,0.1); color: var(--success); }
    .badge-sm.offline { background: rgba(255,255,255,0.05); color: var(--text-muted); }
    .progress-bg { height: 4px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin: 10px 0; }
    .progress-fg { height: 100%; background: var(--primary); border-radius: 4px; }
    .user-actions { display: flex; gap: 8px; margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 10px; }
    .btn-tiny { flex: 1; padding: 6px; background: rgba(255,255,255,0.05); border: none; color: var(--text-muted); border-radius: 8px; cursor: pointer; font-size: 11px; transition: 0.2s; }
    .btn-tiny:hover { background: var(--primary); color: #000; }

    /* Toolbar */
    .toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 20px; background: var(--bg-card); padding: 15px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); }
    .search-box { flex: 1; min-width: 200px; padding: 10px 15px; background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; color: #fff; outline: none; }
    .filter-chip { padding: 6px 12px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); background: transparent; color: var(--text-muted); cursor: pointer; font-size: 12px; }
    .filter-chip.active { border-color: var(--primary); color: var(--primary); background: rgba(255,216,111,0.1); }
    .btn-primary { padding: 8px 20px; background: var(--primary); color: #000; border: none; border-radius: 10px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; }
    .btn-danger { padding: 8px 20px; background: var(--danger); color: #fff; border: none; border-radius: 10px; cursor: pointer; font-size: 12px; }

    /* Modals */
    .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 200; display: none; align-items: center; justify-content: center; padding: 20px; backdrop-filter: blur(5px); }
    .modal-bg.show { display: flex; }
    .modal-box { background: #0a0a0a; border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; width: 100%; max-width: 600px; max-height: 85vh; overflow-y: auto; padding: 30px; position: relative; }
    .close-btn { position: absolute; top: 15px; left: 15px; background: none; border: none; color: var(--text-muted); font-size: 24px; cursor: pointer; }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-top: 20px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    .form-group.full { grid-column: 1 / -1; }
    label { font-size: 12px; color: var(--text-muted); }
    input, select, textarea { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 10px; color: #fff; outline: none; font-family: inherit; }
    input:focus, select:focus { border-color: var(--primary); }
    
    /* Logs */
    .log-row { display: grid; grid-template-columns: 100px 1fr 1.5fr 100px; gap: 10px; padding: 10px; font-size: 12px; border-bottom: 1px solid rgba(255,255,255,0.03); }
    .log-time { color: var(--text-muted); font-family: monospace; }
    .log-uuid { color: var(--accent); font-family: monospace; font-size: 11px; }
    .log-details span { display: block; }
    .log-ua { font-size: 10px; color: var(--text-muted); }
    .log-action { font-weight: 600; }
    .log-action.ok { color: var(--success); }
    .log-action.err { color: var(--danger); }

    /* Settings */
    .color-picker-wrapper { display: flex; align-items: center; gap: 10px; }
    .color-picker { width: 40px; height: 40px; border: none; border-radius: 10px; cursor: pointer; background: none; }
    
    /* Mobile */
    @media (max-width: 768px) {
      .sidebar { transform: translateX(100%); }
      .sidebar.open { transform: translateX(0); }
      .main-content { margin-right: 0; }
      .form-grid { grid-template-columns: 1fr; }
    }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div id="splash"><div class="loader"></div><p style="margin-top:15px;color:var(--text-muted)">Loading System...</p></div>

  <div id="login-screen">
    <div class="modal-box" style="max-width:400px;text-align:center;">
      <h2 style="color:var(--primary);margin-bottom:20px;">Admin Login</h2>
      <input type="password" id="password" placeholder="Password" style="width:100%;text-align:center;font-size:16px;margin-bottom:15px;">
      <button onclick="login()" class="btn-primary" style="width:100%;justify-content:center;">Access Panel</button>
      <button onclick="initDB()" style="width:100%;margin-top:10px;padding:10px;background:none;border:1px solid rgba(255,255,255,0.1);color:var(--text-muted);border-radius:10px;cursor:pointer;">Init DB</button>
    </div>
  </div>

  <div id="app-container">
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <div class="sidebar-logo" id="sidebar-logo-text">L</div>
        <h3 id="sidebar-title" style="color:var(--primary);font-weight:800;">LOWKEY</h3>
        <p style="font-size:11px;color:var(--text-muted)">Management System</p>
      </div>
      <div class="sidebar-menu">
        <div class="menu-item active" onclick="showPage('dashboard', this)">📊 Dashboard</div>
        <div class="menu-item" onclick="showPage('users', this)">👥 Users</div>
        <div class="menu-item" onclick="showPage('logs', this)">📋 Live Logs</div>
        <div class="menu-item" onclick="showPage('settings', this)">⚙️ Settings</div>
      </div>
    </aside>

    <main class="main-content">
      <!-- Dashboard -->
      <div id="page-dashboard" class="page active">
        <h2 style="margin-bottom:20px;">Dashboard Overview</h2>
        <div class="grid-4">
          <div class="stat-card"><h3>Total Users</h3><div class="value" id="s-total">0</div></div>
          <div class="stat-card"><h3>Active Now</h3><div class="value" id="s-online" style="color:var(--success)">0</div></div>
          <div class="stat-card"><h3>Expired</h3><div class="value" id="s-expired" style="color:var(--danger)">0</div></div>
          <div class="stat-card"><h3>Traffic Used</h3><div class="value" id="s-traffic" style="font-size:22px;">0 GB</div>
            <div class="chart-container" id="chart-traffic"></div>
          </div>
        </div>
      </div>

      <!-- Users -->
      <div id="page-users" class="page">
        <div class="toolbar">
          <button class="btn-primary" onclick="openAddModal()">+ New User</button>
          <button class="btn-danger hidden" id="bulk-del-btn" onclick="bulkAction('delete')">Delete Selected</button>
          <button class="btn-tiny hidden" id="bulk-ext-btn" style="padding:8px 15px;border:1px solid var(--primary);color:var(--primary)" onclick="bulkAction('extend', 30)">+30 Days Selected</button>
          <div style="margin-right:auto; display:flex; gap:8px; flex-wrap:wrap;">
            <button class="filter-chip active" onclick="setFilter('all', this)">All</button>
            <button class="filter-chip" onclick="setFilter('active', this)">Active</button>
            <button class="filter-chip" onclick="setFilter('online', this)">Online</button>
            <button class="filter-chip" onclick="setFilter('expired', this)">Expired</button>
            <button class="filter-chip" onclick="setFilter('limited', this)">Limited</button>
          </div>
          <input type="text" class="search-box" placeholder="Search name..." oninput="loadUsers()">
        </div>
        <div class="users-grid" id="users-grid"></div>
      </div>

      <!-- Logs -->
      <div id="page-logs" class="page">
        <div class="toolbar">
          <select id="log-time" onchange="loadLogs()" style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);padding:8px;color:#fff;border-radius:8px;">
            <option value="all">All Time</option><option value="3600">Last Hour</option><option value="86400">Last 24h</option>
          </select>
          <input type="text" class="search-box" placeholder="Search IP/UUID..." id="log-search" oninput="loadLogs()">
        </div>
        <div style="background:var(--bg-card);border-radius:12px;padding:10px;border:1px solid rgba(255,255,255,0.05);">
          <div class="log-row" style="font-weight:bold;color:var(--primary);border-bottom:1px solid rgba(255,255,255,0.1);"><div>Time</div><div>User/UUID</div><div>Details / Client</div><div>Action</div></div>
          <div id="logs-list"></div>
        </div>
      </div>

      <!-- Settings -->
      <div id="page-settings" class="page">
        <div class="modal-box" style="max-width:600px;position:static;">
          <h2 style="margin-bottom:20px;color:var(--primary);">System Customization</h2>
          <div class="form-grid">
            <div class="form-group"><label>Panel Name</label><input type="text" id="set-name" onchange="saveSetting('panel_name', this.value)"></div>
            <div class="form-group"><label>Logo URL (Image)</label><input type="text" id="set-logo" onchange="saveSetting('logo_url', this.value)"></div>
            <div class="form-group"><label>Primary Color</label>
              <div class="color-picker-wrapper">
                <input type="color" class="color-picker" id="set-color" value="#ffd86f" onchange="changeTheme(this.value)">
                <span id="color-code" style="font-family:monospace;font-size:12px;">#ffd86f</span>
              </div>
            </div>
            <div class="form-group"><label>SNI</label><input type="text" id="set-sni" onchange="saveSetting('sni', this.value)"></div>
            <div class="form-group full"><label>Node Remark</label><input type="text" id="set-remark" onchange="saveSetting('remark', this.value)"></div>
          </div>
        </div>
      </div>
    </main>
  </div>

  <!-- Modals -->
  <div class="modal-bg" id="modal-add">
    <div class="modal-box">
      <button class="close-btn" onclick="closeModal('modal-add')">&times;</button>
      <h2 id="add-title" style="color:var(--primary);margin-bottom:20px;">Create User</h2>
      <input type="hidden" id="edit-id">
      <div class="form-grid">
        <div class="form-group"><label>Name</label><input type="text" id="f-name"></div>
        <div class="form-group"><label>Data Limit (GB)</label><input type="number" id="f-limit" value="0"></div>
        <div class="form-group"><label>Expiry (Days)</label><input type="number" id="f-days" value="0"></div>
        <div class="form-group"><label>Max Connections</label><input type="number" id="f-conn" value="0"></div>
        <div class="form-group"><label>Port</label><select id="f-port"><option value="443">443</option><option value="2053">2053</option><option value="2087">2087</option></select></div>
        <div class="form-group"><label>Target IP/Country</label><select id="f-country" onchange="updateIpList()"><option value="AUTO">Auto</option><option value="DE">Germany</option><option value="NL">Netherlands</option></select></div>
        <div class="form-group"><label>Specific IP</label><select id="f-ip"><option value="">Select</option></select></div>
        <div class="form-group"><label>Custom Path</label><input type="text" id="f-path"></div>
        <div class="form-group full"><label>Note</label><input type="text" id="f-note"></div>
      </div>
      <button class="btn-primary" style="width:100%;justify-content:center;margin-top:20px;" onclick="saveUser()">Save User</button>
    </div>
  </div>

  <div class="modal-bg" id="modal-detail">
    <div class="modal-box" style="max-width:700px;">
      <button class="close-btn" onclick="closeModal('modal-detail')">&times;</button>
      <div id="detail-content"></div>
    </div>
  </div>

<script>
let curSet={}, ipDB={}, selectedUsers = new Set(), currentFilter = 'all';

window.onload = () => { setTimeout(()=>{document.getElementById('splash').classList.add('hide'); document.getElementById('login-screen').style.display='flex';}, 1500); };

async function initDB() { await fetch('/api/init'); alert('DB Initialized! Pass: admin'); }
async function login() {
  const p = document.getElementById('password').value;
  const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:p})});
  if((await r.json()).success) { document.getElementById('login-screen').style.display='none'; document.getElementById('app-container').style.display='flex'; loadApp(); } else alert('Wrong Pass');
}

async function loadApp() {
  curSet = await (await fetch('/api/settings')).json();
  ipDB = await (await fetch('/api/ips')).json();
  applyTheme(curSet.theme_color || '#ffd86f');
  document.getElementById('set-name').value = curSet.panel_name || 'LOWKEY';
  document.getElementById('set-logo').value = curSet.logo_url || '';
  document.getElementById('set-sni').value = curSet.sni || '';
  document.getElementById('set-remark').value = curSet.remark || '';
  loadDashboard(); loadUsers(); loadLogs(); setInterval(()=>{ loadDashboard(); if(document.querySelector('.menu-item.active').innerText.includes('Log')) loadLogs(); }, 5000);
}

function applyTheme(color) {
  document.documentElement.style.setProperty('--primary', color);
  document.documentElement.style.setProperty('--primary-dark', color);
  document.getElementById('set-color').value = color;
  document.getElementById('color-code').innerText = color;
}
async function saveSetting(key, val) { curSet[key] = val; await fetch('/api/settings', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(curSet)}); if(key==='panel_name') document.getElementById('sidebar-title').innerText = val; if(key==='theme_color') applyTheme(val); if(key==='logo_url') { const l = document.getElementById('sidebar-logo-text'); if(val) { l.innerText=''; l.style.backgroundImage=`url(${ val })`; l.style.backgroundSize='cover'; } else { l.innerText='L'; l.style.backgroundImage='none'; } } }
function showPage(id, el) { document.querySelectorAll('.page').forEach(p=>p.classList.remove('active')); document.querySelectorAll('.menu-item').forEach(m=>m.classList.remove('active')); document.getElementById('page-'+id).classList.add('active'); if(el) el.classList.add('active'); if(id==='users') loadUsers(); if(id==='logs') loadLogs(); }
function openModal(id) { document.getElementById(id).classList.add('show'); }
function closeModal(id) { document.getElementById(id).classList.remove('show'); }

async function loadDashboard() {
  const s = await (await fetch('/api/stats')).json();
  document.getElementById('s-total').innerText = s.total;
  document.getElementById('s-online').innerText = s.online;
  document.getElementById('s-expired').innerText = s.expired;
  document.getElementById('s-traffic').innerText = (s.traffic/1073741824).toFixed(1) + ' GB';
  
  // Fake CSS Chart Data based on traffic
  const chart = document.getElementById('chart-traffic');
  chart.innerHTML = '';
  for(let i=0; i<7; i++) { const bar = document.createElement('div'); bar.className='bar'; bar.style.height = Math.random() * 80 + 10 + 'px'; chart.appendChild(bar); }
}

async function loadUsers() {
  const search = document.querySelector('.search-box').value;
  const users = await (await fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({filter: currentFilter, search})})).json();
  const grid = document.getElementById('users-grid');
  grid.innerHTML = '';
  
  users.forEach(u => {
    const usedGB = (u.data_used/1073741824).toFixed(2);
    const limitGB = u.data_limit > 0 ? (u.data_limit/1073741824).toFixed(1) : '∞';
    const percent = u.data_limit > 0 ? Math.min((u.data_used / u.data_limit) * 100, 100) : 0;
    const isOn = u.current_conns > 0;
    const isExp = u.expiry_time > 0 && u.expiry_time < Math.floor(Date.now()/1000);
    const isLim = u.data_limit > 0 && u.data_used >= u.data_limit;
    
    const card = document.createElement('div');
    card.className = `user - card ${ selectedUsers.has(u.id) ? 'selected' : '' }`;
    card.innerHTML = `
  < div style = "position:absolute;top:15px;left:15px;" >
        <input type="checkbox" ${selectedUsers.has(u.id)?'checked':''} onclick="event.stopPropagation(); toggleSelect(${u.id})" style="cursor:pointer;">
      </>
      <div class="user-header" onclick="openDetail(${u.id})">
        <img src="https://ui-avatars.com/api/?name=${u.name}&background=${encodeURIComponent(curSet.theme_color)}&color=000&size=45" class="avatar">
        <div class="user-info">
          <h4>${u.name} ${u.port && u.port!==443 ? `<span style="font-size:10px;color:var(--accent);margin-right:5px;">[${u.port}]</span>` : ''}</h4>
          <div class="user-meta">
            <span class="badge-sm ${isOn ? 'online' : 'offline'}">${isOn ? '● Online' : 'Offline'}</span>
            ${isExp ? '<span class="badge-sm" style="color:var(--danger)">Expired</span>' : ''}
            ${isLim ? '<span class="badge-sm" style="color:var(--danger)">Limited</span>' : ''}
          </div>
        </div>
      </div>
      <div style="font-size:12px;display:flex;justify-content:space-between;color:var(--text-muted);margin-bottom:5px;">
        <span>${usedGB} GB Used</span><span>${limitGB} Limit</span>
      </div>
      <div class="progress-bg"><div class="progress-fg" style="width:${percent}%;${percent>90?'background:var(--danger)':''}"></div></div>
      ${ u.last_ip ? `<div style="font-size:10px;color:var(--text-muted);text-align:left;direction:ltr;">IP: ${u.last_ip}</div>` : '' }

  < div class= "user-actions" >
        <button class="btn-tiny" onclick="event.stopPropagation(); copySub('${u.sub_token}')">Copy Sub</button>
        <button class="btn-tiny" onclick="event.stopPropagation(); toggleUser(${u.id})" style="color:${u.enabled?'var(--success)':'var(--danger)'}">${u.enabled?'Disable':'Enable'}</button>
        <button class="btn-tiny" onclick="event.stopPropagation(); deleteUser(${u.id})" style="color:var(--danger)">Del</button>
      </ >
    `;
    grid.appendChild(card);
  });
  
  document.getElementById('bulk-del-btn').classList.toggle('hidden', selectedUsers.size === 0);
  document.getElementById('bulk-ext-btn').classList.toggle('hidden', selectedUsers.size === 0);
}

function setFilter(f, el) { currentFilter = f; document.querySelectorAll('.filter-chip').forEach(c=>c.classList.remove('active')); el.classList.add('active'); loadUsers(); }
function toggleSelect(id) { if(selectedUsers.has(id)) selectedUsers.delete(id); else selectedUsers.add(id); loadUsers(); }
async function bulkAction(action, days) { if(!confirm(`Apply ${ action } to ${ selectedUsers.size } users ? `)) return; await fetch('/api/users/bulk', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ids: Array.from(selectedUsers), action, days})}); selectedUsers.clear(); loadUsers(); }

function openAddModal() { document.getElementById('add-title').innerText='Create User'; document.getElementById('edit-id').value=''; document.querySelectorAll('#modal-add input:not([type=hidden]), #modal-add select').forEach(e=>{if(e.type==='number')e.value='0';else e.value=''}); openModal('modal-add'); }
function updateIpList() { const c=document.getElementById('f-country').value, s=document.getElementById('f-ip'); s.innerHTML='<option value="">Domain</option>'; (ipDB[c]?.ips||[]).forEach(i=>s.innerHTML+=`< option value = "${i}" > ${ i }</ > `); }

async function saveUser() {
  const id = document.getElementById('edit-id').value;
  const data = { name: document.getElementById('f-name').value, data_limit: document.getElementById('f-limit').value, expiry_days: document.getElementById('f-days').value, conn_limit: document.getElementById('f-conn').value, port: document.getElementById('f-port').value, country_code: document.getElementById('f-country').value, target_ip: document.getElementById('f-ip').value, custom_path: document.getElementById('f-path').value, note: document.getElementById('f-note').value };
  if(!data.name) return alert('Name is required');
  await fetch(id ? '/api/user/edit' : '/api/user/add', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...data, id})});
  closeModal('modal-add'); loadUsers();
}

async function openDetail(id) {
  const u = await (await fetch('/api/users', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({})})).json().then(r=>r.find(x=>x.id===id));
  const logs = await (await fetch(`/ api / logs ? q = ${ u.uuid }`)).json();
  
  let logsHtml = logs.map(l=>`< div class= "log-row" ><div class="log-time">${new Date(l.created_at*1000).toLocaleTimeString('fa-IR')}</div><div class="log-uuid">${l.uuid.substring(0,8)}...</div><div class="log-details"><span>${l.ip}</span><span class="log-ua">${(l.ua||'').substring(0,40)}</span></div><div class="log-action ${l.action.includes('Rejected')||l.action==='Disconnected'?'err':'ok'}">${l.action}</div></ > `).join('');
  
  document.getElementById('detail-content').innerHTML = `
  < div style = "display:flex;align-items:center;gap:15px;margin-bottom:25px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:20px;" >
      <img src="https://ui-avatars.com/api/?name=${u.name}&background=${encodeURIComponent(curSet.theme_color)}&color=000&size=60" style="border-radius:50%;border:3px solid var(--primary);">
      <div><h2>${u.name}</h2><p style="color:var(--text-muted);font-size:12px;">UUID: ${u.uuid}</p></div>
    </>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:25px;">
      <div class="stat-card"><h3>Usage</h3><div class="value" style="font-size:18px;">${(u.data_used/1073741824).toFixed(2)} GB</div></div>
      <div class="stat-card"><h3>Status</h3><div class="value" style="font-size:18px;color:${u.enabled?'var(--success)':'var(--danger)'}">${u.enabled?'Active':'Disabled'}</div></div>
    </div>
    <h3 style="margin-bottom:10px;color:var(--primary);">Connection History</h3>
    <div style="background:rgba(0,0,0,0.3);border-radius:10px;overflow:hidden;max-height:200px;overflow-y:auto;">
      ${logsHtml || '<p style="padding:15px;text-align:center;color:var(--text-muted)">No logs found</p>'}
    </div>
    <div style="display:flex;gap:10px;margin-top:20px;">
      <button class="btn-primary" style="flex:1;justify-content:center;" onclick="forceDisconnect('${u.uuid}')">⛔ Force Disconnect</button>
      <button class="btn-tiny" style="flex:1;padding:10px;border:1px solid var(--primary);color:var(--primary);" onclick="resetTraffic(${u.id});closeModal('modal-detail')">Reset Traffic</button>
    </div>
  `;
  openModal('modal-detail');
}

async function forceDisconnect(uuid) { await fetch('/api/user/force-disconnect', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uuid})}); alert('Disconnected!'); }
function copySub(token) { navigator.clipboard.writeText(`https://${location.host}/sub/${token}`); alert('Sub Link Copied!'); }
    async function toggleUser(id) { await fetch(`/api/user/toggle/${id}`, { method: 'POST' }); loadUsers(); }
async function resetTraffic(id) { await fetch(`/api/user/reset/${id}`, { method: 'POST' }); }
async function deleteUser(id) { if (confirm('Delete?')) { await fetch(`/api/user/delete/${id}`, { method: 'DELETE' }); loadUsers(); } }

async function loadLogs() {
      const q = document.getElementById('log-search').value;
      const t = document.getElementById('log-time').value;
      const logs = await (await fetch(`/api/logs?q=${q}&t=${t}`)).json();
      document.getElementById('logs-list').innerHTML = logs.map(l => `
    <div class="log-row">
      <div class="log-time">${new Date(l.created_at * 1000).toLocaleTimeString('fa-IR')}</div>
      <div class="log-uuid">${l.uuid.substring(0, 8)}...</div>
      <div class="log-details"><span>${l.ip}</span><span class="log-ua">${(l.ua || '').substring(0, 40)}</span></div>
      <div class="log-action ${l.action.includes('Rejected') || l.action === 'Disconnected' ? 'err' : 'ok'}">${l.action}</div>
    </div>`).join('');
    }
    <\/script>
</body ></html > `, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}
