export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/status') return new Response(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Status</title><style>body{background:#0f172a;color:#fff;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.box{text-align:center;background:rgba(30,41,59,0.8);padding:40px;border-radius:20px;border:1px solid rgba(34,197,94,0.3)}</style></head><body><div class="box"><h1 style="color:#22c55e;font-size:50px;margin:0">●</h1><h2>Lowkey Edge Network</h2><p style="color:#94a3b8">All Systems Operational</p></div></body></html>`, {headers: {'Content-Type':'text/html'}});
    
    if (path.startsWith('/api/')) return handleAPI(request, env, ctx);
    if (path.startsWith('/sub/')) return handleSub(request, env, path.split('/')[2]);
    if (path === '/' || path === '/panel') return getPanelHTML(env);
    
    if (request.headers.get('Upgrade') !== 'websocket') return new Response('<!DOCTYPE html><html><head><title>404 Not Found</title></head><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;color:#333;background:#fff"><div style="text-align:center"><h1>404</h1><p>Not Found</p></div></body></html>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } });

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const segments = path.split('/').filter(Boolean);
    
    const customPathUser = await env.DB.prepare('SELECT uuid FROM users WHERE custom_path = ? AND enabled = 1').bind(segments[0]).first();
    if (customPathUser) return handleVLESS(request, env, customPathUser.uuid, ctx);
    
    if (segments.length > 0 && uuidRegex.test(segments[0])) return handleVLESS(request, env, segments[0], ctx);

    return new Response('404', { status: 404 });
  },

  async scheduled(event, env, ctx) {
    const { keys } = await env.KV.list({ prefix: 'conn_' });
    const now = Math.floor(Date.now() / 1000);
    for (const key of keys) {
      const lastActive = parseInt(await env.KV.get(`${key}_time`) || '0');
      if (now - lastActive > 300) { await env.KV.delete(key); await env.KV.delete(`${key}_time`); }
    }
    await env.DB.prepare('UPDATE users SET enabled = 0 WHERE enabled = 1 AND expiry_time > 0 AND expiry_time < ?').bind(now).run();
  }
};

async function sendTg(env, msg) {
  const s = await getSettings(env);
  if (s.tg_token && s.tg_chat_id) {
    await fetch(`https://api.telegram.org/bot${s.tg_token}/sendMessage`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({chat_id: s.tg_chat_id, text: msg, parse_mode: 'HTML'}) }).catch(()=>{});
  }
}

async function handleSub(request, env, token) {
  if (!token) return new Response('Forbidden', { status: 403 });
  const user = await env.DB.prepare('SELECT * FROM users WHERE sub_token = ? AND enabled = 1').bind(token).first();
  if (!user || (user.expiry_time > 0 && user.expiry_time < Math.floor(Date.now() / 1000)) || (user.data_limit > 0 && user.data_used >= user.data_limit)) return new Response('Expired', { status: 403 });

  const settings = await getSettings(env);
  const address = user.target_ip || request.headers.get('Host');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const wsPath = user.custom_path || user.uuid;
  const nodeName = `${settings.remark}-${user.name}`;
  const fragEnabled = settings.fragment_enabled === 'true';
  const fragSize = settings.fragment_size || '10-20';
  const fragInterval = settings.fragment_interval || '10-20';

  if (ua.includes('clash')) {
    const proxy = { name: nodeName, type: "vless", server: address, port: user.port || 443, uuid: user.uuid, network: "ws", tls: true, udp: true, "client-fingerprint": settings.fp, servername: settings.sni, "ws-opts": { path: `/${wsPath}`, headers: { Host: settings.sni } } };
    if(fragEnabled) proxy.fragment = { enabled: true, size: fragSize, interval: fragInterval };
    return new Response(JSON.stringify({proxies: [proxy]}, null, 2), {headers:{'Content-Type':'text/yaml'}});
  }
  if (ua.includes('sing-box') || ua.includes('sfi')) {
    const outbound = { type: "vless", tag: nodeName, server: address, server_port: user.port || 443, uuid: user.uuid, tls: { enabled: true, server_name: settings.sni, utls: { enabled: true, fingerprint: settings.fp } }, transport: { type: "ws", path: `/${wsPath}`, headers: { Host: settings.sni } } };
    if(fragEnabled) outbound.fragment = { enabled: true, packets: fragSize, interval: fragInterval + "ms" };
    return new Response(JSON.stringify({outbounds: [outbound]}, null, 2), {headers:{'Content-Type':'application/json'}});
  }
  
  let rawLink = `vless://${user.uuid}@${address}:${user.port || 443}?type=ws&security=tls&sni=${settings.sni}&fp=${settings.fp}&path=%2F${wsPath}&host=${settings.sni}#${nodeName}`;
  if(fragEnabled) rawLink += `&fragment=${fragSize},${fragInterval},true`;
  return new Response(btoa(rawLink), {headers:{'Content-Type':'text/plain'}});
}

async function handleVLESS(request, env, clientUUID, ctx) {
  const user = await env.DB.prepare('SELECT * FROM users WHERE uuid = ? AND enabled = 1').bind(clientUUID).first();
  const realIP = request.headers.get('CF-Connecting-IP') || 'Unknown';
  const ua = request.headers.get('User-Agent') || 'Unknown';
  
  if (!user) { ctx.waitUntil(logAction(env, clientUUID, realIP, 'Rejected: Not Found', ua)); return new Response('Not Found', { status: 403 }); }
  if (user.expiry_time > 0 && user.expiry_time < Math.floor(Date.now() / 1000)) { ctx.waitUntil(logAction(env, clientUUID, realIP, 'Rejected: Expired', ua)); return new Response('Expired', { status: 403 }); }
  if (user.data_limit > 0 && user.data_used >= user.data_limit) { ctx.waitUntil(logAction(env, clientUUID, realIP, 'Rejected: Limit', ua)); return new Response('Limit', { status: 403 }); }

  const currentConns = parseInt(await env.KV.get(`conn_${clientUUID}`) || '0');
  if (user.conn_limit > 0 && currentConns >= user.conn_limit) { ctx.waitUntil(logAction(env, clientUUID, realIP, 'Rejected: Max Conn', ua)); return new Response('Too Many Connections', { status: 429 }); }

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  
  await env.KV.put(`conn_${clientUUID}`, (currentConns + 1).toString());
  await env.KV.put(`conn_${clientUUID}_time`, Math.floor(Date.now()/1000).toString());
  
  ctx.waitUntil(logAction(env, clientUUID, realIP, 'Connected', ua));
  ctx.waitUntil(env.DB.prepare('UPDATE users SET last_ip = ?, last_seen = ? WHERE uuid = ?').bind(realIP, Math.floor(Date.now()/1000), clientUUID).run());
  
  let remoteSocketWapper = null;
  const settings = await getSettings(env);
  const dlMultiplier = parseFloat(settings.dl_multiplier || '1');

  server.addEventListener('message', async (event) => {
    try {
      await env.KV.put(`conn_${clientUUID}_time`, Math.floor(Date.now()/1000).toString());
      const parser = new VLESSParser(event.data);
      await parser.parse();
      const tcpSocket = connect({ hostname: parser.address, port: parser.port });
      remoteSocketWapper = tcpSocket;
      const writer = tcpSocket.writable.getWriter();
      await writer.write(parser.payload);
      writer.releaseLock();
      
      const calculatedUsage = parser.payload.byteLength + Math.floor(parser.payload.byteLength * dlMultiplier);
      tcpSocket.readable.pipeTo(new WritableStream({ write(chunk) { if (server.readyState === WebSocket.OPEN) server.send(chunk); } })).catch(() => {});
      ctx.waitUntil(env.DB.prepare('UPDATE users SET data_used = data_used + ? WHERE uuid = ?').bind(calculatedUsage, clientUUID).run());
    } catch (e) { server.close(); }
  });

  const cleanup = async () => {
    let c = parseInt(await env.KV.get(`conn_${clientUUID}`) || '0'); if(c > 0) await env.KV.put(`conn_${clientUUID}`, (c - 1).toString());
    ctx.waitUntil(logAction(env, clientUUID, realIP, 'Disconnected', ua));
    if (remoteSocketWapper) remoteSocketWapper.close();
  };
  server.addEventListener('close', cleanup);
  server.addEventListener('error', cleanup);
  return new Response(null, { status: 101, webSocket: client });
}

class VLESSParser { constructor(b){this.buffer=b;this.address='';this.port=0;this.payload=null} async parse(){if(this.buffer instanceof ArrayBuffer){const v=new DataView(this.buffer);let o=0;o+=1+v.getUint8(1)+1+v.getUint8(o+2)+1;const t=v.getUint8(o);o+=1;if(t===1){this.address=`${v.getUint8(o)}.${v.getUint8(o+1)}.${v.getUint8(o+2)}.${v.getUint8(o+3)}`;o+=4}else if(t===2){const d=v.getUint8(o);o+=1;this.address=new TextDecoder().decode(this.buffer.slice(o,o+d));o+=d}else if(t===3){this.address=Array.from(new Uint8Array(this.buffer,o,16)).map(b=>b.toString(16).padStart(2,'0')).join(':');o+=16}this.port=v.getUint16(o);o+=2;this.payload=this.buffer.slice(o)}}}
async function logAction(env, uuid, ip, action, ua) { await env.DB.prepare('INSERT INTO logs (uuid, ip, action, ua, created_at) VALUES (?, ?, ?, ?, ?)').bind(uuid, ip, action, ua, Math.floor(Date.now()/1000)).run(); await env.DB.prepare('DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 100)').run(); }

const CF_IPS = { 'AUTO': { name: 'خودکار', flag: '🌐', ips: [] }, 'DE': { name: 'آلمان', flag: '🇩🇪', ips: ['162.159.192.1', '162.159.193.1'] }, 'NL': { name: 'هلند', flag: '🇳🇱', ips: ['104.18.0.1'] }, 'FI': { name: 'فنلاند', flag: '🇫🇮', ips: ['162.159.36.1'] }, 'US': { name: 'آمریکا', flag: '🇺🇸', ips: ['172.64.0.1'] } };
async function getSettings(env) { const s = await env.KV.get('SETTINGS') || '{}'; return { panel_pass: 'admin', sni: env.HOST || 'example.com', fp: 'chrome', remark: 'Lowkey', dl_multiplier: '2', tg_token: '', tg_chat_id: '', fragment_enabled: 'false', fragment_size: '10-20', fragment_interval: '10-20', ...JSON.parse(s) }; }

async function handleAPI(request, env, ctx) {
  const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
  if (request.method === 'OPTIONS') return new Response(null, { headers });
  const path = new URL(request.url).pathname;
  const body = request.method !== 'GET' ? await request.json() : {};

  if (path === '/api/init') {
    await env.DB.exec(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT); CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT UNIQUE NOT NULL, name TEXT, sub_token TEXT UNIQUE, enabled INTEGER DEFAULT 1, data_limit INTEGER DEFAULT 0, data_used INTEGER DEFAULT 0, expiry_time INTEGER DEFAULT 0, country_code TEXT DEFAULT 'AUTO', target_ip TEXT DEFAULT '', port INTEGER DEFAULT 443, conn_limit INTEGER DEFAULT 0, last_ip TEXT DEFAULT '', last_seen INTEGER DEFAULT 0, tg_id TEXT DEFAULT '', phone TEXT DEFAULT '', note TEXT DEFAULT '', custom_path TEXT DEFAULT '', admin_id INTEGER DEFAULT 1, created_at INTEGER DEFAULT (strftime('%s', 'now'))); CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT, ip TEXT, action TEXT, ua TEXT, created_at INTEGER);`);
    if (!(await env.KV.get('SETTINGS'))) await env.KV.put('SETTINGS', JSON.stringify({panel_pass:'admin'}));
    const admin = await env.DB.prepare('SELECT id FROM admins WHERE id=1').first();
    if(!admin) await env.DB.prepare('INSERT INTO admins (id, username, password) VALUES (1, ?, ?)').bind('superadmin', 'admin').run();
    return new Response(JSON.stringify({ status: 'ok' }), { headers });
  }
  
  if (path === '/api/login') {
    if(body.password === (await getSettings(env)).panel_pass) return new Response(JSON.stringify({ success: true, role: 'super', id: 1 }), {headers});
    const reseller = await env.DB.prepare('SELECT id FROM admins WHERE password = ? AND id > 1').bind(body.password).first();
    if(reseller) return new Response(JSON.stringify({ success: true, role: 'reseller', id: reseller.id }), {headers});
    return new Response(JSON.stringify({ success: false }), { status: 401, headers });
  }

  if (path === '/api/ips') return new Response(JSON.stringify(CF_IPS), { headers });
  if (path === '/api/settings' && request.method === 'GET') return new Response(JSON.stringify(await getSettings(env)), { headers });
  if (path === '/api/settings' && request.method === 'POST') { await env.KV.put('SETTINGS', JSON.stringify(body)); return new Response(JSON.stringify({ success: true }), { headers }); }
  if (path === '/api/logs') { const search = new URL(request.url).searchParams.get('q') || ''; const q = search ? `SELECT * FROM logs WHERE uuid LIKE '%${search}%' OR ip LIKE '%${search}%' ORDER BY id DESC LIMIT 100` : 'SELECT * FROM logs ORDER BY id DESC LIMIT 100'; return new Response(JSON.stringify((await env.DB.prepare(q).all()).results), { headers }); }
  if (path === '/api/admins' && request.method === 'GET') { return new Response(JSON.stringify((await env.DB.prepare('SELECT id, username FROM admins WHERE id > 1').all()).results), { headers }); }
  if (path === '/api/admins' && request.method === 'POST') { if(!body.username || !body.password) return new Response(JSON.stringify({error:'Missing'}), {status:400, headers}); await env.DB.prepare('INSERT INTO admins (username, password) VALUES (?, ?)').bind(body.username, body.password).run(); return new Response(JSON.stringify({success:true}), {headers}); }
  if (path.startsWith('/api/admins/') && request.method === 'DELETE') { await env.DB.prepare('DELETE FROM admins WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({success:true}), {headers}); }
  if (path === '/api/backup') { const users = (await env.DB.prepare('SELECT * FROM users').all()).results; return new Response(JSON.stringify({users}), {headers:{'Content-Disposition':'attachment; filename=backup.json'}}); }
  if (path === '/api/restore' && request.method === 'POST') { for(const u of body.users) { await env.DB.prepare('INSERT OR REPLACE INTO users (id,uuid,name,sub_token,enabled,data_limit,data_used,expiry_time,country_code,target_ip,port,conn_limit,last_ip,last_seen,tg_id,phone,note,custom_path,admin_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(u.id,u.uuid,u.name,u.sub_token,u.enabled,u.data_limit,u.data_used,u.expiry_time,u.country_code,u.target_ip,u.port,u.conn_limit,u.last_ip,u.last_seen,u.tg_id,u.phone,u.note,u.custom_path,u.admin_id,u.created_at).run(); } return new Response(JSON.stringify({success:true}), {headers}); }
  if (path === '/api/stats') { const t = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first(); const a = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE enabled = 1').first(); const tr = await env.DB.prepare('SELECT SUM(data_used) as c FROM users').first(); const o = await env.DB.prepare("SELECT COUNT(*) as c FROM logs WHERE action = 'Connected'").first(); return new Response(JSON.stringify({ total: t.c, active: a.c, traffic: tr.c || 0, online_logs: o.c }), { headers }); }
  
  if (path === '/api/users' && request.method === 'GET') {
    let query = 'SELECT * FROM users';
    if(body.admin_id && body.admin_id !== 1) query += ` WHERE admin_id = ${body.admin_id}`;
    query += ' ORDER BY id DESC';
    const results = (await env.DB.prepare(query).all()).results;
    const users = await Promise.all(results.map(async u => { u.current_conns = parseInt(await env.KV.get(`conn_${u.uuid}`) || '0'); return u; }));
    return new Response(JSON.stringify(users), { headers });
  }
  
  if (path === '/api/user/add' && request.method === 'POST') { 
    const uuid = crypto.randomUUID(); const sub = crypto.randomUUID().replace(/-/g,''); const exp = body.expiry_days > 0 ? Math.floor(Date.now()/1000) + (body.expiry_days*86400) : 0;
    await env.DB.prepare('INSERT INTO users (uuid,name,sub_token,data_limit,expiry_time,country_code,target_ip,port,conn_limit,tg_id,phone,note,custom_path,admin_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uuid, body.name, sub, body.data_limit*1073741824, exp, body.country_code, body.target_ip, body.port || 443, body.conn_limit, body.tg_id||'', body.phone||'', body.note||'', body.custom_path||'', body.admin_id||1).run();
    ctx.waitUntil(sendTg(env, `✅ User Created:\nName: ${body.name}\nPort: ${body.port || 443}`));
    return new Response(JSON.stringify({success:true}), {headers}); 
  }
  if (path.startsWith('/api/user/edit/') && request.method === 'POST') { 
    const id = path.split('/')[3]; const exp = body.expiry_days > 0 ? Math.floor(Date.now()/1000) + (body.expiry_days*86400) : 0;
    await env.DB.prepare('UPDATE users SET name=?,data_limit=?,expiry_time=?,country_code=?,target_ip=?,port=?,conn_limit=?,tg_id=?,phone=?,note=?,custom_path=? WHERE id=?').bind(body.name, body.data_limit*1073741824, exp, body.country_code, body.target_ip, body.port || 443, body.conn_limit, body.tg_id, body.phone, body.note, body.custom_path, id).run();
    return new Response(JSON.stringify({success:true}), {headers}); 
  }
  if (path.startsWith('/api/user/reset/')) { await env.DB.prepare('UPDATE users SET data_used = 0 WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({success:true}), {headers}); }
  if (path.startsWith('/api/user/toggle/')) { await env.DB.prepare('UPDATE users SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({success:true}), {headers}); }
  if (path.startsWith('/api/user/delete/')) { await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(path.split('/')[3]).run(); return new Response(JSON.stringify({success:true}), {headers}); }
  
  return new Response('Not Found', { status: 404 });
}

function getPanelHTML(env) {
  return new Response(`<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Lowkey SaaS Panel</title><script src="https://cdn.tailwindcss.com"><\/script><script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"><\/script><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;700;900&display=swap" rel="stylesheet"><style>body{font-family:'Vazirmatn',sans-serif;background:#020617;color:#e2e8f0}.glass{background:rgba(15,23,42,0.6);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.05)}.btn{transition:all .2s}.btn:active{transform:scale(.95)}input,select,textarea{background:rgba(2,6,23,0.8)!important;border:1px solid rgba(139,92,246,0.3)!important;color:#fff!important}input:focus,select:focus,textarea:focus{border-color:rgba(139,92,246,0.8)!important;outline:none}.modal-bg{background:rgba(0,0,0,0.85);backdrop-filter:blur(8px)}.stat-card{background:linear-gradient(145deg,rgba(30,27,75,0.4),rgba(15,23,42,0.6));border:1px solid rgba(139,92,246,0.1)}@keyframes pulse-green{0%{box-shadow:0 0 0 0 rgba(34,197,94,0.7)}70%{box-shadow:0 0 0 6px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}.online-dot{width:10px;height:10px;background:#22c55e;border-radius:50%;display:inline-block;animation:pulse-green 2s infinite;margin-left:8px}.offline-dot{width:10px;height:10px;background:#374151;border-radius:50%;display:inline-block;margin-left:8px}#toast-container{position:fixed;top:20px;left:20px;z-index:9999;display:flex;flex-direction:column;gap:10px}.toast{padding:12px 20px;border-radius:12px;color:#fff;font-size:14px;backdrop-filter:blur(10px);animation:slideIn .3s ease-out}.toast-success{background:rgba(22,163,74,0.9)}.toast-error{background:rgba(220,38,38,0.9)}@keyframes slideIn{from{transform:translateX(-100%);opacity:0}to{transform:translateX(0);opacity:1}}.tab-btn{cursor:pointer;padding:8px 16px;border-radius:8px;font-size:14px;transition:all .2s;border:1px solid transparent}.tab-btn.active{background:rgba(139,92,246,0.2);color:#a78bfa;border-color:rgba(139,92,246,0.5)}</style></head><body class="min-h-screen">
<div id="toast-container"></div>

<div id="login-screen" class="min-h-screen flex items-center justify-center p-4"><div class="glass rounded-3xl p-10 w-full max-w-md shadow-2xl border-violet-500/20"><div class="text-center mb-10"><div class="w-20 h-20 bg-violet-600/20 border border-violet-500/50 rounded-full mx-auto mb-5 flex items-center justify-center text-4xl">👁️‍🗨️</div><h1 class="text-4xl font-black text-violet-400 tracking-wide" style="text-shadow:0 0 20px rgba(139,92,246,0.6)">LOWKEY</h1><p class="text-sm text-gray-500 mt-2">SaaS Edge Management</p></div><input type="password" id="password" placeholder="Admin / Reseller Password" class="w-full p-4 rounded-2xl mb-6 text-center text-lg tracking-widest"><button onclick="login()" class="w-full btn bg-violet-600 hover:bg-violet-500 text-white font-bold py-4 rounded-2xl shadow-lg shadow-violet-500/20">Access Panel</button><button onclick="initDB()" class="w-full mt-4 border border-violet-500/30 text-violet-400 py-3 rounded-2xl btn text-sm">Initialize Database</button></div></div>

<div id="dashboard" class="hidden p-4 md:p-8 max-w-7xl mx-auto">
<div class="flex flex-wrap justify-between items-center mb-6 gap-4"><div class="flex items-center gap-3"><span class="text-2xl">👁️‍🗨️</span><h1 class="text-2xl font-black text-violet-400">LOWKEY</h1><span id="role-badge" class="text-xs bg-violet-900 text-violet-300 px-2 py-1 rounded">SUPER ADMIN</span></div>
<div class="flex gap-2 flex-wrap">
  <button onclick="showTab('users')" id="tab-users" class="tab-btn active">Users</button>
  <button onclick="showTab('logs')" id="tab-logs" class="tab-btn">Logs</button>
  <div id="super-only" class="flex gap-2">
    <button onclick="showTab('resellers')" id="tab-resellers" class="tab-btn">Resellers</button>
    <button onclick="openSettings()" class="tab-btn">Settings</button>
    <button onclick="backupDB()" class="tab-btn border border-green-500/50 text-green-400">Backup</button>
    <button onclick="document.getElementById('restore-file').click()" class="tab-btn border border-amber-500/50 text-amber-400">Restore</button>
    <input type="file" id="restore-file" accept=".json" class="hidden" onchange="restoreDB(event)">
  </div>
  <button onclick="showAddModal()" class="btn bg-violet-600 text-white px-4 py-2 rounded-xl font-semibold shadow-lg shadow-violet-500/20">+ New</button>
  <button onclick="logout()" class="btn border border-red-500/30 text-red-400 px-4 py-2 rounded-xl">Logout</button>
</div></div>

<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
<div class="stat-card rounded-2xl p-4"><p class="text-gray-400 text-[10px] uppercase">Total</p><p id="stat-total" class="text-2xl font-bold text-white mt-1">0</p></div>
<div class="stat-card rounded-2xl p-4"><p class="text-gray-400 text-[10px] uppercase">Active</p><p id="stat-active" class="text-2xl font-bold text-emerald-400 mt-1">0</p></div>
<div class="stat-card rounded-2xl p-4"><p class="text-gray-400 text-[10px] uppercase">Online</p><p id="stat-online" class="text-2xl font-bold text-violet-400 mt-1">0</p></div>
<div class="stat-card rounded-2xl p-4"><p class="text-gray-400 text-[10px] uppercase">Traffic</p><p id="stat-traffic" class="text-2xl font-bold text-blue-400 mt-1">0 GB</p></div>
</div>

<div id="content-users" class="glass rounded-2xl overflow-hidden shadow-2xl"><div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-slate-900/80 text-violet-300 text-right text-[10px] uppercase tracking-wider"><tr><th class="p-3">User / Info</th><th class="p-3">Status</th><th class="p-3">Data</th><th class="p-3">Links</th><th class="p-3">Actions</th></tr></thead><tbody id="users-tbody"></tbody></table></div></div>

<div id="content-logs" class="glass rounded-2xl overflow-hidden shadow-2xl hidden p-4">
  <input type="text" id="log-search" placeholder="Search UUID or IP..." class="w-full p-2 rounded-lg mb-4 text-sm" oninput="loadLogs()">
  <div class="overflow-x-auto max-h-[60vh] overflow-y-auto"><table class="w-full text-sm text-left"><thead class="bg-slate-900/50 text-gray-400 text-xs uppercase sticky top-0"><tr><th class="p-2">Time</th><th class="p-2">UUID</th><th class="p-2">IP / Client</th><th class="p-2">Action</th></tr></thead><tbody id="logs-tbody" class="text-xs text-gray-300"></tbody></table></div>
</div>

<div id="content-resellers" class="glass rounded-2xl overflow-hidden shadow-2xl hidden p-4">
  <button onclick="showResellerModal()" class="btn bg-cyan-600 text-white px-4 py-2 rounded-lg mb-4 text-sm">+ Add Reseller</button>
  <div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-slate-900/50 text-gray-400 text-xs uppercase"><tr><th class="p-2 text-right">ID</th><th class="p-2 text-right">Username</th><th class="p-2 text-right">Password</th><th class="p-2 text-right">Action</th></tr></thead><tbody id="resellers-tbody" class="text-xs text-gray-300"></tbody></table></div>
</div>
</div>

<!-- Modals -->
<div id="add-modal" class="fixed inset-0 modal-bg flex items-center justify-center z-50 hidden"><div class="glass rounded-2xl p-8 w-full max-w-md border border-violet-500/20 max-h-[90vh] overflow-y-auto">
  <h2 class="text-xl font-bold mb-6 text-violet-400" id="modal-title">Create User</h2><input type="hidden" id="edit-id">
  <input type="text" id="name" placeholder="Username" class="w-full p-3 rounded-xl mb-3 outline-none">
  <div class="grid grid-cols-2 gap-3 mb-3"><input type="number" id="limit" placeholder="Limit(GB)" class="w-full p-3 rounded-xl outline-none"><input type="number" id="expiry" placeholder="Days" class="w-full p-3 rounded-xl outline-none"></div>
  <div class="grid grid-cols-2 gap-3 mb-3">
    <input type="number" id="conn_limit" placeholder="Max Conn (0=inf)" class="w-full p-3 rounded-xl outline-none">
    <select id="port" class="w-full p-3 rounded-xl outline-none">
      <option value="443">Port 443 (Default)</option>
      <option value="8443">Port 8443</option>
      <option value="2053">Port 2053</option>
      <option value="2083">Port 2083</option>
      <option value="2087">Port 2087</option>
      <option value="2096">Port 2096</option>
    </select>
  </div>
  <input type="text" id="custom_path" placeholder="Custom WS Path (e.g. api/v1) - Optional" class="w-full p-3 rounded-xl mb-3 outline-none">
  <div class="grid grid-cols-2 gap-3 mb-3"><input type="text" id="tg_id" placeholder="Telegram ID" class="w-full p-3 rounded-xl outline-none"><input type="text" id="phone" placeholder="Phone Number" class="w-full p-3 rounded-xl outline-none"></div>
  <textarea id="note" placeholder="Admin Note..." class="w-full p-3 rounded-xl mb-3 outline-none h-16 resize-none"></textarea>
  <select id="country" onchange="updateIpList()" class="w-full p-3 rounded-xl mb-3 outline-none"><option value="AUTO">🌐 Auto IP</option><option value="DE">🇩🇪 Germany</option><option value="NL">🇳🇱 Netherlands</option><option value="FI">🇫🇮 Finland</option><option value="US">🇺🇸 USA</option></select>
  <select id="target-ip" class="w-full p-3 rounded-xl outline-none mb-4"><option value="">Select IP</option></select>
  <div class="flex gap-3"><button onclick="saveUser()" class="flex-1 btn bg-violet-600 text-white py-3 rounded-xl font-bold">Save</button><button onclick="closeModal('add-modal')" class="flex-1 btn border border-gray-600 py-3 rounded-xl">Cancel</button></div>
</div></div>

<div id="reseller-modal" class="fixed inset-0 modal-bg flex items-center justify-center z-50 hidden"><div class="glass rounded-2xl p-8 w-full max-w-sm border border-cyan-500/20">
  <h2 class="text-xl font-bold mb-6 text-cyan-400">New Reseller</h2>
  <input type="text" id="r-user" placeholder="Username" class="w-full p-3 rounded-xl mb-3 outline-none">
  <input type="text" id="r-pass" placeholder="Password" class="w-full p-3 rounded-xl mb-4 outline-none">
  <div class="flex gap-3"><button onclick="addReseller()" class="flex-1 btn bg-cyan-600 text-white py-3 rounded-xl font-bold">Create</button><button onclick="closeModal('reseller-modal')" class="flex-1 btn border border-gray-600 py-3 rounded-xl">Cancel</button></div>
</div></div>

<div id="settings-modal" class="fixed inset-0 modal-bg flex items-center justify-center z-50 hidden"><div class="glass rounded-2xl p-8 w-full max-w-md border border-slate-600/50 max-h-[90vh] overflow-y-auto">
  <h2 class="text-xl font-bold mb-6 text-slate-300">Node & SaaS Settings</h2>
  <input type="text" id="s-sni" placeholder="SNI" class="w-full p-3 rounded-xl mb-3 outline-none">
  <input type="text" id="s-remark" placeholder="Node Name" class="w-full p-3 rounded-xl mb-3 outline-none">
  <input type="number" id="s-dl_multiplier" step="0.1" placeholder="DL Multiplier (Default 2)" class="w-full p-3 rounded-xl mb-3 outline-none">
  <select id="s-fp" class="w-full p-3 rounded-xl mb-6 outline-none"><option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="random">Random</option></select>
  
  <h3 class="text-violet-400 text-sm font-bold mb-3">Telegram Notifications</h3>
  <input type="text" id="s-tg_token" placeholder="Bot Token" class="w-full p-3 rounded-xl mb-3 outline-none">
  <input type="text" id="s-tg_chat_id" placeholder="Chat ID" class="w-full p-3 rounded-xl mb-6 outline-none">

  <h3 class="text-violet-400 text-sm font-bold mb-3">Fragmentation (Anti-DPI)</h3>
  <select id="s-fragment_enabled" class="w-full p-3 rounded-xl mb-3 outline-none"><option value="false">Disabled</option><option value="true">Enabled</option></select>
  <input type="text" id="s-fragment_size" placeholder="Size (e.g. 10-20)" class="w-full p-3 rounded-xl mb-3 outline-none">
  <input type="text" id="s-fragment_interval" placeholder="Interval (e.g. 10-20)" class="w-full p-3 rounded-xl mb-6 outline-none">

  <div class="flex gap-3"><button onclick="saveSettings()" class="flex-1 btn bg-slate-700 hover:bg-slate-600 text-white py-3 rounded-xl font-bold">Save All</button><button onclick="closeModal('settings-modal')" class="flex-1 btn border border-gray-600 py-3 rounded-xl">Close</button></div>
</div></div>

<div id="qr-modal" onclick="this.style.display='none'" class="fixed inset-0 modal-bg flex items-center justify-center z-50 hidden"><div class="glass rounded-2xl p-6 text-center border border-gray-700" onclick="event.stopPropagation()"><canvas id="qr-canvas" class="mx-auto mb-4 bg-white p-3 rounded-xl"></canvas><p id="qr-text" class="text-[10px] text-gray-500 break-all mb-4 max-w-sm max-h-20 overflow-y-auto"></p><button onclick="document.getElementById('qr-modal').style.display='none'" class="btn border border-violet-500 text-violet-400 px-8 py-2 rounded-xl">Close</button></div></div>

<script>
const host=location.host;let curSet={},ipDB={},refInt, myRole='super', myId=1;
function showToast(m,t='success'){const c=document.getElementById('toast-container'),e=document.createElement('div');e.className='toast toast-'+t;e.innerHTML=(t==='success'?'✅ ':'❌ ')+m;c.appendChild(e);setTimeout(()=>{e.style.opacity='0';e.style.transition='opacity 0.5s';setTimeout(()=>e.remove(),500)},3000)}
async function initDB(){await fetch('/api/init');showToast('DB Initialized! Super Pass: admin')}
async function login(){
  const p=document.getElementById('password').value;
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  const d=await r.json();
  if(d.success){
    myRole=d.role; myId=d.id;
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('dashboard').classList.remove('hidden');
    if(myRole==='reseller'){document.getElementById('super-only').classList.add('hidden');document.getElementById('role-badge').innerText='RESELLER';document.getElementById('role-badge').className='text-xs bg-cyan-900 text-cyan-300 px-2 py-1 rounded';}
    loadAll();startRef();
  }else showToast('Wrong Password!','error');
}
function logout(){clearInterval(refInt);document.getElementById('dashboard').classList.add('hidden');document.getElementById('login-screen').classList.remove('hidden')}
function showTab(t){['users','logs','resellers'].forEach(id=>{document.getElementById('content-'+id).classList.toggle('hidden',id!==t);document.getElementById('tab-'+id).classList.toggle('active',id===t)});if(t==='logs')loadLogs();if(t==='resellers')loadResellers()}
function closeModal(id){document.getElementById(id).classList.add('hidden')}
async function loadAll(){ipDB=await(await fetch('/api/ips')).json();loadStats();loadUsers();loadSetUI()}
function startRef(){clearInterval(refInt);refInt=setInterval(()=>{loadStats();loadUsers()},5000)}
async function loadStats(){const s=await(await fetch('/api/stats')).json();document.getElementById('stat-total').innerText=s.total;document.getElementById('stat-active').innerText=s.active;document.getElementById('stat-online').innerText=s.online_logs;document.getElementById('stat-traffic').innerText=(s.traffic/1073741824).toFixed(1)+' GB'}
async function loadLogs(){const q=document.getElementById('log-search').value;const l=await(await fetch(`/api/logs?q=${q}`)).json();const tb=document.getElementById('logs-tbody');tb.innerHTML='';l.forEach(l=>{const shortUa=l.ua?l.ua.substring(0,20):'';tb.innerHTML+=`<tr class="border-b border-gray-800"><td class="p-2">${new Date(l.created_at*1000).toLocaleTimeString('fa-IR')}</td><td class="p-2 font-mono text-[10px]">${l.uuid.substring(0,8)}...</td><td class="p-2 text-cyan-400 text-[10px]">${l.ip}<br><span class="text-gray-600">${shortUa}</span></td><td class="p-2 ${l.action.includes('Rejected')?'text-red-400':'text-emerald-400'}">${l.action}</td></tr>`})}
async function loadResellers(){const r=await(await fetch('/api/admins')).json();const tb=document.getElementById('resellers-tbody');tb.innerHTML='';r.forEach(r=>{tb.innerHTML+=`<tr class="border-b border-gray-800"><td class="p-2">${r.id}</td><td class="p-2">${r.username}</td><td class="p-2 font-mono">${r.password}</td><td class="p-2"><button onclick="delReseller(${r.id})" class="btn text-red-400 text-xs border border-red-500/30 px-2 py-1 rounded">Delete</button></td></tr>`})}
function showResellerModal(){document.getElementById('r-user').value='';document.getElementById('r-pass').value='';document.getElementById('reseller-modal').classList.remove('hidden')}
async function addReseller(){const u=document.getElementById('r-user').value,p=document.getElementById('r-pass').value;if(!u||!p)return showToast('Fill fields!','error');await fetch('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});closeModal('reseller-modal');showToast('Reseller Added');loadResellers()}
async function delReseller(id){if(!confirm('Delete?'))return;await fetch(`/api/admins/${id}`,{method:'DELETE'});showToast('Deleted','error');loadResellers()}

async function loadSetUI(){curSet=await(await fetch('/api/settings')).json();document.getElementById('s-sni').value=curSet.sni||'';document.getElementById('s-remark').value=curSet.remark||'';document.getElementById('s-dl_multiplier').value=curSet.dl_multiplier||'2';document.getElementById('s-fp').value=curSet.fp||'chrome';document.getElementById('s-tg_token').value=curSet.tg_token||'';document.getElementById('s-tg_chat_id').value=curSet.tg_chat_id||'';document.getElementById('s-fragment_enabled').value=curSet.fragment_enabled||'false';document.getElementById('s-fragment_size').value=curSet.fragment_size||'';document.getElementById('s-fragment_interval').value=curSet.fragment_interval||''}
async function saveSettings(){curSet.sni=document.getElementById('s-sni').value;curSet.remark=document.getElementById('s-remark').value;curSet.dl_multiplier=document.getElementById('s-dl_multiplier').value;curSet.fp=document.getElementById('s-fp').value;curSet.tg_token=document.getElementById('s-tg_token').value;curSet.tg_chat_id=document.getElementById('s-tg_chat_id').value;curSet.fragment_enabled=document.getElementById('s-fragment_enabled').value;curSet.fragment_size=document.getElementById('s-fragment_size').value;curSet.fragment_interval=document.getElementById('s-fragment_interval').value;await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(curSet)});closeModal('settings-modal');showToast('Saved');loadAll()}
function openSettings(){loadSetUI();document.getElementById('settings-modal').classList.remove('hidden')}

async function backupDB(){const data=await(await fetch('/api/backup')).json();const blob=new Blob([JSON.stringify(data)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='lowkey_backup.json';a.click();showToast('Downloaded')}
async function restoreDB(e){const file=e.target.files[0];if(!file)return;const text=await file.text();await fetch('/api/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:text});showToast('Restored!');loadAll()}

function updateIpList(){const c=document.getElementById('country').value,s=document.getElementById('target-ip');s.innerHTML='';const ips=ipDB[c]?.ips||[];if(!ips.length)s.innerHTML='<option value="">Domain</option>';else ips.forEach(i=>s.innerHTML+=`<option value="${i}">${i}</option>`)}
function genLink(u){const a=u.target_ip||host;const p=u.custom_path||u.uuid;return \`vless://\${u.uuid}@\${a}:\${u.port || 443}?type=ws&security=tls&sni=\${curSet.sni}&fp=\${curSet.fp}&path=%2F\${p}&host=\${curSet.sni}#\${curSet.remark}-\${u.name}\`}

async function loadUsers(){
  const users=await(await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_id:myId})})).json();
  const tb=document.getElementById('users-tbody');tb.innerHTML='';
  users.forEach(u=>{
    const lG=u.data_limit>0?(u.data_limit/1073741824).toFixed(1)+'G':'∞';const uG=(u.data_used/1073741824).toFixed(2)+'G';const f=ipDB[u.country_code]?.flag||'🌐';const isO=u.current_conns>0;const dC=isO?'online-dot':'offline-dot';
    const note=u.note?`<span class="text-[9px] text-gray-600 block">📌 ${u.note.substring(0,15)}</span>`:'';
    const portBadge=u.port && u.port !== 443 ? `<span class="text-[9px] bg-blue-900 text-blue-300 px-1 rounded">Port:${u.port}</span>` : '';
    const l=genLink(u);const s=`https://${host}/sub/${u.sub_token}`;
    tb.innerHTML+=`<tr class="border-t border-gray-800/50 hover:bg-slate-800/20 transition-colors"><td class="p-3"><div class="flex items-center"><span class="text-lg ml-2">${f}</span><div><span class="font-semibold text-sm">${u.name}</span> ${portBadge}${note}</div></div></td><td class="p-3"><div class="flex items-center gap-2"><span class="${dC}"></span><div><span class="${u.enabled?'text-emerald-400':'text-red-400'} text-[10px] font-bold block">${u.enabled?'ON':'OFF'}</span><span class="text-violet-400 text-[10px] block">${u.current_conns} Conn</span></div></div></td><td class="p-3 text-xs"><span class="text-blue-400">${uG}</span> / ${lG}</td><td class="p-3"><div class="flex flex-col gap-1"><button onclick="showQR('${l}')" class="bg-violet-600/10 text-violet-300 px-2 py-1 rounded text-[10px] btn">QR</button><button onclick="copyText('${s}')" class="bg-slate-600/10 text-slate-300 px-2 py-1 rounded text-[10px] btn">Sub</button></div></td><td class="p-3"><div class="flex flex-col gap-1"><button onclick="openEditModal(${u.id},'${u.name}',${u.data_limit>0?(u.data_limit/1073741824).toFixed(0):0},${u.expiry_time>0?Math.ceil((u.expiry_time-Math.floor(Date.now()/1000))/86400):0},'${u.country_code}','${u.target_ip||''}',${u.port || 443},${u.conn_limit},'${u.tg_id||''}','${u.phone||''}','${(u.note||'').replace(/'/g,"\\'")}','${u.custom_path||''}')" class="bg-amber-600/10 text-amber-300 px-2 py-1 rounded text-[10px] btn">Edit</button><div class="flex gap-1 mt-1"><button onclick="resetTraffic(${u.id})" class="flex-1 bg-cyan-600/10 text-cyan-300 px-1 py-1 rounded text-[9px] btn">Res</button><button onclick="toggleUser(${u.id})" class="flex-1 bg-slate-700/30 text-slate-400 px-1 py-1 rounded text-[9px] btn">Tgl</button><button onclick="deleteUser(${u.id})" class="flex-1 bg-red-600/10 text-red-400 px-1 py-1 rounded text-[9px] btn">Del</button></div></div></td></tr>`})
}

function showAddModal(){document.getElementById('modal-title').innerText='Create User';document.getElementById('edit-id').value='';['name','limit','expiry','conn_limit','custom_path','tg_id','phone','note'].forEach(id=>document.getElementById(id).value='');document.getElementById('port').value='443';document.getElementById('country').value='AUTO';updateIpList();document.getElementById('add-modal').classList.remove('hidden')}
function openEditModal(id,n,l,e,c,ip,port,cl,tg,ph,nt,cp){document.getElementById('modal-title').innerText='Edit User';document.getElementById('edit-id').value=id;document.getElementById('name').value=n;document.getElementById('limit').value=l;document.getElementById('expiry').value=e;document.getElementById('conn_limit').value=cl;document.getElementById('port').value=port;document.getElementById('tg_id').value=tg;document.getElementById('phone').value=ph;document.getElementById('note').value=nt;document.getElementById('custom_path').value=cp;document.getElementById('country').value=c;updateIpList();setTimeout(()=>document.getElementById('target-ip').value=ip,50);document.getElementById('add-modal').classList.remove('hidden')}

async function saveUser(){
  const id=document.getElementById('edit-id').value;
  const d={name:document.getElementById('name').value,data_limit:document.getElementById('limit').value||0,expiry_days:document.getElementById('expiry').value||0,country_code:document.getElementById('country').value,target_ip:document.getElementById('target-ip').value,port:document.getElementById('port').value,conn_limit:document.getElementById('conn_limit').value||0,tg_id:document.getElementById('tg_id').value,phone:document.getElementById('phone').value,note:document.getElementById('note').value,custom_path:document.getElementById('custom_path').value, admin_id: myId};
  if(!d.name){showToast('Name required!','error');return}
  await fetch(id?`/api/user/edit/${id}`:'/api/user/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  closeModal('add-modal');showToast('Saved');loadAll();
}
async function resetTraffic(id){if(confirm('Reset?')){await fetch(`/api/user/reset/${id}`,{method:'POST'});showToast('Reset');loadAll()}}
async function toggleUser(id){await fetch(`/api/user/toggle/${id}`,{method:'POST'});showToast('Toggled');loadAll()}
async function deleteUser(id){if(confirm('Delete?')){await fetch(`/api/user/delete/${id}`,{method:'DELETE'});showToast('Deleted','error');loadAll()}}
function copyText(t){navigator.clipboard.writeText(t);showToast('Copied')}
function showQR(l){document.getElementById('qr-modal').style.display='flex';document.getElementById('qr-text').innerText=l;QRCode.toCanvas(document.getElementById('qr-canvas'),l,{width:250,color:{dark:'#000',light:'#fff'}})}
<\/script></body></html>`, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
		}
