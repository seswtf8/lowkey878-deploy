import { connect } from "cloudflare:sockets";

const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;

const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const TCP_CONCURRENCY = 2;
const PRELOAD_RACE_DIAL = true;

export default {
    async fetch(request, env, ctx) {
        trackRequest(env, ctx);
        await DbService.ensureSchema(env.DB);
        const url = new URL(request.url);
        
        if (Router.isWebSocketUpgrade(request) && url.pathname === "/lowkey") {
            return await Router.handleWebSocket(request, env, ctx);
        }
        if (Router.isSubscriptionPath(url.pathname)) {
            return await Router.handleSubscription(url, env);
        }
        if (url.pathname.startsWith("/api/") || url.pathname === "/locations") {
            return await Router.handleApi(request, url, env, ctx);
        }
        if (url.pathname === "/panel" || url.pathname === "/login") {
            return await Router.handlePanel(request, env);
        }
        if (url.pathname.startsWith("/status/")) {
            return await Router.handleUserStatus(url, env);
        }
        return new Response(HTML_TEMPLATES.nginx, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
        });
    },
};

const Router = {
    isWebSocketUpgrade(request) {
        return (request.headers.get("Upgrade") || "").toLowerCase() === "websocket";
    },
    isSubscriptionPath(pathname) {
        return pathname.startsWith("/sub/") || pathname.startsWith("/feed/");
    },
    async handleWebSocket(request, env, ctx) {
        try {
            let proxyIP = "proxyip.cmliussss.net";
            let socks5 = "";
            try {
                const proxyRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
                if (proxyRow && proxyRow.value) proxyIP = proxyRow.value;
                const socksRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
                if (socksRow && socksRow.value) socks5 = socksRow.value;
            } catch (e) {}
            const mockStoredData = { proxy_ip: proxyIP, socks5: socks5 };
            return handleVLESS(env, mockStoredData, ctx, request);
        } catch (e) {
            return new Response("Internal Server Error", { status: 500 });
        }
    },
    async handleSubscription(url, env) {
        const isSubPath = url.pathname.startsWith("/sub/");
        const offset = isSubPath ? 5 : 6;
        let subUser = decodeURIComponent(url.pathname.slice(offset));
        const host = url.hostname;
        try {
            const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
            if (!user || user.connection_type !== "vless") {
                return new Response("Not Found", { status: 404 });
            }
            return await SubscriptionService.generateText(user, host);
        } catch (err) {
            return new Response("Error building config: " + err.message, { status: 500 });
        }
    },
    async handlePanel(request, env) {
        const hasPassword = await DbService.getPanelPassword(env.DB);
        if (!hasPassword) {
            return new Response(HTML_TEMPLATES.setup, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        const authorized = await DbService.verifyApiAuth(request, env);
        if (!authorized) {
            return new Response(HTML_TEMPLATES.login, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        }
        return new Response(HTML_TEMPLATES.panel, {
            headers: {
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            },
        });
    },
    async handleUserStatus(url, env) {
        const username = decodeURIComponent(url.pathname.slice(8));
        if (!username) return new Response("Username is required", { status: 400 });
        try {
            const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
            if (!user) return new Response("User not found", { status: 404 });
            const userJson = JSON.stringify({
                username: user.username, uuid: user.uuid, limit_gb: user.limit_gb,
                expiry_days: user.expiry_days, used_gb: user.used_gb, limit_req: user.limit_req,
                used_req: user.used_req, is_active: user.is_active, online_count: getActiveIpCount(user.active_ips),
                ip_limit: user.ip_limit, created_at: user.created_at, tls: user.tls, port: user.port,
                ips: user.ips, fingerprint: user.fingerprint || "chrome",
            });
            const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
            return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
        } catch (err) {
            return new Response("Error: " + err.message, { status: 500 });
        }
    },
    async handleApi(request, url, env, ctx) {
        const hasPassword = await DbService.getPanelPassword(env.DB);
        
        if (url.pathname === "/api/setup-password" && request.method === "POST") {
            if (hasPassword) return new Response(JSON.stringify({ error: "Password already set" }), { status: 400, headers: { "Content-Type": "application/json" } });
            const { password } = await request.json();
            if (!password || password.length < 4) return new Response(JSON.stringify({ error: "Password too short" }), { status: 400, headers: { "Content-Type": "application/json" } });
            const hashed = await DbService.sha256(password);
            await DbService.setPanelPassword(env.DB, hashed);
            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json", "Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000" },
            });
        }

        if (url.pathname === "/api/login" && request.method === "POST") {
            const { password } = await request.json();
            const hashedInput = await DbService.sha256(password);
            const storedHash = await DbService.getPanelPassword(env.DB);
            if (storedHash === hashedInput) {
                return new Response(JSON.stringify({ success: true }), {
                    headers: { "Content-Type": "application/json", "Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000" },
                });
            }
            return new Response(JSON.stringify({ error: "Incorrect password" }), { status: 401, headers: { "Content-Type": "application/json" } });
        }

        if (url.pathname === "/api/logout" && request.method === "POST") {
            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json", "Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax" },
            });
        }

        if (url.pathname === "/api/recover" && request.method === "POST") {
            const { api_token } = await request.json();
            if (!api_token) return new Response(JSON.stringify({ error: "Token is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
            try {
                const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", { headers: { Authorization: "Bearer " + api_token } });
                const cfData = await cfRes.json();
                if (!cfRes.ok || !cfData.success) return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401, headers: { "Content-Type": "application/json" } });
                const host = url.hostname;
                let isAuthorized = false;
                if (host.endsWith(".workers.dev")) {
                    const parts = host.split(".");
                    const targetSubdomain = parts[parts.length - 3];
                    const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: { Authorization: "Bearer " + api_token } });
                    const accountsData = await accountsRes.json();
                    if (accountsData.success && accountsData.result) {
                        for (const acc of accountsData.result) {
                            const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, { headers: { Authorization: "Bearer " + api_token } });
                            const subData = await subRes.json();
                            if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) { isAuthorized = true; break; }
                        }
                    }
                } else {
                    const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", { headers: { Authorization: "Bearer " + api_token } });
                    const zonesData = await zonesRes.json();
                    if (zonesData.success && zonesData.result) {
                        for (const zone of zonesData.result) {
                            if (host === zone.name || host.endsWith("." + zone.name)) { isAuthorized = true; break; }
                        }
                    }
                }
                if (!isAuthorized) return new Response(JSON.stringify({ error: "Access denied" }), { status: 403, headers: { "Content-Type": "application/json" } });
                await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
                cachedPanelPassword = null;
                return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
            } catch (err) {
                return new Response(JSON.stringify({ error: "Connection error" }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        const authorized = await DbService.verifyApiAuth(request, env);
        if (!authorized) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });

        if (url.pathname === "/api/update-panel" && request.method === "POST") {
            const body = await request.json().catch(() => ({}));
            let currentToken = env.CF_API_TOKEN || body.cf_token;
            let currentAccountId = env.CF_ACCOUNT_ID;
            if (!currentToken) return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
            try {
                if (!currentAccountId) {
                    const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: { Authorization: "Bearer " + currentToken } });
                    const accData = await accRes.json();
                    if (!accData.success || accData.result.length === 0) throw new Error("Invalid token");
                    currentAccountId = accData.result[0].id;
                }
                const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now(), { headers: { "Cache-Control": "no-cache" } });
                if (!githubRes.ok) throw new Error("Failed to fetch source");
                const newCode = await githubRes.text();
                const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
                const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, { headers: { Authorization: "Bearer " + currentToken } });
                const bindingsData = await bindingsRes.json();
                if (!bindingsData.success) throw new Error("Access denied to worker settings");
                const newBindings = [];
                for (const b of bindingsData.result) {
                    if (b.type === "d1") newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
                    else if (b.name === "CF_API_TOKEN") newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
                    else if (b.name === "CF_ACCOUNT_ID") newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
                }
                if (!newBindings.some((b) => b.name === "CF_API_TOKEN")) newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
                if (!newBindings.some((b) => b.name === "CF_ACCOUNT_ID")) newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
                const metadata = { main_module: "zeus.js", compatibility_date: "2024-02-08", bindings: newBindings };
                const formData = new FormData();
                formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
                formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");
                const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, { method: "PUT", headers: { Authorization: "Bearer " + currentToken }, body: formData });
                if (!deployRes.ok) throw new Error("Deploy failed");
                return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname === "/api/restart-core" && request.method === "POST") {
            let currentToken = env.CF_API_TOKEN; let currentAccountId = env.CF_ACCOUNT_ID;
            if (!currentToken || !currentAccountId) return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
            try {
                const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now(), { headers: { "Cache-Control": "no-cache" } });
                if (!githubRes.ok) throw new Error("Failed to fetch source");
                const newCode = await githubRes.text();
                const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
                const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, { headers: { Authorization: "Bearer " + currentToken } });
                const bindingsData = await bindingsRes.json();
                if (!bindingsData.success) throw new Error("Access denied");
                const newBindings = [];
                for (const b of bindingsData.result) { if (b.type === "d1") newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id }); }
                newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
                newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
                const metadata = { main_module: "zeus.js", compatibility_date: "2024-02-08", bindings: newBindings };
                const formData = new FormData();
                formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
                formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");
                const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, { method: "PUT", headers: { Authorization: "Bearer " + currentToken }, body: formData });
                if (!deployRes.ok) throw new Error("Restart failed");
                return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
            } catch (err) {
                return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname === "/api/change-password" && request.method === "POST") {
            const { current_password, new_password } = await request.json();
            if (!current_password || !new_password) return new Response(JSON.stringify({ error: "Missing fields" }), { status: 400, headers: { "Content-Type": "application/json" } });
            const currentHash = await DbService.sha256(current_password);
            const storedHash = await DbService.getPanelPassword(env.DB);
            if (storedHash && storedHash !== currentHash) return new Response(JSON.stringify({ error: "Incorrect current password" }), { status: 401, headers: { "Content-Type": "application/json" } });
            if (new_password.length < 4) return new Response(JSON.stringify({ error: "Password too short" }), { status: 400, headers: { "Content-Type": "application/json" } });
            const newHash = await DbService.sha256(new_password);
            await DbService.setPanelPassword(env.DB, newHash);
            return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json", "Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000" } });
        }

        if (url.pathname === "/locations") {
            try {
                const response = await fetch("https://speed.cloudflare.com/locations", { headers: { Referer: "https://speed.cloudflare.com/" } });
                const data = await response.json();
                return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
            } catch (e) {
                return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname === "/api/settings/bulk") {
            if (request.method === "GET") {
                const { results } = await env.DB.prepare("SELECT * FROM settings").all();
                const settingsObj = {}; if (results) results.forEach((r) => settingsObj[r.key] = r.value);
                return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
            }
            if (request.method === "POST") {
                const body = await request.json();
                if (body.settings && typeof body.settings === "object") {
                    for (const [k, v] of Object.entries(body.settings)) {
                        await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
                    }
                }
                return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname === "/api/proxy-ip") {
            if (request.method === "POST") {
                const { proxy_ip, iata, socks5 } = await request.json();
                if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
                if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
                if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
                return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
            }
            if (request.method === "GET") {
                const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
                const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
                const rowSocks = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
                return new Response(JSON.stringify({ proxy_ip: rowIp ? rowIp.value : "", iata: rowIata ? rowIata.value : "", socks5: rowSocks ? rowSocks.value : "" }), { headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname === "/api/test-proxy" && request.method === "POST") {
            const { proxy } = await request.json();
            if (!proxy) return new Response(JSON.stringify({ error: "Proxy required" }), { status: 400, headers: { "Content-Type": "application/json" } });
            try {
                let ip = "";
                if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) { ip = proxy.match(/server=([^&]+)/)?.[1] || ""; }
                else {
                    let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
                    let remain = cleanProxy; if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
                    if (remain.startsWith("[")) { ip = remain.substring(1, remain.indexOf("]")); }
                    else { const lastColon = remain.lastIndexOf(":"); if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon); else ip = remain; }
                }
                let country = "UN";
                if (ip) { try { const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`); const geoData = await geoRes.json(); if (geoData && geoData.countryCode) country = geoData.countryCode; } catch (e) {} }
                const startTime = Date.now();
                const payload = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
                const s = await connectProxy(proxy, "1.1.1.1", 80, payload);
                const reader = s.readable.getReader();
                const res = await reader.read();
                if (res.done || !res.value) { s.close(); throw new Error("Timeout"); }
                s.close();
                const ping = Date.now() - startTime;
                return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
            } catch (e) {
                return new Response(JSON.stringify({ error: e.message || "Connection failed" }), { status: 500, headers: { "Content-Type": "application/json" } });
            }
        }

        if (url.pathname.startsWith("/api/users")) {
            const pathParts = url.pathname.split("/");
            const isUserAction = pathParts.length > 3;
            if (isUserAction) {
                const username = decodeURIComponent(pathParts.pop());
                if (request.method === "PUT") {
                    const body = await request.json();
                    if (body.toggle_only !== undefined) {
                        await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
                        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
                    } else if (body.reset_action !== undefined) {
                        if (body.reset_action === "volume") { await env.DB.prepare("UPDATE users SET used_gb = 0 WHERE username = ?").bind(username).run(); GLOBAL_TRAFFIC_CACHE.set(username, 0); }
                        else if (body.reset_action === "req") { await env.DB.prepare("UPDATE users SET used_req = 0 WHERE username = ?").bind(username).run(); USER_REQ_CACHE.set(username, 0); }
                        else if (body.reset_action === "time") { await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = ?").bind(username).run(); }
                        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
                    } else {
                        const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = body;
                        if (new_username && new_username !== username) {
                            const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(new_username).first();
                            if (existing) return new Response(JSON.stringify({ error: "Username exists" }), { status: 400, headers: { "Content-Type": "application/json" } });
                            ['GLOBAL_TRAFFIC_CACHE', 'USER_REQ_CACHE', 'ACTIVE_CONNECTIONS_COUNT', 'GLOBAL_LAST_ACTIVE_WRITE'].forEach(cache => { if(eval(cache).has(username)) { eval(cache).set(new_username, eval(cache).get(username)); eval(cache).delete(username); } });
                        }
                        await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ? WHERE username = ?")
                            .bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, username).run();
                        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
                    }
                }
                if (request.method === "DELETE") {
                    await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
                    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
                }
            } else {
                if (request.method === "GET") {
                    try { await flushExpiredTraffic(env); } catch (e) {}
                    const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
                    const now = Date.now();
                    const enrichedUsers = (results || []).map((user) => ({ ...user, is_online: user.last_active && now - user.last_active < 20000 ? 1 : 0, online_count: getActiveIpCount(user.active_ips) }));
                    let cfReqs = { today: 0, total: 0 };
                    try {
                        const liveCf = await getCfUsage(env);
                        const todayStr = new Date().toISOString().split("T")[0];
                        const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
                        const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
                        let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
                        let dbToday = 0;
                        if (dateRow && dateRow.value === todayStr) { const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first(); dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0; }
                        if (liveCf.today > dbToday) { dbToday = liveCf.today; await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run(); await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run(); }
                        if (liveCf.total > dbTotal) { dbTotal = liveCf.total; await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run(); }
                        cfReqs.today = dbToday + GLOBAL_REQ_COUNT; cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
                    } catch (e) {}
                    return new Response(JSON.stringify({ users: enrichedUsers, serverTime: now, cfRequestsToday: cfReqs.today, cfRequestsTotal: cfReqs.total }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
                }
                if (request.method === "POST") {
                    const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = await request.json();
                    if (!username) return new Response(JSON.stringify({ error: "Username required" }), { status: 400, headers: { "Content-Type": "application/json" } });
                    const finalUuid = uuid || crypto.randomUUID();
                    try {
                        await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                            .bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, "vless", tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, parseFloat(used_gb) || 0, parseInt(used_req) || 0, created_at || new Date().toISOString(), parseInt(is_active) || 1, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null).run();
                        return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
                    } catch (err) {
                        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
                    }
                }
            }
        }
        return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
    },
};

let schemaEnsured = false;
let cachedPanelPassword = null;

const DbService = {
    async ensureSchema(db) {
        if (schemaEnsured) return;
        const tables = [
            `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
            `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`
        ];
        for (const sql of tables) { try { await db.prepare(sql).run(); } catch (e) {} }
        const alters = [
            "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1", "ALTER TABLE users ADD COLUMN last_active INTEGER",
            "ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'chrome'", "ALTER TABLE users ADD COLUMN max_connections INTEGER",
            "ALTER TABLE users ADD COLUMN limit_req INTEGER", "ALTER TABLE users ADD COLUMN used_req INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN ip_limit INTEGER DEFAULT NULL", "ALTER TABLE users ADD COLUMN active_ips TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN block_porn INTEGER DEFAULT 0", "ALTER TABLE users ADD COLUMN block_ads INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN frag_len TEXT DEFAULT '200-3000'", "ALTER TABLE users ADD COLUMN frag_int TEXT DEFAULT '1-2'",
            "ALTER TABLE users ADD COLUMN lifetime_used_gb REAL DEFAULT 0", "ALTER TABLE users ADD COLUMN user_proxy_ip TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN user_proxy_iata TEXT DEFAULT NULL", "ALTER TABLE users ADD COLUMN user_socks5 TEXT DEFAULT NULL"
        ];
        for (const sql of alters) { try { await db.prepare(sql).run(); } catch (e) {} }
        try { await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run(); } catch(e){}
        try { await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run(); } catch(e){}
        schemaEnsured = true;
    },
    async getPanelPassword(db) {
        if (cachedPanelPassword !== null) return cachedPanelPassword;
        try { const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first(); cachedPanelPassword = row ? row.value : ""; return cachedPanelPassword || null; } catch (e) { return null; }
    },
    async setPanelPassword(db, password) {
        await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
        cachedPanelPassword = password;
    },
    async verifyApiAuth(request, env) {
        const storedPasswordHash = await this.getPanelPassword(env.DB);
        if (!storedPasswordHash) return true;
        const cookies = request.headers.get("Cookie") || "";
        const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
        if (!sessionCookie) return false;
        return sessionCookie.split("=")[1].trim() === storedPasswordHash;
    },
    async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
        return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
    },
};

function getActiveIpCount(activeIpsJson) {
    if (!activeIpsJson) return 0;
    try {
        const activeIps = JSON.parse(activeIpsJson); const now = Date.now(); let count = 0;
        for (const data of Object.values(activeIps)) { const lastSeen = data && typeof data === "object" ? data.timestamp : data; if (now - lastSeen <= 20000) count++; }
        return count;
    } catch (e) { return 0; }
}

async function getCfUsage(env) {
    try {
        const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/scripts/${env.WORKER_NAME || "lowkey"}/analytics/simple?since=-1440`, { headers: { Authorization: "Bearer " + env.CF_API_TOKEN } });
        const data = await res.json();
        if (data.success && data.result && data.result[0]) {
            const total = data.result[0].requestCount || 0;
            return { today: total, total: total };
        }
    } catch(e){}
    return { today: 0, total: 0 };
}

const SubscriptionService = {
    async generateText(user, host) {
        let ips = [host];
        if (user.ips) { const p = user.ips.split("\n").map(ip => ip.trim()).filter(ip => ip.length > 0); if (p.length > 0) ips = p; }
        const ports = String(user.port || "443").split(",").map(p => p.trim()).filter(p => p.length > 0);
        const fp = user.fingerprint || "chrome";
        const links = [];
        
        let remVol = "Unlimited"; if (user.limit_gb) { let rem = user.limit_gb - (user.used_gb || 0); remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB"; }
        let remTime = "Unlimited"; if (user.expiry_days && user.created_at) { const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000); const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / 86400000); remTime = diffDays > 0 ? diffDays + "Days" : "0Days"; }
        let remReq = "Unlimited"; if (user.limit_req) { let rem = user.limit_req - (user.used_req || 0); remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req"; }
        
        const infoRemark = `lowkey | ${remVol} | ${remTime} | ${remReq}`;
        
        ips.forEach((ip) => {
            ports.forEach((portStr) => {
                const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
                const tlsVal = isTlsPort ? "tls" : "none";
                const userFrag = user.frag_len && user.frag_int ? `&fragment=${user.frag_len},${user.frag_int}` : "";
                const remark = `${user.username} | ${ip} | ${portStr}`;
                links.push(`vless://${user.uuid}@${ip}:${portStr}?path=%2Flowkey&security=${tlsVal}&encryption=none&insecure=0&host=${host}&fp=${fp}&type=ws&allowInsecure=0&sni=${host}${userFrag}#${encodeURIComponent(remark)}`);
            });
        });

        const plainContent = links.join("\n");
        const subContent = btoa(unescape(encodeURIComponent(plainContent)));
        const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
        const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
        let expireTimestamp = 0;
        if (user.expiry_days && user.created_at) { expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000); }
        
        return new Response(subContent, {
            headers: {
                "Content-Type": "text/plain; charset=utf-8",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store",
                "Subscription-Userinfo": `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`,
            },
        });
    },
};

async function flushExpiredTraffic(env) {
    const now = Date.now();
    for (const [uname, cachedBytes] of GLOBAL_TRAFFIC_CACHE.entries()) {
        const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
        if (cachedBytes <= 0 && cachedReqs <= 0) continue;
        if (GLOBAL_WRITE_LOCK.get(uname)) continue;
        const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
        const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
        if (activeCount <= 0 || now - lastActive > 20000) {
            GLOBAL_WRITE_LOCK.set(uname, true);
            const deltaGb = cachedBytes / (1024 * 1024 * 1024);
            try { await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run(); } catch (e) {} finally {
                GLOBAL_WRITE_LOCK.delete(uname); GLOBAL_TRAFFIC_CACHE.delete(uname); USER_REQ_CACHE.delete(uname); GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
            }
        }
    }
}

async function trackRequest(env, ctx) { GLOBAL_REQ_COUNT++; }

async function connectProxy(proxyStr, targetHost, targetPort, initialPayload) {
    let sock;
    if (proxyStr.includes("@")) {
        const [auth, addr] = proxyStr.split("@");
        const [user, pass] = auth.split(":");
        const [host, port] = addr.split(":");
        sock = await connect({ hostname: host, port: parseInt(port) || 1080 }, { secureTransport: "starttls" });
        const encoder = new TextEncoder();
        const authMsg = encoder.encode(`\x05\x02\x00\x02` + (Buffer.from(user).length) + Buffer.from(user) + (Buffer.from(pass).length) + Buffer.from(pass));
        sock.write(authMsg);
        const res = await sock.read(new Uint8Array(2)); 
        if (res[1] !== 0) throw new Error("Proxy auth failed");
    } else {
        const [host, port] = proxyStr.split(":");
        sock = await connect({ hostname: host, port: parseInt(port) || 1080 });
        const res = await sock.read(new Uint8Array(2));
        if (res[1] !== 0) throw new Error("Proxy connect failed");
    }
    const reqB = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, targetHost.length]), Buffer.from(targetHost), Buffer.alloc(2), Buffer.alloc(0)]);
    sock.write(reqB);
    const respH = await sock.read(new Uint8Array(10));
    if (respH[1] !== 0) throw new Error("Proxy target connect failed");
    if (initialPayload) sock.write(initialPayload);
    return sock;
}

async function handleVLESS(env, storedData = null, ctx = null, request = null) {
    const clientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
    const socketPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(socketPair);
    serverSock.accept();
    serverSock.binaryType = "arraybuffer";

    let username = null;
    let validUUID = null;
    let uncountedBytes = 0;
    const proxyIP = storedData?.proxy_ip || "proxyip.cmliussss.net";
    
    function addBytes(bytes) {
        if (bytes <= 0) return;
        if (!username) { uncountedBytes += bytes; return; }
        if (uncountedBytes > 0) { bytes += uncountedBytes; uncountedBytes = 0; }
        let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
        GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
        GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
        if (GLOBAL_WRITE_LOCK.get(username)) return;
        let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
        let now = Date.now();
        if (current >= 10 * 1024 * 1024 || (current > 0 && now - lastDbWrite > 60000)) {
            GLOBAL_WRITE_LOCK.set(username, true);
            let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
            let toCommitReq = USER_REQ_CACHE.get(username) || 0;
            if (toCommit <= 0 && toCommitReq <= 0) { GLOBAL_WRITE_LOCK.set(username, false); return; }
            GLOBAL_TRAFFIC_CACHE.set(username, 0); USER_REQ_CACHE.set(username, 0); GLOBAL_LAST_DB_WRITE.set(username, now);
            let deltaGb = toCommit / (1024 * 1024 * 1024);
            let writeTask = async () => {
                try { await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, username).run(); } catch (e) {} finally { GLOBAL_WRITE_LOCK.set(username, false); }
            };
            if (ctx) ctx.waitUntil(writeTask()); else writeTask();
        }
    }

    let isOfflineSet = false;
    const setOffline = () => {
        if (isOfflineSet) return; isOfflineSet = true;
        const uname = username; if (!uname) return;
        if (clientIP && clientIP !== "unknown" && validUUID) {
            const removeIpTask = async () => {
                try {
                    const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
                    if (user) {
                        let activeIps = JSON.parse(user.active_ips || "{}");
                        if (activeIps[clientIP]) {
                            if (typeof activeIps[clientIP] === "object") { activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1; if (activeIps[clientIP].count <= 0) delete activeIps[clientIP]; }
                            else delete activeIps[clientIP];
                            await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
                        }
                    }
                } catch (e) {}
            };
            if (ctx) ctx.waitUntil(removeIpTask()); else removeIpTask();
        }
        let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 1; activeCount--;
        if (activeCount <= 0) {
            ACTIVE_CONNECTIONS_COUNT.delete(uname);
            let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0; let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
            if ((cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
                GLOBAL_WRITE_LOCK.set(uname, true); GLOBAL_TRAFFIC_CACHE.set(uname, 0); USER_REQ_CACHE.set(uname, 0);
                const deltaGb = cachedBytes / (1024 * 1024 * 1024);
                const writeTask = async () => {
                    try { await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run(); } catch (e) {} finally { GLOBAL_WRITE_LOCK.delete(uname); GLOBAL_LAST_ACTIVE_WRITE.delete(uname); }
                };
                if (ctx) ctx.waitUntil(writeTask()); else writeTask();
            } else { GLOBAL_LAST_ACTIVE_WRITE.delete(uname); }
        } else { ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount); }
    };

    const closeSocketQuietly = (s) => { try { s.close(); } catch(e){} };

    serverSock.addEventListener("close", () => { setOffline(); });
    serverSock.addEventListener("error", () => { setOffline(); });

    let chunkBuffer = new Uint8Array(0);
    let remoteSocket = null;
    let remoteWriter = null;
    let isHeaderParsed = false;

    serverSock.addEventListener("message", async (event) => {
        if (typeof event.data === "string") return;
        let data = new Uint8Array(event.data);
        
        if (!isHeaderParsed) {
            chunkBuffer = new Uint8Array([...chunkBuffer, ...data]);
            if (chunkBuffer.length < 17) return; // Wait for full VLESS header

            const version = chunkBuffer[0];
            const uuidLength = chunkBuffer[1];
            if (version !== 0 || uuidLength !== 16) { closeSocketQuietly(serverSock); return; }

            const uuidArray = chunkBuffer.slice(2, 18);
            validUUID = Array.from(uuidArray).map(b => b.toString(16).padStart(2, '0')).join('');
            
            try {
                const user = await env.DB.prepare("SELECT username, is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
                if (!user || user.is_active === 0) { closeSocketQuietly(serverSock); return; }
                if (user.limit_gb && user.used_gb >= user.limit_gb) { closeSocketQuietly(serverSock); return; }
                if (user.limit_req && user.used_req >= user.limit_req) { closeSocketQuietly(serverSock); return; }
                if (user.expiry_days && user.created_at) { if (new Date() > new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000)) { closeSocketQuietly(serverSock); return; } }
                
                username = user.username;
                ACTIVE_CONNECTIONS_COUNT.set(username, (ACTIVE_CONNECTIONS_COUNT.get(username) || 0) + 1);
                USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) + 1);

                if (clientIP && clientIP !== "unknown" && user.ip_limit) {
                    let activeIps = JSON.parse(user.active_ips || "{}");
                    activeIps[clientIP] = { count: (activeIps[clientIP]?.count || 0) + 1, timestamp: Date.now() };
                    if (Object.keys(activeIps).length > user.ip_limit) { closeSocketQuietly(serverSock); return; }
                    env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), Date.now(), validUUID).run();
                } else {
                    env.DB.prepare("UPDATE users SET last_active = ? WHERE uuid = ?").bind(Date.now(), validUUID).run();
                }
            } catch(e) { closeSocketQuietly(serverSock); return; }

            // Parse target address
            const addrlen = chunkBuffer[18];
            let targetHost, targetPort;
            let payloadStart = 19 + addrlen;

            if (chunkBuffer[17] === 1) { // IPv4
                targetHost = Array.from(chunkBuffer.slice(19, 23)).join('.');
                targetPort = (chunkBuffer[23] << 8) | chunkBuffer[24];
                payloadStart = 25;
            } else if (chunkBuffer[17] === 2) { // Domain
                targetHost = new TextDecoder().decode(chunkBuffer.slice(19, 19 + addrlen - 2));
                targetPort = (chunkBuffer[19 + addrlen - 2] << 8) | chunkBuffer[19 + addrlen - 1];
            } else if (chunkBuffer[17] === 3) { // IPv6
                targetHost = `[${Array.from(chunkBuffer.slice(19, 35)).map(b=>b.toString(16).padStart(2,'0')).join(':')}]`;
                targetPort = (chunkBuffer[35] << 8) | chunkBuffer[36];
                payloadStart = 37;
            } else { closeSocketQuietly(serverSock); return; }

            const initialPayload = chunkBuffer.slice(payloadStart);
            isHeaderParsed = true;

            try {
                if (targetPort === 80 || targetHost.includes("cloudflare")) {
                    remoteSocket = await connect({ hostname: targetHost.replace("[","").replace("]",""), port: targetPort });
                } else {
                    remoteSocket = await connect({ hostname: proxyIP, port: targetPort || 443 });
                }
                remoteWriter = remoteSocket.writable.getWriter();
                if (initialPayload.length > 0) {
                    addBytes(initialPayload.length);
                    await remoteWriter.write(initialPayload);
                }
                
                // Pipe remote to client
                (async () => {
                    const reader = remoteSocket.readable.getReader();
                    try {
                        while (true) {
                            const { done, value } = await reader.read();
                            if (done) break;
                            addBytes(value.length);
                            if (serverSock.readyState === WebSocket.OPEN) serverSock.send(value);
                        }
                    } catch(e) {} finally { closeSocketQuietly(serverSock); }
                })();

            } catch(e) { closeSocketQuietly(serverSock); }
        } else {
            // Forward data to remote
            if (remoteWriter) {
                addBytes(data.length);
                try { await remoteWriter.write(data); } catch(e) { closeSocketQuietly(serverSock); }
            }
        }
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}


// ================= HTML / CSS TEMPLATES (LOWKEY THEME) =================

const THEME_CSS = `
:root {
  --gold-1: #ffd86f; --gold-2: #f5c242; --gold-3: #c89c2b;
  --bg-1: #050505; --bg-2: #0b0b0f;
  --text-main: #f9f6ee; --text-muted: #aaa39a;
  --danger: #ff4f4f; --accent: #40c9ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(circle at 10% 0%, #3d2a0b 0, transparent 45%), radial-gradient(circle at 90% 100%, #332007 0, transparent 50%), radial-gradient(circle at 50% 0%, #222 0, #050505 65%); color: var(--text-main); font-family: system-ui, -apple-system, sans-serif; padding: 16px; }
.wrapper { width: 100%; max-width: 960px; }
.card { position: relative; border-radius: 18px; padding: 24px 22px 20px; background: linear-gradient(135deg, rgba(255, 216, 111, 0.08), rgba(12, 12, 12, 0.9)), radial-gradient(circle at 0 0, rgba(255, 216, 111, 0.35), transparent 55%); border: 1px solid rgba(255, 216, 111, 0.35); box-shadow: 0 18px 40px rgba(0,0,0,0.9); backdrop-filter: blur(22px); }
.card::before { content: ""; position: absolute; inset: 0; border-radius: inherit; padding: 1px; background: linear-gradient(135deg, rgba(255, 216, 111, 0.8), rgba(64, 201, 255, 0.3)); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude; opacity: 0.45; pointer-events: none; }
.header { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: baseline; justify-content: space-between; margin-bottom: 18px; }
.brand { display: flex; align-items: center; gap: 10px; }
.logo-circle { width: 40px; height: 40px; border-radius: 50%; background: conic-gradient(from 210deg, #fff2c2, #ffd86f, #f5c242, #c89c2b, #fff2c2); padding: 2px; box-shadow: 0 0 20px rgba(255, 216, 111, 0.75); flex-shrink: 0; }
.logo-circle-inner { width: 100%; height: 100%; border-radius: 50%; background: radial-gradient(circle at 30% 20%, #ffffff, #201805 60%, #050505 100%); display: flex; align-items: center; justify-content: center; color: var(--gold-1); font-weight: 700; font-size: 18px; letter-spacing: 1px; }
.brand-text-main { font-size: 24px; font-weight: 800; letter-spacing: 0.12em; text-transform: uppercase; background: linear-gradient(120deg, #fff6d4, #ffd86f, #f5c242, #ffec9a); -webkit-background-clip: text; color: transparent; }
.brand-sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
.field { display: flex; flex-direction: column; gap: 5px; font-size: 13px; margin-bottom: 12px; }
.field-label { color: #ddd2bf; font-size: 12px; margin-bottom: 4px; }
.field input, .field select { background: rgba(5, 5, 5, 0.9); border-radius: 9px; border: 1px solid rgba(255, 216, 111, 0.3); padding: 10px 12px; color: var(--text-main); font: inherit; outline: none; transition: border 0.16s ease, box-shadow 0.16s ease; }
.field input:focus, .field select:focus { border-color: var(--gold-1); box-shadow: 0 0 0 1px rgba(255, 216, 111, 0.4); }
.btn-primary { border-radius: 999px; border: none; padding: 11px 28px; font-size: 14px; font-weight: 600; cursor: pointer; color: #111; background: linear-gradient(135deg, #fff6da, #ffd86f, #f5c242, #ffec9a); box-shadow: 0 10px 24px rgba(0,0,0,0.85), 0 0 18px rgba(255, 216, 111, 0.9); display: inline-flex; align-items: center; gap: 8px; transition: transform 0.12s ease, box-shadow 0.12s ease; margin-top: 10px; width: 100%; justify-content: center; }
.btn-primary:hover { filter: brightness(1.05); transform: translateY(-1px); }
.error { color: var(--danger); font-size: 12px; margin-top: 8px; display: none; }
a { color: var(--gold-1); text-decoration: none; }
`;

const HTML_TEMPLATES = {
    nginx: `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>lowkey</title><style>${THEME_CSS}</style></head><body><div class="wrapper"><div class="card" style="text-align:center; padding: 40px;"><div class="brand" style="justify-content:center;"><div class="logo-circle"><div class="logo-circle-inner">L</div></div><div><div class="brand-text-main">lowkey</div><div class="brand-sub">Stay invisible.</div></div></div></div></div></body></html>`,
    
    setup: `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>lowkey - Setup</title><style>${THEME_CSS}</style></head><body><div class="wrapper"><div class="card"><div class="header"><div class="brand"><div class="logo-circle"><div class="logo-circle-inner">L</div></div><div><div class="brand-text-main">lowkey</div><div class="brand-sub">Initial Setup</div></div></div></div><div class="field"><div class="field-label">Create Admin Password</div><input type="password" id="pwd" placeholder="Enter password..."></div><button class="btn-primary" onclick="setup()">Initialize Panel</button><div class="error" id="err"></div></div></div><script>async function setup(){const p=document.getElementById('pwd').value;const r=await fetch('/api/setup-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});const d=await r.json();if(d.success)window.location.href='/panel';else{document.getElementById('err').style.display='block';document.getElementById('err').innerText=d.error;}}</script></body></html>`,
    
    login: `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>lowkey - Login</title><style>${THEME_CSS}</style></head><body><div class="wrapper"><div class="card"><div class="header"><div class="brand"><div class="logo-circle"><div class="logo-circle-inner">L</div></div><div><div class="brand-text-main">lowkey</div><div class="brand-sub">Secure Access</div></div></div></div><div class="field"><div class="field-label">Password</div><input type="password" id="pwd" placeholder="Enter password..." onkeypress="if(event.key==='Enter')login()"></div><button class="btn-primary" onclick="login()">Unlock Dashboard</button><div class="error" id="err"></div></div></div><script>async function login(){const p=document.getElementById('pwd').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});const d=await r.json();if(d.success)window.location.href='/panel';else{document.getElementById('err').style.display='block';document.getElementById('err').innerText=d.error;}}</script></body></html>`,

    status: `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>lowkey - Status</title><style>${THEME_CSS} .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 20px; } .stat-box { background: rgba(0,0,0,0.4); border: 1px solid rgba(255,216,111,0.2); border-radius: 12px; padding: 12px; text-align: center; } .stat-val { font-size: 18px; font-weight: 700; color: var(--gold-1); } .stat-lbl { font-size: 11px; color: var(--text-muted); margin-top: 4px; }</style></head><body><div class="wrapper"><div class="card"><div class="header"><div class="brand"><div class="logo-circle"><div class="logo-circle-inner">L</div></div><div><div class="brand-text-main" id="uname">lowkey</div><div class="brand-sub">Connection Status</div></div></div></div><div class="stat-grid" id="stats"></div><div style="margin-top:20px; font-size:12px; color:var(--text-muted); text-align:center;">Telegram: <a href="https://t.me/lowkey">@lowkey</a></div></div></div>/* {{USER_DATA_PLACEHOLDER}} */<script>const u=window.statusUser;if(!u){document.getElementById('stats').innerHTML='<p style="color:var(--danger)">User not found</p>';}else{document.getElementById('uname').innerText=u.username;const remG=u.limit_gb?(u.limit_gb-u.used_gb).toFixed(2)+' GB':'Unlimited';const remR=u.limit_req?(u.limit_req-u.used_req)+' Req':'Unlimited';let remT='Unlimited';if(u.expiry_days&&u.created_at){const exp=new Date(new Date(u.created_at).getTime()+u.expiry_days*86400000);const d=Math.ceil((exp.getTime()-Date.now())/86400000);remT=d>0?d+' Days':'Expired';}document.getElementById('stats').innerHTML=\`<div class="stat-box"><div class="stat-val">\${u.online_count}</div><div class="stat-lbl">Online IPs</div></div><div class="stat-box"><div class="stat-val">\${remG}</div><div class="stat-lbl">Remaining Vol</div></div><div class="stat-box"><div class="stat-val">\${remT}</div><div class="stat-lbl">Remaining Time</div></div><div class="stat-box"><div class="stat-val">\${remR}</div><div class="stat-lbl">Remaining Req</div></div>\`;}</script></body></html>`,

    panel: `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>lowkey - Admin</title><style>
        ${THEME_CSS}
        body { align-items: flex-start; padding: 20px; }
        .top-bar { width: 100%; max-width: 1200px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .dash-grid { width: 100%; max-width: 1200px; display: grid; grid-template-columns: 1fr 320px; gap: 20px; }
        .main-card { grid-column: 1; }
        .side-card { grid-column: 2; display: flex; flex-direction: column; gap: 20px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 15px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }
        th { color: var(--text-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; }
        .badge-status { padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
        .bg-green { background: rgba(36,255,141,0.15); color: #24ff8d; }
        .bg-red { background: rgba(255,79,79,0.15); color: #ff4f4f; }
        .btn-sm { padding: 5px 10px; border-radius: 8px; border: 1px solid rgba(255,216,111,0.3); background: transparent; color: var(--gold-1); cursor: pointer; font-size: 11px; margin-right: 4px; }
        .btn-sm:hover { background: rgba(255,216,111,0.1); }
        .btn-sm.danger { border-color: rgba(255,79,79,0.3); color: var(--danger); }
        .btn-sm.danger:hover { background: rgba(255,79,79,0.1); }
        .settings-group { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 12px; border: 1px solid rgba(255,216,111,0.15); }
        .settings-title { font-size: 14px; color: var(--gold-1); margin-bottom: 12px; font-weight: 600; }
        @media (max-width: 900px) { .dash-grid { grid-template-columns: 1fr; } .side-card { grid-column: 1; } }
    </style></head><body>
    <div class="top-bar">
        <div class="brand"><div class="logo-circle"><div class="logo-circle-inner">L</div></div><div><div class="brand-text-main">lowkey</div><div class="brand-sub">Admin Dashboard</div></div></div>
        <div style="display:flex;gap:10px;align-items:center;">
            <span style="font-size:12px;color:var(--text-muted)">Telegram: <a href="https://t.me/lowkey">@lowkey</a></span>
            <button class="btn-sm" onclick="location.href='/api/logout'" style="background:rgba(255,79,79,0.1);color:var(--danger);border-color:var(--danger)">Logout</button>
        </div>
    </div>
    
    <div class="dash-grid">
        <div class="card main-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <div class="settings-title" style="margin:0;">Users</div>
                <button class="btn-sm" onclick="openAddModal()">+ Add User</button>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead><tr><th>Name</th><th>Usage</th><th>Expiry</th><th>IPs</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody id="users-tbody"></tbody>
                </table>
            </div>
        </div>

        <div class="side-card">
            <div class="card settings-group">
                <div class="settings-title">Proxy Settings</div>
                <div class="field"><div class="field-label">Proxy IP</div><input id="s-proxy" placeholder="e.g. proxyip.cmliussss.net"></div>
                <div class="field"><div class="field-label">SOCKS5 (optional)</div><input id="s-socks" placeholder="user:pass@host:port"></div>
                <button class="btn-primary" style="margin-top:0;padding:8px;font-size:12px;" onclick="saveSettings()">Save Proxy</button>
            </div>
            
            <div class="card settings-group">
                <div class="settings-title">System</div>
                <button class="btn-sm" style="width:100%;margin-bottom:8px;" onclick="restartCore()">Restart Core</button>
                <button class="btn-sm" style="width:100%;" onclick="updatePanel()">Update Panel</button>
            </div>
        </div>
    </div>

    <!-- Add/Edit Modal -->
    <div id="modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.8);z-index:99;align-items:center;justify-content:center;padding:20px;">
        <div class="card" style="max-width:500px;width:100%;max-height:90vh;overflow-y:auto;">
            <div class="settings-title">User Details</div>
            <input type="hidden" id="m-username-old">
            <div class="field"><div class="field-label">Username</div><input id="m-username"></div>
            <div class="field"><div class="field-label">UUID</div><input id="m-uuid"></div>
            <div class="field"><div class="field-label">Data Limit (GB)</div><input id="m-limit_gb" type="number" step="0.1" placeholder="0 = unlimited"></div>
            <div class="field"><div class="field-label">Days Limit</div><input id="m-expiry_days" type="number" placeholder="0 = unlimited"></div>
            <div class="field"><div class="field-label">Custom IPs (newline separated)</div><textarea id="m-ips" style="width:100%;min-height:60px;background:rgba(5,5,5,0.9);border:1px solid rgba(255,216,111,0.3);border-radius:9px;padding:8px;color:var(--text-main);resize:vertical;"></textarea></div>
            <div class="field"><div class="field-label">Ports (comma separated)</div><input id="m-port" placeholder="443,2053,8443"></div>
            <div style="display:flex;gap:10px;margin-top:15px;">
                <button class="btn-primary" style="flex:1" onclick="saveUser()">Save</button>
                <button class="btn-sm" style="flex:1;text-align:center;padding:10px" onclick="closeModal()">Cancel</button>
            </div>
        </div>
    </div>

    <script>
        let usersData = [];
        async function load() {
            const r = await fetch('/api/users');
            usersData = (await r.json()).users || [];
         renderTable();
         loadSettings();
        }

        function renderTable() {
            const tb = document.getElementById('users-tbody');
            tb.innerHTML = usersData.map(u => {
                const exp = u.expiry_days && u.created_at ? Math.ceil((new Date(u.created_at).getTime() + u.expiry_days*86400000 - Date.now())/86400000) : 'Inf';
                const usage = u.limit_gb ? (u.used_gb||0).toFixed(2)+'/'+u.limit_gb : (u.used_gb||0).toFixed(2)+' GB';
                const status = u.is_active == 1 ? '<span class="badge-status bg-green">Active</span>' : '<span class="badge-status bg-red">Disabled</span>';
                return \`<tr>
                    <td>\${u.username}</td>
                    <td>\${usage}</td>
                    <td>\${exp} Days</td>
                    <td>\${u.online_count || 0}/\${u.ip_limit || 'Inf'}</td>
                    <td>\${status}</td>
                    <td>
                        <button class="btn-sm" onclick="editUser('\${u.username}')">Edit</button>
                        <button class="btn-sm" onclick="toggleUser('\${u.username}')">Toggle</button>
                        <button class="btn-sm danger" onclick="delUser('\${u.username}')">Del</button>
                    </td>
                </tr>\`;
            }).join('');
        }

        function openAddModal() {
            document.getElementById('m-username-old').value = '';
            document.getElementById('m-username').value = '';
            document.getElementById('m-uuid').value = crypto.randomUUID();
            document.getElementById('m-limit_gb').value = '';
            document.getElementById('m-expiry_days').value = '';
            document.getElementById('m-ips').value = '';
            document.getElementById('m-port').value = '443,8443,2053';
            document.getElementById('modal').style.display = 'flex';
        }

        function editUser(name) {
            const u = usersData.find(x=>x.username===name);
            if(!u) return;
            document.getElementById('m-username-old').value = u.username;
            document.getElementById('m-username').value = u.username;
            document.getElementById('m-uuid').value = u.uuid;
            document.getElementById('m-limit_gb').value = u.limit_gb||'';
            document.getElementById('m-expiry_days').value = u.expiry_days||'';
            document.getElementById('m-ips').value = u.ips||'';
            document.getElementById('m-port').value = u.port||'';
            document.getElementById('modal').style.display = 'flex';
        }

        function closeModal() { document.getElementById('modal').style.display = 'none'; }

        async function saveUser() {
            const oldName = document.getElementById('m-username-old').value;
            const data = {
                username: document.getElementById('m-username').value,
                uuid: document.getElementById('m-uuid').value,
                limit_gb: document.getElementById('m-limit_gb').value || null,
                expiry_days: document.getElementById('m-expiry_days').value || null,
                ips: document.getElementById('m-ips').value || null,
                port: document.getElementById('m-port').value || null
            };
            const url = oldName ? '/api/users/'+encodeURIComponent(oldName) : '/api/users';
            const res = await fetch(url, { method: oldName?'PUT':'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
            if(res.ok) { closeModal(); load(); } else alert('Error saving user');
        }

        async function toggleUser(name) { await fetch('/api/users/'+encodeURIComponent(name), {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({toggle_only:true})}); load(); }
        async function delUser(name) { if(confirm('Delete?')){ await fetch('/api/users/'+encodeURIComponent(name), {method:'DELETE'}); load(); } }

        async function loadSettings() {
            const r = await fetch('/api/proxy-ip');
            const d = await r.json();
            document.getElementById('s-proxy').value = d.proxy_ip || '';
            document.getElementById('s-socks').value = d.socks5 || '';
        }

        async function saveSettings() {
            await fetch('/api/proxy-ip', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ proxy_ip: document.getElementById('s-proxy').value, socks5: document.getElementById('s-socks').value }) });
            alert('Saved');
        }

        async function restartCore() { if(confirm('Restart?')){ const r = await fetch('/api/restart-core', {method:'POST'}); alert(r.ok?'Restarting':'Error'); } }
        async function updatePanel() { if(confirm('Update?')){ const r = await fetch('/api/update-panel', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({})}); alert(r.ok?'Updating':'Error'); } }

        load();
    </script>
    </body></html>`
};
