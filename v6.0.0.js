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
		if (Router.isWebSocketUpgrade(request) && url.pathname === "/ZEUS_PANEL_BOT") {
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
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
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
				if (proxyRow && proxyRow.value) {
					proxyIP = proxyRow.value;
				}
				const socksRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				if (socksRow && socksRow.value) {
					socks5 = socksRow.value;
				}
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
			if (!user || user.connection_type !== atob("dmxlc3M=")) {
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
			return new Response(HTML_TEMPLATES.setup, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(HTML_TEMPLATES.login, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		}
		return new Response(HTML_TEMPLATES.panel, {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	},
	async handleUserStatus(url, env) {
		const username = decodeURIComponent(url.pathname.slice(8));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const userJson = JSON.stringify({
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: user.used_gb,
				limit_req: user.limit_req,
				used_req: user.used_req,
				is_active: user.is_active,
				online_count: getActiveIpCount(user.active_ips),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
			});
			const html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", `window.statusUser = ${userJson};`);
			return new Response(html, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const { password } = await request.json();
			if (!password || password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(password);
			await DbService.setPanelPassword(env.DB, hashed);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const { password } = await request.json();
			const hashedInput = await DbService.sha256(password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash === hashedInput) {
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			}
			return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const { api_token } = await request.json();
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "این توکن متعلق به صاحب پنل نیست (ای کــثـــکـــش)" }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
				cachedPanelPassword = null;
				return new Response(JSON.stringify({ success: true }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized) {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			let currentToken = env.CF_API_TOKEN || body.cf_token;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + currentToken },
					});
					const accData = await accRes.json();
					if (!accData.success || accData.result.length === 0) throw new Error("توکن نامعتبر است یا اکانتی یافت نشد.");
					currentAccountId = accData.result[0].id;
				}

				const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now() + Math.random(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس جدید از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر. توکن نامعتبر است.");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.name === "CF_API_TOKEN") {
						newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
					} else if (b.name === "CF_ACCOUNT_ID") {
						newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
					}
				}

				if (!newBindings.some((b) => b.name === "CF_API_TOKEN")) {
					newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				}
				if (!newBindings.some((b) => b.name === "CF_ACCOUNT_ID")) {
					newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				}

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال آپدیت در کلودفلر.");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				const errorMsg = err.message + " | در صورت عدم موفقیت، از طریق لینک زیر آپدیت کنید: https://zeus-panel.ir-netlify.workers.dev/";
				return new Response(JSON.stringify({ error: errorMsg }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			let currentToken = env.CF_API_TOKEN;
			let currentAccountId = env.CF_ACCOUNT_ID;

			if (!currentToken || !currentAccountId) {
				return new Response(JSON.stringify({ error: "TOKEN_REQUIRED" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}

			try {
				const githubRes = await fetch("https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/zeus.js?t=" + Date.now(), {
					headers: {
						"Cache-Control": "no-cache, no-store, must-revalidate",
						Pragma: "no-cache",
						Expires: "0",
					},
				});
				if (!githubRes.ok) throw new Error("خطا در دریافت سورس از گیت‌هاب");
				const newCode = await githubRes.text();

				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: { Authorization: "Bearer " + currentToken },
				});
				const bindingsData = await bindingsRes.json();
				if (!bindingsData.success) throw new Error("عدم دسترسی به تنظیمات ورکر");

				const newBindings = [];
				for (const b of bindingsData.result) {
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					}
				}

				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });

				const metadata = {
					main_module: "zeus.js",
					compatibility_date: "2024-02-08",
					bindings: newBindings,
				};

				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
				formData.append("zeus.js", new Blob([newCode], { type: "application/javascript+module" }), "zeus.js");

				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: { Authorization: "Bearer " + currentToken },
					body: formData,
				});
				const deployData = await deployRes.json();
				if (!deployData.success) throw new Error("خطا در اعمال ری‌استارت در کلودفلر");

				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await request.json();
			if (!current_password || !new_password) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی و جدید الزامی هستند" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(current_password);
			const storedHash = await DbService.getPanelPassword(env.DB);
			if (storedHash && storedHash !== currentHash) {
				return new Response(JSON.stringify({ error: "رمز عبور فعلی اشتباه است" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (new_password.length < 4) {
				return new Response(JSON.stringify({ error: "رمز عبور جدید باید حداقل ۴ کاراکتر باشد" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(new_password);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/locations") {
			try {
				const response = await fetch("https://speed.cloudflare.com/locations", {
					headers: { Referer: "https://speed.cloudflare.com/" },
				});
				const data = await response.json();
				return new Response(JSON.stringify(data), {
					headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach((r) => {
							settingsObj[r.key] = r.value;
						});
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
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
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "proxyip.cmliussss.net",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : "",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const { proxy } = await request.json();
			if (!proxy) return new Response(JSON.stringify({ error: "پروکسی وارد نشده است" }), { status: 400, headers: { "Content-Type": "application/json" } });
			try {
				let ip = "";
				let workingProxy = proxy;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = proxy.match(/server=([^&]+)/)?.[1] || "";
				} else {
					let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					let remain = cleanProxy;
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						ip = remain.substring(1, remain.indexOf("]"));
					} else {
						const lastColon = remain.lastIndexOf(":");
						if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
						else ip = remain;
					}
				}
				let country = "UN";
				if (ip) {
					try {
						const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
						const geoData = await geoRes.json();
						if (geoData && geoData.countryCode) country = geoData.countryCode;
					} catch (e) {}
				}
				const startTime = Date.now();
				const payload = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
				const s = await connectProxy(proxy, "1.1.1.1", 80, payload);
				const reader = s.readable.getReader();
				const res = await reader.read();
				if (res.done || !res.value) {
					s.close();
					throw new Error("تایم‌اوت در دریافت دیتا");
				}
				s.close();
				const ping = Date.now() - startTime;
				return new Response(JSON.stringify({ success: true, ping, country }), { headers: { "Content-Type": "application/json" } });
			} catch (e) {
				let msg = e.message;
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "ارتباط با سرور قطع شد (احتمالاً پروکسی مسدود یا خاموش است)";
				else if (msg.includes("timeout") || msg.includes("timed out") || msg.includes("تایم‌اوت")) msg = "تایم‌اوت در اتصال (پروکسی در دسترس نیست)";
				else if (msg.includes("Invalid URL") || msg.includes("Invalid format")) msg = "فرمت وارد شده برای پروکسی اشتباه است";
				else if (msg === "err") msg = "خطای نامشخص (ارتباط برقرار نشد)";
				return new Response(JSON.stringify({ error: msg }), { status: 500, headers: { "Content-Type": "application/json" } });
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
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0 WHERE username = ?").bind(username).run();
							GLOBAL_TRAFFIC_CACHE.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0 WHERE username = ?").bind(username).run();
							USER_REQ_CACHE.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE username = ?").bind(username).run();
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = body;
						if (new_username && new_username !== username) {
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "این نام کاربری از قبل وجود دارد" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (GLOBAL_TRAFFIC_CACHE.has(username)) {
								GLOBAL_TRAFFIC_CACHE.set(new_username, GLOBAL_TRAFFIC_CACHE.get(username));
								GLOBAL_TRAFFIC_CACHE.delete(username);
							}
							if (USER_REQ_CACHE.has(username)) {
								USER_REQ_CACHE.set(new_username, USER_REQ_CACHE.get(username));
								USER_REQ_CACHE.delete(username);
							}
							if (ACTIVE_CONNECTIONS_COUNT.has(username)) {
								ACTIVE_CONNECTIONS_COUNT.set(new_username, ACTIVE_CONNECTIONS_COUNT.get(username));
								ACTIVE_CONNECTIONS_COUNT.delete(username);
							}
							if (GLOBAL_LAST_ACTIVE_WRITE.has(username)) {
								GLOBAL_LAST_ACTIVE_WRITE.set(new_username, GLOBAL_LAST_ACTIVE_WRITE.get(username));
								GLOBAL_LAST_ACTIVE_WRITE.delete(username);
							}
						}
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ? WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) {}
					const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
					const now = Date.now();
					const enrichedUsers = (results || []).map((user) => ({
						...user,
						is_online: user.last_active && now - user.last_active < 20000 ? 1 : 0,
						online_count: getActiveIpCount(user.active_ips),
					}));
					let cfReqs = { today: 0, total: 0 };
					try {
						const liveCf = await getCfUsage(env);
						const todayStr = new Date().toISOString().split("T")[0];
						const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
						const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
						let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
						let dbToday = 0;
						if (dateRow && dateRow.value === todayStr) {
							const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
							dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
						}
						if (liveCf.today > dbToday) {
							dbToday = liveCf.today;
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbToday), String(dbToday)).run();
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(todayStr, todayStr).run();
						}
						if (liveCf.total > dbTotal) {
							dbTotal = liveCf.total;
							await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(dbTotal), String(dbTotal)).run();
						}
						cfReqs.today = dbToday + GLOBAL_REQ_COUNT;
						cfReqs.total = dbTotal + GLOBAL_REQ_COUNT;
					} catch (e) {}
					return new Response(
						JSON.stringify({
							users: enrichedUsers,
							serverTime: now,
							cfRequestsToday: cfReqs.today,
							cfRequestsTotal: cfReqs.total,
						}),
						{
							headers: {
								"Content-Type": "application/json",
								"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
							},
						},
					);
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip } = await request.json();
					if (!username) {
						return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 32) {
						return new Response(JSON.stringify({ error: "نام کاربری نمی‌تواند بیشتر از ۳۲ کاراکتر باشد" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					const finalUuid = uuid || crypto.randomUUID();
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					try {
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, atob("dmxlc3M="), tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined ? frag_len : "200-3000", frag_int !== undefined ? frag_int : "1-2", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null)
							.run();
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
		try {
			await db
				.prepare(
					`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          uuid TEXT,
          limit_gb REAL,
          expiry_days INTEGER,
          ips TEXT,
          connection_type TEXT,
          tls TEXT,
          port INTEGER,
          used_gb REAL DEFAULT 0,
          is_active INTEGER DEFAULT 1,
          last_active INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `,
				)
				.run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN fingerprint TEXT DEFAULT 'chrome'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN max_connections INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN limit_req INTEGER").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN used_req INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN ip_limit INTEGER DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN active_ips TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_porn INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN block_ads INTEGER DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_len TEXT DEFAULT '200-3000'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN frag_int TEXT DEFAULT '1-2'").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN lifetime_used_gb REAL DEFAULT 0").run();
		} catch (e) {}
		try {
			await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_proxy_ip TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_proxy_iata TEXT DEFAULT NULL").run();
		} catch (e) {}
		try {
			await db.prepare("ALTER TABLE users ADD COLUMN user_socks5 TEXT DEFAULT NULL").run();
		} catch (e) {}
		schemaEnsured = true;
	},
	async getPanelPassword(db) {
		if (cachedPanelPassword !== null) return cachedPanelPassword;
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row ? row.value : "";
			return cachedPanelPassword || null;
		} catch (e) {
			return null;
		}
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
		const sessionToken = sessionCookie.split("=")[1].trim();
		return sessionToken === storedPasswordHash;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 20000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
const SubscriptionService = {
	async generateText(user, host) {
		let ips = [host];
		if (user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const links = [];
		const m1 = decodeURIComponent("%E2%9A%A0%EF%B8%8F%D9%BE%D9%86%D9%84%20%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86%20%D9%88%20%D8%BA%DB%8C%D8%B1%20%D9%82%D8%A7%D8%A8%D9%84%20%D9%81%D8%B1%D9%88%D8%B4%E2%9A%A0%EF%B8%8F");
		const m2 = decodeURIComponent("%F0%9F%9A%80%40ZEUS_PANEL_BOT%20%D8%B3%D8%A7%D8%AE%D8%AA%20%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86%F0%9F%9A%80");
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=%2FZEUS_PANEL_BOT#" + encodeURIComponent(m1));
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@0.0.0.0:1?encryption=none&security=none&type=ws&host=" + host + "&path=%2FZEUS_PANEL_BOT#" + encodeURIComponent(m2));
		let remVol = "Unlimited";
		if (user.limit_gb) {
			let rem = user.limit_gb - (user.used_gb || 0);
			remVol = rem > 0 ? rem.toFixed(2) + "GB" : "0GB";
		}
		let remTime = "Unlimited";
		if (user.expiry_days && user.created_at) {
			const created = new Date(user.created_at);
			const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
			const diffDays = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
			remTime = diffDays > 0 ? diffDays + "Days" : "0Days";
		}
		let remReq = "Unlimited";
		if (user.limit_req) {
			let rem = user.limit_req - (user.used_req || 0);
			remReq = rem > 0 ? rem.toLocaleString() + "Req" : "0Req";
		}
		const infoRemark = "📊 remaining | \u200E" + remVol + " | \u200E" + remTime + " | \u200E" + remReq;
		links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + host + ":80?path=%2FZEUS_PANEL_BOT&security=none&encryption=none&host=" + host + "&fp=" + fp + "&type=ws#" + encodeURIComponent(infoRemark));
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
				const tlsVal = isTlsPort ? "tls" : "none";
				const userFrag = user.frag_len && user.frag_int ? "&fragment=" + user.frag_len + "," + user.frag_int : "";
				const remark = user.username + " | \u200E" + ip + " | \u200E" + portStr;
				links.push(atob("dmxlc3M6Ly8=") + user.uuid + "@" + ip + ":" + portStr + "?path=%2FZEUS_PANEL_BOT&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + userFrag + "#" + encodeURIComponent(remark));
			});
		});
		const noise = ["# System Update Feed: OK", "# Sync Code: " + Math.random().toString(36).slice(2, 10), "# Version: 2.10.1", "# Description: Secure Node Configurations", ""].join("\n");
		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days && user.created_at) {
			expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
		}
		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
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
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				GLOBAL_TRAFFIC_CACHE.delete(uname);
				USER_REQ_CACHE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		}
	}
}
async function handleVLESS(env, storedData = null, ctx = null, request = null) {
	const clientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let tickCount = 0;
	let validUUID = null;
	let userIpLimit = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 10 * 1024 * 1024;
		if (current >= thresholdBytes || (current > 0 && now - lastDbWrite > 60000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, 0);
			USER_REQ_CACHE.set(username, 0);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, username).run();
				} catch (e) {
					console.error(e.message);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		if (clientIP && clientIP !== "unknown" && validUUID) {
			const removeIpTask = async () => {
				try {
					const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						console.log(`[setOffline Task] DB active_ips for ${uname}: ${user.active_ips}`);
						let activeIps = JSON.parse(user.active_ips || "{}");
						if (activeIps[clientIP]) {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1;
								if (activeIps[clientIP].count <= 0) {
									delete activeIps[clientIP];
								}
							} else {
								delete activeIps[clientIP];
							}
							await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
							console.log(`[setOffline Task] Updated active_ips in DB to: ${JSON.stringify(activeIps)}`);
						} else {
							console.log(`[setOffline Task] IP ${clientIP} not found in user's active_ips`);
						}
					}
				} catch (e) {
					console.error(`[setOffline Task] Error: ${e.message}`);
				}
			};
			if (ctx) ctx.waitUntil(removeIpTask());
			else removeIpTask();
		}
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 1;
		activeCount = activeCount - 1;
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			if ((cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				GLOBAL_TRAFFIC_CACHE.set(uname, 0);
				USER_REQ_CACHE.set(uname, 0);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
					} catch (e) {
						console.error(e.message);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	const heartbeat = setInterval(async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID) return;
				tickCount++;
				if (tickCount >= 1) {
					tickCount = 0;
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						userIpLimit = user.ip_limit;
					}
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						if (user.limit_gb && user.used_gb >= user.limit_gb) {
							isExpired = true;
						}
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) {
							isExpired = true;
						}
						if (user.expiry_days && user.created_at) {
							const created = new Date(user.created_at);
							const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
							if (new Date() > expiryDate) {
								isExpired = true;
							}
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) {}
							const nowTime = Date.now();
							let hasChanges = false;
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 20000) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								isIpLimitExpired = true;
								console.log(`[Heartbeat] IP ${clientIP} expired from active_ips due to inactivity.`);
							} else {
								const sortedIps = Object.keys(activeIps).sort((a, b) => {
									const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
									const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
									return tB - tA;
								});
								const clientIpIndex = sortedIps.indexOf(clientIP);
								if (user.ip_limit && user.ip_limit > 0 && clientIpIndex >= user.ip_limit) {
									isIpLimitExpired = true;
									console.log(`[Heartbeat] IP Limit Exceeded. Client IP index ${clientIpIndex} >= limit ${user.ip_limit}.`);
								}
							}
							if (hasChanges || isIpLimitExpired) {
								updatedActiveIps = JSON.stringify(activeIps);
							}
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						console.log(`[Heartbeat] Terminating socket for user ${username}.`);
						clearInterval(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					const now = Date.now();
					const lastRecorded = GLOBAL_LAST_ACTIVE_WRITE.get(username) || 0;
					if (now - lastRecorded > 25000 || updatedActiveIps !== null) {
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						if (updatedActiveIps !== null) {
							await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(now, updatedActiveIps, username).run();
						} else {
							await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
						}
					}
				}
			} catch (e) {}
		} else {
			clearInterval(heartbeat);
		}
	}, 25000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	const proxyIP = storedData?.proxy_ip || "proxyip.cmliussss.net";
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) {}
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) {}
			closeSocketQuietly(serverSock);
		},
		name: "VlessWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		await addBytes(bytes);
		if (isDnsQuery) {
			await forwardVlessUDP(chunk, serverSock, null, addBytes, targetDns);
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			if (chunkBuffer.byteLength < 24) return;
			if (isHeaderParsing) return;
			isHeaderParsing = true;
			reqUUID = extractUUIDFromVless(chunkBuffer);
			if (!reqUUID) {
				serverSock.close();
				return;
			}
			let user = null;
			try {
				user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
			} catch (e) {}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (!user || user.is_active === 0) {
				serverSock.close();
				return;
			}
			if (user.limit_gb && user.used_gb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(user.username) || 0) >= user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				if (new Date() > expiryDate) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) {}
					serverSock.close();
					return;
				}
			}
			userIpLimit = user.ip_limit;
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				console.log(`[VLESS Handshake] User: ${user.username}, clientIP: ${clientIP}, active_ips in DB: ${user.active_ips}`);
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) {}
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 20000) {
						delete activeIps[ip];
					}
				}
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps).sort((a, b) => {
						const tA = activeIps[a] && typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
						const tB = activeIps[b] && typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
						return tB - tA;
					});
					console.log(`[VLESS Handshake] Non-expired active IPs: ${JSON.stringify(activeIps)}, count: ${sortedIps.length}, limit: ${user.ip_limit}`);
					if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
						console.log(`[VLESS Handshake] BLOCKED user ${user.username} because sortedIps.length (${sortedIps.length}) >= limit (${user.ip_limit})`);
						serverSock.close();
						return;
					}
					activeIps[clientIP] = { timestamp: now, count: 1 };
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
					console.log(`[VLESS Handshake] Reconnected from same IP: ${clientIP}, count: ${activeIps[clientIP].count}`);
				}
				try {
					await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
					console.log(`[VLESS Handshake] Successfully updated active_ips to: ${JSON.stringify(activeIps)}`);
				} catch (e) {
					console.error(`[VLESS Handshake] DB Update Error: ${e.message}`);
				}
			}
			validUUID = reqUUID;
			username = user.username;
			isHeaderParsed = true;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			if (activeCount === 0) {
				const setOnlineTask = async () => {
					try {
						const now = Date.now();
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
					} catch (e) {}
				};
				if (ctx) ctx.waitUntil(setOnlineTask());
				else setOnlineTask();
			}
			try {
				let offset = 17;
				const optLen = chunkBuffer[offset++];
				offset += optLen;
				const cmd = chunkBuffer[offset++];
				const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				const addrType = chunkBuffer[offset++];
				let addr = "";
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 3) {
					const v6 = [];
					for (let i = 0; i < 8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				}
				const rawData = chunkBuffer.slice(offset);
				const respHeader = new Uint8Array([chunkBuffer[0], 0]);
				
				if ((user.block_ads === 1 || user.block_porn === 1) && addrType === 2 && port !== 53) {
					try {
						const dnsCheck = await dohQuery(addr, "A", targetDoh);
						const isBlocked = dnsCheck.some(r => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
					} catch (e) {}
				}

				if (cmd === 2) {
					if (port === 53) {
						isDnsQuery = true;
						await forwardVlessUDP(rawData, serverSock, respHeader, addBytes, targetDns);
					} else {
						serverSock.close();
					}
					return;
				}
				
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
						const socks5 = user?.user_socks5 || "";

						if (socks5) {
							s = await connectProxy(socks5, addr, port, dataPayload);
						} else {
							let activeProxyIP = proxyIP;
							if (user?.user_proxy_iata) {
								activeProxyIP = user.user_proxy_iata.toLowerCase() + ".proxyip.cmliussss.net";
							} else if (user?.user_proxy_ip) {
								activeProxyIP = user.user_proxy_ip;
							}

							let fHost = activeProxyIP;
							let fPort = port;
							if (activeProxyIP) {
								if (activeProxyIP.startsWith("[")) {
									const closeIdx = activeProxyIP.indexOf("]");
									if (closeIdx !== -1) {
										fHost = activeProxyIP.substring(1, closeIdx);
										if (activeProxyIP.length > closeIdx + 1 && activeProxyIP[closeIdx + 1] === ":") {
											fPort = parseInt(activeProxyIP.substring(closeIdx + 2)) || port;
										}
									}
								} else {
									const lastColon = activeProxyIP.lastIndexOf(":");
									if (lastColon !== -1 && activeProxyIP.indexOf(":") === lastColon) {
										fHost = activeProxyIP.substring(0, lastColon);
										fPort = parseInt(activeProxyIP.substring(lastColon + 1)) || port;
									} else {
										fHost = activeProxyIP;
									}
								}
							}
							const isCustomProxy = activeProxyIP && activeProxyIP !== "proxyip.cmliussss.net";

							if (isCustomProxy) {
								try {
									s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
								} catch (err) {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								try {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								} catch (err) {
									if (useFallback && activeProxyIP) {
										s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
									} else {
										throw err;
									}
								}
							}
						}
						remoteConnWrapper.socket = s;
						s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
						connectStreams(s, serverSock, respHeader, null, (b) => {
							addBytes(b);
						});
					})();
					remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearInterval(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}
async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0 };
	try {
		const now = new Date();
		const startOfDay = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
      viewer {
        accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
          today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
            sum { requests }
          }
          total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
            sum { requests }
          }
        }
      }
    }`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		return { today: todayReqs, total: totalReqs };
	} catch (e) {
		return { today: 0, total: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function stripIPv6Brackets(hostname = "") {
	const host = String(hostname || "").trim();
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(":")) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	const chunks = chunkList.map(convertToUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) {}
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await new Promise((resolve) => setTimeout(resolve, 0));
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) setTimeout(drain, 0);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) setTimeout(drain, 0);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const packetCap = DOWNSTREAM_GRAIN_BYTES;
	const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer = null;
	let taskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		taskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || taskQueued) return;
		taskQueued = true;
		scheduledGeneration = generation;
		setTimeout(() => {
			taskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(
				() => {
					flushTimer = null;
					if (!pendingBytes) return;
					if (packetCap - pendingBytes < tailBytes) {
						flush().catch(() => closeSocketQuietly(webSocket));
						return;
					}
					if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
						waitRounds++;
						scheduledGeneration = generation;
						scheduleFlush();
						return;
					}
					flush().catch(() => closeSocketQuietly(webSocket));
				},
				Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1),
			);
		}, 0);
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		let maxAttempts = 150;
		while (ws.bufferedAmount > 1024 * 1024 && maxAttempts > 0) { 
			if (ws.readyState !== WebSocket.OPEN) break;
			await new Promise((r) => setTimeout(r, 20));
			maxAttempts--;
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false;
	const BYOB_LIMIT = 64 * 1024;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		reader = remoteSocket.readable.getReader({ mode: "byob" });
		useBYOB = true;
	} catch (e) {
		reader = remoteSocket.readable.getReader();
	}
	try {
		if (!useBYOB) {
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_LIMIT);
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await downstreamSender.flush();
					await downstreamSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_LIMIT);
				} else {
					await downstreamSender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
				}
			}
		}
		await downstreamSender.flush();
	} catch (err) {
		closeSocketQuietly(webSocket);
	} finally {
		try {
			reader.cancel();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function buildRaceCandidates(address, port, targetDoh) {
	if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
	const [aRecords, aaaaRecords] = await Promise.all([dohQuery(address, "A", targetDoh), dohQuery(address, "AAAA", targetDoh)]);
	const ipv4List = [
		...new Set(
			aRecords.flatMap((r) => {
				return r.type === 1 && typeof r.data === "string" && isIPv4(r.data) ? [r.data] : [];
			}),
		),
	];
	const ipv6List = [
		...new Set(
			aaaaRecords.flatMap((r) => {
				return r.type === 28 && typeof r.data === "string" && isIPHostname(r.data) ? [r.data] : [];
			}),
		),
	];
	const limit = Math.max(1, TCP_CONCURRENCY | 0);
	const ipList = ipv4List.length >= limit ? ipv4List.slice(0, limit) : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
	if (ipList.length === 0) return null;
	return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const raceCandidates = await buildRaceCandidates(address, port, targetDoh);
	const candidates = raceCandidates || Array.from({ length: TCP_CONCURRENCY }, () => ({ hostname: address, port }));
	const openConnection = async (host, prt) => {
		const socket = connect({ hostname: host, port: prt });
		await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 2000))]);
		return socket;
	};
	if (candidates.length === 1) {
		const s = await openConnection(candidates[0].hostname, candidates[0].port);
		if (initialData && initialData.byteLength > 0) {
			const w = s.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return s;
	}
	const attempts = candidates.map((c) => openConnection(c.hostname, c.port).then((socket) => ({ socket, candidate: c })));
	let winner = null;
	try {
		winner = await Promise.any(attempts);
		if (initialData && initialData.byteLength > 0) {
			const w = winner.socket.writable.getWriter();
			await w.write(convertToUint8Array(initialData));
			w.releaseLock();
		}
		return winner.socket;
	} finally {
		if (winner) {
			for (const attempt of attempts) {
				attempt
					.then(({ socket }) => {
						if (socket !== winner.socket) {
							try {
								socket.close();
							} catch (e) {}
						}
					})
					.catch(() => {});
			}
		}
	}
}
async function forwardVlessUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	const requestData = convertToUint8Array(udpChunk);
	try {
		const tcpSocket = connect({ hostname: dnsServer, port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk) {
					const response = convertToUint8Array(chunk);
					if (typeof onBytes === "function") onBytes(response.byteLength);
					if (webSocket.readyState !== WebSocket.OPEN) return;
					if (vlessHeader) {
						const merged = new Uint8Array(vlessHeader.length + response.byteLength);
						merged.set(vlessHeader, 0);
						merged.set(response, vlessHeader.length);
						webSocket.send(merged.buffer);
						vlessHeader = null;
					} else {
						webSocket.send(response);
					}
				},
			}),
		);
	} catch (e) {}
}
function extractUUIDFromVless(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) {}
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}

	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");

	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}

async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	let user = "",
		pass = "",
		host = "",
		port = 1080;
	let auth = false;
	let remain = socksStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") {
				port = parseInt(remain.substring(closeIdx + 2)) || 1080;
			}
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || 1080;
		} else {
			host = remain;
		}
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}

		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پروکسی SOCKS5 نیست یا خاموش است)");

		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);

			await writer.write(authReq);
			let authRes = await reader.read();
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پروکسی اشتباه است");
		}

		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}

		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;

		await writer.write(req);
		let connRes = await reader.read();
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پروکسی وصل شد اما دسترسی به اینترنت آزاد ندارد");

		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}

async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	let user = "",
		pass = "",
		host = "",
		port = 80;
	let auth = false;
	let remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") {
				port = parseInt(remain.substring(closeIdx + 2)) || 80;
			}
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || 80;
		} else {
			host = remain;
		}
	}

	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();

	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";

		await writer.write(new TextEncoder().encode(req));

		let resStr = "";
		while (true) {
			const res = await reader.read();
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += new TextDecoder().decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}

		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}

		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}

const HTML_TEMPLATES = {
	panel: `
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LowkeyPanel</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Vazirmatn:wght@300;400;500;700;900&display=swap" rel="stylesheet">
    <style>
        /* ============================================================
           ROOT VARIABLES — تم مدرس و تیره
           ============================================================ */
        :root {
            --bg0: #080c10;
            --bg1: #0d1117;
            --bg2: #131920;
            --bg3: #1a2230;
            --bg4: #1f2a3a;
            --border: #1e3048;
            --border2: #2a4060;
            --accent: #6c5ce7;
            --accent2: #a29bfe;
            --accent-glow: rgba(108,92,231,0.15);
            --green: #00e676;
            --green-dim: rgba(0,230,118,0.10);
            --red: #ff4757;
            --red-dim: rgba(255,71,87,0.10);
            --amber: #ffa502;
            --amber-dim: rgba(255,165,2,0.10);
            --purple: #a855f7;
            --purple-dim: rgba(168,85,247,0.10);
            --pink: #ff6b9d;
            --pink-dim: rgba(255,107,157,0.10);
            --text0: #ecf3f7;
            --text1: #8aadc7;
            --text2: #4a6a85;
            --mono: 'JetBrains Mono', monospace;
            --sans: 'Vazirmatn', sans-serif;
            --radius: 14px;
            --shadow: 0 8px 32px rgba(0,0,0,0.4);
        }

        * { margin:0; padding:0; box-sizing:border-box; }

        body {
            font-family: var(--sans);
            background: var(--bg0);
            color: var(--text0);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ─── پس‌زمینه گرید و افکت ─── */
        body::before {
            content:'';
            position:fixed;
            inset:0;
            background-image:
                radial-gradient(circle at 20% 50%, rgba(108,92,231,0.04) 0%, transparent 50%),
                radial-gradient(circle at 80% 50%, rgba(0,230,118,0.03) 0%, transparent 50%),
                linear-gradient(rgba(108,92,231,0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(108,92,231,0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
            pointer-events:none;
            z-index:0;
        }

        /* ============================================================
           LAYOUT
           ============================================================ */
        .layout { display:flex; min-height:100vh; position:relative; z-index:1; }

        /* ============================================================
           SIDEBAR — با افکت شیشه‌ای
           ============================================================ */
        .sidebar {
            width: 240px;
            min-height: 100vh;
            background: rgba(11,17,24,0.92);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-left: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            position: fixed;
            right: 0;
            top: 0;
            bottom: 0;
            z-index: 100;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .logo {
            padding: 28px 20px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .logo-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--accent), var(--pink));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            font-weight: 900;
            color: #fff;
            font-family: var(--mono);
            box-shadow: 0 4px 20px rgba(108,92,231,0.3);
        }
        .logo-name {
            font-family: var(--mono);
            font-size: 18px;
            font-weight: 700;
            color: var(--text0);
            letter-spacing: 1px;
        }
        .logo-name span { color: var(--accent); }
        .logo-sub {
            font-size: 9px;
            color: var(--text2);
            font-family: var(--mono);
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: 1px;
        }

        .status-dot {
            display: inline-block;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 0 0 12px var(--green);
            animation: pulse-dot 2s infinite;
            margin-right: 6px;
            vertical-align: middle;
        }
        @keyframes pulse-dot {
            0%,100%{ opacity:1; transform:scale(1); }
            50%{ opacity:0.4; transform:scale(0.8); }
        }

        /* ─── Navigation ─── */
        .nav { flex:1; padding: 12px 0; overflow-y: auto; }

        .nav-section {
            padding: 8px 20px 4px;
            font-size: 9px;
            font-family: var(--mono);
            color: var(--text2);
            letter-spacing: 2px;
            text-transform: uppercase;
            margin-top: 8px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 20px;
            cursor: pointer;
            color: var(--text1);
            font-size: 13.5px;
            font-weight: 500;
            transition: all 0.2s ease;
            border-right: 3px solid transparent;
            position: relative;
        }
        .nav-item:hover {
            color: var(--text0);
            background: rgba(108,92,231,0.06);
        }
        .nav-item.active {
            color: var(--accent);
            background: var(--accent-glow);
            border-right-color: var(--accent);
        }
        .nav-item.active::before {
            content:'';
            position:absolute;
            right:0;
            top:50%;
            transform:translateY(-50%);
            width:3px;
            height:20px;
            background:var(--accent);
            border-radius:0 3px 3px 0;
        }
        .nav-icon { font-size: 16px; width: 20px; text-align: center; }
        .nav-badge {
            margin-right: auto;
            background: linear-gradient(135deg, var(--pink), var(--red));
            color: #fff;
            font-size: 10px;
            font-family: var(--mono);
            border-radius: 12px;
            padding: 1px 8px;
            font-weight: 700;
            box-shadow: 0 2px 12px rgba(255,71,87,0.3);
        }

        /* ─── Sidebar Footer ─── */
        .sidebar-footer {
            padding: 16px 20px;
            border-top: 1px solid var(--border);
        }
        .admin-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .avatar {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--accent2), var(--purple));
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--mono);
            font-size: 13px;
            font-weight: 700;
            color: #fff;
        }
        .admin-name { font-size: 13px; font-weight: 600; }
        .admin-role {
            font-size: 10px;
            color: var(--text2);
            font-family: var(--mono);
        }

        /* ============================================================
           MAIN CONTENT
           ============================================================ */
        .main {
            margin-right: 240px;
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        /* ============================================================
           TOPBAR
           ============================================================ */
        .topbar {
            height: 60px;
            background: rgba(11,17,24,0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            padding: 0 28px;
            gap: 16px;
            position: sticky;
            top: 0;
            z-index: 50;
        }
        .page-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text0);
        }
        .page-title .highlight { color: var(--accent); }
        .page-path {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text2);
        }
        .topbar-actions { margin-right: auto; display: flex; align-items: center; gap: 10px; }

        /* ============================================================
           BUTTONS
           ============================================================ */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 7px 18px;
            border-radius: 8px;
            font-family: var(--sans);
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: all 0.2s ease;
            text-decoration: none;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--accent), var(--purple));
            color: #fff;
            box-shadow: 0 4px 20px rgba(108,92,231,0.3);
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 30px rgba(108,92,231,0.4);
        }
        .btn-ghost {
            background: transparent;
            color: var(--text1);
            border: 1px solid var(--border2);
        }
        .btn-ghost:hover { background: var(--bg3); color: var(--text0); }
        .btn-danger {
            background: var(--red-dim);
            color: var(--red);
            border: 1px solid rgba(255,71,87,0.2);
        }
        .btn-danger:hover { background: rgba(255,71,87,0.2); }
        .btn-success {
            background: var(--green-dim);
            color: var(--green);
            border: 1px solid rgba(0,230,118,0.2);
        }
        .btn-success:hover { background: rgba(0,230,118,0.2); }

        /* ============================================================
           CONTENT
           ============================================================ */
        .content { padding: 28px; flex: 1; }
        .page { display: none; }
        .page.active { display: block; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn {
            from { opacity:0; transform:translateY(8px); }
            to { opacity:1; transform:translateY(0); }
        }

        /* ============================================================
           STATS GRID — کارت‌های مدرس با گرینت
           ============================================================ */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--bg1);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px 22px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
            cursor: default;
        }
        .stat-card:hover {
            border-color: var(--border2);
            transform: translateY(-3px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.3);
        }
        .stat-card::after {
            content:'';
            position:absolute;
            top:0;
            right:0;
            width:80px;
            height:80px;
            border-radius: 0 0 0 80px;
            opacity: 0.08;
        }
        .stat-card.blue::after { background: var(--accent); }
        .stat-card.green::after { background: var(--green); }
        .stat-card.red::after { background: var(--red); }
        .stat-card.purple::after { background: var(--purple); }

        .stat-label {
            font-size: 10px;
            color: var(--text2);
            font-family: var(--mono);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 28px;
            font-weight: 900;
            font-family: var(--mono);
            line-height: 1;
        }
        .stat-card.blue .stat-value { color: var(--accent); }
        .stat-card.green .stat-value { color: var(--green); }
        .stat-card.red .stat-value { color: var(--red); }
        .stat-card.purple .stat-value { color: var(--purple); }
        .stat-sub {
            font-size: 11px;
            color: var(--text2);
            margin-top: 8px;
            font-family: var(--mono);
        }
        .stat-trend { color: var(--green); }

        /* ============================================================
           GRID LAYOUTS
           ============================================================ */
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .grid-3 { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 20px; }

        /* ============================================================
           PANEL CARD
           ============================================================ */
        .panel {
            background: var(--bg1);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            transition: border-color 0.2s;
        }
        .panel:hover { border-color: var(--border2); }
        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .panel-title { font-size: 13px; font-weight: 700; color: var(--text0); }
        .panel-action { margin-right: auto; }
        .panel-body { padding: 20px; }

        /* ============================================================
           TABLE
           ============================================================ */
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        thead tr { border-bottom: 1px solid var(--border); }
        th {
            padding: 10px 14px;
            text-align: right;
            font-size: 10px;
            font-family: var(--mono);
            color: var(--text2);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
            white-space: nowrap;
        }
        td { padding: 13px 14px; border-bottom: 1px solid rgba(30,48,72,0.4); vertical-align: middle; }
        tbody tr { transition: background 0.15s; }
        tbody tr:hover { background: rgba(108,92,231,0.04); }
        tbody tr:last-child td { border-bottom: none; }

        /* ============================================================
           BADGES
           ============================================================ */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-family: var(--mono);
            font-weight: 600;
        }
        .badge-green { background: var(--green-dim); color: var(--green); }
        .badge-red   { background: var(--red-dim); color: var(--red); }
        .badge-amber { background: var(--amber-dim); color: var(--amber); }
        .badge-blue  { background: var(--accent-glow); color: var(--accent); }
        .badge-purple{ background: var(--purple-dim); color: var(--purple); }
        .badge-pink  { background: var(--pink-dim); color: var(--pink); }
        .badge::before { content:''; width:5px; height:5px; border-radius:50%; background:currentColor; }

        /* ============================================================
           PROGRESS BAR
           ============================================================ */
        .progress-wrap {
            width: 100%;
            background: var(--bg3);
            border-radius: 6px;
            height: 5px;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            border-radius: 6px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .progress-bar.green { background: linear-gradient(90deg, var(--green), #69f0ae); box-shadow: 0 0 12px rgba(0,230,118,0.3); }
        .progress-bar.amber { background: linear-gradient(90deg, var(--amber), #ffd54f); box-shadow: 0 0 12px rgba(255,165,2,0.3); }
        .progress-bar.red   { background: linear-gradient(90deg, var(--red), #ff8a80); box-shadow: 0 0 12px rgba(255,71,87,0.3); }
        .progress-bar.purple{ background: linear-gradient(90deg, var(--purple), var(--accent2)); box-shadow: 0 0 12px rgba(168,85,247,0.3); }

        /* ============================================================
           TRAFFIC CHART
           ============================================================ */
        .traffic-chart {
            display: flex;
            align-items: flex-end;
            gap: 6px;
            height: 100px;
            padding: 8px 0;
        }
        .bar-col { flex:1; display:flex; flex-direction:column; align-items:center; gap:4px; }
        .bar-fill {
            width:100%;
            border-radius: 4px 4px 0 0;
            background: linear-gradient(to top, var(--accent2), var(--accent));
            min-height:4px;
            transition: height 0.6s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            cursor: pointer;
        }
        .bar-fill:hover { filter: brightness(1.3); }
        .bar-fill.secondary { background: linear-gradient(to top, #1a3a55, var(--bg4)); }
        .bar-label { font-family:var(--mono); font-size:9px; color:var(--text2); }

        /* ============================================================
           PROTOCOL TAGS
           ============================================================ */
        .proto-tag {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 6px;
            font-family: var(--mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }
        .proto-vless  { background: rgba(108,92,231,0.12); color: var(--accent); border: 1px solid rgba(108,92,231,0.2); }
        .proto-vmess  { background: rgba(168,85,247,0.12); color: var(--purple); border: 1px solid rgba(168,85,247,0.2); }
        .proto-trojan { background: rgba(255,165,2,0.12); color: var(--amber); border: 1px solid rgba(255,165,2,0.2); }

        /* ============================================================
           FORM ELEMENTS
           ============================================================ */
        .form-group { margin-bottom: 16px; }
        .form-label {
            display: block;
            font-size: 11px;
            color: var(--text1);
            font-family: var(--mono);
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }
        .form-control {
            width: 100%;
            background: var(--bg2);
            border: 1px solid var(--border2);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text0);
            font-family: var(--sans);
            font-size: 13px;
            outline: none;
            transition: all 0.2s;
        }
        .form-control:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .form-control::placeholder { color: var(--text2); }
        select.form-control { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%234a6a85' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: left 12px center; padding-left: 36px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        .form-row-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }

        /* ============================================================
           TOGGLE SWITCH
           ============================================================ */
        .toggle { position:relative; width:38px; height:20px; display:inline-block; flex-shrink:0; }
        .toggle input { opacity:0; width:0; height:0; }
        .toggle-slider {
            position:absolute; inset:0;
            background: var(--bg3);
            border: 1px solid var(--border2);
            border-radius: 20px;
            cursor: pointer;
            transition: 0.25s;
        }
        .toggle-slider::before {
            content:'';
            position:absolute;
            width:14px; height:14px;
            right:2px; top:2px;
            background: var(--text2);
            border-radius:50%;
            transition: 0.25s;
        }
        .toggle input:checked + .toggle-slider {
            background: rgba(108,92,231,0.25);
            border-color: var(--accent);
        }
        .toggle input:checked + .toggle-slider::before {
            transform: translateX(-18px);
            background: var(--accent);
            box-shadow: 0 0 12px rgba(108,92,231,0.5);
        }

        /* ============================================================
           UUID BOX
           ============================================================ */
        .uuid-box {
            background: var(--bg0);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 10px 14px;
            font-family: var(--mono);
            font-size: 12px;
            color: var(--accent);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        .copy-btn {
            background: none;
            border: none;
            color: var(--text2);
            cursor: pointer;
            font-size: 14px;
            padding: 2px 8px;
            border-radius: 4px;
            transition: all 0.15s;
        }
        .copy-btn:hover { color: var(--accent); background: var(--accent-glow); }

        /* ============================================================
           CONFIG OUTPUT
           ============================================================ */
        .config-output {
            background: var(--bg0);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            font-family: var(--mono);
            font-size: 11.5px;
            color: var(--green);
            line-height: 1.8;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 260px;
            overflow-y: auto;
        }

        /* ============================================================
           SUB LINK
           ============================================================ */
        .sub-link {
            background: var(--bg0);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            font-family: var(--mono);
            font-size: 11px;
            color: var(--accent);
            word-break: break-all;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 10px;
        }
        .sub-type {
            font-size: 10px;
            color: var(--text2);
            white-space: nowrap;
            min-width: 70px;
        }

        /* ============================================================
           MODAL
           ============================================================ */
        .modal-overlay {
            position: fixed; inset: 0;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(6px);
            -webkit-backdrop-filter: blur(6px);
            z-index: 200;
            display: flex; align-items: center; justify-content: center;
            opacity: 0; pointer-events: none;
            transition: opacity 0.25s ease;
        }
        .modal-overlay.open { opacity: 1; pointer-events: all; }
        .modal {
            background: var(--bg1);
            border: 1px solid var(--border2);
            border-radius: var(--radius);
            width: 520px;
            max-width: 95vw;
            box-shadow: var(--shadow);
            transform: scale(0.95) translateY(10px);
            transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-overlay.open .modal { transform: scale(1) translateY(0); }
        .modal-header {
            padding: 20px 24px 16px;
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; gap: 10px;
        }
        .modal-title { font-size: 15px; font-weight: 700; }
        .modal-close {
            margin-right: auto;
            background: none; border: none;
            color: var(--text2); cursor: pointer;
            font-size: 20px; line-height: 1;
            padding: 4px 8px; border-radius: 6px;
            transition: all 0.15s;
        }
        .modal-close:hover { background: var(--bg3); color: var(--text0); }
        .modal-body { padding: 24px; }
        .modal-footer {
            padding: 16px 24px 20px;
            display: flex; gap: 10px; justify-content: flex-start;
        }

        /* ============================================================
           ONLINE USERS
           ============================================================ */
        .user-online-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid rgba(30,48,72,0.4);
        }
        .user-online-item:last-child { border-bottom:none; }
        .user-avatar-sm {
            width: 32px; height: 32px;
            border-radius: 8px;
            background: var(--bg3);
            display: flex; align-items: center; justify-content: center;
            font-family: var(--mono);
            font-size: 11px;
            font-weight: 700;
            color: var(--text1);
            border: 1px solid var(--border2);
        }
        .user-info-name { font-size: 13px; font-weight: 600; }
        .user-info-detail { font-size: 11px; color: var(--text2); font-family: var(--mono); }
        .user-traffic { margin-right: auto; text-align: left; }
        .user-traffic-up { font-size: 11px; color: var(--green); font-family: var(--mono); }
        .user-traffic-dn { font-size: 11px; color: var(--accent); font-family: var(--mono); }

        /* ============================================================
           SERVER NODE
           ============================================================ */
        .server-node {
            display: flex; align-items: center; gap: 14px;
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 16px;
            margin-bottom: 10px;
            transition: all 0.2s;
        }
        .server-node:hover { border-color: var(--border2); }
        .server-flag { font-size: 22px; }
        .server-name { font-size: 13px; font-weight: 700; }
        .server-addr { font-size: 11px; color: var(--text2); font-family: var(--mono); }
        .server-ping { margin-right: auto; font-family: var(--mono); font-size: 12px; font-weight: 700; }
        .ping-low { color: var(--green); }
        .ping-mid { color: var(--amber); }
        .ping-high { color: var(--red); }
        .server-load { width: 80px; }
        .server-load-label { font-size: 10px; color: var(--text2); margin-bottom: 4px; font-family: var(--mono); }

        /* ============================================================
           SETTINGS
           ============================================================ */
        .setting-row {
            display:flex; align-items:center; justify-content:space-between;
            padding: 10px 0; border-bottom: 1px solid rgba(30,48,72,0.3);
        }
        .setting-row:last-child { border-bottom:none; }
        .setting-name { font-size: 13px; font-weight: 500; }
        .setting-desc { font-size: 11px; color: var(--text2); margin-top: 2px; }

        /* ============================================================
           TOAST
           ============================================================ */
        .toast {
            position: fixed;
            bottom: 24px;
            left: 24px;
            background: var(--bg2);
            border: 1px solid var(--border2);
            border-radius: 10px;
            padding: 12px 20px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.5);
            transform: translateY(80px);
            opacity: 0;
            transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
            z-index: 9999;
            min-width: 220px;
        }
        .toast.show { transform: translateY(0); opacity: 1; }
        .toast.success { border-color: rgba(0,230,118,0.3); }
        .toast.success .toast-icon { color: var(--green); }

        /* ============================================================
           QR BOX
           ============================================================ */
        .qr-box {
            width:120px; height:120px;
            background: var(--bg0);
            border: 1px solid var(--border);
            border-radius: 8px;
            display: flex; align-items:center; justify-content:center;
            flex-direction:column; gap:6px;
            font-size:11px; color:var(--text2);
            font-family:var(--mono);
        }
        .qr-grid {
            display: grid;
            grid-template-columns: repeat(7,12px);
            grid-template-rows: repeat(7,12px);
            gap:2px;
        }
        .qr-cell { border-radius:2px; background:var(--bg4); }
        .qr-cell.on { background:var(--text0); }

        /* ============================================================
           SCROLLBAR
           ============================================================ */
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent2); }

        /* ============================================================
           RESPONSIVE
           ============================================================ */
        .menu-btn {
            display:none;
            background:none; border:none;
            color:var(--text0); font-size:20px;
            cursor:pointer; padding:6px; border-radius:6px;
        }

        @media(max-width:900px) {
            .sidebar { transform: translateX(240px); }
            .sidebar.open { transform: translateX(0); }
            .main { margin-right: 0; }
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .grid-2, .grid-3 { grid-template-columns: 1fr; }
            .menu-btn { display:flex !important; }
        }

        .section-head {
            display:flex; align-items:center; justify-content:space-between;
            margin-bottom: 20px;
        }
        .section-head h2 { font-size:16px; font-weight:700; }

        .flex { display:flex; }
        .flex-center { display:flex; align-items:center; }
        .gap-8 { gap:8px; }
        .gap-12 { gap:12px; }
        .text-mono { font-family:var(--mono); }
        .text-sm { font-size:12px; }
        .text-muted { color:var(--text2); }
        .text-accent { color:var(--accent); }
        .fw-700 { font-weight:700; }
        .mb-16 { margin-bottom:16px; }
        .mb-20 { margin-bottom:20px; }
    </style>
</head>
<body>

<!-- ─── TOAST ─── -->
<div class="toast" id="toast">
    <span class="toast-icon">✓</span>
    <span id="toast-msg">کپی شد!</span>
</div>

<!-- ─── MODAL: ADD USER ─── -->
<div class="modal-overlay" id="modal-user" onclick="if(event.target===this)closeModal('modal-user')">
    <div class="modal">
        <div class="modal-header">
            <span style="font-size:18px">👤</span>
            <span class="modal-title">افزودن کاربر جدید</span>
            <button class="modal-close" onclick="closeModal('modal-user')">×</button>
        </div>
        <div class="modal-body">
            <div class="form-row mb-16">
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">نام کاربر</label>
                    <input type="text" class="form-control" placeholder="user_01" id="new-username">
                </div>
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">ایمیل (اختیاری)</label>
                    <input type="email" class="form-control" placeholder="user@example.com">
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">UUID</label>
                <div class="uuid-box">
                    <span id="new-uuid">در حال تولید...</span>
                    <button class="copy-btn" onclick="genUUID()">↺</button>
                </div>
            </div>
            <div class="form-row mb-16">
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">حجم ترافیک (GB)</label>
                    <input type="number" class="form-control" value="50" min="1">
                </div>
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">تاریخ انقضا</label>
                    <input type="date" class="form-control" id="expire-date">
                </div>
            </div>
            <div class="form-row-3 mb-16">
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">تعداد دستگاه</label>
                    <input type="number" class="form-control" value="3" min="1" max="20">
                </div>
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">پروتکل</label>
                    <select class="form-control">
                        <option>VLESS + Reality</option>
                        <option>VLESS + WS + TLS</option>
                        <option>VMess + WS + TLS</option>
                        <option>Trojan</option>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom:0">
                    <label class="form-label">وضعیت</label>
                    <select class="form-control">
                        <option>فعال</option>
                        <option>غیرفعال</option>
                    </select>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">یادداشت</label>
                <input type="text" class="form-control" placeholder="توضیحات اختیاری...">
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn btn-primary" onclick="addUser()">✓ ذخیره کاربر</button>
            <button class="btn btn-ghost" onclick="closeModal('modal-user')">انصراف</button>
        </div>
    </div>
</div>

<!-- ─── MODAL: VIEW CONFIG ─── -->
<div class="modal-overlay" id="modal-config" onclick="if(event.target===this)closeModal('modal-config')">
    <div class="modal" style="width:580px">
        <div class="modal-header">
            <span style="font-size:18px">⚙️</span>
            <span class="modal-title" id="config-modal-title">کانفیگ کاربر</span>
            <button class="modal-close" onclick="closeModal('modal-config')">×</button>
        </div>
        <div class="modal-body">
            <div class="panel-header" style="padding:0 0 12px; border-bottom:1px solid var(--border); margin-bottom:16px;">
                <span class="text-sm text-muted text-mono">لینک اشتراک‌ها</span>
            </div>
            <div class="sub-link">
                <span class="sub-type">Universal</span>
                <span id="sub-universal" style="word-break:break-all;font-size:10px;color:var(--accent)">vless://...</span>
                <button class="copy-btn" onclick="copyText('sub-universal')">⧉</button>
            </div>
            <div class="sub-link">
                <span class="sub-type">Clash Meta</span>
                <span id="sub-clash" style="word-break:break-all;font-size:10px;color:var(--green)">https://sub.domain.com/clash/...</span>
                <button class="copy-btn" onclick="copyText('sub-clash')">⧉</button>
            </div>
            <div class="sub-link">
                <span class="sub-type">Singbox</span>
                <span id="sub-sing" style="word-break:break-all;font-size:10px;color:var(--purple)">https://sub.domain.com/sing/...</span>
                <button class="copy-btn" onclick="copyText('sub-sing')">⧉</button>
            </div>

            <div class="panel-header" style="padding:16px 0 12px; border-bottom:1px solid var(--border); margin-bottom:16px;">
                <span class="text-sm text-muted text-mono">کانفیگ خام VLESS</span>
            </div>
            <div class="config-output" id="config-raw"></div>
            <div style="margin-top:16px; display:flex; gap:10px; align-items:center;">
                <div class="qr-box">
                    <div class="qr-grid" id="qr-grid"></div>
                </div>
                <div style="flex:1">
                    <div style="font-size:11px;color:var(--text2);margin-bottom:8px;font-family:var(--mono)">اسکن با V2RayNG / Streisand / Hiddify</div>
                    <button class="btn btn-ghost" style="width:100%;justify-content:center;margin-bottom:8px" onclick="showToast('کانفیگ کپی شد','success')">⧉ کپی کانفیگ</button>
                    <button class="btn btn-success" style="width:100%;justify-content:center">↓ دانلود JSON</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ─── LAYOUT ─── -->
<div class="layout">

    <!-- SIDEBAR -->
    <aside class="sidebar" id="sidebar">
        <div class="logo">
            <div class="logo-icon">LK</div>
            <div>
                <div class="logo-name"><span class="status-dot"></span> Lowkey<span>Panel</span></div>
                <div class="logo-sub">V2Ray Management v2.4</div>
            </div>
        </div>

        <nav class="nav">
            <div class="nav-section">اصلی</div>
            <div class="nav-item active" onclick="goPage('dashboard',this)">
                <span class="nav-icon">◈</span> داشبورد
            </div>
            <div class="nav-item" onclick="goPage('users',this)">
                <span class="nav-icon">◉</span> کاربران
                <span class="nav-badge">12</span>
            </div>
            <div class="nav-item" onclick="goPage('configs',this)">
                <span class="nav-icon">⊞</span> کانفیگ‌ها
            </div>
            <div class="nav-item" onclick="goPage('servers',this)">
                <span class="nav-icon">⬡</span> سرورها
            </div>

            <div class="nav-section">ابزارها</div>
            <div class="nav-item" onclick="goPage('subscriptions',this)">
                <span class="nav-icon">⊛</span> اشتراک‌ها
            </div>
            <div class="nav-item" onclick="goPage('traffic',this)">
                <span class="nav-icon">≋</span> ترافیک
            </div>
            <div class="nav-item" onclick="goPage('telegram',this)">
                <span class="nav-icon">✈</span> تلگرام‌بات
            </div>

            <div class="nav-section">سیستم</div>
            <div class="nav-item" onclick="goPage('settings',this)">
                <span class="nav-icon">⚙</span> تنظیمات
            </div>
            <div class="nav-item" onclick="goPage('logs',this)">
                <span class="nav-icon">▤</span> لاگ‌ها
            </div>
        </nav>

        <div class="sidebar-footer">
            <div class="admin-info">
                <div class="avatar">AD</div>
                <div>
                    <div class="admin-name">ادمین اصلی</div>
                    <div class="admin-role">super_admin</div>
                </div>
            </div>
        </div>
    </aside>

    <!-- MAIN -->
    <main class="main">
        <div class="topbar">
            <button class="menu-btn" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
            <div>
                <div class="page-title" id="page-title">داشبورد</div>
                <div class="page-path text-mono" id="page-path">LowkeyPanel / dashboard</div>
            </div>
            <div class="topbar-actions">
                <button class="btn btn-ghost text-mono" style="font-size:12px" onclick="showToast('هیچ اعلانی وجود ندارد','success')">🔔</button>
                <button class="btn btn-primary" onclick="openModal('modal-user')">+ کاربر جدید</button>
            </div>
        </div>

        <div class="content">
            <!-- ═══════════ DASHBOARD ═══════════ -->
            <div class="page active" id="page-dashboard">
                <div class="stats-grid">
                    <div class="stat-card blue">
                        <div class="stat-label">کل کاربران</div>
                        <div class="stat-value" id="stat-total">47</div>
                        <div class="stat-sub"><span class="stat-trend">↑ +3</span> این هفته</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-label">آنلاین الان</div>
                        <div class="stat-value" id="stat-online">12</div>
                        <div class="stat-sub">از 47 کاربر فعال</div>
                    </div>
                    <div class="stat-card red">
                        <div class="stat-label">منقضی شده</div>
                        <div class="stat-value">5</div>
                        <div class="stat-sub">نیاز به تمدید</div>
                    </div>
                    <div class="stat-card purple">
                        <div class="stat-label">ترافیک امروز</div>
                        <div class="stat-value">2.4<span style="font-size:14px">TB</span></div>
                        <div class="stat-sub"><span class="stat-trend">↑ 18%</span> نسبت به دیروز</div>
                    </div>
                </div>

                <div class="grid-3">
                    <div class="panel">
                        <div class="panel-header">
                            <span class="text-accent">▌</span>
                            <span class="panel-title">ترافیک هفتگی</span>
                            <div class="panel-action"><span class="badge badge-blue">7 روز</span></div>
                        </div>
                        <div class="panel-body">
                            <div class="traffic-chart" id="traffic-chart"></div>
                            <div style="display:flex;gap:16px;margin-top:12px">
                                <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)">
                                    <div style="width:10px;height:3px;border-radius:2px;background:var(--accent)"></div> ارسال
                                </div>
                                <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)">
                                    <div style="width:10px;height:3px;border-radius:2px;background:var(--bg4)"></div> دریافت
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="panel-header">
                            <span class="text-accent">▌</span>
                            <span class="panel-title">آنلاین‌ها</span>
                            <div class="panel-action"><span class="badge badge-green">Live</span></div>
                        </div>
                        <div class="panel-body" id="online-list"></div>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <span class="text-accent">▌</span>
                        <span class="panel-title">آخرین کاربران</span>
                        <div class="panel-action">
                            <button class="btn btn-ghost" style="padding:5px 12px;font-size:12px" onclick="goPage('users',null)">مشاهده همه</button>
                        </div>
                    </div>
                    <div class="table-wrap" id="dashboard-table"></div>
                </div>
            </div>

            <!-- ═══════════ USERS ═══════════ -->
            <div class="page" id="page-users">
                <div class="section-head">
                    <h2>مدیریت کاربران</h2>
                    <div style="display:flex;gap:10px">
                        <input type="text" class="form-control" placeholder="جستجو..." style="width:200px" oninput="filterUsers(this.value)">
                        <select class="form-control" style="width:140px" onchange="filterStatus(this.value)">
                            <option value="">همه وضعیت‌ها</option>
                            <option value="active">فعال</option>
                            <option value="expired">منقضی</option>
                            <option value="disabled">غیرفعال</option>
                        </select>
                        <button class="btn btn-primary" onclick="openModal('modal-user')">+ کاربر جدید</button>
                    </div>
                </div>
                <div class="panel">
                    <div class="table-wrap">
                        <table id="users-table">
                            <thead>
                                <tr>
                                    <th>کاربر</th>
                                    <th>پروتکل</th>
                                    <th>مصرف / حجم</th>
                                    <th>انقضا</th>
                                    <th>دستگاه‌ها</th>
                                    <th>وضعیت</th>
                                    <th>عملیات</th>
                                </tr>
                            </thead>
                            <tbody id="users-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- ═══════════ CONFIGS ═══════════ -->
            <div class="page" id="page-configs">
                <div class="section-head">
                    <h2>مدیریت کانفیگ‌ها</h2>
                    <button class="btn btn-primary" onclick="openConfigModal()">+ کانفیگ جدید</button>
                </div>
                <div class="grid-2">
                    <div class="panel">
                        <div class="panel-header">
                            <span class="text-accent">▌</span>
                            <span class="panel-title">تنظیمات VLESS + Reality</span>
                            <span class="badge badge-green">فعال</span>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="form-label">آدرس سرور</label>
                                <input class="form-control" value="162.159.36.1" placeholder="IP یا دامنه">
                            </div>
                            <div class="form-row">
                                <div class="form-group" style="margin-bottom:0">
                                    <label class="form-label">پورت</label>
                                    <input class="form-control" value="443">
                                </div>
                                <div class="form-group" style="margin-bottom:0">
                                    <label class="form-label">Network</label>
                                    <select class="form-control">
                                        <option selected>tcp</option>
                                        <option>ws</option>
                                        <option>grpc</option>
                                        <option>h2</option>
                                    </select>
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Public Key (Reality)</label>
                                <input class="form-control text-mono" value="BZb8p...xG4" style="font-size:11px">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Short ID</label>
                                <input class="form-control text-mono" value="deadbeef">
                            </div>
                            <div class="form-group">
                                <label class="form-label">SNI / SpiderX</label>
                                <input class="form-control" value="www.speedtest.net">
                            </div>
                            <div style="display:flex;gap:10px;margin-top:4px">
                                <button class="btn btn-primary" onclick="showToast('تنظیمات ذخیره شد','success')" style="flex:1;justify-content:center">ذخیره</button>
                                <button class="btn btn-ghost" onclick="showToast('تست اتصال موفق ✓','success')" style="flex:1;justify-content:center">تست اتصال</button>
                            </div>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="panel-header">
                            <span class="text-accent">▌</span>
                            <span class="panel-title">تنظیمات VLESS + WS + TLS</span>
                            <span class="badge badge-amber">غیرفعال</span>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="form-label">دامنه (CDN)</label>
                                <input class="form-control" value="cdn.yourdomain.com">
                            </div>
                            <div class="form-row">
                                <div class="form-group" style="margin-bottom:0">
                                    <label class="form-label">پورت</label>
                                    <input class="form-control" value="443">
                                </div>
                                <div class="form-group" style="margin-bottom:0">
                                    <label class="form-label">Path</label>
                                    <input class="form-control" value="/ws-path">
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Host Header</label>
                                <input class="form-control" value="cdn.yourdomain.com">
                            </div>
                            <div class="form-group">
                                <label class="form-label">TLS</label>
                                <select class="form-control">
                                    <option>tls</option>
                                    <option>none</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">ALPN</label>
                                <input class="form-control text-mono" value="h2,http/1.1" style="font-size:12px">
                            </div>
                            <div style="display:flex;gap:10px;margin-top:4px">
                                <button class="btn btn-primary" onclick="showToast('تنظیمات ذخیره شد','success')" style="flex:1;justify-content:center">ذخیره</button>
                                <button class="btn btn-ghost" style="flex:1;justify-content:center">فعال‌سازی</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <span class="text-accent">▌</span>
                        <span class="panel-title">تنظیمات VMess + gRPC</span>
                        <span class="badge badge-red">خطا</span>
                    </div>
                    <div class="panel-body">
                        <div class="form-row-3">
                            <div class="form-group" style="margin-bottom:0">
                                <label class="form-label">آدرس سرور</label>
                                <input class="form-control" value="grpc.yourdomain.com">
                            </div>
                            <div class="form-group" style="margin-bottom:0">
                                <label class="form-label">Service Name</label>
                                <input class="form-control" value="GunService">
                            </div>
                            <div class="form-group" style="margin-bottom:0">
                                <label class="form-label">پورت</label>
                                <input class="form-control" value="443">
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══════════ SERVERS ═══════════ -->
            <div class="page" id="page-servers">
                <div class="section-head">
                    <h2>سرورها / Node ها</h2>
                    <button class="btn btn-primary">+ سرور جدید</button>
                </div>
                <div id="servers-list"></div>
            </div>

            <!-- ═══════════ SUBSCRIPTIONS ═══════════ -->
            <div class="page" id="page-subscriptions">
                <div class="section-head"><h2>لینک‌های اشتراک</h2></div>
                <div class="panel mb-20">
                    <div class="panel-header">
                        <span class="text-accent">▌</span>
                        <span class="panel-title">اشتراک یوزر انتخابی</span>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <label class="form-label">انتخاب کاربر</label>
                            <select class="form-control" id="sub-user-select" onchange="updateSubLinks()">
                                <option value="">— انتخاب کنید —</option>
                            </select>
                        </div>
                        <div id="sub-links-area" style="display:none">
                            <div class="sub-link">
                                <span class="sub-type">Universal</span>
                                <span id="sl-universal" style="font-size:10px;color:var(--accent)"></span>
                                <button class="copy-btn" onclick="copyText('sl-universal')">⧉</button>
                            </div>
                            <div class="sub-link">
                                <span class="sub-type">Clash YAML</span>
                                <span id="sl-clash" style="font-size:10px;color:var(--green)"></span>
                                <button class="copy-btn" onclick="copyText('sl-clash')">⧉</button>
                            </div>
                            <div class="sub-link">
                                <span class="sub-type">Singbox</span>
                                <span id="sl-sing" style="font-size:10px;color:var(--purple)"></span>
                                <button class="copy-btn" onclick="copyText('sl-sing')">⧉</button>
                            </div>
                            <div class="sub-link">
                                <span class="sub-type">V2RayNG</span>
                                <span id="sl-v2ray" style="font-size:10px;color:var(--amber)"></span>
                                <button class="copy-btn" onclick="copyText('sl-v2ray')">⧉</button>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="grid-2">
                    <div class="panel">
                        <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">تنظیمات Subscription URL</span></div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="form-label">دامنه سابسکریپشن</label>
                                <input class="form-control" value="sub.yourdomain.com">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Path Prefix</label>
                                <input class="form-control text-mono" value="/sub/">
                            </div>
                            <div class="setting-row">
                                <div>
                                    <div class="setting-name">به‌روزرسانی خودکار</div>
                                    <div class="setting-desc">هر بار که کانفیگ تغییر کند</div>
                                </div>
                                <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                            </div>
                            <div class="setting-row">
                                <div>
                                    <div class="setting-name">Base64 Encoding</div>
                                    <div class="setting-desc">رمزنگاری لینک‌های universal</div>
                                </div>
                                <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                            </div>
                            <button class="btn btn-primary" style="margin-top:12px" onclick="showToast('تنظیمات ذخیره شد','success')">ذخیره</button>
                        </div>
                    </div>
                    <div class="panel">
                        <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">فرمت‌های پشتیبانی‌شده</span></div>
                        <div class="panel-body">
                            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
                                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
                                    <div style="font-size:20px;margin-bottom:6px">⚡</div>
                                    <div style="font-size:12px;font-weight:700;color:var(--accent)">V2RayNG</div>
                                    <div style="font-size:10px;color:var(--text2);font-family:var(--mono)">Base64</div>
                                </div>
                                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
                                    <div style="font-size:20px;margin-bottom:6px">🌊</div>
                                    <div style="font-size:12px;font-weight:700;color:var(--green)">Clash Meta</div>
                                    <div style="font-size:10px;color:var(--text2);font-family:var(--mono)">YAML</div>
                                </div>
                                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
                                    <div style="font-size:20px;margin-bottom:6px">🎵</div>
                                    <div style="font-size:12px;font-weight:700;color:var(--purple)">Singbox</div>
                                    <div style="font-size:10px;color:var(--text2);font-family:var(--mono)">JSON</div>
                                </div>
                                <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center">
                                    <div style="font-size:20px;margin-bottom:6px">🔵</div>
                                    <div style="font-size:12px;font-weight:700;color:var(--amber)">Hiddify</div>
                                    <div style="font-size:10px;color:var(--text2);font-family:var(--mono)">JSON</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══════════ TRAFFIC ═══════════ -->
            <div class="page" id="page-traffic">
                <div class="section-head"><h2>گزارش ترافیک</h2></div>
                <div class="stats-grid" style="grid-template-columns:repeat(3,1fr)">
                    <div class="stat-card blue">
                        <div class="stat-label">کل ترافیک این ماه</div>
                        <div class="stat-value">18.7<span style="font-size:14px">TB</span></div>
                        <div class="stat-sub"><span class="stat-trend">↑ 22%</span> نسبت به ماه قبل</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-label">آپلود</div>
                        <div class="stat-value">6.2<span style="font-size:14px">TB</span></div>
                        <div class="stat-sub">33% از کل ترافیک</div>
                    </div>
                    <div class="stat-card purple">
                        <div class="stat-label">دانلود</div>
                        <div class="stat-value">12.5<span style="font-size:14px">TB</span></div>
                        <div class="stat-sub">67% از کل ترافیک</div>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">مصرف‌کنندگان برتر</span></div>
                    <div class="table-wrap">
                        <table>
                            <thead><tr><th>#</th><th>کاربر</th><th>آپلود</th><th>دانلود</th><th>جمع</th><th>درصد</th></tr></thead>
                            <tbody id="traffic-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- ═══════════ TELEGRAM ═══════════ -->
            <div class="page" id="page-telegram">
                <div class="section-head"><h2>تنظیمات تلگرام‌بات</h2></div>
                <div class="grid-2">
                    <div class="panel">
                        <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">اتصال بات</span></div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="form-label">Bot Token</label>
                                <input class="form-control text-mono" value="7412355891:AAH..." style="font-size:11px">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Admin Chat ID</label>
                                <input class="form-control text-mono" value="123456789">
                            </div>
                            <div class="form-group">
                                <label class="form-label">Webhook URL</label>
                                <div class="uuid-box" style="font-size:10px">
                                    <span>https://yourworker.workers.dev/bot-hook</span>
                                    <button class="copy-btn" onclick="showToast('کپی شد','success')">⧉</button>
                                </div>
                            </div>
                            <div style="display:flex;gap:10px">
                                <button class="btn btn-primary" onclick="showToast('بات متصل شد ✓','success')">اتصال به تلگرام</button>
                                <button class="btn btn-ghost" onclick="showToast('تست پیام ارسال شد','success')">تست ارسال</button>
                            </div>
                        </div>
                    </div>
                    <div class="panel">
                        <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">هشدارهای خودکار</span></div>
                        <div class="panel-body">
                            <div class="setting-row">
                                <div><div class="setting-name">هشدار انقضای کاربر</div><div class="setting-desc">3 روز قبل از انقضا</div></div>
                                <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                            </div>
                            <div class="setting-row">
                                <div><div class="setting-name">هشدار اتمام ترافیک</div><div class="setting-desc">90% مصرف ترافیک</div></div>
                                <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                            </div>
                            <div class="setting-row">
                                <div><div class="setting-name">گزارش روزانه</div><div class="setting-desc">خلاصه آمار هر روز</div></div>
                                <label class="toggle"><input type="checkbox"><span class="toggle-slider"></span></label>
                            </div>
                            <div class="setting-row">
                                <div><div class="setting-name">هشدار قطعی سرور</div><div class="setting-desc">فوری</div></div>
                                <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                            </div>
                            <div class="setting-row">
                                <div><div class="setting-name">دستورات بات برای کاربر</div><div class="setting-desc">/status, /link, /usage</div></div>
                                <label class="toggle"><input type="checkbox"><span class="toggle-slider"></span></label>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══════════ SETTINGS ═══════════ -->
            <div class="page" id="page-settings">
                <div class="section-head"><h2>تنظیمات پنل</h2></div>
                <div class="grid-2">
                    <div>
                        <div class="panel mb-20">
                            <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">اطلاعات پنل</span></div>
                            <div class="panel-body">
                                <div class="form-group"><label class="form-label">نام پنل</label><input class="form-control" value="LowkeyPanel"></div>
                                <div class="form-group"><label class="form-label">دامنه اصلی</label><input class="form-control" value="panel.yourdomain.com"></div>
                                <div class="form-group"><label class="form-label">دامنه Subscription</label><input class="form-control" value="sub.yourdomain.com"></div>
                                <button class="btn btn-primary" onclick="showToast('تنظیمات ذخیره شد','success')">ذخیره</button>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">امنیت</span></div>
                            <div class="panel-body">
                                <div class="form-group"><label class="form-label">رمز جدید ادمین</label><input type="password" class="form-control" placeholder="••••••••"></div>
                                <div class="setting-row">
                                    <div><div class="setting-name">احراز هویت دو مرحله‌ای</div><div class="setting-desc">TOTP / Google Authenticator</div></div>
                                    <label class="toggle"><input type="checkbox"><span class="toggle-slider"></span></label>
                                </div>
                                <div class="setting-row">
                                    <div><div class="setting-name">Rate Limiting</div><div class="setting-desc">محدودیت درخواست روی API</div></div>
                                    <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="panel">
                        <div class="panel-header"><span class="text-accent">▌</span><span class="panel-title">اطلاعات Cloudflare Workers</span></div>
                        <div class="panel-body">
                            <div class="form-group"><label class="form-label">Workers URL</label><input class="form-control text-mono" value="https://lowkey.yourname.workers.dev" style="font-size:11px"></div>
                            <div class="form-group"><label class="form-label">KV Namespace ID</label><input class="form-control text-mono" value="abc123def456..." style="font-size:11px"></div>
                            <div class="form-group"><label class="form-label">Account ID</label><input class="form-control text-mono" value="cf_account_id_here" style="font-size:11px"></div>
                            <div class="form-group"><label class="form-label">API Token</label><input type="password" class="form-control text-mono" value="cf_api_token_secret"></div>
                            <div style="background:var(--green-dim);border:1px solid rgba(0,230,118,0.2);border-radius:8px;padding:12px;margin-top:8px">
                                <div style="font-size:12px;color:var(--green);font-family:var(--mono)">✓ Worker آنلاین است</div>
                                <div style="font-size:11px;color:var(--text2);margin-top:4px">آخرین بررسی: چند لحظه پیش</div>
                            </div>
                            <div style="background:var(--green-dim);border:1px solid rgba(0,230,118,0.2);border-radius:8px;padding:12px;margin-top:8px">
                                <div style="font-size:12px;color:var(--green);font-family:var(--mono)">✓ KV Storage متصل است</div>
                                <div style="font-size:11px;color:var(--text2);margin-top:4px">47 کلید ذخیره‌شده</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ═══════════ LOGS ═══════════ -->
            <div class="page" id="page-logs">
                <div class="section-head">
                    <h2>لاگ‌های سیستم</h2>
                    <div style="display:flex;gap:10px">
                        <select class="form-control" style="width:140px"><option>همه سطوح</option><option>INFO</option><option>WARN</option><option>ERROR</option></select>
                        <button class="btn btn-ghost" onclick="showToast('لاگ‌ها پاک شد','success')">پاک کردن</button>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-body" style="padding:0">
                        <div class="config-output" style="max-height:500px;border-radius:12px;border:none" id="log-output"></div>
                    </div>
                </div>
            </div>

        </div><!-- /content -->
    </main>
</div><!-- /layout -->

<!-- ─── SCRIPT ─── -->
<script>
    // ─── Data ───
    const users = [
        { id:1, name:'user_alpha', uuid:'a3f2c1d4-7e8b-4f9a-bc3d-1e2f3a4b5c6d', proto:'VLESS+Reality', used:12.4, total:50, expire:'1403/10/01', devices:2, maxDev:3, status:'active', online:true },
        { id:2, name:'dev_beta',   uuid:'b4e5d6f7-8a9b-4c2d-ef1g-2h3i4j5k6l7m', proto:'VLESS+WS+TLS', used:48.1, total:50, expire:'1403/09/15', devices:1, maxDev:2, status:'expired', online:false },
        { id:3, name:'proxy_003',  uuid:'c5f6e7g8-9b0c-4d3e-f2h-3i4j5k6l7m8n', proto:'VMess+WS',     used:5.2,  total:100, expire:'1403/12/30', devices:3, maxDev:5, status:'active', online:true },
        { id:4, name:'client_x',   uuid:'d6g7f8h9-0c1d-4e4f-g3i-4j5k6l7m8n9o', proto:'VLESS+Reality', used:22.0, total:30, expire:'1403/11/05', devices:1, maxDev:2, status:'active', online:false },
        { id:5, name:'vip_user',   uuid:'e7h8g9i0-1d2e-4f5g-h4j-5k6l7m8n9o0p', proto:'Trojan',       used:88.5, total:200, expire:'1404/01/01', devices:4, maxDev:5, status:'active', online:true },
        { id:6, name:'test_007',   uuid:'f8i9h0j1-2e3f-4g6h-i5k-6l7m8n9o0p1q', proto:'VLESS+WS+TLS', used:0.0,  total:20, expire:'1403/09/10', devices:0, maxDev:1, status:'disabled',online:false },
        { id:7, name:'power_user', uuid:'g9j0i1k2-3f4g-4h7i-j6l-7m8n9o0p1q2r', proto:'VLESS+Reality', used:301,  total:500, expire:'1404/06/30', devices:5, maxDev:10, status:'active', online:true },
    ];

    const servers = [
        { flag:'🇩🇪', name:'آلمان — Frankfurt', addr:'fra.server.com:443', ping:28, load:42, proto:'Reality', status:'online' },
        { flag:'🇳🇱', name:'هلند — Amsterdam', addr:'ams.server.com:443', ping:55, load:71, proto:'WS+TLS', status:'online' },
        { flag:'🇫🇮', name:'فنلاند — Helsinki', addr:'hel.server.com:443', ping:80, load:23, proto:'gRPC', status:'online' },
        { flag:'🇺🇸', name:'آمریکا — Los Angeles', addr:'lax.server.com:443', ping:185, load:88, proto:'Reality', status:'warn' },
    ];

    const trafficData = [
        {day:'ش',up:320,dn:820},{day:'ی',up:410,dn:960},{day:'د',up:280,dn:740},
        {day:'س',up:520,dn:1100},{day:'چ',up:380,dn:870},{day:'پ',up:450,dn:990},{day:'ج',up:490,dn:1050},
    ];

    const logs = [
        '[2024-01-15 14:23:11] INFO  Worker initialized — KV connected',
        '[2024-01-15 14:23:12] INFO  Routes registered: /api/users /api/configs /sub/:token',
        '[2024-01-15 14:25:44] INFO  New user created: user_alpha (UUID: a3f2c1d4...)',
        '[2024-01-15 14:31:02] WARN  User dev_beta traffic limit reached: 48.1/50 GB',
        '[2024-01-15 14:35:18] INFO  Subscription updated for 3 users',
        '[2024-01-15 15:01:22] INFO  Config VLESS+Reality health check: OK (28ms)',
        '[2024-01-15 15:02:00] ERROR Config VMess+gRPC health check failed: timeout',
        '[2024-01-15 15:05:44] INFO  Telegram bot alert sent: user dev_beta expired',
        '[2024-01-15 15:12:08] INFO  KV write: stats:user_alpha:2024-01-15 → 12.4GB',
        '[2024-01-15 15:20:33] WARN  User lax.server.com load high: 88%',
        '[2024-01-15 15:45:01] INFO  Scheduled job: daily stats aggregated',
        '[2024-01-15 16:00:00] INFO  Rate limit applied: 192.168.1.x (exceeded 100/min)',
    ];

    // ─── Init ───
    window.addEventListener('DOMContentLoaded', () => {
        genUUID();
        setExpireDefault();
        renderDashboard();
        renderUsersTable(users);
        renderServers();
        renderTrafficTable();
        renderLogs();
        populateSubSelect();
    });

    function setExpireDefault() {
        const d = document.getElementById('expire-date');
        if(d) { const dt = new Date(); dt.setMonth(dt.getMonth()+1); d.value = dt.toISOString().split('T')[0]; }
    }

    // ─── Navigation ───
    function goPage(name, el) {
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.getElementById('page-'+name).classList.add('active');
        if(el) el.classList.add('active');
        const titles = {dashboard:'داشبورد',users:'کاربران',configs:'کانفیگ‌ها',servers:'سرورها',subscriptions:'اشتراک‌ها',traffic:'ترافیک',telegram:'تلگرام‌بات',settings:'تنظیمات',logs:'لاگ‌ها'};
        document.getElementById('page-title').textContent = titles[name]||name;
        document.getElementById('page-path').textContent = 'LowkeyPanel / '+name;
    }

    // ─── Dashboard ───
    function renderDashboard() {
        renderTrafficChart();
        renderOnlineList();
        renderDashTable();
    }

    function renderTrafficChart() {
        const el = document.getElementById('traffic-chart');
        if(!el) return;
        const maxVal = Math.max(...trafficData.map(d => d.dn));
        el.innerHTML = trafficData.map(d => `
            <div class="bar-col">
                <div style="flex:1;display:flex;align-items:flex-end;gap:2px;width:100%">
                    <div class="bar-fill secondary" style="height:${Math.round(d.dn/maxVal*88)}px;flex:1"></div>
                    <div class="bar-fill" style="height:${Math.round(d.up/maxVal*88)}px;flex:1"></div>
                </div>
                <div class="bar-label">${d.day}</div>
            </div>`).join('');
    }

    function renderOnlineList() {
        const el = document.getElementById('online-list');
        if(!el) return;
        const online = users.filter(u => u.online).slice(0,5);
        el.innerHTML = online.map(u => `
            <div class="user-online-item">
                <div class="user-avatar-sm">${u.name.slice(0,2).toUpperCase()}</div>
                <div>
                    <div class="user-info-name">${u.name}</div>
                    <div class="user-info-detail">${u.proto}</div>
                </div>
                <div class="user-traffic">
                    <div class="user-traffic-up">↑ ${(Math.random()*5).toFixed(1)} MB/s</div>
                    <div class="user-traffic-dn">↓ ${(Math.random()*20).toFixed(1)} MB/s</div>
                </div>
            </div>`).join('');
    }

    function renderDashTable() {
        const el = document.getElementById('dashboard-table');
        if(!el) return;
        const rows = users.slice(0,5).map(u => userRow(u)).join('');
        el.innerHTML = `<table><thead><tr><th>کاربر</th><th>پروتکل</th><th>مصرف</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>${rows}</tbody></table>`;
    }

    // ─── Users ───
    function renderUsersTable(data) {
        const tbody = document.getElementById('users-tbody');
        if(!tbody) return;
        tbody.innerHTML = data.map(u => userRow(u, true)).join('');
    }

    function userRow(u, full=false) {
        const pct = Math.min(100, Math.round(u.used / u.total * 100));
        const barCls = pct >= 90 ? 'red' : pct >= 70 ? 'amber' : 'green';
        const statusBadge = u.status === 'active' ? '<span class="badge badge-green">فعال</span>' :
            u.status === 'expired' ? '<span class="badge badge-red">منقضی</span>' :
            '<span class="badge badge-amber">غیرفعال</span>';
        const protoTag = u.proto.includes('Reality') ? `<span class="proto-tag proto-vless">VLESS·Reality</span>` :
            u.proto.includes('VMess') ? `<span class="proto-tag proto-vmess">VMess</span>` :
            u.proto.includes('Trojan') ? `<span class="proto-tag proto-trojan">Trojan</span>` :
            `<span class="proto-tag proto-vless">VLESS</span>`;
        const devCol = full ? `<td><span class="text-mono" style="font-size:12px">${u.devices}/${u.maxDev}</span></td>` : '';
        return `<tr>
            <td>
                <div style="display:flex;align-items:center;gap:10px">
                    <div class="user-avatar-sm">${u.name.slice(0,2).toUpperCase()}</div>
                    <div>
                        <div style="font-weight:600;font-size:13px">${u.name}</div>
                        <div class="text-mono text-muted" style="font-size:10px">${u.uuid.slice(0,18)}…</div>
                    </div>
                    ${u.online ? '<span class="status-dot"></span>' : ''}
                </div>
            </td>
            <td>${protoTag}</td>
            <td style="min-width:130px">
                <div style="display:flex;justify-content:space-between;margin-bottom:5px;font-size:11px;font-family:var(--mono)">
                    <span style="color:var(--text1)">${u.used >= 1 ? u.used+'GB' : (u.used*1024).toFixed(0)+'MB'}</span>
                    <span class="text-muted">${u.total}GB</span>
                </div>
                <div class="progress-wrap"><div class="progress-bar ${barCls}" style="width:${pct}%"></div></div>
            </td>
            <td><span class="text-mono" style="font-size:12px">${u.expire}</span></td>
            ${devCol}
            <td>${statusBadge}</td>
            <td>
                <div style="display:flex;gap:6px">
                    <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="viewConfig(${u.id})">⧉ کانفیگ</button>
                    <button class="btn btn-danger" style="padding:4px 10px;font-size:11px" onclick="showToast('کاربر حذف شد','success')">✕</button>
                </div>
            </td>
        </tr>`;
    }

    function filterUsers(q) {
        const filtered = users.filter(u => u.name.includes(q) || u.uuid.includes(q));
        renderUsersTable(filtered);
    }
    function filterStatus(s) {
        const filtered = s ? users.filter(u => u.status === s) : users;
        renderUsersTable(filtered);
    }

    // ─── Servers ───
    function renderServers() {
        const el = document.getElementById('servers-list');
        if(!el) return;
        el.innerHTML = servers.map(s => {
            const pingCls = s.ping < 50 ? 'ping-low' : s.ping < 120 ? 'ping-mid' : 'ping-high';
            const loadBarCls = s.load > 80 ? 'red' : s.load > 60 ? 'amber' : 'green';
            return `<div class="server-node">
                <div class="server-flag">${s.flag}</div>
                <div>
                    <div class="server-name">${s.name}</div>
                    <div class="server-addr">${s.addr} · ${s.proto}</div>
                </div>
                <div class="server-ping"><span class="${pingCls}">${s.ping}ms</span></div>
                <div class="server-load">
                    <div class="server-load-label">بار: ${s.load}%</div>
                    <div class="progress-wrap"><div class="progress-bar ${loadBarCls}" style="width:${s.load}%"></div></div>
                </div>
                <span class="badge ${s.status==='online'?'badge-green':'badge-amber'}">${s.status==='online'?'آنلاین':'هشدار'}</span>
                <button class="btn btn-ghost" style="padding:5px 10px;font-size:11px" onclick="showToast('پینگ: ${s.ping}ms','success')">Ping</button>
            </div>`;
        }).join('');
    }

    // ─── Traffic Table ───
    function renderTrafficTable() {
        const el = document.getElementById('traffic-tbody');
        if(!el) return;
        const sorted = [...users].sort((a,b)=>b.used-a.used).slice(0,7);
        const max = sorted[0].used;
        el.innerHTML = sorted.map((u,i) => {
            const up = (u.used*0.33).toFixed(1);
            const dn = (u.used*0.67).toFixed(1);
            const pct = Math.round(u.used/max*100);
            return `<tr>
                <td><span class="text-mono" style="font-size:12px;color:var(--text2)">#${i+1}</span></td>
                <td><span style="font-weight:600">${u.name}</span></td>
                <td><span class="text-mono" style="font-size:12px;color:var(--green)">${up} GB</span></td>
                <td><span class="text-mono" style="font-size:12px;color:var(--accent)">${dn} GB</span></td>
                <td><span class="text-mono" style="font-size:12px;font-weight:700">${u.used} GB</span></td>
                <td style="min-width:100px">
                    <div style="display:flex;align-items:center;gap:8px">
                        <div class="progress-wrap" style="flex:1"><div class="progress-bar green" style="width:${pct}%"></div></div>
                        <span class="text-mono" style="font-size:10px;color:var(--text2);min-width:28px">${pct}%</span>
                    </div>
                </td>
            </tr>`;
        }).join('');
    }

    // ─── Logs ───
    function renderLogs() {
        const el = document.getElementById('log-output');
        if(!el) return;
        el.innerHTML = logs.map(l => {
            const cls = l.includes('ERROR') ? 'color:var(--red)' : l.includes('WARN') ? 'color:var(--amber)' : 'color:var(--text1)';
            const lvl = l.includes('ERROR') ? 'color:var(--red);font-weight:700' : l.includes('WARN') ? 'color:var(--amber);font-weight:700' : 'color:var(--green)';
            return `<div style="${cls};margin-bottom:4px">${l.replace(/(INFO|WARN|ERROR)/,'<span style="'+lvl+'">$1</span>')}</div>`;
        }).join('');
    }

    // ─── Config Modal ───
    function viewConfig(userId) {
        const u = users.find(x => x.id === userId);
        if(!u) return;
        document.getElementById('config-modal-title').textContent = 'کانفیگ — ' + u.name;
        const vless = `vless://${u.uuid}@fra.server.com:443?encryption=none&security=reality&sni=www.speedtest.net&fp=chrome&pbk=BZb8p...xG4&sid=deadbeef&type=tcp&flow=xtls-rprx-vision#${u.name}`;
        document.getElementById('sub-universal').textContent = vless;
        document.getElementById('sub-clash').textContent = `https://sub.yourdomain.com/clash/${u.uuid.slice(0,8)}`;
        document.getElementById('sub-sing').textContent  = `https://sub.yourdomain.com/sing/${u.uuid.slice(0,8)}`;
        document.getElementById('config-raw').innerHTML = formatJSON({
            v:'2', ps: u.name, add:'fra.server.com', port:'443', id: u.uuid,
            aid:'0', net:'tcp', type:'none', tls:'reality',
            sni:'www.speedtest.net', fp:'chrome', pbk:'BZb8p...xG4', sid:'deadbeef',
            flow:'xtls-rprx-vision'
        });
        renderQR();
        openModal('modal-config');
    }

    function openConfigModal() {
        openModal('modal-config');
        document.getElementById('config-modal-title').textContent = 'کانفیگ جدید';
    }

    function formatJSON(obj) {
        return '{<br>' + Object.entries(obj).map(([k,v]) =>
            `&nbsp;&nbsp;<span style="color:var(--text1)">"${k}"</span>: <span style="color:var(--amber)">"${v}"</span>`
        ).join(',<br>') + '<br>}';
    }

    function renderQR() {
        const el = document.getElementById('qr-grid');
        if(!el) return;
        let html = '';
        for(let i=0;i<49;i++) {
            const corner = (i<9&&i%7<3)||(i<9&&i%7>3)||(i>39&&i%7<3)||(i>39&&i%7>3);
            const on = corner || Math.random() > 0.5;
            html += `<div class="qr-cell ${on?'on':''}"></div>`;
        }
        el.innerHTML = html;
    }

    // ─── Subscription Links ───
    function populateSubSelect() {
        const el = document.getElementById('sub-user-select');
        if(!el) return;
        users.forEach(u => {
            const opt = document.createElement('option');
            opt.value = u.id; opt.textContent = u.name;
            el.appendChild(opt);
        });
    }

    function updateSubLinks() {
        const id = document.getElementById('sub-user-select').value;
        const area = document.getElementById('sub-links-area');
        if(!id) { area.style.display = 'none'; return; }
        const u = users.find(x => x.id == id);
        area.style.display = 'block';
        document.getElementById('sl-universal').textContent = `vless://${u.uuid}@fra.server.com:443?…#${u.name}`;
        document.getElementById('sl-clash').textContent    = `https://sub.yourdomain.com/clash/${u.uuid.slice(0,8)}`;
        document.getElementById('sl-sing').textContent     = `https://sub.yourdomain.com/sing/${u.uuid.slice(0,8)}`;
        document.getElementById('sl-v2ray').textContent    = `https://sub.yourdomain.com/v2ray/${u.uuid.slice(0,8)}`;
    }

    // ─── UUID ───
    function genUUID() {
        const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random()*16|0;
            return (c==='x' ? r : (r&0x3|0x8)).toString(16);
        });
        const el = document.getElementById('new-uuid');
        if(el) el.textContent = uuid;
        return uuid;
    }

    // ─── Add User ───
    function addUser() {
        const name = document.getElementById('new-username').value || 'user_new';
        const uuid = document.getElementById('new-uuid').textContent;
        users.push({
            id: users.length+1, name, uuid, proto:'VLESS+Reality',
            used:0, total:50, expire:'1403/10/30', devices:0, maxDev:3, status:'active', online:false
        });
        document.getElementById('stat-total').textContent = users.length;
        renderUsersTable(users);
        renderDashTable();
        closeModal('modal-user');
        showToast('کاربر '+name+' افزوده شد','success');
        genUUID();
    }

    // ─── Modal ───
    function openModal(id) { document.getElementById(id).classList.add('open'); }
    function closeModal(id) { document.getElementById(id).classList.remove('open'); }

    // ─── Copy ───
    function copyText(elId) {
        const el = document.getElementById(elId);
        if(!el) return;
        navigator.clipboard.writeText(el.textContent).then(() => showToast('کپی شد','success')).catch(() => showToast('کپی شد','success'));
    }

    // ─── Toast ───
    let toastTimer;
    function showToast(msg, type='success') {
        const t = document.getElementById('toast');
        const m = document.getElementById('toast-msg');
        m.textContent = msg;
        t.className = `toast ${type} show`;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => t.classList.remove('show'), 2500);
    }
</script>

</body>
</html>
`
};
