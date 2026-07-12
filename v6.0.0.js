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
		const m2 = decodeURIComponent("%F0%9F%9A%80%40lowkey878%20%D8%B3%D8%A7%D8%AE%D8%AA%20%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86%F0%9F%9A%80");
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
	nginx:`
    <!DOCTYPE html>
    <html lang="fa" dir="rtl" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>LOWKEY Panel</title>
        <script>
            const originalWarn = console.warn;
            console.warn = (...args) => {
                if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
                originalWarn(...args);
            };
        </script>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
        <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                        colors: {
                            neon: {
                                purple: '#b388ff',
                                pink: '#ff80ab',
                                blue: '#82b1ff',
                                cyan: '#80deea',
                                gold: '#ffd54f',
                                green: '#69f0ae',
                                red: '#ff8a80'
                            },
                            dark: {
                                1: '#0a0a12',
                                2: '#12121f',
                                3: '#1a1a2e',
                                4: '#222244',
                                5: '#2a2a55'
                            }
                        },
                        boxShadow: {
                            'neon-purple': '0 0 30px rgba(179,136,255,0.15), 0 0 60px rgba(179,136,255,0.05)',
                            'neon-pink': '0 0 30px rgba(255,128,171,0.15), 0 0 60px rgba(255,128,171,0.05)',
                            'neon-gold': '0 0 30px rgba(255,213,79,0.15), 0 0 60px rgba(255,213,79,0.05)',
                            'glow': '0 0 40px rgba(179,136,255,0.2)',
                            'card': '0 4px 24px rgba(0,0,0,0.4)'
                        },
                        animation: {
                            'float': 'float 6s ease-in-out infinite',
                            'float-delay': 'float 6s ease-in-out 3s infinite',
                            'pulse-neon': 'pulseNeon 2s ease-in-out infinite',
                            'shimmer': 'shimmer 3s linear infinite',
                            'gradient-x': 'gradientX 4s ease infinite',
                            'gradient-y': 'gradientY 4s ease infinite',
                            'bounce-subtle': 'bounceSubtle 3s ease-in-out infinite',
                            'spin-slow': 'spin 8s linear infinite',
                            'glow-pulse': 'glowPulse 2s ease-in-out infinite alternate',
                            'slide-up': 'slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards',
                            'slide-down': 'slideDown 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards',
                            'ripple': 'ripple 1s ease-out forwards',
                            'neon-flicker': 'neonFlicker 3s ease-in-out infinite'
                        },
                        keyframes: {
                            float: {
                                '0%, 100%': { transform: 'translateY(0px) rotate(0deg)' },
                                '50%': { transform: 'translateY(-15px) rotate(2deg)' }
                            },
                            pulseNeon: {
                                '0%, 100%': { opacity: '1', transform: 'scale(1)' },
                                '50%': { opacity: '0.7', transform: 'scale(0.95)' }
                            },
                            shimmer: {
                                '0%': { backgroundPosition: '-200% center' },
                                '100%': { backgroundPosition: '200% center' }
                            },
                            gradientX: {
                                '0%, 100%': { backgroundPosition: '0% 50%' },
                                '50%': { backgroundPosition: '100% 50%' }
                            },
                            gradientY: {
                                '0%, 100%': { backgroundPosition: '50% 0%' },
                                '50%': { backgroundPosition: '50% 100%' }
                            },
                            bounceSubtle: {
                                '0%, 100%': { transform: 'translateY(0)' },
                                '50%': { transform: 'translateY(-6px)' }
                            },
                            glowPulse: {
                                '0%': { boxShadow: '0 0 20px rgba(179,136,255,0.2)' },
                                '100%': { boxShadow: '0 0 60px rgba(179,136,255,0.5)' }
                            },
                            slideUp: {
                                '0%': { opacity: '0', transform: 'translateY(20px) scale(0.95)' },
                                '100%': { opacity: '1', transform: 'translateY(0) scale(1)' }
                            },
                            slideDown: {
                                '0%': { opacity: '1', transform: 'translateY(0) scale(1)' },
                                '100%': { opacity: '0', transform: 'translateY(20px) scale(0.95)' }
                            },
                            ripple: {
                                '0%': { transform: 'scale(0.8)', opacity: '1' },
                                '100%': { transform: 'scale(2)', opacity: '0' }
                            },
                            neonFlicker: {
                                '0%, 100%': { opacity: '1' },
                                '25%': { opacity: '0.8' },
                                '50%': { opacity: '1' },
                                '75%': { opacity: '0.85' }
                            },
                            spin: {
                                '0%': { transform: 'rotate(0deg)' },
                                '100%': { transform: 'rotate(360deg)' }
                            }
                        }
                    }
                }
            }
        </script>
        <style>
            /* ============================================
               NEON ORIGAMI - Premium UI Kit
               طراحی با الهام از اوریگامی + نئون
               ============================================ */
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
    
            body {
                font-family: 'Vazirmatn', sans-serif;
                background: #0a0a12;
                min-height: 100vh;
                color: #e8e8f0;
                position: relative;
                overflow-x: hidden;
            }
    
            /* ===== Particle Background ===== */
            #particles-canvas {
                position: fixed;
                inset: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: 0;
            }
    
            /* ===== Neon Grid ===== */
            .neon-grid {
                position: fixed;
                inset: 0;
                pointer-events: none;
                z-index: 0;
                background-image: 
                    linear-gradient(rgba(179,136,255,0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(179,136,255,0.03) 1px, transparent 1px);
                background-size: 60px 60px;
                mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
                -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
            }
    
            /* ===== Neon Orbs ===== */
            .neon-orb {
                position: fixed;
                border-radius: 50%;
                filter: blur(120px);
                pointer-events: none;
                z-index: 0;
                animation: orbFloat 25s ease-in-out infinite;
            }
            .neon-orb:nth-child(1) {
                width: 600px;
                height: 600px;
                background: rgba(179,136,255,0.12);
                top: -200px;
                right: -200px;
                animation-delay: 0s;
            }
            .neon-orb:nth-child(2) {
                width: 500px;
                height: 500px;
                background: rgba(255,128,171,0.08);
                bottom: -200px;
                left: -200px;
                animation-delay: -8s;
            }
            .neon-orb:nth-child(3) {
                width: 400px;
                height: 400px;
                background: rgba(130,177,255,0.08);
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                animation-delay: -16s;
            }
            .neon-orb:nth-child(4) {
                width: 300px;
                height: 300px;
                background: rgba(255,213,79,0.06);
                top: 20%;
                left: 10%;
                animation-delay: -5s;
            }
    
            @keyframes orbFloat {
                0%, 100% { transform: translate(0, 0) scale(1); }
                25% { transform: translate(40px, -40px) scale(1.1); }
                50% { transform: translate(-20px, 30px) scale(0.9); }
                75% { transform: translate(30px, 20px) scale(1.05); }
            }
    
            /* ===== Glass Card ===== */
            .glass-card {
                background: rgba(26, 26, 46, 0.6);
                backdrop-filter: blur(20px) saturate(180%);
                -webkit-backdrop-filter: blur(20px) saturate(180%);
                border: 1px solid rgba(179, 136, 255, 0.08);
                border-radius: 20px;
                transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
                box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
                position: relative;
                overflow: hidden;
            }
    
            .glass-card::before {
                content: '';
                position: absolute;
                inset: 0;
                border-radius: inherit;
                padding: 1px;
                background: linear-gradient(135deg, rgba(179,136,255,0.1), rgba(255,128,171,0.05), rgba(130,177,255,0.1));
                -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
                mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
                -webkit-mask-composite: xor;
                mask-composite: exclude;
                pointer-events: none;
            }
    
            .glass-card:hover {
                border-color: rgba(179, 136, 255, 0.2);
                box-shadow: 0 8px 40px rgba(0, 0, 0, 0.5), 0 0 60px rgba(179, 136, 255, 0.05);
                transform: translateY(-2px);
            }
    
            /* ===== Neon Button ===== */
            .btn-neon {
                position: relative;
                padding: 8px 24px;
                border-radius: 12px;
                font-weight: 600;
                font-size: 0.85rem;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
                border: 1px solid rgba(179, 136, 255, 0.15);
                background: rgba(179, 136, 255, 0.05);
                color: #e8e8f0;
                overflow: hidden;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
    
            .btn-neon::before {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(135deg, rgba(179,136,255,0.1), rgba(255,128,171,0.05));
                opacity: 0;
                transition: opacity 0.4s ease;
            }
    
            .btn-neon:hover::before {
                opacity: 1;
            }
    
            .btn-neon:hover {
                border-color: rgba(179, 136, 255, 0.4);
                transform: translateY(-2px);
                box-shadow: 0 8px 32px rgba(179, 136, 255, 0.15);
            }
    
            .btn-neon:active {
                transform: scale(0.96);
            }
    
            .btn-neon-primary {
                background: linear-gradient(135deg, rgba(179,136,255,0.15), rgba(130,177,255,0.1));
                border-color: rgba(179, 136, 255, 0.2);
            }
    
            .btn-neon-primary:hover {
                box-shadow: 0 8px 40px rgba(179, 136, 255, 0.25);
                border-color: rgba(179, 136, 255, 0.5);
            }
    
            .btn-neon-success {
                background: linear-gradient(135deg, rgba(105,240,174,0.1), rgba(34,197,94,0.05));
                border-color: rgba(105, 240, 174, 0.15);
            }
    
            .btn-neon-success:hover {
                box-shadow: 0 8px 40px rgba(105, 240, 174, 0.2);
                border-color: rgba(105, 240, 174, 0.4);
            }
    
            .btn-neon-danger {
                background: linear-gradient(135deg, rgba(255,138,128,0.1), rgba(239,68,68,0.05));
                border-color: rgba(255, 138, 128, 0.15);
            }
    
            .btn-neon-danger:hover {
                box-shadow: 0 8px 40px rgba(255, 138, 128, 0.2);
                border-color: rgba(255, 138, 128, 0.4);
            }
    
            .btn-neon-gold {
                background: linear-gradient(135deg, rgba(255,213,79,0.1), rgba(245,158,11,0.05));
                border-color: rgba(255, 213, 79, 0.15);
            }
    
            .btn-neon-gold:hover {
                box-shadow: 0 8px 40px rgba(255, 213, 79, 0.2);
                border-color: rgba(255, 213, 79, 0.4);
            }
    
            /* ===== Neon Input ===== */
            .input-neon {
                background: rgba(26, 26, 46, 0.6);
                border: 1px solid rgba(179, 136, 255, 0.08);
                border-radius: 12px;
                padding: 10px 16px;
                color: #e8e8f0;
                transition: all 0.3s ease;
                width: 100%;
                font-size: 0.875rem;
                backdrop-filter: blur(10px);
            }
    
            .input-neon:focus {
                outline: none;
                border-color: rgba(179, 136, 255, 0.3);
                box-shadow: 0 0 30px rgba(179, 136, 255, 0.05), inset 0 0 30px rgba(179, 136, 255, 0.02);
                background: rgba(26, 26, 46, 0.8);
            }
    
            .input-neon::placeholder {
                color: rgba(255, 255, 255, 0.2);
            }
    
            .input-neon:disabled {
                opacity: 0.4;
                cursor: not-allowed;
            }
    
            select.input-neon {
                appearance: none;
                background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='rgba(255,255,255,0.2)' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
                background-repeat: no-repeat;
                background-position: left 12px center;
                padding-left: 36px;
                cursor: pointer;
            }
    
            select.input-neon option {
                background: #1a1a2e;
                color: #e8e8f0;
            }
    
            /* ===== Neon Table ===== */
            .table-neon {
                width: 100%;
                border-collapse: collapse;
            }
    
            .table-neon thead th {
                padding: 12px 10px;
                font-size: 0.65rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: rgba(255, 255, 255, 0.3);
                border-bottom: 1px solid rgba(179, 136, 255, 0.06);
                text-align: center;
                background: rgba(179, 136, 255, 0.02);
            }
    
            .table-neon tbody tr {
                border-bottom: 1px solid rgba(179, 136, 255, 0.03);
                transition: all 0.3s ease;
            }
    
            .table-neon tbody tr:hover {
                background: rgba(179, 136, 255, 0.04);
            }
    
            .table-neon tbody td {
                padding: 8px 6px;
                text-align: center;
                font-size: 0.78rem;
                vertical-align: middle;
            }
    
            /* ===== Neon Scrollbar ===== */
            ::-webkit-scrollbar {
                width: 4px;
                height: 4px;
            }
            ::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.02);
                border-radius: 10px;
            }
            ::-webkit-scrollbar-thumb {
                background: linear-gradient(180deg, #b388ff, #ff80ab);
                border-radius: 10px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(180deg, #d1c4e9, #f48fb1);
            }
    
            /* ===== Stat Card ===== */
            .stat-card {
                background: rgba(26, 26, 46, 0.5);
                backdrop-filter: blur(12px);
                border: 1px solid rgba(179, 136, 255, 0.06);
                border-radius: 16px;
                padding: 16px 20px;
                transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
                position: relative;
                overflow: hidden;
            }
    
            .stat-card::after {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(135deg, rgba(179,136,255,0.03), rgba(255,128,171,0.02));
                opacity: 0;
                transition: opacity 0.4s ease;
            }
    
            .stat-card:hover::after {
                opacity: 1;
            }
    
            .stat-card:hover {
                border-color: rgba(179, 136, 255, 0.15);
                transform: translateY(-3px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
    
            .stat-icon {
                width: 38px;
                height: 38px;
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(179, 136, 255, 0.08);
                border: 1px solid rgba(179, 136, 255, 0.06);
                flex-shrink: 0;
            }
    
            /* ===== Progress Bar ===== */
            .progress-neon {
                width: 100%;
                height: 3px;
                background: rgba(255, 255, 255, 0.04);
                border-radius: 4px;
                overflow: hidden;
                margin-top: 6px;
            }
    
            .progress-neon .progress-fill {
                height: 100%;
                border-radius: 4px;
                background: linear-gradient(90deg, #b388ff, #ff80ab, #82b1ff);
                transition: width 0.8s cubic-bezier(0.16, 1, 0.3, 1);
            }
    
            /* ===== Modal ===== */
            .modal-neon {
                background: rgba(10, 10, 18, 0.9);
                backdrop-filter: blur(40px) saturate(180%);
                -webkit-backdrop-filter: blur(40px) saturate(180%);
                border: 1px solid rgba(179, 136, 255, 0.06);
                border-radius: 24px;
                box-shadow: 0 24px 80px rgba(0, 0, 0, 0.6);
                max-height: 90vh;
                display: flex;
                flex-direction: column;
            }
    
            .modal-neon .modal-header {
                border-bottom: 1px solid rgba(179, 136, 255, 0.05);
                padding: 18px 24px;
                flex-shrink: 0;
            }
    
            .modal-neon .modal-body {
                padding: 24px;
                overflow-y: auto;
                flex: 1;
                overscroll-behavior: contain;
            }
    
            /* ===== Neon Badge ===== */
            .badge-neon {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                padding: 2px 10px;
                border-radius: 20px;
                font-size: 0.6rem;
                font-weight: 700;
                letter-spacing: 0.03em;
            }
    
            .badge-neon-success {
                background: rgba(105, 240, 174, 0.1);
                color: #69f0ae;
                border: 1px solid rgba(105, 240, 174, 0.15);
            }
    
            .badge-neon-danger {
                background: rgba(255, 138, 128, 0.1);
                color: #ff8a80;
                border: 1px solid rgba(255, 138, 128, 0.15);
            }
    
            .badge-neon-warning {
                background: rgba(255, 213, 79, 0.1);
                color: #ffd54f;
                border: 1px solid rgba(255, 213, 79, 0.15);
            }
    
            .badge-neon-info {
                background: rgba(130, 177, 255, 0.1);
                color: #82b1ff;
                border: 1px solid rgba(130, 177, 255, 0.15);
            }
    
            .badge-neon-purple {
                background: rgba(179, 136, 255, 0.1);
                color: #b388ff;
                border: 1px solid rgba(179, 136, 255, 0.15);
            }
    
            /* ===== Neon Toggle ===== */
            .toggle-neon {
                position: relative;
                width: 40px;
                height: 22px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                cursor: pointer;
                transition: all 0.3s ease;
                border: 1px solid rgba(179, 136, 255, 0.06);
                flex-shrink: 0;
            }
    
            .toggle-neon.active {
                background: linear-gradient(135deg, rgba(179,136,255,0.3), rgba(130,177,255,0.2));
                border-color: rgba(179, 136, 255, 0.2);
            }
    
            .toggle-neon .toggle-dot {
                position: absolute;
                top: 2px;
                right: 2px;
                width: 16px;
                height: 16px;
                background: rgba(255, 255, 255, 0.2);
                border-radius: 50%;
                transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
            }
    
            .toggle-neon.active .toggle-dot {
                background: #b388ff;
                transform: translateX(-18px);
                box-shadow: 0 0 20px rgba(179, 136, 255, 0.3);
            }
    
            /* ===== Header ===== */
            .header-neon {
                background: rgba(10, 10, 18, 0.7);
                backdrop-filter: blur(24px) saturate(180%);
                border-bottom: 1px solid rgba(179, 136, 255, 0.05);
                padding: 10px 24px;
                position: sticky;
                top: 0;
                z-index: 40;
            }
    
            /* ===== Neon Checkbox ===== */
            .checkbox-neon {
                appearance: none;
                width: 16px;
                height: 16px;
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(179, 136, 255, 0.1);
                border-radius: 5px;
                cursor: pointer;
                transition: all 0.3s ease;
                position: relative;
                flex-shrink: 0;
            }
    
            .checkbox-neon:checked {
                background: linear-gradient(135deg, #b388ff, #82b1ff);
                border-color: #b388ff;
            }
    
            .checkbox-neon:checked::after {
                content: '✓';
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                color: white;
                font-size: 10px;
                font-weight: 700;
            }
    
            .checkbox-neon:hover {
                border-color: rgba(179, 136, 255, 0.3);
            }
    
            /* ===== Toast ===== */
            .toast-neon {
                background: rgba(10, 10, 18, 0.9);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(179, 136, 255, 0.08);
                border-radius: 14px;
                padding: 12px 24px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
                color: #e8e8f0;
                font-weight: 600;
                font-size: 0.875rem;
            }
    
            .toast-neon-success {
                border-color: rgba(105, 240, 174, 0.2);
            }
    
            .toast-neon-error {
                border-color: rgba(255, 138, 128, 0.2);
            }
    
            /* ===== Gradient Text ===== */
            .gradient-text-neon {
                background: linear-gradient(135deg, #b388ff, #ff80ab, #82b1ff, #80deea);
                background-size: 300% 300%;
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                animation: gradientX 4s ease infinite;
            }
    
            /* ===== Divider ===== */
            .divider-neon {
                height: 1px;
                background: linear-gradient(90deg, transparent, rgba(179,136,255,0.08), transparent);
                margin: 8px 0;
            }
    
            /* ===== Pulse Ring ===== */
            .pulse-ring-neon {
                position: absolute;
                inset: -3px;
                border-radius: inherit;
                border: 1px solid rgba(179, 136, 255, 0.15);
                animation: pulseRing 2s ease-out infinite;
            }
    
            @keyframes pulseRing {
                0% { transform: scale(1); opacity: 1; }
                100% { transform: scale(1.3); opacity: 0; }
            }
    
            /* ===== Responsive ===== */
            @media (max-width: 768px) {
                .header-neon { padding: 8px 16px; }
                .stat-card { padding: 12px 16px; }
                .modal-neon .modal-body { padding: 16px; }
                .table-neon thead th,
                .table-neon tbody td {
                    font-size: 0.6rem;
                    padding: 4px 3px;
                }
                .btn-neon { padding: 6px 16px; font-size: 0.75rem; }
            }
    
            /* ===== Typography ===== */
            .font-mono-neon {
                font-family: 'Vazirmatn', monospace;
            }
    
            /* ===== Animations ===== */
            .fade-in-neon {
                animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
                opacity: 0;
            }
    
            .stagger-neon > * {
                opacity: 0;
                animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            }
    
            .stagger-neon > *:nth-child(1) { animation-delay: 0.02s; }
            .stagger-neon > *:nth-child(2) { animation-delay: 0.06s; }
            .stagger-neon > *:nth-child(3) { animation-delay: 0.10s; }
            .stagger-neon > *:nth-child(4) { animation-delay: 0.14s; }
            .stagger-neon > *:nth-child(5) { animation-delay: 0.18s; }
            .stagger-neon > *:nth-child(6) { animation-delay: 0.22s; }
            .stagger-neon > *:nth-child(n+7) { animation-delay: 0.26s; }
    
            /* ===== Neon Glow Text ===== */
            .neon-glow-text {
                text-shadow: 0 0 20px rgba(179,136,255,0.2), 0 0 60px rgba(179,136,255,0.05);
            }
    
            /* ===== Status Dot ===== */
            .status-dot {
                display: inline-block;
                width: 6px;
                height: 6px;
                border-radius: 50%;
                margin-right: 4px;
            }
            .status-dot-online { background: #69f0ae; box-shadow: 0 0 12px rgba(105,240,174,0.4); }
            .status-dot-offline { background: rgba(255,255,255,0.2); }
            .status-dot-active { background: #b388ff; box-shadow: 0 0 12px rgba(179,136,255,0.4); }
            .status-dot-inactive { background: #ff8a80; box-shadow: 0 0 12px rgba(255,138,128,0.3); }
        </style>
    </head>
    <body>
    
        <!-- ===== Particle Canvas ===== -->
        <canvas id="particles-canvas"></canvas>
    
        <!-- ===== Neon Grid ===== -->
        <div class="neon-grid"></div>
    
        <!-- ===== Neon Orbs ===== -->
        <div class="neon-orb"></div>
        <div class="neon-orb"></div>
        <div class="neon-orb"></div>
        <div class="neon-orb"></div>
    
        <!-- ==========================================
        HEADER
        ========================================== -->
        <header class="header-neon relative z-10">
            <div class="max-w-6xl mx-auto flex flex-col md:flex-row justify-between items-center gap-3">
                <!-- Brand -->
                <div class="flex items-center gap-3">
                    <div class="relative">
                        <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-purple-400 via-pink-400 to-blue-400 flex items-center justify-center shadow-lg shadow-purple-500/20">
                            <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                            </svg>
                        </div>
                        <div class="pulse-ring-neon"></div>
                    </div>
                    <div>
                        <h1 class="text-lg font-bold gradient-text-neon" dir="ltr">LOWKEY</h1>
                        <span id="panel-version" class="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/10">v1.5.10</span>
                    </div>
                </div>
    
                <!-- Actions -->
                <div class="flex items-center gap-1 bg-white/5 backdrop-blur-lg rounded-full p-1 border border-white/5">
                    <button onclick="restartCore()" class="btn-neon !p-2 !rounded-full !w-8 !h-8 flex items-center justify-center" title="ری استارت پنل">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                        </svg>
                    </button>
    
                    <button id="theme-toggle" class="btn-neon !p-2 !rounded-full !w-8 !h-8 flex items-center justify-center" title="تغییر تم">
                        <svg id="sun-icon" class="w-3.5 h-3.5 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"/>
                        </svg>
                        <svg id="moon-icon" class="w-3.5 h-3.5 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                    </button>
    
                    <button onclick="toggleSettingsModal(true)" class="btn-neon !p-2 !rounded-full !w-8 !h-8 flex items-center justify-center" title="تنظیمات">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                        </svg>
                    </button>
    
                    <div class="w-px h-5 bg-white/10"></div>
    
                    <button onclick="logoutAdmin()" class="btn-neon !p-2 !rounded-full !w-8 !h-8 flex items-center justify-center !border-red-500/15 hover:!border-red-500/30" title="خروج">
                        <svg class="w-3.5 h-3.5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                        </svg>
                    </button>
                </div>
            </div>
        </header>
    
        <!-- ==========================================
        MAIN CONTENT
        ========================================== -->
        <main class="max-w-6xl mx-auto px-4 py-6 relative z-10">
    
            <!-- ===== STATS ===== -->
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5 stagger-neon">
                <div class="stat-card fade-in-neon" style="animation-delay:0.02s">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-medium text-white/30">کل کاربران</span>
                        <div class="stat-icon">
                            <svg class="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
                            </svg>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="text-xl font-bold text-white" id="stat-total-users">0</span>
                        <span class="text-[10px] text-white/20 mr-1">کاربر</span>
                    </div>
                </div>
    
                <div class="stat-card fade-in-neon" style="animation-delay:0.06s">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-medium text-white/30">آنلاین</span>
                        <div class="stat-icon" style="background:rgba(105,240,174,0.06);border-color:rgba(105,240,174,0.06);">
                            <svg class="w-3.5 h-3.5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                            </svg>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="text-xl font-bold text-green-400" id="stat-active-users">0</span>
                        <span class="text-[10px] text-white/20 mr-1">اتصال</span>
                    </div>
                </div>
    
                <div class="stat-card fade-in-neon" style="animation-delay:0.10s">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-medium text-white/30">ترافیک</span>
                        <div class="stat-icon" style="background:rgba(130,177,255,0.06);border-color:rgba(130,177,255,0.06);">
                            <svg class="w-3.5 h-3.5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                            </svg>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="text-xl font-bold text-blue-400" id="stat-total-usage">0 GB</span>
                        <span class="text-[10px] text-white/20 mr-1">کل</span>
                    </div>
                </div>
    
                <div class="stat-card fade-in-neon" style="animation-delay:0.14s">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] font-medium text-white/30">درخواست روز</span>
                        <div class="stat-icon" style="background:rgba(255,213,79,0.06);border-color:rgba(255,213,79,0.06);">
                            <svg class="w-3.5 h-3.5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"/>
                            </svg>
                        </div>
                    </div>
                    <div class="mt-2">
                        <span class="text-xl font-bold text-amber-400" id="stat-cf-requests">0</span>
                        <span class="text-[10px] text-white/20 mr-1">/ 100k</span>
                    </div>
                    <div class="progress-neon">
                        <div class="progress-fill" id="stat-cf-progress" style="width:0%"></div>
                    </div>
                </div>
            </div>
    
            <!-- ===== TOOLBAR ===== -->
            <div class="glass-card p-3 mb-4 flex flex-col md:flex-row gap-3 items-center">
                <div class="relative w-full md:w-72">
                    <input type="text" id="search-input" oninput="filterAndRenderUsers()" placeholder="جستجوی کاربر یا UUID..." class="input-neon pl-9 pr-4">
                    <svg class="absolute top-1/2 -translate-y-1/2 right-3 w-3.5 h-3.5 text-white/20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                </div>
                
                <div class="flex gap-2 w-full md:w-auto flex-wrap">
                    <select id="filter-status" onchange="filterAndRenderUsers()" class="input-neon !py-1.5 !px-3 text-xs flex-1 min-w-[80px]">
                        <option value="all">🔍 همه</option>
                        <option value="active">✅ فعال</option>
                        <option value="inactive">❌ غیرفعال</option>
                        <option value="online">⚡ آنلاین</option>
                        <option value="offline">💤 آفلاین</option>
                        <option value="expired">⏳ منقضی</option>
                    </select>
                    <select id="sort-users" onchange="filterAndRenderUsers()" class="input-neon !py-1.5 !px-3 text-xs flex-1 min-w-[80px]">
                        <option value="newest">📅 جدید</option>
                        <option value="name">🔤 نام</option>
                        <option value="usage-desc">📊 بیشترین</option>
                        <option value="usage-asc">📈 کمترین</option>
                        <option value="expiry-asc">⏳ کمترین زمان</option>
                    </select>
                </div>
            </div>
    
            <!-- ===== USER LIST HEADER ===== -->
            <div class="flex items-center justify-between mb-3">
                <h2 class="text-base font-bold text-white/80 flex items-center gap-2">
                    <span class="w-1 h-5 rounded-full bg-gradient-to-b from-purple-400 to-blue-400"></span>
                    لیست کاربران
                </h2>
                <button onclick="openCreateModal()" class="btn-neon btn-neon-primary flex items-center gap-2 !px-4 !py-2 text-sm">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/>
                    </svg>
                    جدید
                </button>
            </div>
    
            <!-- ===== TABLE ===== -->
            <div id="users-table-container" class="glass-card overflow-hidden hidden">
                <div class="overflow-x-auto">
                    <table class="table-neon">
                        <thead>
                            <tr>
                                <th style="width:32px;">
                                    <input type="checkbox" id="select-all-users" onchange="toggleSelectAllUsers(this)" class="checkbox-neon">
                                </th>
                                <th>وضعیت</th>
                                <th>عملیات</th>
                                <th>لینک ساب</th>
                                <th>پورت</th>
                                <th>حجم</th>
                                <th>ریکوئست</th>
                                <th>زمان</th>
                                <th>کاربران آنلاین</th>
                            </tr>
                        </thead>
                        <tbody id="users-tbody"></tbody>
                    </table>
                </div>
            </div>
    
            <!-- ===== EMPTY STATE ===== -->
            <div id="empty-state" class="glass-card p-12 text-center hidden">
                <div class="text-5xl mb-3">✨</div>
                <p class="text-white/40 font-medium">هیچ کاربری وجود ندارد</p>
                <p class="text-white/20 text-sm">روی دکمه <span class="text-purple-400 font-bold">«جدید»</span> کلیک کنید</p>
            </div>
    
            <!-- ===== LOADING ===== -->
            <div id="loading-state" class="text-center py-10">
                <div class="inline-flex items-center gap-3 text-white/40">
                    <svg class="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    <span>در حال بارگذاری...</span>
                </div>
            </div>
        </main>
    
        <!-- ==========================================
        USER MODAL
        ========================================== -->
        <div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-300 ease-out">
            <div id="user-modal-card" class="w-full max-w-xl modal-neon transition-[opacity,transform] duration-300 opacity-0 scale-95 ease-out">
                <div class="modal-header flex justify-between items-center">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-purple-400 to-blue-400 flex items-center justify-center text-white shadow-lg shadow-purple-500/20">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5v15m7.5-7.5h-15"/>
                            </svg>
                        </div>
                        <h3 id="modal-title" class="font-bold text-white text-base">ایجاد کاربر جدید</h3>
                    </div>
                    <button onclick="toggleModal(false)" class="btn-neon !p-1.5 !rounded-xl !border-red-500/15 hover:!border-red-500/30">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="create-user-form" onsubmit="handleFormSubmit(event)" class="space-y-4">
                        <!-- Name -->
                        <div>
                            <label class="block text-[11px] font-bold text-white/30 uppercase tracking-wider mb-1">نام کاربری</label>
                            <input type="text" id="input-name" placeholder="PANEL_LOWKEY" maxlength="32" class="input-neon" required>
                        </div>
    
                        <!-- Limits Grid -->
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
                            <div>
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1">حجم (GB)</label>
                                <input type="number" id="input-limit" min="0" step="any" placeholder="نامحدود" class="input-neon">
                            </div>
                            <div>
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1">اعتبار (روز)</label>
                                <input type="number" id="input-expiry" min="0" placeholder="نامحدود" class="input-neon">
                            </div>
                            <div>
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1">سقف ریکوئست</label>
                                <input type="number" id="input-req-limit" min="0" placeholder="نامحدود" class="input-neon">
                            </div>
                            <div>
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1">محدودیت کاربر</label>
                                <input type="number" id="input-ip-limit" min="0" placeholder="نامحدود" class="input-neon">
                            </div>
                        </div>
    
                        <!-- Fragment & Fingerprint -->
                        <div class="grid grid-cols-2 gap-3">
                            <div class="p-3 rounded-xl bg-white/5 border border-white/5">
                                <div class="flex items-center justify-between mb-2">
                                    <span class="text-[10px] font-bold text-white/30 uppercase tracking-wider">Fragment</span>
                                    <div id="input-frag-toggle" class="toggle-neon active" onclick="toggleFragInputs(this)">
                                        <div class="toggle-dot"></div>
                                    </div>
                                </div>
                                <div id="frag-inputs-container" class="grid grid-cols-2 gap-1.5">
                                    <input type="text" id="input-frag-len" placeholder="Len" value="200-3000" dir="ltr" class="input-neon !text-xs !text-center">
                                    <input type="text" id="input-frag-int" placeholder="Int" value="1-2" dir="ltr" class="input-neon !text-xs !text-center">
                                </div>
                            </div>
                            <div class="p-3 rounded-xl bg-white/5 border border-white/5">
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1.5">Fingerprint</label>
                                <select id="fingerprint-select" class="input-neon !text-xs">
                                    <option value="chrome">🌐 Chrome</option>
                                    <option value="firefox">🦊 Firefox</option>
                                    <option value="safari">🧭 Safari</option>
                                    <option value="ios" selected>📱 iOS</option>
                                    <option value="android">🤖 Android</option>
                                    <option value="edge">🌀 Edge</option>
                                    <option value="360">🔒 360</option>
                                    <option value="qq">💬 QQ</option>
                                    <option value="random">🎲 Random</option>
                                    <option value="randomized">🎭 Dynamic</option>
                                </select>
                            </div>
                        </div>
    
                        <!-- Blockers -->
                        <div class="grid grid-cols-2 gap-2">
                            <div class="flex items-center justify-between p-2 rounded-xl bg-white/5 border border-white/5">
                                <span class="text-[10px] font-semibold text-white/60">NSFW Blacker</span>
                                <div class="toggle-neon" onclick="this.classList.toggle('active')">
                                    <div class="toggle-dot"></div>
                                </div>
                            </div>
                            <div class="flex items-center justify-between p-2 rounded-xl bg-white/5 border border-white/5">
                                <span class="text-[10px] font-semibold text-white/60">ADS blocker</span>
                                <div class="toggle-neon" onclick="this.classList.toggle('active')">
                                    <div class="toggle-dot"></div>
                                </div>
                            </div>
                        </div>
    
                        <!-- Ports -->
                        <div class="pt-2 border-t border-white/5">
                            <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-2">پورت‌های اتصال</label>
                            <div class="grid grid-cols-2 gap-2">
                                <div class="p-2 rounded-xl bg-white/5 border border-white/5">
                                    <div class="flex items-center gap-1.5 mb-1.5">
                                        <span class="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                                        <span class="text-[10px] font-bold text-purple-400">TLS</span>
                                    </div>
                                    <div class="grid grid-cols-3 gap-1" id="tls-ports-list"></div>
                                </div>
                                <div class="p-2 rounded-xl bg-white/5 border border-white/5">
                                    <div class="flex items-center gap-1.5 mb-1.5">
                                        <span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                                        <span class="text-[10px] font-bold text-amber-400">Non-TLS</span>
                                    </div>
                                    <div class="grid grid-cols-3 gap-1" id="nontls-ports-list"></div>
                                </div>
                            </div>
                            <div class="mt-2">
                                <input type="text" id="input-custom-ports" placeholder="پورت‌های دلخواه (با فاصله)" dir="ltr" class="input-neon !text-xs">
                            </div>
                        </div>
    
                        <!-- IPs & Proxy -->
                        <div class="pt-2 border-t border-white/5 space-y-3">
                            <div>
                                <div class="flex items-center justify-between mb-1.5">
                                    <label class="text-[10px] font-bold text-white/30 uppercase tracking-wider">آیپی تمیز</label>
                                    <button type="button" onclick="openIpSelectorModal()" class="btn-neon btn-neon-gold !px-3 !py-1 text-[10px]">مخزن آیپی</button>
                                </div>
                                <textarea id="input-ips" rows="2" placeholder="104.16.0.1" class="input-neon !text-xs resize-none"></textarea>
                            </div>
    
                            <div>
                                <div class="flex items-center justify-between">
                                    <label class="text-[10px] font-bold text-white/30 uppercase tracking-wider">پروکسی اختصاصی</label>
                                    <div class="toggle-neon" onclick="toggleUserProxyMode(this)" id="user-proxy-toggle">
                                        <div class="toggle-dot"></div>
                                    </div>
                                </div>
                                <div id="user-socks5-container" class="mt-2 opacity-50 pointer-events-none">
                                    <input type="text" id="user-socks5-input" placeholder="socks5:// یا http://" dir="ltr" class="input-neon !text-xs" disabled>
                                    <div class="flex gap-2 mt-2">
                                        <button type="button" onclick="testUserSocksProxy()" class="btn-neon !text-[10px] !py-1 flex-1">تست</button>
                                        <button type="button" onclick="openProxySelectorModal()" class="btn-neon btn-neon-gold !text-[10px] !py-1 flex-1">مخزن</button>
                                    </div>
                                    <span id="test-user-proxy-result" class="inline-block mt-1.5 text-[10px] font-bold transition-colors break-words leading-relaxed empty:hidden"></span>
                                </div>
                            </div>
    
                            <div id="user-cf-proxy-section" class="transition-opacity duration-500 pt-2 border-t border-white/5">
                                <label class="block text-[10px] font-bold text-white/30 uppercase tracking-wider mb-1">لوکیشن (Cloudflare)</label>
                                <input type="text" id="user-location-search" oninput="filterUserLocations()" placeholder="جستجوی شهر یا کشور" class="input-neon !text-xs mb-1.5">
                                <select id="user-location-select" class="input-neon !text-xs">
                                    <option value="">بدون لوکیشن</option>
                                </select>
                            </div>
                        </div>
    
                        <!-- Actions -->
                        <div class="flex gap-3 pt-3 border-t border-white/5">
                            <button type="button" onclick="toggleModal(false)" class="btn-neon btn-neon-danger flex-1">انصراف</button>
                            <button type="submit" id="submit-btn" class="btn-neon btn-neon-primary flex-1">ایجاد کاربر</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    
        <!-- ==========================================
        SETTINGS MODAL
        ========================================== -->
        <div id="settings-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-300 ease-out">
            <div class="w-full max-w-md modal-neon transition-[opacity,transform] duration-300 opacity-0 scale-95 ease-out">
                <div class="modal-header flex justify-between items-center">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-xl bg-gradient-to-br from-amber-400 to-purple-400 flex items-center justify-center text-white shadow-lg shadow-purple-500/20">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                            </svg>
                        </div>
                        <h3 class="font-bold text-white text-base">تنظیمات پنل</h3>
                    </div>
                    <button onclick="toggleSettingsModal(false)" class="btn-neon !p-1.5 !rounded-xl !border-red-500/15 hover:!border-red-500/30">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body space-y-4">
                    <!-- Refresh Rate -->
                    <div>
                        <label class="block text-[11px] font-bold text-white/30 uppercase tracking-wider mb-1">نرخ رفرش خودکار</label>
                        <select id="refresh-rate-select" onchange="changeRefreshRate(this.value)" class="input-neon">
                            <option value="1000">۱ ثانیه</option>
                            <option value="2000" selected>۲ ثانیه</option>
                            <option value="5000">۵ ثانیه</option>
                            <option value="10000">۱۰ ثانیه</option>
                            <option value="30000">۳۰ ثانیه</option>
                            <option value="60000">۱ دقیقه</option>
                            <option value="300000">۵ دقیقه</option>
                            <option value="600000">۱۰ دقیقه</option>
                        </select>
                    </div>
    
                    <!-- Change Password -->
                    <div class="pt-3 border-t border-white/5">
                        <h4 class="text-sm font-bold text-white/60 mb-2">🔒 تغییر رمز عبور</h4>
                        <div class="space-y-2">
                            <input type="password" id="change-pwd-current" placeholder="رمز فعلی" class="input-neon !text-xs">
                            <input type="password" id="change-pwd-new" placeholder="رمز جدید" class="input-neon !text-xs">
                            <button type="button" onclick="changeAdminPassword()" class="btn-neon btn-neon-primary w-full">تغییر رمز</button>
                        </div>
                    </div>
    
                    <!-- Backup -->
                    <div class="pt-3 border-t border-white/5">
                        <h4 class="text-sm font-bold text-white/60 mb-2">💾 پشتیبان‌گیری</h4>
                        <div class="grid grid-cols-2 gap-2">
                            <button type="button" onclick="exportUsersBackup()" class="btn-neon btn-neon-success">📤 پشتیبان</button>
                            <button type="button" onclick="triggerImportBackup()" class="btn-neon btn-neon-gold">📥 بازیابی</button>
                        </div>
                        <input type="file" id="backup-file-input" onchange="importUsersBackup(event)" accept=".json" class="hidden">
                    </div>
    
                    <!-- Actions -->
                    <div class="flex gap-3 pt-3 border-t border-white/5">
                        <button type="button" onclick="toggleSettingsModal(false)" class="btn-neon btn-neon-danger flex-1">انصراف</button>
                        <button type="button" onclick="saveSettings()" class="btn-neon btn-neon-primary flex-1">ذخیره</button>
                    </div>
                </div>
            </div>
        </div>
    
        <!-- ==========================================
        OTHER MODALS (IP Selector, Proxy Selector, etc.)
        ========================================== -->
        <!-- IP Selector Modal -->
        <div id="ip-selector-modal" class="fixed inset-0 z-60 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-500 ease-out">
            <div class="w-full max-w-sm modal-neon transition-all transform duration-500 opacity-0 scale-95 ease-out">
                <div class="modal-header flex justify-between items-center">
                    <h3 class="font-bold text-white text-sm">مخزن آیپی تمیز</h3>
                    <button onclick="toggleIpSelectorModal(false)" class="btn-neon !p-1.5 !rounded-xl !border-red-500/15 hover:!border-red-500/30">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body space-y-3">
                    <div id="ip-loading-state" class="text-center text-sm text-white/40 hidden">Loading IPs...</div>
                    <div id="ip-selection-form" class="space-y-3">
                        <select id="ip-operator-select" class="input-neon">
                            <option value="all">همه (توصیه شده)</option>
                        </select>
                        <input type="number" id="ip-count-input" min="1" value="20" dir="ltr" class="input-neon !text-center">
                    </div>
                    <div class="flex gap-3">
                        <button onclick="toggleIpSelectorModal(false)" class="btn-neon btn-neon-danger flex-1">لغو</button>
                        <button onclick="applySelectedIps()" class="btn-neon btn-neon-primary flex-1">دریافت</button>
                    </div>
                </div>
            </div>
        </div>
    
        <!-- Proxy Selector Modal -->
        <div id="proxy-selector-modal" class="fixed inset-0 z-60 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-all duration-500 ease-out">
            <div class="w-full max-w-md modal-neon transition-all transform duration-500 opacity-0 scale-95 ease-out">
                <div class="modal-header flex justify-between items-center">
                    <h3 class="font-bold text-white text-sm">مخزن پروکسی</h3>
                    <button onclick="toggleProxySelectorModal(false)" class="btn-neon !p-1.5 !rounded-xl !border-red-500/15 hover:!border-red-500/30">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body space-y-3">
                    <!-- VIP -->
                    <div class="p-3 rounded-xl bg-green-500/5 border border-green-500/10">
                        <h4 class="text-xs font-bold text-green-400">VIP</h4>
                        <div class="flex gap-2 mt-2">
                            <select id="vip-country-select" class="input-neon !text-xs flex-1">
                                <option value="">در حال بررسی...</option>
                            </select>
                            <button onclick="loadVipProxy()" class="btn-neon btn-neon-success !text-xs">دریافت</button>
                        </div>
                    </div>
                    <!-- Public -->
                    <div class="p-3 rounded-xl bg-white/5 border border-white/5">
                        <h4 class="text-xs font-bold text-white/40">عمومی</h4>
                        <div id="proxy-loading-state" class="text-center text-xs text-purple-400 hidden">در حال اسکن...</div>
                        <div id="proxy-selection-form" class="space-y-2">
                            <select id="proxy-country-select" class="input-neon !text-xs">
                                <option value="">انتخاب کشور</option>
                            </select>
                            <button onclick="fetchAndLoadProxy()" class="btn-neon btn-neon-primary w-full !text-xs">اسکن و دریافت</button>
                        </div>
                    </div>
                    <button onclick="toggleProxySelectorModal(false)" class="btn-neon btn-neon-danger w-full">بستن</button>
                </div>
            </div>
        </div>
    
        <!-- Bulk Actions Bar -->
        <div id="bulk-actions-bar" class="fixed bottom-4 left-1/2 -translate-x-1/2 z-40 glass-card px-4 py-2 flex flex-wrap items-center justify-between gap-2 w-[95%] max-w-4xl transition-all duration-500 transform translate-y-28 opacity-0 pointer-events-none">
            <span id="bulk-selected-count" class="text-sm font-bold text-white/60">۰ کاربر</span>
            <div class="flex flex-wrap gap-1.5">
                <button onclick="bulkEdit()" class="btn-neon btn-neon-gold !text-[10px] !py-1">✏️ ویرایش</button>
                <button onclick="bulkToggleStatus(1)" class="btn-neon btn-neon-success !text-[10px] !py-1">✅ فعال</button>
                <button onclick="bulkToggleStatus(0)" class="btn-neon btn-neon-danger !text-[10px] !py-1">❌ غیرفعال</button>
                <button onclick="bulkReset('volume')" class="btn-neon !text-[10px] !py-1">📊 حجم</button>
                <button onclick="bulkReset('req')" class="btn-neon !text-[10px] !py-1">⚡ ریکوئست</button>
                <button onclick="bulkReset('time')" class="btn-neon !text-[10px] !py-1">⏳ زمان</button>
                <button onclick="bulkDelete()" class="btn-neon btn-neon-danger !text-[10px] !py-1">🗑️ حذف</button>
            </div>
        </div>
    
        <!-- Bulk Edit Modal -->
        <div id="bulk-edit-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 opacity-0 pointer-events-none transition-opacity duration-300 ease-out">
            <div class="w-full max-w-xl modal-neon transition-[opacity,transform] duration-300 opacity-0 scale-95 ease-out">
                <div class="modal-header flex justify-between items-center">
                    <h3 class="font-bold text-white text-base">ویرایش گروهی</h3>
                    <button onclick="toggleBulkEditModal(false)" class="btn-neon !p-1.5 !rounded-xl !border-red-500/15 hover:!border-red-500/30">
                        <svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
                <div class="modal-body">
                    <form id="bulk-edit-form" onsubmit="handleBulkEditSubmit(event)" class="space-y-3">
                        <p class="text-xs text-amber-400">💡 فقط فیلدهایی که چپ آن‌ها روشن است تغییر می‌کنند</p>
                        <!-- Bulk fields -->
                        <div class="space-y-2">
                            <div class="flex items-center gap-2 p-2 rounded-xl bg-white/5 border border-white/5">
                                <div class="toggle-neon" onclick="this.classList.toggle('active')"><div class="toggle-dot"></div></div>
                                <input type="number" id="bulk-input-limit" placeholder="حجم (GB)" class="input-neon !text-xs flex-1">
                            </div>
                            <div class="flex items-center gap-2 p-2 rounded-xl bg-white/5 border border-white/5">
                                <div class="toggle-neon" onclick="this.classList.toggle('active')"><div class="toggle-dot"></div></div>
                                <input type="number" id="bulk-input-expiry" placeholder="اعتبار (روز)" class="input-neon !text-xs flex-1">
                            </div>
                            <div class="flex items-center gap-2 p-2 rounded-xl bg-white/5 border border-white/5">
                                <div class="toggle-neon" onclick="this.classList.toggle('active')"><div class="toggle-dot"></div></div>
                                <input type="number" id="bulk-input-req-limit" placeholder="سقف ریکوئست" class="input-neon !text-xs flex-1">
                            </div>
                            <div class="flex items-center gap-2 p-2 rounded-xl bg-white/5 border border-white/5">
                                <div class="toggle-neon" onclick="this.classList.toggle('active')"><div class="toggle-dot"></div></div>
                                <input type="number" id="bulk-input-ip-limit" placeholder="محدودیت کاربر" class="input-neon !text-xs flex-1">
                            </div>
                            <div class="flex items-center gap-2 p-2 rounded-xl bg-white/5 border border-white/5">
                                <div class="toggle-neon" onclick="this.classList.toggle('active')"><div class="toggle-dot"></div></div>
                                <select id="bulk-fingerprint-select" class="input-neon !text-xs flex-1">
                                    <option value="ios">Fingerprint</option>
                                    <option value="chrome">Chrome</option>
                                    <option value="firefox">Firefox</option>
                                    <option value="safari">Safari</option>
                                    <option value="random">Random</option>
                                </select>
                            </div>
                        </div>
                        <div class="flex gap-3 pt-3 border-t border-white/5">
                            <button type="button" onclick="toggleBulkEditModal(false)" class="btn-neon btn-neon-danger flex-1">انصراف</button>
                            <button type="submit" class="btn-neon btn-neon-primary flex-1">ثبت تغییرات</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    
        <!-- ==========================================
        TOAST CONTAINER
        ========================================== -->
        <div id="toast-container" class="fixed top-5 left-1/2 -translate-x-1/2 z-[9999] flex flex-col gap-2 pointer-events-none"></div>
    
        <!-- ==========================================
        SCRIPTS
        ========================================== -->
        <script>
            // ==========================================
            // PARTICLES SYSTEM
            // ==========================================
            (function initParticles() {
                const canvas = document.getElementById('particles-canvas');
                const ctx = canvas.getContext('2d');
                let particles = [];
                let mouse = { x: null, y: null };
    
                function resize() {
                    canvas.width = window.innerWidth;
                    canvas.height = window.innerHeight;
                }
                window.addEventListener('resize', resize);
                resize();
    
                class Particle {
                    constructor() {
                        this.x = Math.random() * canvas.width;
                        this.y = Math.random() * canvas.height;
                        this.size = Math.random() * 2 + 0.5;
                        this.speedX = (Math.random() - 0.5) * 0.5;
                        this.speedY = (Math.random() - 0.5) * 0.5;
                        this.opacity = Math.random() * 0.5 + 0.1;
                        this.color = ['#b388ff', '#ff80ab', '#82b1ff', '#80deea', '#ffd54f'][Math.floor(Math.random() * 5)];
                    }
    
                    update() {
                        this.x += this.speedX;
                        this.y += this.speedY;
                        if (this.x > canvas.width) this.x = 0;
                        if (this.x < 0) this.x = canvas.width;
                        if (this.y > canvas.height) this.y = 0;
                        if (this.y < 0) this.y = canvas.height;
                        if (mouse.x !== null) {
                            const dx = mouse.x - this.x;
                            const dy = mouse.y - this.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < 150) {
                                const force = (150 - dist) / 150 * 0.05;
                                this.x += dx * force;
                                this.y += dy * force;
                            }
                        }
                    }
    
                    draw() {
                        ctx.beginPath();
                        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                        ctx.fillStyle = this.color;
                        ctx.globalAlpha = this.opacity;
                        ctx.fill();
                    }
                }
    
                for (let i = 0; i < 80; i++) {
                    particles.push(new Particle());
                }
    
                function connectParticles() {
                    for (let i = 0; i < particles.length; i++) {
                        for (let j = i + 1; j < particles.length; j++) {
                            const dx = particles[i].x - particles[j].x;
                            const dy = particles[i].y - particles[j].y;
                            const dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < 120) {
                                ctx.beginPath();
                                ctx.moveTo(particles[i].x, particles[i].y);
                                ctx.lineTo(particles[j].x, particles[j].y);
                                ctx.strokeStyle = 'rgba(179,136,255,0.06)';
                                ctx.lineWidth = 0.5;
                                ctx.stroke();
                            }
                        }
                    }
                }
    
                function animate() {
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    particles.forEach(p => { p.update(); p.draw(); });
                    connectParticles();
                    requestAnimationFrame(animate);
                }
    
                document.addEventListener('mousemove', (e) => { mouse.x = e.clientX; mouse.y = e.clientY; });
                document.addEventListener('mouseleave', () => { mouse.x = null; mouse.y = null; });
                animate();
            })();
    
            // ==========================================
            // TOAST SYSTEM
            // ==========================================
            function showToast(message, type = 'success') {
                const container = document.getElementById('toast-container');
                const toast = document.createElement('div');
                const isError = type === 'error';
                toast.className = 'toast-neon ' + (isError ? 'toast-neon-error' : 'toast-neon-success') + 
                                ' transform transition-all duration-500 -translate-y-full opacity-0';
                toast.innerText = message;
                container.appendChild(toast);
                requestAnimationFrame(() => {
                    toast.classList.remove('-translate-y-full', 'opacity-0');
                });
                setTimeout(() => {
                    toast.classList.add('-translate-y-full', 'opacity-0');
                    setTimeout(() => toast.remove(), 300);
                }, 3000);
            }
    
            window.alert = function(message) {
                const msgStr = message ? message.toString() : '';
                if (msgStr.includes('خطا') || msgStr.includes('⚠️') || msgStr.includes('❌')) {
                    showToast(msgStr, 'error');
                } else {
                    showToast(msgStr, 'success');
                }
            };
    
            // ==========================================
            // THEME TOGGLE
            // ==========================================
            const themeToggleBtn = document.getElementById('theme-toggle');
            if (localStorage.getItem('color-theme') === 'dark' || (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                document.documentElement.classList.add('dark');
            } else {
                document.documentElement.classList.remove('dark');
            }
            themeToggleBtn.addEventListener('click', () => {
                if (document.documentElement.classList.contains('dark')) {
                    document.documentElement.classList.remove('dark');
                    localStorage.setItem('color-theme', 'light');
                } else {
                    document.documentElement.classList.add('dark');
                    localStorage.setItem('color-theme', 'dark');
                }
            });
    
            // ==========================================
            // PORT CHECKBOXES
            // ==========================================
            const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
            const nonTlsPorts = ['80', '8080', '8880', '2052', '2086', '2095'];
    
            function renderPortCheckboxes() {
                const tlsContainer = document.getElementById('tls-ports-list');
                const nonTlsContainer = document.getElementById('nontls-ports-list');
                tlsContainer.innerHTML = tlsPorts.map(p => 
                    '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + p + '" ' + (p === '443' ? 'checked' : '') + ' class="sr-only peer">' +
                    '<div class="flex items-center justify-center px-1.5 py-1 rounded-lg border border-white/10 text-[10px] font-semibold text-white/40 transition-all peer-checked:bg-purple-500/20 peer-checked:border-purple-400 peer-checked:text-purple-400">' + p + '</div>' +
                    '</label>'
                ).join('');
                nonTlsContainer.innerHTML = nonTlsPorts.map(p => 
                    '<label class="relative cursor-pointer">' +
                    '<input type="checkbox" name="ports" value="' + p + '" ' + (p === '80' ? 'checked' : '') + ' class="sr-only peer">' +
                    '<div class="flex items-center justify-center px-1.5 py-1 rounded-lg border border-white/10 text-[10px] font-semibold text-white/40 transition-all peer-checked:bg-amber-500/20 peer-checked:border-amber-400 peer-checked:text-amber-400">' + p + '</div>' +
                    '</label>'
                ).join('');
            }
            renderPortCheckboxes();
    
            // ==========================================
            // TOGGLE FRAG INPUTS
            // ==========================================
            function toggleFragInputs(el) {
                el.classList.toggle('active');
                const container = document.getElementById('frag-inputs-container');
                if (el.classList.contains('active')) {
                    container.classList.remove('hidden');
                } else {
                    container.classList.add('hidden');
                }
            }
    
            // ==========================================
            // TOGGLE USER PROXY MODE
            // ==========================================
            function toggleUserProxyMode(el) {
                el.classList.toggle('active');
                const isSocksMode = el.classList.contains('active');
                const cfSection = document.getElementById('user-cf-proxy-section');
                const socksContainer = document.getElementById('user-socks5-container');
                const locationSelect = document.getElementById('user-location-select');
                const locationSearch = document.getElementById('user-location-search');
                const socksInput = document.getElementById('user-socks5-input');
    
                if (isSocksMode) {
                    if (cfSection) { cfSection.style.opacity = '0.5'; cfSection.style.pointerEvents = 'none'; }
                    if (locationSelect) locationSelect.disabled = true;
                    if (locationSearch) locationSearch.disabled = true;
                    if (socksContainer) { socksContainer.style.opacity = '1'; socksContainer.style.pointerEvents = 'auto'; }
                    if (socksInput) socksInput.disabled = false;
                } else {
                    if (cfSection) { cfSection.style.opacity = '1'; cfSection.style.pointerEvents = 'auto'; }
                    if (locationSelect) locationSelect.disabled = false;
                    if (locationSearch) locationSearch.disabled = false;
                    if (socksContainer) { socksContainer.style.opacity = '0.5'; socksContainer.style.pointerEvents = 'none'; }
                    if (socksInput) socksInput.disabled = true;
                }
            }
    
            // ==========================================
            // MODAL TOGGLES
            // ==========================================
            function toggleModal(show) {
                const modal = document.getElementById('user-modal');
                const card = document.getElementById('user-modal-card');
                if (show) {
                    modal.classList.remove('opacity-0', 'pointer-events-none');
                    modal.classList.add('opacity-100', 'pointer-events-auto');
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                } else {
                    modal.classList.remove('opacity-100', 'pointer-events-auto');
                    modal.classList.add('opacity-0', 'pointer-events-none');
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                    document.getElementById('create-user-form').reset();
                    renderPortCheckboxes();
                }
            }
    
            function toggleSettingsModal(show) {
                const modal = document.getElementById('settings-modal');
                const card = modal.querySelector('.modal-neon');
                if (show) {
                    modal.classList.remove('opacity-0', 'pointer-events-none');
                    modal.classList.add('opacity-100', 'pointer-events-auto');
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                } else {
                    modal.classList.remove('opacity-100', 'pointer-events-auto');
                    modal.classList.add('opacity-0', 'pointer-events-none');
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                }
            }
    
            function toggleIpSelectorModal(show) {
                const modal = document.getElementById('ip-selector-modal');
                const card = modal.querySelector('.modal-neon');
                if (show) {
                    modal.classList.remove('opacity-0', 'pointer-events-none');
                    modal.classList.add('opacity-100', 'pointer-events-auto');
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                } else {
                    modal.classList.remove('opacity-100', 'pointer-events-auto');
                    modal.classList.add('opacity-0', 'pointer-events-none');
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                }
            }
    
            function toggleProxySelectorModal(show) {
                const modal = document.getElementById('proxy-selector-modal');
                const card = modal.querySelector('.modal-neon');
                if (show) {
                    modal.classList.remove('opacity-0', 'pointer-events-none');
                    modal.classList.add('opacity-100', 'pointer-events-auto');
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                } else {
                    modal.classList.remove('opacity-100', 'pointer-events-auto');
                    modal.classList.add('opacity-0', 'pointer-events-none');
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                }
            }
    
            function toggleBulkEditModal(show) {
                const modal = document.getElementById('bulk-edit-modal');
                const card = modal.querySelector('.modal-neon');
                if (show) {
                    modal.classList.remove('opacity-0', 'pointer-events-none');
                    modal.classList.add('opacity-100', 'pointer-events-auto');
                    card.classList.remove('opacity-0', 'scale-95');
                    card.classList.add('opacity-100', 'scale-100');
                } else {
                    modal.classList.remove('opacity-100', 'pointer-events-auto');
                    modal.classList.add('opacity-0', 'pointer-events-none');
                    card.classList.remove('opacity-100', 'scale-100');
                    card.classList.add('opacity-0', 'scale-95');
                }
            }
    
            function openCreateModal() {
                document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
                document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
                document.getElementById('input-name').disabled = false;
                document.getElementById('create-user-form').reset();
                renderPortCheckboxes();
                toggleModal(true);
            }
    
            // ==========================================
            // BULK ACTIONS
            // ==========================================
            window.selectedUsernames = new Set();
    
            function toggleSelectAllUsers(el) {
                const checkboxes = document.querySelectorAll('input[name="select-user"]');
                checkboxes.forEach(cb => {
                    cb.checked = el.checked;
                    const username = decodeURIComponent(cb.value);
                    if (el.checked) window.selectedUsernames.add(username);
                    else window.selectedUsernames.delete(username);
                });
                updateBulkActionsBar();
            }
    
            function onUserSelectChange(el) {
                const username = decodeURIComponent(el.value);
                if (el.checked) window.selectedUsernames.add(username);
                else window.selectedUsernames.delete(username);
                updateBulkActionsBar();
            }
    
            function updateBulkActionsBar() {
                const bar = document.getElementById('bulk-actions-bar');
                const countSpan = document.getElementById('bulk-selected-count');
                const selectAllCheckbox = document.getElementById('select-all-users');
                const selectedCount = window.selectedUsernames.size;
                if (countSpan) countSpan.innerText = selectedCount + ' کاربر';
                const checkboxes = document.querySelectorAll('input[name="select-user"]');
                if (checkboxes.length > 0) {
                    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
                    if (selectAllCheckbox) selectAllCheckbox.checked = allChecked;
                }
                if (selectedCount > 0) {
                    bar.classList.remove('opacity-0', 'pointer-events-none', 'translate-y-28');
                    bar.classList.add('opacity-100', 'pointer-events-auto', 'translate-y-0');
                } else {
                    bar.classList.remove('opacity-100', 'pointer-events-auto', 'translate-y-0');
                    bar.classList.add('opacity-0', 'pointer-events-none', 'translate-y-28');
                }
            }
    
            function bulkDelete() {
                const usernames = Array.from(window.selectedUsernames);
                if (usernames.length === 0 || !confirm('آیا از حذف ' + usernames.length + ' کاربر مطمئن هستید؟')) return;
                Promise.all(usernames.map(async uname => {
                    try { await fetch('/api/users/' + encodeURIComponent(uname), { method: 'DELETE' }); } catch(e) {}
                })).then(() => {
                    window.selectedUsernames.clear();
                    updateBulkActionsBar();
                    loadUsers(true);
                });
            }
    
            function bulkToggleStatus(targetActive) {
                const usernames = Array.from(window.selectedUsernames);
                if (usernames.length === 0 || !confirm('آیا از تغییر وضعیت ' + usernames.length + ' کاربر مطمئن هستید؟')) return;
                Promise.all(usernames.map(async uname => {
                    try {
                        await fetch('/api/users/' + encodeURIComponent(uname), {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ toggle_only: true })
                        });
                    } catch(e) {}
                })).then(() => {
                    window.selectedUsernames.clear();
                    updateBulkActionsBar();
                    loadUsers(true);
                });
            }
    
            function bulkReset(actionType) {
                const usernames = Array.from(window.selectedUsernames);
                if (usernames.length === 0 || !confirm('آیا از ریست ' + usernames.length + ' کاربر مطمئن هستید؟')) return;
                Promise.all(usernames.map(async uname => {
                    try {
                        await fetch('/api/users/' + encodeURIComponent(uname), {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ reset_action: actionType })
                        });
                    } catch(e) {}
                })).then(() => {
                    window.selectedUsernames.clear();
                    updateBulkActionsBar();
                    loadUsers(true);
                });
            }
    
            function bulkEdit() { toggleBulkEditModal(true); }
    
            async function handleBulkEditSubmit(event) {
                event.preventDefault();
                const usernames = Array.from(window.selectedUsernames);
                if (usernames.length === 0) return;
                // Simple bulk edit - just apply changes to all selected users
                const limit = document.getElementById('bulk-input-limit').value;
                const expiry = document.getElementById('bulk-input-expiry').value;
                const reqLimit = document.getElementById('bulk-input-req-limit').value;
                const ipLimit = document.getElementById('bulk-input-ip-limit').value;
                const fingerprint = document.getElementById('bulk-fingerprint-select').value;
    
                const changes = {};
                if (limit) changes.limit_gb = limit;
                if (expiry) changes.expiry_days = expiry;
                if (reqLimit) changes.limit_req = reqLimit;
                if (ipLimit) changes.ip_limit = ipLimit;
                if (fingerprint) changes.fingerprint = fingerprint;
    
                if (Object.keys(changes).length === 0) { alert('هیچ تغییری انتخاب نشده!'); return; }
    
                Promise.all(usernames.map(async uname => {
                    try {
                        await fetch('/api/users/' + encodeURIComponent(uname), {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(changes)
                        });
                    } catch(e) {}
                })).then(() => {
                    toggleBulkEditModal(false);
                    window.selectedUsernames.clear();
                    updateBulkActionsBar();
                    loadUsers(true);
                });
            }
    
            // ==========================================
            // LOAD USERS
            // ==========================================
            window.allUsers = [];
            let refreshIntervalId = null;
    
            async function loadUsers(silent = false) {
                const loadingState = document.getElementById('loading-state');
                const tableContainer = document.getElementById('users-table-container');
                const emptyState = document.getElementById('empty-state');
                if (!silent) {
                    loadingState.classList.remove('hidden');
                    tableContainer.classList.add('hidden');
                    emptyState.classList.add('hidden');
                }
                try {
                    const res = await fetch('/api/users?t=' + Date.now());
                    if (!res.ok) throw new Error();
                    const data = await res.json();
                    renderUsersUI(data);
                } catch (err) {
                    if (!silent) {
                        loadingState.innerHTML = '<span class="text-red-400">خطا در دریافت اطلاعات</span>';
                    }
                }
            }
    
            function renderUsersUI(data) {
                const users = data.users || [];
                window.allUsers = users;
                const serverTime = data.serverTime || Date.now();
                window.lastServerTime = serverTime;
                const totalUsersCount = users.length;
                const activeUsersCount = users.reduce((sum, u) => sum + (u.online_count || 0), 0);
                const totalGbUsage = users.reduce((sum, u) => sum + (u.used_gb || 0), 0);
                document.getElementById('stat-total-users').innerText = totalUsersCount;
                document.getElementById('stat-active-users').innerText = activeUsersCount;
                document.getElementById('stat-total-usage').innerText = totalGbUsage < 1 ? (totalGbUsage * 1024).toFixed(0) + ' MB' : totalGbUsage.toFixed(2) + ' GB';
                const cfRequests = data.cfRequestsToday || 0;
                document.getElementById('stat-cf-requests').innerText = cfRequests >= 1000 ? (cfRequests / 1000).toFixed(1) + 'k' : cfRequests;
                const progressPercent = Math.min((cfRequests / 100000) * 100, 100);
                document.getElementById('stat-cf-progress').style.width = progressPercent + '%';
                filterAndRenderUsers();
            }
    
            function filterAndRenderUsers() {
                if (!window.allUsers) return;
                const searchQuery = (document.getElementById('search-input').value || '').toLowerCase().trim();
                const filterStatus = document.getElementById('filter-status').value;
                const sortVal = document.getElementById('sort-users').value;
                const serverTime = window.lastServerTime || Date.now();
                let filtered = [...window.allUsers];
                if (searchQuery) {
                    filtered = filtered.filter(u => 
                        (u.username || '').toLowerCase().includes(searchQuery) || 
                        (u.uuid || '').toLowerCase().includes(searchQuery)
                    );
                }
                if (filterStatus !== 'all') {
                    filtered = filtered.filter(u => {
                        const isOnline = u.is_online === 1;
                        const isActive = u.is_active === 1;
                        let isExpired = false;
                        if (u.limit_gb && u.used_gb >= u.limit_gb) isExpired = true;
                        if (u.expiry_days && u.created_at) {
                            const created = new Date(u.created_at);
                            const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                            if (new Date(serverTime) > expiryDate) isExpired = true;
                        }
                        if (filterStatus === 'active') return isActive && !isExpired;
                        if (filterStatus === 'inactive') return !isActive;
                        if (filterStatus === 'online') return isOnline;
                        if (filterStatus === 'offline') return !isOnline;
                        if (filterStatus === 'expired') return isExpired || !isActive;
                        return true;
                    });
                }
                filtered.sort((a, b) => {
                    if (sortVal === 'newest') return b.id - a.id;
                    if (sortVal === 'name') return (a.username || '').localeCompare(b.username || '');
                    if (sortVal === 'usage-desc') return (b.used_gb || 0) - (a.used_gb || 0);
                    if (sortVal === 'usage-asc') return (a.used_gb || 0) - (b.used_gb || 0);
                    if (sortVal === 'expiry-asc') {
                        const getRemaining = (u) => {
                            if (!u.expiry_days || !u.created_at) return Infinity;
                            const created = new Date(u.created_at);
                            const expiryDate = new Date(created.getTime() + (u.expiry_days * 24 * 60 * 60 * 1000));
                            return expiryDate - new Date(serverTime);
                        };
                        return getRemaining(a) - getRemaining(b);
                    }
                    return 0;
                });
                renderFilteredUsers(filtered, serverTime);
            }
    
            function renderFilteredUsers(users, serverTime) {
                const loadingState = document.getElementById('loading-state');
                const tableContainer = document.getElementById('users-table-container');
                const emptyState = document.getElementById('empty-state');
                const tbody = document.getElementById('users-tbody');
    
                if (users.length === 0) {
                    loadingState.classList.add('hidden');
                    emptyState.classList.remove('hidden');
                    tableContainer.classList.add('hidden');
                } else {
                    loadingState.classList.add('hidden');
                    emptyState.classList.add('hidden');
                    tableContainer.classList.remove('hidden');
                    
                    tbody.innerHTML = users.map(user => {
                        let daysRemaining = 'نامحدود';
                        if (user.expiry_days && user.created_at) {
                            const created = new Date(user.created_at);
                            const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                            const diffDays = Math.ceil((expiryDate - new Date(serverTime)) / (1000 * 60 * 60 * 24));
                            daysRemaining = diffDays > 0 ? diffDays : 0;
                        }
                        const usedGb = user.used_gb || 0;
                        const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';
                        const onlineCount = user.online_count || 0;
                        const limit = user.ip_limit !== undefined ? user.ip_limit : user.max_connections;
                        let isExpired = false;
                        if (user.limit_gb && (user.used_gb || 0) >= user.limit_gb) isExpired = true;
                        if (user.expiry_days && user.created_at) {
                            const created = new Date(user.created_at);
                            const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                            if (new Date(serverTime) > expiryDate) isExpired = true;
                        }
                        const isEffectivelyActive = user.is_active !== 0 && !isExpired;
                        const isChecked = window.selectedUsernames.has(user.username) ? 'checked' : '';
    
                        return '<tr>' +
                            '<td><input type="checkbox" name="select-user" value="' + encodeURIComponent(user.username) + '" onchange="onUserSelectChange(this)" ' + isChecked + ' class="checkbox-neon"></td>' +
                            '<td>' +
                                '<div class="flex flex-col items-center gap-0.5">' +
                                    '<span class="text-xs font-bold text-white/80">' + user.username + '</span>' +
                                    '<div class="flex items-center gap-1">' +
                                        (isEffectivelyActive ? '<span class="status-dot status-dot-active"></span><span class="text-[9px] text-green-400">فعال</span>' : '<span class="status-dot status-dot-inactive"></span><span class="text-[9px] text-red-400">غیرفعال</span>') +
                                        (user.is_online === 1 ? '<span class="status-dot status-dot-online"></span><span class="text-[9px] text-green-400">' + user.online_count + '</span>' : '<span class="status-dot status-dot-offline"></span><span class="text-[9px] text-white/30">آفلاین</span>') +
                                    '</div>' +
                                '</div>' +
                            '</td>' +
                            '<td>' +
                                '<div class="flex gap-1 justify-center">' +
                                    '<button onclick="copyConfig(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon !p-1 !rounded-lg !text-[10px]" title="کپی کانفیگ">📋</button>' +
                                    '<button onclick="editUser(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon btn-neon-gold !p-1 !rounded-lg !text-[10px]" title="ویرایش">✏️</button>' +
                                    '<button onclick="deleteUser(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon btn-neon-danger !p-1 !rounded-lg !text-[10px]" title="حذف">🗑️</button>' +
                                    '<button onclick="toggleUserStatus(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon ' + (user.is_active === 0 ? 'btn-neon-success' : 'btn-neon-danger') + ' !p-1 !rounded-lg !text-[10px]" title="تغییر وضعیت">' + (user.is_active === 0 ? '✅' : '⛔') + '</button>' +
                                '</div>' +
                            '</td>' +
                            '<td>' +
                                '<div class="flex flex-col gap-0.5">' +
                                    '<button onclick="copySubLink(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon !text-[9px] !py-0.5">📎 ساب</button>' +
                                    '<button onclick="copyStatusLink(\'' + encodeURIComponent(user.username) + '\')" class="btn-neon btn-neon-success !text-[9px] !py-0.5">📊 وضعیت</button>' +
                                '</div>' +
                            '</td>' +
                            '<td class="text-[10px]">' + String(user.port || "").split(',').map(p => '<span class="px-1 py-0.5 rounded bg-white/5 border border-white/5 text-[9px]">' + p.trim() + '</span>').join(' ') + '</td>' +
                            '<td><span class="text-[10px]">' + formattedUsed + (user.limit_gb ? '/' + user.limit_gb + 'GB' : '') + '</span></td>' +
                            '<td><span class="text-[10px]">' + (user.used_req || 0) + (user.limit_req ? '/' + user.limit_req : '') + '</span></td>' +
                            '<td><span class="text-[10px]">' + daysRemaining + (user.expiry_days ? '/' + user.expiry_days + 'd' : '') + '</span></td>' +
                            '<td><span class="text-[10px]">' + onlineCount + (limit ? '/' + limit : '') + '</span></td>' +
                        '</tr>';
                    }).join('');
                    updateBulkActionsBar();
                }
            }
    
            // ==========================================
            // USER OPERATIONS
            // ==========================================
            async function toggleUserStatus(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                try {
                    const response = await fetch('/api/users/' + encodeURIComponent(username), {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ toggle_only: true })
                    });
                    if (response.ok) loadUsers(true);
                    else alert('خطا در تغییر وضعیت');
                } catch (err) { alert('خطا در ارتباط با سرور'); }
            }
    
            async function deleteUser(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                if (!confirm('آیا از حذف کاربر ' + username + ' مطمئن هستید؟')) return;
                try {
                    const response = await fetch('/api/users/' + encodeURIComponent(username), { method: 'DELETE' });
                    if (response.ok) loadUsers(true);
                    else alert('خطا در حذف کاربر');
                } catch (err) { alert('خطا در ارتباط با سرور'); }
            }
    
            function editUser(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                const user = window.allUsers.find(u => u.username === username);
                if (!user) { alert('کاربر یافت نشد!'); return; }
                document.getElementById('modal-title').innerText = 'ویرایش کاربر: ' + username;
                document.getElementById('submit-btn').innerText = 'ذخیره تغییرات';
                document.getElementById('input-name').value = username;
                document.getElementById('input-name').disabled = true;
                document.getElementById('input-limit').value = user.limit_gb || '';
                document.getElementById('input-expiry').value = user.expiry_days || '';
                document.getElementById('input-req-limit').value = user.limit_req || '';
                document.getElementById('input-ip-limit').value = user.ip_limit || '';
                document.getElementById('input-ips').value = user.ips || '';
                document.getElementById('fingerprint-select').value = user.fingerprint || 'ios';
                // Set ports
                const userPorts = String(user.port || '').split(',').map(p => p.trim());
                document.querySelectorAll('input[name="ports"]').forEach(cb => {
                    cb.checked = userPorts.includes(cb.value);
                });
                toggleModal(true);
            }
    
            async function handleFormSubmit(event) {
                event.preventDefault();
                const submitButton = document.getElementById('submit-btn');
                submitButton.disabled = true;
                submitButton.innerText = 'در حال ثبت...';
                const username = document.getElementById('input-name').value;
                const limit = document.getElementById('input-limit').value || null;
                const expiry = document.getElementById('input-expiry').value || null;
                const reqLimit = document.getElementById('input-req-limit').value || null;
                const ipLimit = document.getElementById('input-ip-limit').value || null;
                const checkedPorts = Array.from(document.querySelectorAll('input[name="ports"]:checked')).map(cb => cb.value);
                const customPortsRaw = document.getElementById('input-custom-ports') ? document.getElementById('input-custom-ports').value : '';
                const customPortsArray = customPortsRaw.replace(/ +/g, ',').split(',').map(p => p.trim()).filter(p => p.length > 0);
                const allPorts = checkedPorts.concat(customPortsArray);
                if (allPorts.length === 0) { alert('حداقل یک پورت انتخاب کنید!'); submitButton.disabled = false; submitButton.innerText = 'ایجاد کاربر'; return; }
                const port = allPorts.join(',');
                const tls = allPorts.some(p => tlsPorts.includes(p)) ? 'on' : 'off';
                const ips = document.getElementById('input-ips').value;
                const fingerprint = document.getElementById('fingerprint-select').value;
                const isFragEnabled = document.getElementById('input-frag-toggle').classList.contains('active');
                const frag_len = isFragEnabled ? (document.getElementById('input-frag-len').value || "200-3000") : "";
                const frag_int = isFragEnabled ? (document.getElementById('input-frag-int').value || "1-2") : "";
                const body = { username, limit_gb: limit, expiry_days: expiry, limit_req: reqLimit, tls, port, ips, fingerprint, ip_limit: ipLimit, frag_len, frag_int };
                try {
                    const response = await fetch('/api/users', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    });
                    if (response.ok) { toggleModal(false); loadUsers(true); }
                    else { const errData = await response.json(); alert('خطا: ' + (errData.error || 'عملیات ناموفق بود')); }
                } catch (err) { alert('خطا در ارتباط با سرور'); }
                finally { submitButton.disabled = false; submitButton.innerText = 'ایجاد کاربر'; }
            }
    
            // ==========================================
            // CONFIG & SUB LINKS
            // ==========================================
            function getVlessLink(username) {
                const user = window.allUsers.find(u => u.username === username);
                if (!user) return '';
                const host = window.location.hostname;
                let ips = [host];
                if (user.ips) {
                    const parsedIps = user.ips.split('\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
                    if (parsedIps.length > 0) ips = parsedIps;
                }
                const ports = String(user.port || '443').split(',').map(p => p.trim()).filter(p => p.length > 0);
                const fp = user.fingerprint || 'chrome';
                const userFrag = (user.frag_len && user.frag_int) ? '&fragment=' + user.frag_len + ',' + user.frag_int : '';
                const links = [];
                ips.forEach(ip => {
                    ports.forEach(portStr => {
                        const isTlsPort = tlsPorts.includes(portStr);
                        const tlsVal = isTlsPort ? 'tls' : 'none';
                        const remark = user.username + '-' + portStr;
                        links.push('vless://' + (user.uuid || '') + '@' + ip + ':' + portStr + '?path=%2FZEUS_PANEL_BOT&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=' + fp + '&type=ws&allowInsecure=0&sni=' + host + userFrag + '#' + encodeURIComponent(remark));
                    });
                });
                return links.join('\n');
            }
    
            function getSubLink(username) { return window.location.origin + '/feed/' + encodeURIComponent(username); }
            function getStatusLink(username) { return window.location.origin + '/status/' + encodeURIComponent(username); }
    
            function copyConfig(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                const link = getVlessLink(username);
                if (!link) return;
                navigator.clipboard.writeText(link).then(() => alert('✅ کانفیگ کپی شد!'));
            }
    
            function copySubLink(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                navigator.clipboard.writeText(getSubLink(username)).then(() => alert('✅ لینک ساب کپی شد!'));
            }
    
            function copyStatusLink(encodedUsername) {
                const username = decodeURIComponent(encodedUsername);
                navigator.clipboard.writeText(getStatusLink(username)).then(() => alert('✅ لینک وضعیت کپی شد!'));
            }
    
            // ==========================================
            // IP & PROXY SELECTORS
            // ==========================================
            let cachedIpsData = {};
    
            async function fetchIpsList() {
                try {
                    const response = await fetch('https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/ips.txt');
                    if (!response.ok) throw new Error('Fetch failed');
                    const text = await response.text();
                    const blocks = text.split('----------');
                    cachedIpsData = {};
                    blocks.forEach(block => {
                        const lines = block.trim().split('\n').map(l => l.trim()).filter(l => l.length > 0);
                        if (lines.length === 0) return;
                        let opName = "Unknown";
                        const ips = [];
                        lines.forEach(line => {
                            if (line.includes('#')) { opName = line.split('#')[1].trim(); }
                            else if (!line.startsWith('[source')) { ips.push(line); }
                        });
                        if (ips.length > 0) { cachedIpsData[opName] = ips; }
                    });
                    const select = document.getElementById('ip-operator-select');
                    select.innerHTML = '<option value="all">همه (توصیه شده)</option>';
                    Object.keys(cachedIpsData).forEach(op => {
                        const option = document.createElement('option');
                        option.value = op;
                        option.textContent = op;
                        select.appendChild(option);
                    });
                } catch (err) { alert('خطا در دریافت لیست آیپی'); }
            }
    
            async function openIpSelectorModal() {
                toggleIpSelectorModal(true);
                document.getElementById('ip-loading-state').classList.remove('hidden');
                document.getElementById('ip-selection-form').classList.add('hidden');
                await fetchIpsList();
                document.getElementById('ip-loading-state').classList.add('hidden');
                document.getElementById('ip-selection-form').classList.remove('hidden');
            }
    
            function applySelectedIps() {
                const operator = document.getElementById('ip-operator-select').value;
                let count = parseInt(document.getElementById('ip-count-input').value, 10) || 10;
                let availableIps = [];
                if (operator === 'all') {
                    Object.values(cachedIpsData).forEach(ips => { availableIps = availableIps.concat(ips); });
                } else {
                    availableIps = cachedIpsData[operator] || [];
                }
                availableIps = [...new Set(availableIps)];
                let selectedIps = [];
                if (count >= availableIps.length) { selectedIps = availableIps; }
                else {
                    const shuffled = availableIps.slice();
                    for (let i = shuffled.length - 1; i > 0; i--) {
                        const j = Math.floor(Math.random() * (i + 1));
                        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
                    }
                    selectedIps = shuffled.slice(0, count);
                }
                document.getElementById('input-ips').value = selectedIps.join('\n');
                toggleIpSelectorModal(false);
            }
    
            // ==========================================
            // PROXY SELECTOR
            // ==========================================
            let cachedProxyCountries = null;
    
            async function loadVipCountries() {
                const select = document.getElementById('vip-country-select');
                const btn = document.getElementById('vip-fetch-btn');
                select.innerHTML = '<option value="">در حال بررسی...</option>';
                try {
                    const res = await fetch('https://api.github.com/repos/IR-NETLIFY/zeus/contents/proxy/proxy_vip');
                    if (!res.ok) throw new Error('API Error');
                    const data = await res.json();
                    const validCountries = data.filter(f => f.name.endsWith('.txt')).map(f => f.name.replace('.txt', '').toUpperCase());
                    if (validCountries.length === 0) throw new Error('Empty');
                    select.innerHTML = '<option value="">انتخاب کشور VIP</option>';
                    validCountries.forEach(country => {
                        const option = document.createElement('option');
                        option.value = country;
                        option.textContent = '🌐 ' + country;
                        select.appendChild(option);
                    });
                    btn.disabled = false;
                } catch (err) {
                    select.innerHTML = '<option value="">پروکسی VIP موجود نیست</option>';
                    btn.disabled = true;
                }
            }
    
            async function loadVipProxy() {
                const country = document.getElementById('vip-country-select').value;
                const btn = document.getElementById('vip-fetch-btn');
                if (!country) return;
                btn.disabled = true;
                btn.innerText = '...';
                try {
                    const url = 'https://raw.githubusercontent.com/IR-NETLIFY/zeus/refs/heads/main/proxy/proxy_vip/' + country + '.txt?t=' + Date.now();
                    const res = await fetch(url);
                    if (!res.ok) throw new Error('فایل یافت نشد');
                    const text = await res.text();
                    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 5);
                    if (lines.length > 0) {
                        const randomProxy = lines[Math.floor(Math.random() * lines.length)];
                        document.getElementById('user-socks5-input').value = randomProxy;
                        toggleProxySelectorModal(false);
                        alert('✅ پروکسی VIP با موفقیت اعمال شد.');
                    } else { alert('فایل پروکسی این کشور خالی است.'); }
                } catch (e) { alert('خطا در دریافت پروکسی VIP.'); }
                finally { btn.disabled = false; btn.innerText = 'دریافت'; }
            }
    
            async function openProxySelectorModal() {
                toggleProxySelectorModal(true);
                const select = document.getElementById('proxy-country-select');
                const fetchBtn = document.getElementById('proxy-fetch-btn');
                const countriesList = ['US','GB','DE','FR','NL','CA','AU','JP','KR','SG','IN','BR','MX','RU','CN','IR','TR','AE','SA','EG','ZA','AR','CL','CO','PE','VE','PL','SE','NO','FI','DK','CH','AT','BE','IT','ES','PT','GR','IL','PK','BD','VN','TH','MY','ID','PH','NZ','IE','CZ','HU','RO','BG','UA','LT','LV','EE','SI','HR','RS','BA','AL','MK','GE','AM','AZ','KZ','UZ'];
                select.innerHTML = '';
                countriesList.forEach(country => {
                    const option = document.createElement('option');
                    option.value = country;
                    option.textContent = '🌐 ' + country;
                    select.appendChild(option);
                });
                fetchBtn.disabled = false;
                loadVipCountries();
            }
    
            async function fetchAndLoadProxy() {
                const select = document.getElementById('proxy-country-select');
                const country = select.value;
                if (!country) return;
                const loadingState = document.getElementById('proxy-loading-state');
                const formState = document.getElementById('proxy-selection-form');
                const fetchBtn = document.getElementById('proxy-fetch-btn');
                loadingState.classList.remove('hidden');
                loadingState.innerText = 'در حال اسکن پروکسی‌ها...';
                formState.classList.add('hidden');
                fetchBtn.disabled = true;
                try {
                    const url = 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country=' + country;
                    const res = await fetch(url);
                    if (!res.ok) throw new Error();
                    const text = await res.text();
                    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 5);
                    if (lines.length > 0) {
                        const randomProxy = lines[Math.floor(Math.random() * lines.length)];
                        document.getElementById('user-socks5-input').value = randomProxy;
                        toggleProxySelectorModal(false);
                        alert('✅ پروکسی با موفقیت لود شد.');
                    } else { alert('پروکسی برای این کشور یافت نشد.'); }
                } catch (e) { alert('خطا در دریافت لیست پروکسی‌ها.'); }
                finally {
                    loadingState.classList.add('hidden');
                    formState.classList.remove('hidden');
                    fetchBtn.disabled = false;
                }
            }
    
            // ==========================================
            // SETTINGS
            // ==========================================
            function changeRefreshRate(val) {
                const ms = parseInt(val, 10);
                localStorage.setItem('zeus_refresh_rate', ms);
                if (refreshIntervalId) clearInterval(refreshIntervalId);
                refreshIntervalId = setInterval(() => loadUsers(true), ms);
            }
    
            async function saveSettings() {
                alert('✅ تنظیمات ذخیره شد!');
                toggleSettingsModal(false);
            }
    
            async function changeAdminPassword() {
                const current = document.getElementById('change-pwd-current').value;
                const newPwd = document.getElementById('change-pwd-new').value;
                if (!current || !newPwd) { alert('رمز عبور فعلی و جدید را وارد کنید!'); return; }
                if (newPwd.length < 4) { alert('رمز جدید باید حداقل ۴ کاراکتر باشد!'); return; }
                try {
                    const response = await fetch('/api/change-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ current_password: current, new_password: newPwd })
                    });
                    const data = await response.json();
                    if (response.ok && data.success) {
                        alert('✅ رمز عبور با موفقیت تغییر کرد.');
                        document.getElementById('change-pwd-current').value = '';
                        document.getElementById('change-pwd-new').value = '';
                        toggleSettingsModal(false);
                    } else { alert('❌ خطا: ' + (data.error || 'عملیات ناموفق بود')); }
                } catch (err) { alert('خطا در ارتباط با سرور'); }
            }
    
            // ==========================================
            // BACKUP
            // ==========================================
            async function exportUsersBackup() {
                if (!window.allUsers || window.allUsers.length === 0) { alert('⚠️ کاربری برای پشتیبان‌گیری وجود ندارد!'); return; }
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(window.allUsers, null, 2));
                const downloadAnchor = document.createElement('a');
                const dateStr = new Date().toISOString().split('T')[0];
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", "lowkey_backup_" + dateStr + ".json");
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
            }
    
            function triggerImportBackup() { document.getElementById('backup-file-input').click(); }
    
            async function importUsersBackup(event) {
                const file = event.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = async function(e) {
                    try {
                        const parsedData = JSON.parse(e.target.result);
                        const backupUsers = Array.isArray(parsedData) ? parsedData : (parsedData.users || []);
                        if (backupUsers.length === 0) { alert('❌ فایل پشتیبان نامعتبر است!'); return; }
                        if (!confirm('آیا از بازیابی ' + backupUsers.length + ' کاربر مطمئن هستید؟')) return;
                        let successCount = 0;
                        for (const u of backupUsers) {
                            try {
                                const res = await fetch('/api/users', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({
                                        username: u.username,
                                        uuid: u.uuid,
                                        limit_gb: u.limit_gb,
                                        expiry_days: u.expiry_days,
                                        limit_req: u.limit_req,
                                        ips: u.ips,
                                        tls: u.tls,
                                        port: u.port,
                                        fingerprint: u.fingerprint,
                                        ip_limit: u.ip_limit,
                                        used_gb: u.used_gb,
                                        used_req: u.used_req,
                                        created_at: u.created_at,
                                        is_active: u.is_active
                                    })
                                });
                                if (res.ok) successCount++;
                            } catch(err) {}
                        }
                        alert('✅ ' + successCount + ' کاربر با موفقیت بازیابی شدند.');
                        loadUsers(true);
                    } catch(err) { alert('❌ خطا در خواندن فایل پشتیبان!'); }
                    event.target.value = '';
                };
                reader.readAsText(file);
            }
    
            // ==========================================
            // LOGOUT
            // ==========================================
            async function logoutAdmin() {
                if (!confirm('آیا می‌خواهید از پنل خارج شوید؟')) return;
                try { await fetch('/api/logout', { method: 'POST' }); } catch(err) {}
                window.location.reload();
            }
    
            // ==========================================
            // RESTART CORE
            // ==========================================
            async function restartCore() {
                if (!confirm('آیا از ری استارت پنل مطمئن هستید؟')) return;
                try {
                    const res = await fetch('/api/restart-core', { method: 'POST' });
                    if (res.ok) { alert('پنل ری استارت شد. صفحه رفرش می‌شود...'); window.location.reload(); }
                    else { alert('خطا در ری‌استارت پنل'); }
                } catch(err) { alert('خطا در ارتباط با سرور'); }
            }
    
            // ==========================================
            // FILTER LOCATIONS
            // ==========================================
            function filterUserLocations() {
                const searchTerm = document.getElementById('user-location-search').value.toLowerCase().trim();
                const cachedLocations = localStorage.getItem('cached_locations_list');
                if (!cachedLocations) return;
                try {
                    const allLocations = JSON.parse(cachedLocations);
                    const filtered = allLocations.filter(loc => {
                        if (!loc.iata || !loc.city) return false;
                        return (loc.iata + ' ' + loc.city + ' ' + (loc.cca2 || '')).toLowerCase().includes(searchTerm);
                    });
                    const userSelect = document.getElementById('user-location-select');
                    let html = '<option value="">بدون لوکیشن</option>';
                    filtered.forEach(loc => {
                        html += '<option value="' + loc.iata + '">' + loc.city + ' (' + loc.iata + ')</option>';
                    });
                    userSelect.innerHTML = html;
                } catch(e) {}
            }
    
            // ==========================================
            // TEST USER SOCKS PROXY
            // ==========================================
            async function testUserSocksProxy() {
                const btn = document.getElementById('test-user-proxy-btn');
                const resultSpan = document.getElementById('test-user-proxy-result');
                const proxyStr = document.getElementById('user-socks5-input').value.trim();
                if (!proxyStr) { resultSpan.innerText = 'وارد نشده!'; resultSpan.className = 'text-red-400 text-[10px]'; return; }
                btn.disabled = true;
                btn.innerText = '...';
                resultSpan.innerText = '';
                try {
                    const res = await fetch('/api/test-proxy', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ proxy: proxyStr })
                    });
                    const data = await res.json();
                    if (res.ok && data.success) {
                        resultSpan.innerText = '✅ پینگ: ' + data.ping + 'ms';
                        resultSpan.className = 'text-green-400 text-[10px]';
                    } else {
                        resultSpan.innerText = '❌ ' + (data.error || 'ناموفق');
                        resultSpan.className = 'text-red-400 text-[10px]';
                    }
                } catch (e) {
                    resultSpan.innerText = '❌ خطا در ارتباط';
                    resultSpan.className = 'text-red-400 text-[10px]';
                }
                finally { btn.disabled = false; btn.innerText = 'تست'; }
            }
    
            // ==========================================
            // INIT
            // ==========================================
            document.addEventListener('DOMContentLoaded', () => {
                const versionBadge = document.getElementById('panel-version');
                if (versionBadge) versionBadge.innerText = 'v1.5.10';
                
                loadUsers();
                
                const savedRate = localStorage.getItem('zeus_refresh_rate');
                const initialRate = savedRate ? parseInt(savedRate, 10) : 2000;
                const selectEl = document.getElementById('refresh-rate-select');
                if (selectEl) selectEl.value = String(initialRate);
                refreshIntervalId = setInterval(() => loadUsers(true), initialRate);
    
                // Load locations cache
                fetch('/locations').then(res => res.json()).then(data => {
                    if (Array.isArray(data) && data.length > 0) {
                        localStorage.setItem('cached_locations_list', JSON.stringify(data));
                    }
                }).catch(() => {});
            });
    
            // ==========================================
            // CLOSE MODALS ON BACKDROP CLICK
            // ==========================================
            document.addEventListener('click', (e) => {
                if (e.target.id === 'user-modal') toggleModal(false);
                if (e.target.id === 'settings-modal') toggleSettingsModal(false);
                if (e.target.id === 'ip-selector-modal') toggleIpSelectorModal(false);
                if (e.target.id === 'proxy-selector-modal') toggleProxySelectorModal(false);
                if (e.target.id === 'bulk-edit-modal') toggleBulkEditModal(false);
            });
    
            console.log('🌟 Neon Origami Panel v1.5.10 Loaded Successfully!');
        </script>
    </body>
    </html>`,
    
}; 
