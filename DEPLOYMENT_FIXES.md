# Q4S Cloud Deployment — issues & fixes

Deploying `q4s_connect` and `q4s_site_monitoring` to the Hetzner server behind
nginx + Cloudflare, on:

- `q4sconnect-demo.q4s.app`              → q4s_connect          (127.0.0.1:8000)
- `q4sconnect-sitemonitoring-demo.q4s.app` → q4s_site_monitoring (127.0.0.1:1887)

Everything below is now committed in the repo, so a fresh clone deploys cleanly.

## 1. Domains had underscores → renamed to hyphens
`q4sconnect_demo` / `q4sconnect_sitemonitoring_demo` contain underscores, which
are invalid in hostnames and **rejected by Let's Encrypt / all public CAs**.
Renamed everything to hyphens. Update the Cloudflare DNS records to match
(A → 65.108.254.94, Proxied).

## 2. ALLOWED_HOSTS + HTTPS behind a proxy
Both `settings.py` only allowed localhost. Added the server IP and public domain
to `ALLOWED_HOSTS`, plus:
- `CSRF_TRUSTED_ORIGINS` = the https domain (admin login / POST fail without it)
- `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` so Django trusts
  the scheme forwarded by nginx/Cloudflare.

## 3. .dockerignore missing
`COPY . .` was pulling the local `venv/` into the build context. Added
`.dockerignore` to both projects (excludes venv, __pycache__, .git, etc).

## 4. Flutter frontend had hard-coded dev API URLs
The compiled Flutter apps called dev addresses baked in at build time:
- connect `main.dart.js`:    `http://127.0.0.1:8000`  → `https://q4sconnect-demo.q4s.app`
- monitoring `main.dart.js`: `http://localhost:1887`  → `https://q4sconnect-sitemonitoring-demo.q4s.app`
Patched the compiled bundles. (Proper long-term fix: rebuild Flutter with the API
base URL as a `--dart-define`.)

## 5. WASM build was overriding the patched JS build
Flutter produced a dual build. Browsers with WasmGC loaded `main.dart.wasm`
(URL baked into the binary, unpatchable) instead of the patched `main.dart.js`.
Removed the `dart2wasm` entry from `flutter_bootstrap.js` builds list, forcing the
JS/canvaskit build.

## 6. Service worker served stale cache
Flutter's service worker kept serving the old bundle after every change. Disabled
SW registration in `flutter_bootstrap.js` (`_flutter.loader.load({})`), so the app
always loads fresh. (You still need a one-time SW unregister + Cloudflare purge in
any browser that already cached the old version.)

## 7. Cross-app link registration URL
When connect "Generate Client Page" runs, it POSTs the link into the monitoring
DB server-to-server (`EXTERNAL_SERVER_BACKEND_BASE_URL`, BasicAuth admin/123456789).
`host.docker.internal:1887` is **not reachable** from the connect container on this
host; the public domain works. Set both `EXTERNAL_SERVER_UI_BASE_URL` and
`EXTERNAL_SERVER_BACKEND_BASE_URL` to `https://q4sconnect-sitemonitoring-demo.q4s.app`.

## 8. `docker restart` doesn't apply changed env
Changing compose `environment:` requires `docker compose up -d` (recreate). A plain
`docker restart` keeps the container's original env.

## Server-side only (not in the repo)
- nginx vhost: see `Cloud/nginx_q4s_demo.conf` (copy to /etc/nginx/conf.d/).
- TLS via `certbot --nginx -d q4sconnect-demo.q4s.app -d q4sconnect-sitemonitoring-demo.q4s.app`.
- Cloudflare: hyphen A records (Proxied) + SSL mode Full (strict).

## Still worth doing later
- `DEBUG = True` and the dev `SECRET_KEY` are still in both settings — fine for a
  demo, change for production.
- Rebuild the Flutter apps with a configurable API base URL instead of patching
  compiled output.
