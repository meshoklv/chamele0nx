# Docker quick start: server on a VPS, client at home

Five minutes if you already own a domain. The long, hardened manual path
(systemd, sysctl, firewall) is in [INSTALL.md](INSTALL.md); this page is
the short one.

> Status: the Go code builds and its tests pass. The Dockerfile and
> compose file have **not been run end to end by the author** (no Docker
> where this release was prepared). Expect to fix small things and send a PR.

## You need

- A VPS with Docker + the Compose plugin, ports **80** and **443** open.
- A domain whose `A` record points at the VPS (`vpn.example.com` below).
- A Linux machine at home with Docker (the client uses host networking).

## 1. Server (on the VPS)

```bash
git clone https://github.com/meshoklv/chamele0nx && cd chamele0nx
cp .env.example .env
$EDITOR .env                      # set DOMAIN, ACME_EMAIL, API_PATH, SERVER_ID, COOKIE_FORMAT

mkdir -p secrets certs
openssl rand -hex 32 > secrets/secret && chmod 600 secrets/secret

docker compose --profile tools run --rm certbot   # gets a Let's Encrypt cert into ./certs
docker compose up -d server
docker compose logs -f server
```

Put your **own** static site into `COVER_DIR` (default
`deploy/cover-site` is a placeholder identical on every install; see
INSTALL.md section 4). Certificates are copied, not symlinked: re-run the
certbot command and `docker compose restart server` before expiry
(every ~60 days; add it to cron if you want, nothing here does it for you).

Check from anywhere: `https://vpn.example.com/` must show the cover site
in a normal browser.

## 2. Client (at home)

Copy `secrets/secret` from the VPS over a channel you trust, then:

```bash
git clone https://github.com/meshoklv/chamele0nx && cd chamele0nx
cp .env.example .env
$EDITOR .env                      # SERVER=vpn.example.com:443 and the SAME API_PATH, SERVER_ID, COOKIE_FORMAT
mkdir -p secrets && install -m 600 /path/to/secret secrets/secret

docker compose --profile client up -d client
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me     # should print the VPS address
```

Point your browser or app at SOCKS5 `127.0.0.1:1080`. The proxy listens on
loopback only, deliberately: do not expose it to your LAN without
authentication.

## Without compose

```bash
docker build -t chamele0nx .
docker run --rm chamele0nx -version
```

## Notes

- The container runs as non-root with a read-only filesystem and no
  capabilities except binding port 443.
- The secret is read from a file mounted into the container, never from
  arguments or the image.
- `.env`, `secrets/` and `certs/` are git-ignored. Keep them that way.
