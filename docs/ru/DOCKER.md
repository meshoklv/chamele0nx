# Docker: сервер на VPS, клиент дома

Пять минут, если домен уже есть. Подробный «жёсткий» путь (systemd, sysctl,
файрвол) — в [INSTALL.md](INSTALL.md); здесь короткий.

> Статус: Go-код собирается, тесты проходят. Dockerfile и compose-файл
> **автор целиком не прогонял** (на машине подготовки релиза нет Docker).
> Возможны мелкие правки — присылайте PR.

## Что нужно

- VPS с Docker и плагином Compose, открыты порты **80** и **443**.
- Домен, у которого `A`-запись указывает на VPS (ниже `vpn.example.com`).
- Linux-машина дома с Docker (клиент работает в сети хоста).

## 1. Сервер (на VPS)

```bash
git clone https://github.com/meshoklv/chamele0nx && cd chamele0nx
cp .env.example .env
$EDITOR .env                      # DOMAIN, ACME_EMAIL, API_PATH, SERVER_ID, COOKIE_FORMAT

mkdir -p secrets certs
openssl rand -hex 32 > secrets/secret && chmod 600 secrets/secret

docker compose --profile tools run --rm certbot   # сертификат Let's Encrypt в ./certs
docker compose up -d server
docker compose logs -f server
```

В `COVER_DIR` положите **свой** статический сайт (заглушка `deploy/cover-site`
одинакова у всех установок — см. INSTALL.md, раздел 4). Сертификаты
копируются файлами: до истечения (~каждые 60 дней) повторите команду certbot
и `docker compose restart server`. Автоматики для этого здесь нет.

Проверка: `https://vpn.example.com/` в обычном браузере открывает сайт-прикрытие.

## 2. Клиент (дома)

Скопируйте `secrets/secret` с VPS доверенным каналом, затем:

```bash
git clone https://github.com/meshoklv/chamele0nx && cd chamele0nx
cp .env.example .env
$EDITOR .env                      # SERVER=vpn.example.com:443 и ТЕ ЖЕ API_PATH, SERVER_ID, COOKIE_FORMAT
mkdir -p secrets && install -m 600 /path/to/secret secrets/secret

docker compose --profile client up -d client
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me     # должен показать адрес VPS
```

Укажите в браузере/приложении SOCKS5 `127.0.0.1:1080`. Прокси слушает только
loopback — это сознательно, не открывайте его в LAN без аутентификации.

## Без compose

```bash
docker build -t chamele0nx .
docker run --rm chamele0nx -version
```

## Заметки

- Контейнер работает не от root, с read-only файловой системой и без
  привилегий, кроме привязки к порту 443.
- Секрет читается из смонтированного файла, не из аргументов и не из образа.
- `.env`, `secrets/` и `certs/` в `.gitignore`; так и оставьте.
