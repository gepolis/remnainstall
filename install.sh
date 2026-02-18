#!/bin/bash

# =============================================================================
# Remnawave — установка ноды
#
# Использование:
#   ./install.sh --domain <домен> --key <публичный_ключ>
#   ./install.sh --domain <домен> --key-file <путь_к_файлу>
#
# Опции:
#   --domain,   -d  Домен ноды (SELFSTEAL_DOMAIN)   [обязательно]
#   --key,      -k  Публичный ключ (SECRET_KEY)      [обязательно]
#   --key-file      Путь к файлу с публичным ключом  [альтернатива --key]
#   --panel-ip      IP-адрес панели для UFW          [по умолч.: 45.148.119.82]
#   --email         Email для Let's Encrypt          [по умолч.: inbox@transhata.ru]
# =============================================================================

SCRIPT_VERSION="1.0.0"

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"

error() { echo -e "${COLOR_RED}[ОШИБКА] $*${COLOR_RESET}" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Разбор аргументов
# ---------------------------------------------------------------------------

SELFSTEAL_DOMAIN=""
CERTIFICATE=""
PANEL_IP="45.148.119.82"
LE_EMAIL="inbox@transhata.ru"

usage() {
    echo "Использование: $0 --domain <домен> --key <ключ> [--panel-ip <ip>] [--email <email>]"
    echo "         или: $0 --domain <домен> --key-file <файл> [--panel-ip <ip>] [--email <email>]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain|-d)   SELFSTEAL_DOMAIN="$2"; shift 2 ;;
        --key|-k)      CERTIFICATE="$2";      shift 2 ;;
        --key-file)    [ -f "$2" ] || error "Файл ключа не найден: $2"
                       CERTIFICATE=$(cat "$2"); shift 2 ;;
        --panel-ip)    PANEL_IP="$2";          shift 2 ;;
        --email)       LE_EMAIL="$2";          shift 2 ;;
        -h|--help)     usage ;;
        *)             usage ;;
    esac
done

[ -z "$SELFSTEAL_DOMAIN" ] && error "Укажите домен: --domain <домен>"
[ -z "$CERTIFICATE" ]      && error "Укажите публичный ключ: --key <ключ> или --key-file <файл>"

# ---------------------------------------------------------------------------
# Проверки окружения
# ---------------------------------------------------------------------------

[[ $EUID -ne 0 ]] && error "Запустите скрипт с правами root"

grep -qE "bullseye|bookworm|jammy|noble|trixie" /etc/os-release \
    || error "Поддерживается только Debian 11/12 и Ubuntu 22.04/24.04"

# ---------------------------------------------------------------------------
# Установка пакетов и Docker
# ---------------------------------------------------------------------------

install_packages() {
    apt-get update -y -qq >/dev/null 2>&1 \
        || error "Не удалось обновить список пакетов"

    apt-get install -y -qq \
        ca-certificates curl wget \
        gnupg unzip openssl \
        ufw dnsutils \
        certbot \
        >/dev/null 2>&1 \
        || error "Не удалось установить пакеты"

    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh >/dev/null 2>&1 \
            || error "Не удалось скачать установщик Docker"
        sh /tmp/get-docker.sh >/dev/null 2>&1 \
            || error "Ошибка установки Docker"
        rm -f /tmp/get-docker.sh
    fi

    systemctl start  docker >/dev/null 2>&1
    systemctl enable docker >/dev/null 2>&1
    docker info >/dev/null 2>&1 || error "Docker не запустился"

    grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf \
        || echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf \
        || echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    ufw allow 22/tcp  comment 'SSH'   >/dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
    ufw --force enable                >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Сертификаты
# ---------------------------------------------------------------------------

check_certificate_exists() {
    local domain="$1"
    local live_dir
    live_dir=$(find "/etc/letsencrypt/live" -maxdepth 1 -type d -name "${domain}*" 2>/dev/null \
               | sort -V | tail -n 1)
    [ -z "$live_dir" ] && return 1
    for f in cert.pem chain.pem fullchain.pem privkey.pem; do
        [ -f "$live_dir/$f" ] || return 1
    done
    return 0
}

get_certificate_acme() {
    local domain="$1" email="$2"

    ufw allow 80/tcp >/dev/null 2>&1

    certbot certonly \
        --standalone \
        -d "$domain" \
        --email "$email" \
        --agree-tos \
        --non-interactive \
        --http-01-port 80 \
        --key-type ecdsa \
        --elliptic-curve secp384r1 \
        >/dev/null 2>&1 \
        || error "Не удалось получить сертификат. Убедитесь, что $domain указывает на этот сервер и порт 80 не занят."

    ufw delete allow 80/tcp >/dev/null 2>&1
    ufw reload              >/dev/null 2>&1
}

setup_certificates() {
    local domain="$1" target_dir="$2"

    if ! check_certificate_exists "$domain"; then
        get_certificate_acme "$domain" "$LE_EMAIL"
        check_certificate_exists "$domain" || error "Сертификат не найден после генерации"
    fi

    cat >> "$target_dir/docker-compose.yml" <<EOF
      - /etc/letsencrypt/live/$domain/fullchain.pem:/etc/nginx/ssl/$domain/fullchain.pem:ro
      - /etc/letsencrypt/live/$domain/privkey.pem:/etc/nginx/ssl/$domain/privkey.pem:ro
EOF

    local cron_cmd="ufw allow 80 && /usr/bin/certbot renew --quiet && ufw delete allow 80 && ufw reload"
    if ! crontab -u root -l 2>/dev/null | grep -q "/usr/bin/certbot renew"; then
        (crontab -u root -l 2>/dev/null; echo "0 5 * * 0 $cron_cmd") | crontab -u root -
    fi

    local renewal="/etc/letsencrypt/renewal/$domain.conf"
    if [ -f "$renewal" ]; then
        local hook="renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'"
        sed -i '/^renew_hook/d' "$renewal"
        echo "$hook" >> "$renewal"
    fi
}

# ---------------------------------------------------------------------------
# Маскировочный сайт
# ---------------------------------------------------------------------------

install_random_template() {
    cd /opt/ || return 1
    rm -f main.zip 2>/dev/null
    rm -rf sni-templates-main/ 2>/dev/null

    local url="https://github.com/distillium/sni-templates/archive/refs/heads/main.zip"
    local attempts=0
    until wget -q --timeout=30 "$url" -O main.zip 2>/dev/null; do
        attempts=$(( attempts + 1 ))
        [ "$attempts" -ge 3 ] && return 1
        sleep 3
    done

    unzip -o main.zip >/dev/null 2>&1 || return 1
    rm -f main.zip
    cd sni-templates-main/ || return 1
    rm -rf assets README.md index.html 2>/dev/null

    mapfile -t templates < <(find . -maxdepth 1 -type d -not -path .)
    [ ${#templates[@]} -eq 0 ] && { cd /opt/; return 1; }

    local tpl="${templates[$RANDOM % ${#templates[@]}]}"

    local meta_id rand_comment class_sfx title_sfx
    meta_id=$(openssl rand -hex 16)
    rand_comment=$(openssl rand -hex 8)
    class_sfx=$(openssl rand -hex 4)
    title_sfx=$(openssl rand -hex 4)

    find "./$tpl" -type f -name "*.html" -exec sed -i \
        -e "s|<title>.*</title>|<title>Page_${title_sfx}</title>|" \
        -e "s|</head>|<meta name=\"render-id\" content=\"${meta_id}\">\n<!-- ${rand_comment} -->\n</head>|" \
        -e "s|<body|<body class=\"layout-${class_sfx}\"|" \
        {} \;

    mkdir -p /var/www/html
    rm -rf /var/www/html/*
    cp -a "./$tpl/." /var/www/html/

    cd /opt/
    rm -rf sni-templates-main/
}

# ---------------------------------------------------------------------------
# ТОЧКА ВХОДА
# ---------------------------------------------------------------------------

main() {
    local TARGET="/opt/remnawave"
    mkdir -p "$TARGET"

    install_packages

    cat > "$TARGET/docker-compose.yml" <<'COMPOSE'
services:
  remnawave-nginx:
    image: nginx:1.28
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    restart: always
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
COMPOSE

    setup_certificates "$SELFSTEAL_DOMAIN" "$TARGET"

    cat >> "$TARGET/docker-compose.yml" <<COMPOSE_TAIL
      - /dev/shm:/dev/shm:rw
      - /var/www/html:/var/www/html:ro
    command: sh -c 'rm -f /dev/shm/nginx.sock && exec nginx -g "daemon off;"'
    network_mode: host
    depends_on:
      - remnanode
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'

  remnanode:
    image: remnawave/node:latest
    container_name: remnanode
    hostname: remnanode
    restart: always
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    network_mode: host
    environment:
      - NODE_PORT=2222
      - SECRET_KEY=$(echo -e "$CERTIFICATE")
    volumes:
      - /dev/shm:/dev/shm:rw
    logging:
      driver: 'json-file'
      options:
        max-size: '30m'
        max-file: '5'
COMPOSE_TAIL

    cat > "$TARGET/nginx.conf" <<NGINX
server_names_hash_bucket_size 64;

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
ssl_session_tickets off;

server {
    server_name $SELFSTEAL_DOMAIN;
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol;
    http2 on;

    ssl_certificate     "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$SELFSTEAL_DOMAIN/fullchain.pem";

    root /var/www/html;
    index index.html;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
}

server {
    listen unix:/dev/shm/nginx.sock ssl proxy_protocol default_server;
    server_name _;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
    ssl_reject_handshake on;
    return 444;
}
NGINX

    ufw allow from "$PANEL_IP" to any port 2222 >/dev/null 2>&1
    ufw reload >/dev/null 2>&1

    install_random_template

    cd "$TARGET"
    docker compose up -d >/dev/null 2>&1 \
        || error "Не удалось запустить контейнеры"

    # Проверка доступности ноды
    local max_attempts=5 attempt=1 delay=15
    while [ "$attempt" -le "$max_attempts" ]; do
        if curl -s --fail --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -q "html" 2>/dev/null; then
            break
        fi
        if [ "$attempt" -eq "$max_attempts" ]; then
            error "Нода не отвечает. Проверьте логи: cd /opt/remnawave && docker compose logs -f"
        fi
        sleep "$delay"
        (( attempt++ ))
    done

    echo -e "${COLOR_GREEN}OK${COLOR_RESET}"
}

main
exit 0
