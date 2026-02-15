#!/bin/bash

# =============================================================================
# Remnawave — установка только ноды
#
# Интерактивный ввод:
#   1. Домен ноды (SELFSTEAL_DOMAIN)
#   2. Email для Let's Encrypt (только если нет сертификата)
#   3. Публичный ключ от панели (SECRET_KEY)
#   4. IP-адрес панели (для UFW)
#
# Статичные значения:
#   • Метод сертификата  — ACME HTTP-01 (Let's Encrypt standalone)
#   • Порт ноды          — 2222
#   • Образ ноды         — remnawave/node:latest
#   • Образ nginx        — nginx:1.28
#   • Шаблон сайта       — SNI-шаблоны (distillium), случайный
# =============================================================================

SCRIPT_VERSION="1.0.0"

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_WHITE="\033[1;37m"
COLOR_RED="\033[1;31m"

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

question() { echo -e "${COLOR_GREEN}[?]${COLOR_RESET} ${COLOR_YELLOW}$*${COLOR_RESET}"; }
reading()  { read -rp " $(question "$1")" "$2"; }
info()     { echo -e "${COLOR_YELLOW}[•] $*${COLOR_RESET}"; }
ok()       { echo -e "${COLOR_GREEN}[✓] $*${COLOR_RESET}"; }
fail()     { echo -e "${COLOR_RED}[✗] $*${COLOR_RESET}"; }
error()    { echo -e "${COLOR_RED}[ОШИБКА] $*${COLOR_RESET}"; exit 1; }

spinner() {
    local pid=$1 text=$2
    export LC_ALL=C.UTF-8
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' delay=0.1
    printf "${COLOR_GREEN}%s${COLOR_RESET}" "$text" > /dev/tty
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spinstr}; i++ )); do
            printf "\r${COLOR_GREEN}[%s] %s${COLOR_RESET}" "${spinstr:$i:1}" "$text" > /dev/tty
            sleep "$delay"
        done
    done
    printf "\r\033[K" > /dev/tty
}

# ---------------------------------------------------------------------------
# Проверки окружения
# ---------------------------------------------------------------------------

check_root() {
    [[ $EUID -ne 0 ]] && error "Запустите скрипт с правами root"
}

check_os() {
    grep -qE "bullseye|bookworm|jammy|noble|trixie" /etc/os-release \
        || error "Поддерживается только Debian 11/12 и Ubuntu 22.04/24.04"
}

# ---------------------------------------------------------------------------
# Установка пакетов и Docker
# ---------------------------------------------------------------------------

install_packages() {
    info "Устанавливаем зависимости..."

    apt-get update -y               || error "Не удалось обновить список пакетов"
    apt-get install -y \
        ca-certificates curl wget \
        gnupg unzip openssl \
        ufw dnsutils \
        certbot \
        || error "Не удалось установить пакеты"

    if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
        info "Устанавливаем Docker..."
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh \
            || error "Не удалось скачать установщик Docker"
        sh /tmp/get-docker.sh || error "Ошибка установки Docker"
        rm -f /tmp/get-docker.sh
    fi

    systemctl start  docker >/dev/null 2>&1
    systemctl enable docker >/dev/null 2>&1
    docker info >/dev/null 2>&1 || error "Docker не запустился"

    # BBR (ускорение TCP)
    grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf \
        || echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    grep -q "net.core.default_qdisc = fq" /etc/sysctl.conf \
        || echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1

    # Базовые правила UFW
    ufw allow 22/tcp  comment 'SSH'   >/dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
    ufw --force enable                >/dev/null 2>&1

    ok "Зависимости установлены"
}

# ---------------------------------------------------------------------------
# Сертификаты — ACME HTTP-01 (статично)
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
    ok "Сертификат уже есть: $live_dir"
    return 0
}

get_certificate_acme() {
    local domain="$1" email="$2"

    info "Получаем сертификат для $domain через ACME HTTP-01..."

    # Временно открываем порт 80 для верификации
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
        || error "Не удалось получить сертификат. Убедитесь, что домен $domain указывает на этот сервер и порт 80 не занят."

    ufw delete allow 80/tcp >/dev/null 2>&1
    ufw reload              >/dev/null 2>&1
}

setup_certificates() {
    local domain="$1" target_dir="$2"

    info "Проверяем сертификат для $domain..."

    if ! check_certificate_exists "$domain"; then
        local LE_EMAIL="inbox@transhata.ru"
        get_certificate_acme "$domain" "$LE_EMAIL"
        check_certificate_exists "$domain" || error "Сертификат не найден после генерации"
    fi

    # Монтируем сертификат в docker-compose.yml
    cat >> "$target_dir/docker-compose.yml" <<EOF
      - /etc/letsencrypt/live/$domain/fullchain.pem:/etc/nginx/ssl/$domain/fullchain.pem:ro
      - /etc/letsencrypt/live/$domain/privkey.pem:/etc/nginx/ssl/$domain/privkey.pem:ro
EOF

    # Cron: обновление каждое воскресенье в 05:00
    local cron_cmd="ufw allow 80 && /usr/bin/certbot renew --quiet && ufw delete allow 80 && ufw reload"
    if ! crontab -u root -l 2>/dev/null | grep -q "/usr/bin/certbot renew"; then
        info "Добавляем cron для автообновления сертификата..."
        (crontab -u root -l 2>/dev/null; echo "0 5 * * 0 $cron_cmd") | crontab -u root -
    fi

    # renew_hook: перезапуск nginx после обновления
    local renewal="/etc/letsencrypt/renewal/$domain.conf"
    if [ -f "$renewal" ]; then
        local hook="renew_hook = sh -c 'cd /opt/remnawave && docker compose down remnawave-nginx && docker compose up -d remnawave-nginx'"
        sed -i '/^renew_hook/d' "$renewal"
        echo "$hook" >> "$renewal"
    fi
}

# ---------------------------------------------------------------------------
# Маскировочный сайт (SNI-шаблон, случайный)
# ---------------------------------------------------------------------------

install_random_template() {
    info "Устанавливаем маскировочный сайт..."

    cd /opt/ || return 1
    rm -f main.zip 2>/dev/null
    rm -rf sni-templates-main/ 2>/dev/null

    local url="https://github.com/distillium/sni-templates/archive/refs/heads/main.zip"
    local attempts=0
    until wget -q --timeout=30 "$url" -O main.zip; do
        attempts=$(( attempts + 1 ))
        if [ "$attempts" -ge 3 ]; then
            fail "Не удалось скачать шаблон — пропускаем"
            return 1
        fi
        info "Повтор загрузки шаблона ($attempts/3)..."
        sleep 3
    done

    unzip -o main.zip >/dev/null 2>&1 || { fail "Ошибка распаковки шаблона"; return 1; }
    rm -f main.zip
    cd sni-templates-main/ || return 1
    rm -rf assets README.md index.html 2>/dev/null

    mapfile -t templates < <(find . -maxdepth 1 -type d -not -path .)
    if [ ${#templates[@]} -eq 0 ]; then
        fail "Список шаблонов пуст, пропускаем"
        cd /opt/ && return 1
    fi

    local tpl="${templates[$RANDOM % ${#templates[@]}]}"

    # Рандомизация HTML-фингерпринта
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
    ok "Шаблон «$tpl» установлен в /var/www/html/"

    cd /opt/
    rm -rf sni-templates-main/
}

# ---------------------------------------------------------------------------
# ТОЧКА ВХОДА
# ---------------------------------------------------------------------------

main() {
    clear
    echo -e "${COLOR_GREEN}=================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}   Remnawave — установка ноды  v${SCRIPT_VERSION}${COLOR_RESET}"
    echo -e "${COLOR_GREEN}=================================================${COLOR_RESET}"
    echo ""

    check_root
    check_os

    # -----------------------------------------------------------------------
    # ШАГИ ИНТЕРАКТИВНОГО ВВОДА
    # -----------------------------------------------------------------------

    # 1. Домен ноды
    reading "Домен ноды (selfsteal), например node.example.com: " SELFSTEAL_DOMAIN
    [ -z "$SELFSTEAL_DOMAIN" ] && error "Домен не может быть пустым"

    # 2. IP панели — статично
    PANEL_IP="45.148.119.82"

    # 3. Публичный ключ от панели
    echo ""
    info "Вставьте публичный ключ (SECRET_KEY) от панели."
    info "Введите/вставьте текст и нажмите Enter дважды:"
    CERTIFICATE=""
    while IFS= read -r line; do
        [ -z "$line" ] && [ -n "$CERTIFICATE" ] && break
        CERTIFICATE+="$line\n"
    done
    [ -z "$CERTIFICATE" ] && error "Публичный ключ не может быть пустым"

    # Сводка перед началом
    echo ""
    echo -e "${COLOR_YELLOW}------------------------------------------------${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Параметры установки:${COLOR_RESET}"
    echo -e "  Домен ноды        : ${COLOR_WHITE}$SELFSTEAL_DOMAIN${COLOR_RESET}"
    echo -e "  IP панели (UFW)   : ${COLOR_WHITE}$PANEL_IP${COLOR_RESET}"
    echo -e "  Порт ноды         : ${COLOR_WHITE}2222${COLOR_RESET}"
    echo -e "  Метод сертификата : ${COLOR_WHITE}ACME HTTP-01 (Let's Encrypt)${COLOR_RESET}"
    echo -e "  Образ ноды        : ${COLOR_WHITE}remnawave/node:latest${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}------------------------------------------------${COLOR_RESET}"
    echo ""
    reading "Начать установку? (y/n): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { info "Установка отменена."; exit 0; }
    echo ""

    # -----------------------------------------------------------------------
    # УСТАНОВКА
    # -----------------------------------------------------------------------

    local TARGET="/opt/remnawave"
    mkdir -p "$TARGET" && cd "$TARGET"

    # 1. Пакеты / Docker
    install_packages

    # 2. Начало docker-compose.yml
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

    # 3. Сертификаты (спрашивает email если нужно)
    setup_certificates "$SELFSTEAL_DOMAIN" "$TARGET"

    # 4. Продолжение docker-compose.yml
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

    # 5. nginx.conf
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

    # 6. UFW: порт 2222 только для IP панели
    ufw allow from "$PANEL_IP" to any port 2222 >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
    ok "UFW: порт 2222 разрешён только для $PANEL_IP"

    # 7. Маскировочный сайт
    install_random_template

    # 8. Запуск контейнеров
    info "Запускаем контейнеры..."
    sleep 2
    cd "$TARGET"
    docker compose up -d >/dev/null 2>&1 &
    spinner $! "Пожалуйста, подождите..."

    # 9. Проверка selfsteal-сайта
    echo ""
    info "Проверяем доступность $SELFSTEAL_DOMAIN..."
    local max_attempts=5 attempt=1 delay=15
    while [ "$attempt" -le "$max_attempts" ]; do
        info "Попытка $attempt из $max_attempts..."
        if curl -s --fail --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -q "html"; then
            ok "Нода запущена и отвечает!"
            break
        fi
        fail "Нода недоступна (попытка $attempt)"
        if [ "$attempt" -eq "$max_attempts" ]; then
            echo -e "${COLOR_RED}Нода не ответила за $max_attempts попыток.${COLOR_RESET}"
            echo -e "${COLOR_YELLOW}Проверьте логи: cd /opt/remnawave && docker compose logs -f${COLOR_RESET}"
        fi
        sleep "$delay"
        (( attempt++ ))
    done

    # -----------------------------------------------------------------------
    # ИТОГ
    # -----------------------------------------------------------------------
    echo ""
    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}          УСТАНОВКА ЗАВЕРШЕНА!${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
    echo -e "  Домен ноды  : ${COLOR_WHITE}$SELFSTEAL_DOMAIN${COLOR_RESET}"
    echo -e "  Порт ноды   : ${COLOR_WHITE}2222${COLOR_RESET}"
    echo -e "  IP панели   : ${COLOR_WHITE}$PANEL_IP${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Полезные команды:${COLOR_RESET}"
    echo -e "  Логи   : ${COLOR_GREEN}cd /opt/remnawave && docker compose logs -f${COLOR_RESET}"
    echo -e "  Стоп   : ${COLOR_GREEN}cd /opt/remnawave && docker compose down${COLOR_RESET}"
    echo -e "  Старт  : ${COLOR_GREEN}cd /opt/remnawave && docker compose up -d${COLOR_RESET}"
    echo -e "  Рестарт: ${COLOR_GREEN}cd /opt/remnawave && docker compose restart${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
}

main
exit 0
