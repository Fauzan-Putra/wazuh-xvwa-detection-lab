#!/usr/bin/env bash
# =====================================================================
# ASIW: setup VM TARGET untuk XVWA yang berjalan via DOCKER
# ---------------------------------------------------------------------
# Jalankan sebagai root di VM Target:
#   sudo ./docker/asiw-setup-target-docker.sh --check   # periksa saja
#   sudo ./docker/asiw-setup-target-docker.sh           # pasang
#
# Berbeda dari asiw-install-target.sh (native): skrip ini TIDAK memasang
# atau mengubah Apache di host (tidak ada Apache di host pada setup Docker).
# Apache, PHP, dan MariaDB ada DI DALAM container; skrip ini:
#   1. memasang auditd + yara + acl di HOST
#   2. memasang aturan auditd (path host /root/xvwa-lab/xvwa)
#   3. memasang aturan YARA + skrip active response (path host)
#   4. menyambungkan logging container ke host via compose override
#      (log Apache + log JSON + audit MariaDB)
#   5. membuat ulang container agar mount berlaku
#   6. me-restart wazuh-agent
#
# Idempoten: aman dijalankan berulang.
# =====================================================================
set -uo pipefail

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

OSSEC="${OSSEC:-/var/ossec}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../docker
REPO="$(cd "$SRC/.." && pwd)"                                 # root repo
LAB="${ASIW_LAB_DIR:-/root/xvwa-lab}"                         # lokasi compose XVWA
XVWA_DIR="$LAB/xvwa"
WEBUSER="www-data"
STAMP="$(date +%Y%m%d-%H%M%S)"

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
blue(){ printf '\033[34m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Harus root."; exit 1; }

# docker compose v2 (plugin) atau v1
if docker compose version >/dev/null 2>&1; then DC="docker compose"; \
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"; \
else red "docker compose tidak ditemukan."; exit 1; fi

# ---------------------------------------------------------------- 0
blue "0/6 Verifikasi asumsi setup Docker"
FAIL=0
[ -f "$LAB/docker-compose.yml" ] && green "    compose ditemukan: $LAB/docker-compose.yml" \
  || { red "    $LAB/docker-compose.yml tidak ada. Set ASIW_LAB_DIR bila lokasi beda."; FAIL=1; }
[ -d "$XVWA_DIR" ] && green "    bind mount XVWA di host: $XVWA_DIR" \
  || { red "    $XVWA_DIR tidak ada. Pastikan compose mem-bind ./xvwa."; FAIL=1; }
[ -d "$XVWA_DIR/img/uploads" ] && green "    direktori upload: $XVWA_DIR/img/uploads" \
  || yellow "    $XVWA_DIR/img/uploads belum ada (jalankan setup XVWA dulu)"
WEBUID="$(id -u "$WEBUSER" 2>/dev/null || echo '')"
[ "$WEBUID" = "33" ] && green "    UID $WEBUSER = 33" \
  || yellow "    UID $WEBUSER = ${WEBUID:-tidak ada} (rule memfilter audit.key, bukan UID; aman)"
if docker info 2>/dev/null | grep -qiE 'userns'; then
  red "    PERHATIAN: user-namespace remap TERDETEKSI. Filter auditd euid=33"
  red "    mungkin meleset untuk proses container. Verifikasi T3 cmdi dengan teliti."
else
  green "    user-namespace remap tidak aktif (euid=33 host = container)"
fi
docker ps --format '{{.Names}}' | grep -q xvwa-web && green "    container xvwa-web berjalan" \
  || yellow "    container xvwa-web tidak terlihat berjalan"
[ "$FAIL" -ne 0 ] && { red; red "DIBATALKAN: perbaiki dulu."; exit 1; }
[ "$CHECK_ONLY" -eq 1 ] && { echo; green "Mode --check: asumsi OK, tidak ada perubahan."; exit 0; }

# ---------------------------------------------------------------- 1
blue "1/6 Memasang paket host (auditd, yara, acl)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins yara acl >/dev/null 2>&1 \
  && green "    terpasang" || { red "    gagal memasang paket"; exit 1; }

# ---------------------------------------------------------------- 2
blue "2/6 Aturan auditd (path host)"
sed "s/euid=33/euid=${WEBUID:-33}/g; s#/var/www/html/xvwa#$XVWA_DIR#g" \
    "$REPO/agent/auditd/asiw-xvwa.rules" > /etc/audit/rules.d/asiw-xvwa.rules
chmod 640 /etc/audit/rules.d/asiw-xvwa.rules
augenrules --load >/dev/null 2>&1
systemctl enable --now auditd >/dev/null 2>&1
auditctl -l 2>/dev/null | grep -q asiw_web_exec \
  && green "    aturan auditd aktif" || red "    aturan auditd TIDAK aktif (periksa auditctl -l)"

# ---------------------------------------------------------------- 3
blue "3/6 YARA + skrip active response (path host)"
mkdir -p "$OSSEC/etc/yara/rules"
install -o root -g wazuh -m 640 "$REPO/agent/yara/asiw-webshell.yar" "$OSSEC/etc/yara/rules/"
yara -w "$OSSEC/etc/yara/rules/asiw-webshell.yar" /dev/null >/dev/null 2>&1 \
  && green "    aturan YARA valid" || { red "    aturan YARA invalid"; exit 1; }
sed "s#^ALLOWED_PREFIX=.*#ALLOWED_PREFIX=\"\${ALLOWED_PREFIX:-$XVWA_DIR/}\"#" \
    "$REPO/agent/yara/asiw-yara.sh" > "$OSSEC/active-response/bin/asiw-yara.sh"
chown root:wazuh "$OSSEC/active-response/bin/asiw-yara.sh"
chmod 750 "$OSSEC/active-response/bin/asiw-yara.sh"
touch /var/log/asiw-yara.log && chmod 640 /var/log/asiw-yara.log
green "    AR terpasang (ALLOWED_PREFIX=$XVWA_DIR/)"

# ---------------------------------------------------------------- 4
blue "4/6 Menyambungkan logging container ke host (compose override)"
mkdir -p "$LAB/logs/apache" "$LAB/logs/mysql"
chown 999:999 "$LAB/logs/mysql"          # uid mysql di dalam container MariaDB
mkdir -p "$LAB/asiw/apache" "$LAB/asiw/mysql"
install -m 644 "$REPO/agent/apache/asiw-xvwa-json-log.conf" "$LAB/asiw/apache/asiw-xvwa-json-log.conf"
install -m 644 "$SRC/mysql-asiw-server-audit.cnf"           "$LAB/asiw/mysql/asiw-server-audit.cnf"
# Pasang override (backup bila sudah ada dan berbeda)
if [ -f "$LAB/docker-compose.override.yml" ] && \
   ! diff -q "$LAB/docker-compose.override.yml" "$SRC/docker-compose.override.yml" >/dev/null 2>&1; then
  cp "$LAB/docker-compose.override.yml" "$LAB/docker-compose.override.yml.bak-$STAMP"
  yellow "    override lama dibackup: docker-compose.override.yml.bak-$STAMP"
fi
install -m 644 "$SRC/docker-compose.override.yml" "$LAB/docker-compose.override.yml"
green "    override + konfigurasi disalin ke $LAB"

# ---------------------------------------------------------------- 5
blue "5/6 Membuat ulang container agar mount berlaku"
( cd "$LAB" && $DC up -d ) && green "    container diperbarui" \
  || { red "    docker compose up -d gagal. Periksa: cd $LAB && $DC config"; exit 1; }
sleep 6
# Picu satu request agar log JSON terbentuk, lalu cek
curl -s -o /dev/null "http://localhost/xvwa/" 2>/dev/null || true
sleep 2
if [ -f "$LAB/logs/apache/xvwa_access_json.log" ]; then
  green "    log JSON terbentuk: $LAB/logs/apache/xvwa_access_json.log"
else
  yellow "    log JSON belum terlihat. Cek: ls -la $LAB/logs/apache/"
  yellow "    dan: docker exec xvwa-web apache2ctl -S 2>&1 | head"
fi
# Baca password root DB dari environment container (jangan hardcode kredensial)
DBPW="$(docker inspect xvwa-db --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^MYSQL_ROOT_PASSWORD=//p' | head -1)"
if [ -n "$DBPW" ]; then
  if docker exec xvwa-db sh -c "mysql -uroot -p'$DBPW' -e \"SHOW VARIABLES LIKE 'server_audit_logging';\"" 2>/dev/null | grep -qi ON; then
    green "    MariaDB server_audit aktif"
  else
    yellow "    server_audit belum aktif. Cek: docker logs xvwa-db | tail"
  fi
else
  yellow "    tidak bisa membaca MYSQL_ROOT_PASSWORD dari container; lewati cek server_audit"
fi

# ---------------------------------------------------------------- 6
blue "6/6 Restart wazuh-agent"
systemctl restart wazuh-agent
sleep 8
systemctl is-active --quiet wazuh-agent && green "    wazuh-agent aktif" \
  || { red "    wazuh-agent gagal start. tail -40 $OSSEC/logs/ossec.log"; exit 1; }

echo
green "SELESAI (Docker) di $(hostname)."
cat <<NEXT

LANGKAH VERIFIKASI (jalankan dari attacker/host lain):
  curl -s "http://<ip-vm-ini>/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
Lalu di VM ini:
  tail -5 $LAB/logs/apache/xvwa_access_json.log
  sudo ausearch -k asiw_web_exec -i 2>/dev/null | tail -20   # cek comm= dari container
Di Manager:
  sudo grep -E '"id":"(100203|100403|100503)"' /var/ossec/logs/alerts/alerts.json | tail

PENTING - verifikasi auditd container:
  Pada output ausearch, lihat field comm= untuk serangan cmdi.
  Jika comm="id"/"whoami"/dll muncul -> rule 100403 (T3) akan bekerja.
  Jika TIDAK ada event sama sekali -> kemungkinan userns remap atau
  auditd tidak menangkap proses container; laporkan agar rule disesuaikan.
NEXT
