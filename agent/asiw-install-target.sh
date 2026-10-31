#!/usr/bin/env bash
# =====================================================================
# ASIW: pemasangan sisi VM TARGET (XVWA)
# ---------------------------------------------------------------------
# Dijalankan sebagai root di SETIAP VM Target:
#   asiw-target-1 (192.0.2.124, Ubuntu 22.04)
#   asiw-target-2 (192.0.2.143, Ubuntu 22.04)
#   asiw-target-3 (192.0.2.162,  Ubuntu 24.04)
#
#   sudo ./asiw-install-target.sh            # pasang
#   sudo ./asiw-install-target.sh --check    # hanya periksa, tanpa ubah
#
# LINGKUP SKRIP INI
#   Hanya memasang bagian yang TIDAK DAPAT dipusatkan:
#     - konfigurasi Apache (access log JSON)
#     - aturan auditd
#     - biner yara + aturan YARA + skrip Active Response
#   Konfigurasi Wazuh (localfile, syscheck, sca) TIDAK disentuh karena
#   Manager sudah mendorongnya lewat grup asiw-xvwa-targets.
#
# Skrip bersifat idempoten: aman dijalankan berulang.
# =====================================================================
set -uo pipefail

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

OSSEC="${OSSEC:-/var/ossec}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SRC/.." && pwd)"

# --- Muat nilai spesifik infrastruktur dari asiw.env (bila ada) --------
if [ -f "$REPO/asiw.env" ]; then
  # shellcheck disable=SC1090
  . "$REPO/asiw.env"
fi
STAMP="$(date +%Y%m%d-%H%M%S)"
REPORT="/root/asiw-target-verification-$(hostname)-$STAMP.txt"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Harus dijalankan sebagai root."; exit 1; }

# =====================================================================
# LANGKAH 0: VERIFIKASI ASUMSI
# Tiga nilai dipakai keras di dalam rule di Manager. Bila berbeda di VM
# ini, rule TIDAK akan cocok dan hasilnya false negative SENYAP: tidak
# ada error apa pun, alert hanya tidak pernah muncul. Karena itu skrip
# memeriksanya lebih dulu dan menolak lanjut bila ada ketidaksesuaian.
# =====================================================================
blue "0/8 Verifikasi asumsi yang dikodekan ke dalam rule"
FAIL=0

# --- A1: document root / lokasi XVWA
XVWA_DIR=""
for d in "${ASIW_XVWA_DIR:-}" /var/www/html/xvwa /var/www/xvwa /srv/www/htdocs/xvwa; do
  [ -n "$d" ] && [ -d "$d" ] && { XVWA_DIR="$d"; break; }
done
if [ -z "$XVWA_DIR" ]; then
  red "    A1 GAGAL: direktori XVWA tidak ditemukan."
  red "       Rule 100407/100431 memakai path /var/www/html/xvwa/."
  red "       Cari dengan: find / -maxdepth 5 -type d -name xvwa 2>/dev/null"
  FAIL=1
elif [ "$XVWA_DIR" != "/var/www/html/xvwa" ]; then
  red "    A1 TIDAK SESUAI: XVWA ada di $XVWA_DIR, bukan /var/www/html/xvwa"
  red "       Sesuaikan path pada rules/asiw_xvwa_rules.xml (rule 100407,"
  red "       100431, 100507) dan manager/agent.conf-asiw-xvwa (syscheck),"
  red "       lalu jalankan ulang asiw-install-manager.sh."
  FAIL=1
else
  green "    A1 OK  XVWA di $XVWA_DIR"
fi

# --- A2: UID user web
WEBUSER="www-data"
WEBUID="$(id -u "$WEBUSER" 2>/dev/null || echo '')"
if [ -z "$WEBUID" ]; then
  red "    A2 GAGAL: user $WEBUSER tidak ada."; FAIL=1
elif [ "$WEBUID" != "33" ]; then
  yellow "    A2 PERHATIAN: UID $WEBUSER = $WEBUID (rule mengasumsikan 33)"
  yellow "       Skrip akan memakai euid=$WEBUID pada aturan auditd (otomatis),"
  yellow "       jadi sisi agent aman. Rule di Manager memfilter audit.key,"
  yellow "       bukan UID, sehingga tetap bekerja."
else
  green "    A2 OK  UID $WEBUSER = 33"
fi

# --- A3: path biner ping (allowlist baseline modul cmdi, rule 100403)
PING_BIN="$(command -v ping 2>/dev/null || echo '')"
if [ -z "$PING_BIN" ]; then
  yellow "    A3 PERHATIAN: ping tidak ditemukan; modul cmdi tidak akan berfungsi"
elif [ "$PING_BIN" != "/usr/bin/ping" ] && [ "$PING_BIN" != "/bin/ping" ]; then
  red "    A3 TIDAK SESUAI: ping di $PING_BIN"
  red "       Rule 100403 meng-allowlist /usr/bin/ping dan /bin/ping."
  red "       Tambahkan $PING_BIN ke allowlist rule 100403, jika tidak"
  red "       setiap ping SAH dari modul cmdi akan memicu alert CRITICAL."
  FAIL=1
else
  green "    A3 OK  ping di $PING_BIN"
fi

# --- A4: direktori upload (target rule 100407)
if [ -z "$XVWA_DIR" ]; then
  yellow "    A4 DILEWATI: XVWA belum ditemukan (lihat A1)"
elif [ -d "$XVWA_DIR/img/uploads" ]; then
  green "    A4 OK  direktori upload ada: $XVWA_DIR/img/uploads"
else
  yellow "    A4 PERHATIAN: $XVWA_DIR/img/uploads belum ada."
  yellow "       FIM tidak dapat memantau direktori yang tidak ada."
  yellow "       Jalankan setup XVWA ($XVWA_DIR/setup/) lebih dulu."
fi

# --- Konteks lingkungan (dicatat untuk reproducibility, bukan kegagalan)
PHPVER="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo 'tidak ada')"
OSVER="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo '?')"
green "    konteks: $OSVER | PHP $PHPVER"

if [ "$FAIL" -ne 0 ]; then
  red
  red "DIBATALKAN: ada asumsi yang tidak sesuai (lihat di atas)."
  red "Perbaiki dulu, atau sesuaikan rule di Manager, lalu jalankan ulang."
  exit 1
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo; green "Mode --check: semua asumsi terverifikasi. Tidak ada yang diubah."
  exit 0
fi

# =====================================================================
blue "1/8 Memasang paket yang dibutuhkan"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins yara \
                       libapache2-mod-security2 modsecurity-crs acl >/dev/null 2>&1 \
  && green "    auditd, audispd-plugins, yara, ModSecurity+CRS terpasang" \
  || { red "    pemasangan paket gagal"; exit 1; }

# =====================================================================
blue "2/8 Access log JSON Apache (S2, sumber seluruh rule T1)"
install -m 644 "$SRC/apache/asiw-xvwa-json-log.conf" /etc/apache2/conf-available/
a2enconf asiw-xvwa-json-log >/dev/null 2>&1 || true
# Pastikan error PHP masuk ke log (prasyarat tier T2)
PHP_INI="$(php -r 'echo php_ini_loaded_file();' 2>/dev/null)"
PHP_APACHE_INI="/etc/php/${PHPVER%.*}/apache2/php.ini"
if [ -f "$PHP_APACHE_INI" ]; then
  cp -n "$PHP_APACHE_INI" "$PHP_APACHE_INI.bak-$STAMP"
  sed -i 's/^\s*;\?\s*log_errors\s*=.*/log_errors = On/' "$PHP_APACHE_INI"
  grep -q '^log_errors' "$PHP_APACHE_INI" || echo 'log_errors = On' >> "$PHP_APACHE_INI"
  green "    log_errors = On di $PHP_APACHE_INI"
else
  yellow "    php.ini Apache tidak ditemukan; set log_errors=On manual (prasyarat T2)"
fi
if apache2ctl configtest 2>&1 | grep -q 'Syntax OK'; then
  systemctl reload apache2
  green "    konfigurasi Apache valid, direload"
else
  red "    konfigurasi Apache TIDAK valid:"
  apache2ctl configtest 2>&1 | sed 's/^/      /'
  a2disconf asiw-xvwa-json-log >/dev/null 2>&1
  red "    konfigurasi ASIW dinonaktifkan kembali. Perbaiki lalu ulangi."
  exit 1
fi

# =====================================================================
blue "3/8 Aturan auditd (S6, bukti tier T3)"
# Ganti euid sesuai UID nyata di VM ini, bukan asumsi 33.
sed "s/euid=33/euid=$WEBUID/g; s#/var/www/html/xvwa#$XVWA_DIR#g" \
    "$SRC/auditd/asiw-xvwa.rules" > /etc/audit/rules.d/asiw-xvwa.rules
chmod 640 /etc/audit/rules.d/asiw-xvwa.rules
augenrules --load >/dev/null 2>&1
systemctl enable --now auditd >/dev/null 2>&1
if auditctl -l 2>/dev/null | grep -q 'asiw_web_exec'; then
  green "    aturan auditd aktif (euid=$WEBUID)"
else
  red "    aturan auditd TIDAK aktif. Tier T3 untuk XV-03/XV-11 tidak akan bekerja."
  red "    Periksa: auditctl -l ; systemctl status auditd"
fi

# =====================================================================
blue "4/8 YARA dan skrip Active Response (S8)"
mkdir -p "$OSSEC/etc/yara/rules"
install -o root -g wazuh -m 640 "$SRC/yara/asiw-webshell.yar" "$OSSEC/etc/yara/rules/"
if yara -w "$OSSEC/etc/yara/rules/asiw-webshell.yar" /dev/null >/dev/null 2>&1; then
  green "    aturan YARA valid"
else
  red "    aturan YARA TIDAK valid"; exit 1
fi
# Sesuaikan ALLOWED_PREFIX pada skrip bila XVWA tidak di path default
sed "s#^ALLOWED_PREFIX=.*#ALLOWED_PREFIX=\"\${ALLOWED_PREFIX:-$XVWA_DIR/}\"#" \
    "$SRC/yara/asiw-yara.sh" > "$OSSEC/active-response/bin/asiw-yara.sh"
chown root:wazuh "$OSSEC/active-response/bin/asiw-yara.sh"
chmod 750 "$OSSEC/active-response/bin/asiw-yara.sh"
touch /var/log/asiw-yara.log && chmod 640 /var/log/asiw-yara.log
green "    skrip AR di $OSSEC/active-response/bin/asiw-yara.sh"

# =====================================================================
blue "5/8 ModSecurity mode DetectionOnly (S4, menutup FN1)"
# FN1: body POST tidak ada di access log Apache, sehingga modul sqli,
# sqli_blind, xpath, stored_xss, ssrf_xspa, dan fileupload tidak dapat
# mencapai tier T1 tanpa inspeksi body. ModSecurity menutup celah itu.
a2enmod security2 headers >/dev/null 2>&1 || true
install -m 644 "$SRC/modsecurity/asiw-modsecurity.conf" /etc/modsecurity/
# Muat setelah konfigurasi ModSecurity bawaan
if ! grep -q 'asiw-modsecurity.conf' /etc/apache2/mods-enabled/security2.conf 2>/dev/null; then
  echo 'IncludeOptional /etc/modsecurity/asiw-modsecurity.conf' >> /etc/apache2/mods-enabled/security2.conf
fi
# Debian/Ubuntu memasang modsecurity.conf-recommended dengan SecRuleEngine Off.
# Konfigurasi ASIW menyetelnya ke DetectionOnly dan dimuat terakhir.
if [ -f /etc/modsecurity/modsecurity.conf-recommended ] && [ ! -f /etc/modsecurity/modsecurity.conf ]; then
  cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
fi
if apache2ctl configtest 2>&1 | grep -q 'Syntax OK'; then
  systemctl reload apache2
  # PENJAGA KERAS: pastikan TIDAK dalam mode blocking.
  sleep 2
  if apache2ctl -t -D DUMP_MODULES 2>/dev/null | grep -q security2; then
    ENGINE="$(grep -rhoP '^\s*SecRuleEngine\s+\K\w+' /etc/modsecurity/ /etc/apache2/ 2>/dev/null | tail -1)"
    if [ "$ENGINE" = "On" ]; then
      red "    BAHAYA: SecRuleEngine = On (mode BLOCKING)."
      red "    PRD 3.2 menetapkan sistem ini BUKAN IPS inline. Mode blocking"
      red "    akan membuat skenario E4-E8 gagal dan data eksperimen tidak valid."
      red "    Ubah menjadi DetectionOnly lalu reload Apache."
      exit 1
    fi
    green "    ModSecurity aktif, SecRuleEngine = ${ENGINE:-DetectionOnly}"
  else
    yellow "    modul security2 tidak termuat; S4 tidak aktif"
  fi
else
  red "    konfigurasi Apache tidak valid setelah ModSecurity:"
  apache2ctl configtest 2>&1 | sed 's/^/      /'
  sed -i '/asiw-modsecurity.conf/d' /etc/apache2/mods-enabled/security2.conf
  red "    konfigurasi ASIW dicabut. Perbaiki lalu ulangi."
  exit 1
fi
touch /var/log/apache2/modsec_audit.json
chmod 640 /var/log/apache2/modsec_audit.json
setfacl -m u:wazuh:r /var/log/apache2/modsec_audit.json 2>/dev/null || \
  chmod 644 /var/log/apache2/modsec_audit.json
green "    audit log: /var/log/apache2/modsec_audit.json"

# =====================================================================
blue "6/8 Audit MariaDB server_audit (S5, bukti terkuat SQLi)"
if ! command -v mysql >/dev/null 2>&1; then
  yellow "    MariaDB/MySQL tidak terpasang; S5 dilewati"
  yellow "    Akibat: XV-01 berhenti di T2, XV-09 tidak punya T3."
else
  if mysql -e "SHOW PLUGINS;" 2>/dev/null | grep -qi server_audit; then
    green "    plugin server_audit sudah terpasang"
  else
    mysql -e "INSTALL SONAME 'server_audit';" 2>/dev/null \
      && green "    plugin server_audit dipasang" \
      || yellow "    gagal memasang plugin (perlu paket mariadb-plugin-provider atau hak root DB)"
  fi
  install -m 644 "$SRC/mariadb/asiw-server-audit.cnf" \
          /etc/mysql/mariadb.conf.d/99-asiw-audit.cnf 2>/dev/null || \
  install -m 644 "$SRC/mariadb/asiw-server-audit.cnf" \
          /etc/mysql/conf.d/99-asiw-audit.cnf 2>/dev/null || \
  yellow "    direktori konfigurasi MariaDB tidak ditemukan"
  mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql 2>/dev/null || true
  systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null || true
  sleep 4
  if mysql -e "SHOW VARIABLES LIKE 'server_audit_logging';" 2>/dev/null | grep -qi ON; then
    green "    server_audit aktif"
    touch /var/log/mysql/server_audit.log 2>/dev/null || true
    setfacl -m u:wazuh:r /var/log/mysql/server_audit.log 2>/dev/null || \
      chmod 644 /var/log/mysql/server_audit.log 2>/dev/null || true
    green "    audit log: /var/log/mysql/server_audit.log"
  else
    yellow "    server_audit TIDAK aktif. Periksa:"
    yellow "      mysql -e \"SHOW VARIABLES LIKE 'server_audit%';\""
    yellow "      journalctl -u mariadb -n 30"
  fi
fi

# =====================================================================
blue "7/8 Restart agent dan tunggu konfigurasi dari grup"
systemctl restart wazuh-agent
sleep 10
if systemctl is-active --quiet wazuh-agent; then
  green "    wazuh-agent aktif"
else
  red "    wazuh-agent GAGAL start. Periksa: tail -40 $OSSEC/logs/ossec.log"
  exit 1
fi

# =====================================================================
blue "8/8 Verifikasi dan pencatatan bukti"
{
  echo "ASIW - Verifikasi VM Target"
  echo "Host      : $(hostname)"
  echo "Waktu     : $(date -Is)"
  echo "OS        : $OSVER"
  echo "PHP       : $PHPVER"
  echo
  echo "[Asumsi yang terverifikasi]"
  echo "  XVWA dir      : $XVWA_DIR"
  echo "  UID $WEBUSER  : $WEBUID"
  echo "  ping          : $PING_BIN"
  echo
  echo "[Aturan auditd aktif]"
  auditctl -l 2>/dev/null | grep asiw || echo "  (tidak ada)"
  echo
  echo "[Sumber log yang dipantau agent]"
  grep -E "Analyzing file|Monitoring" "$OSSEC/logs/ossec.log" 2>/dev/null | tail -12 || true
  echo
  echo "[Grup agent]"
  grep -iE "assigned group|Group added" "$OSSEC/logs/ossec.log" 2>/dev/null | tail -3 || echo "  (belum tersinkron)"
  echo
  echo "[Konfigurasi terpusat diterima?]"
  if [ -f "$OSSEC/etc/shared/agent.conf" ]; then
    echo "  etc/shared/agent.conf ADA ($(wc -l < "$OSSEC/etc/shared/agent.conf") baris)"
    grep -c '<localfile>' "$OSSEC/etc/shared/agent.conf" | sed 's/^/  blok localfile: /'
  else
    echo "  BELUM ADA. Manager menyinkronkan setiap ~10 menit."
    echo "  Percepat: di Manager jalankan 'systemctl restart wazuh-manager'"
  fi
  echo
  echo "[S4 ModSecurity]"
  apache2ctl -t -D DUMP_MODULES 2>/dev/null | grep security2 | sed 's/^/  /' || echo "  tidak termuat"
  grep -rhoP '^\s*SecRuleEngine\s+\K\w+' /etc/modsecurity/ 2>/dev/null | tail -1 | sed 's/^/  SecRuleEngine: /'
  echo
  echo "[S5 MariaDB server_audit]"
  mysql -e "SHOW VARIABLES LIKE 'server_audit_logging';" 2>/dev/null | sed 's/^/  /' || echo "  tidak tersedia"
  echo
  echo "[Policy SCA diterima?]"
  [ -f "$OSSEC/etc/shared/asiw_xvwa_baseline.yml" ] \
    && echo "  asiw_xvwa_baseline.yml ADA" || echo "  BELUM ADA (tunggu sinkronisasi)"
} | tee "$REPORT"

echo
green "SELESAI di $(hostname)."
echo "Laporan bukti: $REPORT"
cat <<'NEXT'

CATATAN
  Konfigurasi Wazuh (localfile, syscheck, sca) datang dari Manager lewat
  grup. Bila etc/shared/agent.conf belum ada, tunggu beberapa menit atau
  restart wazuh-manager untuk memaksa sinkronisasi.

UJI dari host penyerang lab (bukan dari VM ini, agar srcip benar)
  curl -s "http://<IP-VM-INI>/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
  # lalu di Manager: harus muncul 100203 (T1), 100403 (T3), 100503 (korelasi)
NEXT
