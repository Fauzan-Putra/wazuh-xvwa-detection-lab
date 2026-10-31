#!/usr/bin/env bash
# =====================================================================
# ASIW: pemasangan sisi MANAGER (VM Monitoring, 192.0.2.148)
# ---------------------------------------------------------------------
# Dijalankan SATU KALI sebagai root di VM Monitoring.
#
#   sudo ./asiw-install-manager.sh
#
# Yang dikerjakan skrip ini:
#   1. Backup decoder, rule, dan ossec.conf yang ada sekarang
#   2. Memasang custom decoder dan custom rule ASIW
#   3. MEMVALIDASI ruleset SEBELUM restart (ini krusial, lihat catatan)
#   4. Membuat agent group "asiw-xvwa-targets"
#   5. Memasang agent.conf terpusat + berkas yang disinkronkan ke agent
#   6. Menambahkan blok Active Response YARA ke ossec.conf manager
#   7. Memasukkan ketiga agent target ke grup
#   8. Restart manager dan verifikasi
#
# MENGAPA VALIDASI SEBELUM RESTART ITU KRUSIAL:
#   wazuh-analysisd MENOLAK START bila ada satu saja kesalahan sintaks
#   pada rule. Kalau itu terjadi setelah restart, SELURUH pemrosesan
#   alert berhenti, bukan hanya rule ASIW. Karena itu skrip memvalidasi
#   dengan wazuh-logtest dulu dan membatalkan diri bila gagal.
# =====================================================================
set -uo pipefail

OSSEC="${OSSEC:-/var/ossec}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Muat nilai spesifik infrastruktur dari asiw.env --------------------
# Repositori ini TIDAK memuat IP/hostname nyata (PRD Bagian 12: privasi).
# Nilai nyata dibaca dari asiw.env yang tidak di-commit.
if [ -f "$SRC/asiw.env" ]; then
  # shellcheck disable=SC1090
  . "$SRC/asiw.env"
fi
GROUP="${ASIW_GROUP:-asiw-xvwa-targets}"
AGENTS="${ASIW_AGENT_IDS:-001 002 003}"
MONITOR_IP="${ASIW_MONITOR_IP:-}"

# Tipe deployment XVWA: "native" (Apache di host) atau "docker".
# Menentukan agent.conf dan policy SCA mana yang didorong ke agent.
DEPLOY="${ASIW_DEPLOYMENT:-native}"
case "$DEPLOY" in
  native)
    AGENT_CONF="$SRC/manager/agent.conf-asiw-xvwa"
    SCA_FILE="$SRC/agent/sca/asiw_xvwa_baseline.yml" ;;
  docker)
    AGENT_CONF="$SRC/docker/agent.conf-asiw-xvwa-docker"
    SCA_FILE="$SRC/docker/asiw_xvwa_baseline-docker.yml" ;;
  *) echo "ASIW_DEPLOYMENT harus 'native' atau 'docker'"; exit 1 ;;
esac
# Nilai placeholder yang ada di berkas rule ter-commit
PLACEHOLDER_IP="192.0.2.148"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Harus dijalankan sebagai root."; exit 1; }
[ -d "$OSSEC" ] || { red "$OSSEC tidak ditemukan. Ini Wazuh Manager?"; exit 1; }
[ -x "$OSSEC/bin/wazuh-logtest" ] || { red "wazuh-logtest tidak ada. Pastikan ini Manager, bukan Agent."; exit 1; }

# ---------------------------------------------------------------- 1
blue "1/8 Backup konfigurasi saat ini"
cp -a "$OSSEC/etc/rules"    "$OSSEC/etc/rules.bak-$STAMP"
cp -a "$OSSEC/etc/decoders" "$OSSEC/etc/decoders.bak-$STAMP"
cp -a "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.bak-$STAMP"
green "    backup: etc/{rules,decoders}.bak-$STAMP, etc/ossec.conf.bak-$STAMP"

# ---------------------------------------------------------------- 2
blue "2/8 Memasang custom decoder dan rule ASIW"
install -o root -g wazuh -m 640 "$SRC/decoders/asiw_xvwa_decoders.xml" "$OSSEC/etc/decoders/"
install -o root -g wazuh -m 640 "$SRC/rules/asiw_xvwa_rules.xml"       "$OSSEC/etc/rules/"
green "    etc/decoders/asiw_xvwa_decoders.xml"
green "    etc/rules/asiw_xvwa_rules.xml"

# Rule 100901 men-suppress health check berkala dari VM Monitoring.
# Berkas ter-commit memakai IP placeholder; ganti dengan IP nyata di sini.
if [ -n "$MONITOR_IP" ] && [ "$MONITOR_IP" != "$PLACEHOLDER_IP" ]; then
  sed -i "s/<srcip>$PLACEHOLDER_IP<\/srcip>/<srcip>$MONITOR_IP<\/srcip>/" \
      "$OSSEC/etc/rules/asiw_xvwa_rules.xml"
  if grep -q "<srcip>$MONITOR_IP</srcip>" "$OSSEC/etc/rules/asiw_xvwa_rules.xml"; then
    green "    rule 100901: IP monitoring diset ke $MONITOR_IP"
  else
    red   "    rule 100901: substitusi IP GAGAL. Health check akan tampil sebagai alert."
    exit 1
  fi
else
  yellow "    rule 100901 masih memakai IP placeholder $PLACEHOLDER_IP."
  yellow "    Health check dari VM Monitoring TIDAK akan ter-suppress."
  yellow "    Perbaiki: cp asiw.env.example asiw.env, isi ASIW_MONITOR_IP, jalankan ulang."
fi

# ---------------------------------------------------------------- 3
blue "3/8 Validasi ruleset SEBELUM restart"
probe_out="$(echo 'asiw-install-validation-probe' | timeout 40 "$OSSEC/bin/wazuh-logtest" 2>&1)"
if echo "$probe_out" | grep -qE 'Wazuh-logtest error|ERROR:'; then
  red "    VALIDASI GAGAL. Ruleset DIKEMBALIKAN, manager TIDAK direstart."
  echo "$probe_out" | sed 's/^/      /'
  rm -f "$OSSEC/etc/decoders/asiw_xvwa_decoders.xml" "$OSSEC/etc/rules/asiw_xvwa_rules.xml"
  exit 1
fi
green "    ruleset valid, analysisd menerima konfigurasi"

# ---------------------------------------------------------------- 4
blue "4/8 Membuat agent group '$GROUP'"
if "$OSSEC/bin/agent_groups" -l 2>/dev/null | grep -qw "$GROUP"; then
  green "    grup sudah ada"
else
  "$OSSEC/bin/agent_groups" -a -g "$GROUP" -q && green "    grup dibuat"
fi
mkdir -p "$OSSEC/etc/shared/$GROUP"

# ---------------------------------------------------------------- 5
blue "5/8 Memasang agent.conf terpusat (deployment: ${DEPLOY})"
install -o wazuh -g wazuh -m 660 "$SRC/manager/agent.conf-asiw-xvwa" \
        "$OSSEC/etc/shared/$GROUP/agent.conf"
# Berkas di direktori grup ikut disinkronkan ke etc/shared/ pada agent.
install -o wazuh -g wazuh -m 660 "$SRC/agent/sca/asiw_xvwa_baseline.yml" \
        "$OSSEC/etc/shared/$GROUP/"
green "    etc/shared/$GROUP/agent.conf"
green "    etc/shared/$GROUP/asiw_xvwa_baseline.yml"

if [ -x "$OSSEC/bin/verify-agent-conf" ]; then
  if "$OSSEC/bin/verify-agent-conf" -f "$OSSEC/etc/shared/$GROUP/agent.conf" >/dev/null 2>&1; then
    green "    verify-agent-conf: OK"
  else
    red   "    verify-agent-conf melaporkan masalah:"
    "$OSSEC/bin/verify-agent-conf" -f "$OSSEC/etc/shared/$GROUP/agent.conf" 2>&1 | sed 's/^/      /'
    red   "    DIBATALKAN. Perbaiki agent.conf lalu jalankan ulang."
    exit 1
  fi
fi

# ---------------------------------------------------------------- 6
blue "6/8 Menambahkan blok Active Response YARA ke ossec.conf manager"
# Active Response didefinisikan di MANAGER; skripnya berada di AGENT.
if grep -q 'asiw-yara' "$OSSEC/etc/ossec.conf"; then
  green "    blok sudah ada, dilewati"
else
  python3 - "$OSSEC/etc/ossec.conf" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()
block = '''
  <!-- ASIW: Active Response YARA untuk berkas baru di direktori upload XVWA.
       Blok <command> dan <active-response> HARUS berada di Manager.
       Skrip asiw-yara.sh harus ada di setiap AGENT pada
       /var/ossec/active-response/bin/ (dipasang asiw-install-target.sh).
       rules_id 100407 = berkas eksekutabel baru di direktori upload. -->
  <command>
    <name>asiw-yara</name>
    <executable>asiw-yara.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>asiw-yara</command>
    <location>local</location>
    <rules_id>100407</rules_id>
  </active-response>
'''
# Sisipkan sebelum </ossec_config> terakhir
i = s.rfind('</ossec_config>')
if i == -1:
    sys.exit("ossec.conf tidak memuat </ossec_config>")
open(p, 'w').write(s[:i] + block + '\n' + s[i:])
PY
  green "    blok <command> dan <active-response> ditambahkan"
fi

# ---------------------------------------------------------------- 7
blue "7/8 Memasukkan agent target ke grup"
for id in $AGENTS; do
  name="$("$OSSEC/bin/agent_control" -i "$id" 2>/dev/null | awk -F': ' '/Name:/{print $2; exit}')"
  if [ -z "${name:-}" ]; then
    red "    agent $id tidak ditemukan, dilewati"
    continue
  fi
  "$OSSEC/bin/agent_groups" -a -i "$id" -g "$GROUP" -q >/dev/null 2>&1
  green "    agent $id ($name) -> grup $GROUP"
done

# ---------------------------------------------------------------- 8
blue "8/8 Restart manager dan verifikasi"
systemctl restart wazuh-manager
sleep 12
if systemctl is-active --quiet wazuh-manager; then
  green "    wazuh-manager aktif"
else
  red "    wazuh-manager GAGAL start. Periksa:"
  red "      tail -40 $OSSEC/logs/ossec.log"
  red "    Pulihkan dengan:"
  red "      rm -f $OSSEC/etc/rules/asiw_xvwa_rules.xml $OSSEC/etc/decoders/asiw_xvwa_decoders.xml"
  red "      cp $OSSEC/etc/ossec.conf.bak-$STAMP $OSSEC/etc/ossec.conf"
  red "      systemctl restart wazuh-manager"
  exit 1
fi

echo
blue "Verifikasi akhir"
loaded="$(grep -c 'asiw' "$OSSEC/logs/ossec.log" 2>/dev/null || echo 0)"
echo "  jumlah rule ASIW terpasang : $(grep -c '<rule id="100' "$OSSEC/etc/rules/asiw_xvwa_rules.xml")"
echo "  anggota grup $GROUP        :"
"$OSSEC/bin/agent_groups" -s -g "$GROUP" 2>/dev/null | sed 's/^/    /'

echo
green "SELESAI. Sisi Manager siap."
cat <<'NEXT'

LANGKAH BERIKUTNYA
  Jalankan asiw-install-target.sh di MASING-MASING VM Target. Skrip itu
  memasang bagian yang tidak dapat dipusatkan (konfigurasi Apache,
  aturan auditd, biner yara, dan skrip Active Response).

  Konfigurasi Wazuh (localfile, syscheck, sca) TIDAK perlu disentuh di
  VM Target: Manager sudah mendorongnya lewat grup.

UJI CEPAT dari host penyerang lab
  TARGET=192.0.2.124
  curl -s "http://$TARGET/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
  # lalu di Manager:
  tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002|"id":"1004'
NEXT
