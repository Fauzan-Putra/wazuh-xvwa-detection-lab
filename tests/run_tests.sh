#!/usr/bin/env bash
# =====================================================================
# ASIW: harness uji decoder/rule XVWA terhadap wazuh-logtest
# ---------------------------------------------------------------------
# Dua mode:
#   1. Mode container (default, untuk laptop/CI):
#        ./run_tests.sh
#      Membuat container wazuh-manager, memasang decoder+rule, lalu uji.
#   2. Mode manager nyata (jalankan DI VM Monitoring sebagai root):
#        ASIW_LOCAL=1 ./run_tests.sh
#      Memakai /var/ossec/bin/wazuh-logtest yang sudah ada.
#
# Keluar dengan status 0 bila seluruh kasus lulus.
# =====================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.8}"
CONTAINER="${CONTAINER:-asiw-wazuh-logtest}"
LOCAL="${ASIW_LOCAL:-0}"

POS="$HERE/corpus_positive.tsv"
NEG="$HERE/corpus_negative.tsv"

# ---------------------------------------------------------------- utils
c_red()   { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

run_logtest() {   # stdin = satu baris log; stdout = output logtest
  if [ "$LOCAL" = "1" ]; then
    timeout 30 /var/ossec/bin/wazuh-logtest 2>&1
  else
    timeout 30 docker exec -i "$CONTAINER" /var/ossec/bin/wazuh-logtest 2>&1
  fi
}

# --------------------------------------------------------------- setup
setup_local() {
  c_blue "== Mode: manager lokal (/var/ossec)"
  install -o root -g wazuh -m 640 "$ROOT/decoders/asiw_xvwa_decoders.xml" /var/ossec/etc/decoders/
  install -o root -g wazuh -m 640 "$ROOT/rules/asiw_xvwa_rules.xml"      /var/ossec/etc/rules/
}

# Menunggu wazuh-analysisd benar-benar menerima koneksi logtest.
# Memeriksa keberadaan biner saja TIDAK cukup: biner sudah ada jauh
# sebelum analysisd membuka socket rule_test, sehingga uji akan gagal
# dengan "error when connecting with wazuh-analysisd".
wait_analysisd() {
  local tries="${1:-60}" i out
  printf 'Menunggu wazuh-analysisd siap'
  for i in $(seq 1 "$tries"); do
    out="$(echo 'asiw-readiness-probe' \
           | timeout 20 docker exec -i "$CONTAINER" /var/ossec/bin/wazuh-logtest 2>&1)"
    if echo "$out" | grep -q 'Completed pre-decoding'; then
      echo ' siap'
      return 0
    fi
    printf '.'
    sleep 3
  done
  echo ' GAGAL'
  c_red "analysisd tidak siap setelah $((tries*3)) detik. Keluaran terakhir:"
  echo "$out" | sed 's/^/    /'
  return 1
}

setup_container() {
  c_blue "== Mode: container wazuh/wazuh-manager:${WAZUH_VERSION}"
  if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" "wazuh/wazuh-manager:${WAZUH_VERSION}" >/dev/null
    printf 'Menunggu biner manager tersedia'
    for _ in $(seq 1 40); do
      if docker exec "$CONTAINER" test -x /var/ossec/bin/wazuh-logtest 2>/dev/null; then break; fi
      printf '.'; sleep 2
    done
    echo
    wait_analysisd 60 || exit 1
  fi
  docker cp "$ROOT/decoders/asiw_xvwa_decoders.xml" "$CONTAINER:/var/ossec/etc/decoders/asiw_xvwa_decoders.xml"
  docker cp "$ROOT/rules/asiw_xvwa_rules.xml"      "$CONTAINER:/var/ossec/etc/rules/asiw_xvwa_rules.xml"
  docker exec "$CONTAINER" sh -c '
    chown root:wazuh /var/ossec/etc/decoders/asiw_xvwa_decoders.xml /var/ossec/etc/rules/asiw_xvwa_rules.xml
    chmod 640        /var/ossec/etc/decoders/asiw_xvwa_decoders.xml /var/ossec/etc/rules/asiw_xvwa_rules.xml'
  # Setelah ruleset kustom dipasang, pastikan analysisd masih menerima koneksi.
  wait_analysisd 20 || exit 1
}

# --------------------------------------------------- validasi sintaks XML
c_blue "== Validasi sintaks XML"
xml_fail=0
{ echo '<asiw_validation_root>'; cat "$ROOT/decoders/asiw_xvwa_decoders.xml"; echo '</asiw_validation_root>'; } \
  | xmllint --noout - || { c_red "FAIL: decoders XML tidak valid"; xml_fail=1; }
xmllint --noout "$ROOT/rules/asiw_xvwa_rules.xml" \
  || { c_red "FAIL: rules XML tidak valid"; xml_fail=1; }
[ "$xml_fail" -eq 0 ] && c_green "OK: kedua file XML valid"
[ "$xml_fail" -ne 0 ] && exit 1

if [ "$LOCAL" = "1" ]; then setup_local; else setup_container; fi

# --------------------------------------------- cek analysisd memuat ruleset
c_blue "== Cek ruleset dimuat tanpa error"
load_out="$(echo 'asiw-ruleset-load-check' | run_logtest)"
if echo "$load_out" | grep -qE 'Wazuh-logtest error|ERROR:'; then
  c_red "FAIL: analysisd menolak konfigurasi:"
  echo "$load_out" | sed 's/^/    /'
  exit 1
fi
c_green "OK: decoder dan rule dimuat"

# ------------------------------------------------------------- uji positif
pass=0; fail=0
declare -a failures=()

c_blue "== Uji POSITIF (rule yang diharapkan harus cocok)"
while IFS=$'\t' read -r expected logline; do
  case "$expected" in ''|\#*) continue ;; esac
  [ -z "${logline:-}" ] && continue
  out="$(printf '%s\n' "$logline" | run_logtest)"
  got="$(echo "$out" | grep -oP "^\s+id: '\K[0-9]+" | tail -1)"
  if [ "$got" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    failures+=("POSITIF expected=$expected got=${got:-<none>} :: ${logline:0:110}")
  fi
done < "$POS"
echo "   lulus=$pass gagal=$fail"

# ------------------------------------------------------------- uji negatif
npass=0; nfail=0
c_blue "== Uji NEGATIF (aktivitas normal tidak boleh jadi alert serangan)"
while IFS=$'\t' read -r maxlevel logline; do
  case "$maxlevel" in ''|\#*) continue ;; esac
  [ -z "${logline:-}" ] && continue
  out="$(printf '%s\n' "$logline" | run_logtest)"
  lvl="$(echo "$out" | grep -oP "^\s+level: '\K[0-9]+" | tail -1)"
  lvl="${lvl:-0}"
  if [ "$lvl" -le "$maxlevel" ]; then
    npass=$((npass+1))
  else
    nfail=$((nfail+1))
    rid="$(echo "$out" | grep -oP "^\s+id: '\K[0-9]+" | tail -1)"
    failures+=("NEGATIF level=$lvl (max $maxlevel) rule=${rid:-?} :: ${logline:0:110}")
  fi
done < "$NEG"
echo "   lulus=$npass gagal=$nfail"

# ---------------------------------------------------------------- ringkasan
echo
c_blue "================= RINGKASAN ================="
echo "Positif : $pass lulus, $fail gagal"
echo "Negatif : $npass lulus, $nfail gagal"
total_fail=$((fail + nfail))
if [ "$total_fail" -eq 0 ]; then
  c_green "SEMUA UJI LULUS"
  exit 0
fi
c_red "ADA $total_fail KEGAGALAN:"
for f in "${failures[@]}"; do echo "  - $f"; done
exit 1
