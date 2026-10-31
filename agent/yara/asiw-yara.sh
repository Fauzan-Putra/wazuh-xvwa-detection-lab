#!/usr/bin/env bash
# =====================================================================
# ASIW S8: Active Response YARA untuk file baru di direktori upload XVWA
# ---------------------------------------------------------------------
# Pasang di VM Target:
#   sudo install -o root -g wazuh -m 750 asiw-yara.sh \
#        /var/ossec/active-response/bin/asiw-yara.sh
#   sudo mkdir -p /var/ossec/etc/yara/rules
#   sudo install -o root -g wazuh -m 640 asiw-webshell.yar \
#        /var/ossec/etc/yara/rules/asiw-webshell.yar
#   sudo apt install -y yara
#
# Lalu aktifkan blok <command>/<active-response> pada ossec.conf agent.
#
# CARA KERJA:
#   Wazuh execd mengirim JSON Active Response ke STDIN skrip ini. Skrip
#   mengambil path file dari syscheck.path, memindainya dengan YARA, lalu
#   menulis hasil SATU BARIS JSON ke /var/log/asiw-yara.log. Baris itu
#   dibaca kembali oleh logcollector (program name asiw-yara) dan
#   dicocokkan rule 100408.
#
# MENGAPA MENULIS KE FILE, BUKAN LANGSUNG KE SOCKET:
#   Menulis ke file membuat hasil dapat diaudit ulang dan tidak hilang
#   bila agent sedang terputus dari Manager (prinsip G6 PRD: alert tetap
#   tersedia). Logcollector akan mengirimkannya setelah koneksi pulih.
# =====================================================================
set -uo pipefail

YARA_BIN="${YARA_BIN:-/usr/bin/yara}"
YARA_RULES="${YARA_RULES:-/var/ossec/etc/yara/rules/asiw-webshell.yar}"
OUT_LOG="${OUT_LOG:-/var/log/asiw-yara.log}"
# Hanya pindai file di bawah path ini (membatasi blast radius skrip)
ALLOWED_PREFIX="${ALLOWED_PREFIX:-/var/www/html/xvwa/}"

read -r INPUT_JSON

# --- Ambil path file dari payload Active Response.
# Memakai python3 bila ada (parsing JSON yang benar), fallback ke grep.
if command -v python3 >/dev/null 2>&1; then
  FILE_PATH="$(printf '%s' "$INPUT_JSON" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
p=(d.get("parameters",{}).get("alert",{}).get("syscheck",{}) or {}).get("path","")
print(p)
' 2>/dev/null)"
else
  FILE_PATH="$(printf '%s' "$INPUT_JSON" | grep -oE '"path"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
fi

[ -z "${FILE_PATH:-}" ] && exit 0

# --- Penjaga keamanan. Skrip ini dijalankan sebagai root oleh execd,
#     dan nama berkas SEPENUHNYA dikendalikan penyerang: XVWA memakai
#     basename($_FILES['image']['name']) tanpa sanitasi apa pun
#     (lihat vulnerabilities/fileupload/home.php baris 68).
#
#     Tiga penjaga diterapkan:
#       1. Tolak karakter kendali (termasuk newline/CR). Tanpa ini,
#          nama berkas bernewline dapat MENYUNTIKKAN baris log palsu ke
#          /var/log/asiw-yara.log yang kemudian dibaca logcollector,
#          sehingga penyerang dapat memalsukan alert atau menyembunyikan
#          temuan. Ini risiko log injection yang nyata.
#       2. Tolak path traversal.
#       3. Batasi pemindaian ke bawah direktori aplikasi saja.
#
#     Catatan: path TIDAK pernah dieksekusi lewat shell; ia hanya
#     diteruskan sebagai argumen ber-tanda kutip ke biner yara, jadi
#     tidak ada jalur command injection.

# (1) karakter kendali: bandingkan panjang sebelum dan sesudah penghapusan
FILE_PATH_CLEAN="$(printf '%s' "$FILE_PATH" | tr -d '\000-\037\177')"
if [ "$FILE_PATH_CLEAN" != "$FILE_PATH" ]; then
  printf '{"file":"<rejected: control characters in filename>","matches":"ASIW_Suspicious_Filename","verdict":"suspicious"}\n' >> "$OUT_LOG"
  exit 0
fi

# (2) dan (3)
case "$FILE_PATH" in
  *..*) exit 0 ;;
  "$ALLOWED_PREFIX"*) : ;;
  *) exit 0 ;;
esac

[ -f "$FILE_PATH" ] || exit 0
[ -x "$YARA_BIN" ] || exit 0
[ -r "$YARA_RULES" ] || exit 0

# --- Pindai. -w menekan warning, -N tanpa nama namespace.
SCAN_OUT="$("$YARA_BIN" -w "$YARA_RULES" "$FILE_PATH" 2>/dev/null)"

# Kumpulkan nama rule yang cocok, dipisah titik koma
MATCHES="$(printf '%s\n' "$SCAN_OUT" | awk 'NF {print $1}' | paste -sd';' -)"

if [ -n "$MATCHES" ]; then
  VERDICT="malicious"
else
  VERDICT="clean"
fi

# --- Escape minimal untuk JSON (path bisa memuat karakter aneh)
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

printf '{"file":"%s","matches":"%s","verdict":"%s"}\n' \
  "$(esc "$FILE_PATH")" "$(esc "$MATCHES")" "$VERDICT" >> "$OUT_LOG"

exit 0
