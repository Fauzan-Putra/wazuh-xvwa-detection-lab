# Batasan Deteksi yang Diakui dan Asumsi yang Harus Diverifikasi

Dokumen ini wajib disitasi pada laporan akhir. Menyatakan batasan secara eksplisit
lebih jujur secara ilmiah daripada mengklaim cakupan penuh
(`XVWA_Detection_Mapping_ASIW.md` Bagian 8).

## 1. Batasan struktural (tidak dapat diperbaiki dengan menambah rule)

| # | Batasan | Alasan struktural | Perlakuan pada laporan |
|---|---|---|---|
| B1 | **Body POST tidak ada di access log** | Apache tidak mencatat body request. Pada XVWA, modul `sqli`, `sqli_blind`, `xpath`, `stored_xss`, `ssrf_xspa`, `fileupload`, `formula_injection` memakai POST. | Tanpa S4 (ModSecurity) atau S10 (Suricata), tier T1 untuk modul tersebut **tidak tercapai**; hanya T3 lewat bukti host. Laporkan sebagai FN1 dan ukur dampaknya dengan ablasi (recall dengan vs tanpa S4). |
| B2 | **DOM XSS (XV-10) varian fragment** | Payload pada `#fragment` tidak pernah dikirim ke server. Modul `dom_xss` membaca `document.location.href` di sisi klien. | *Structural blind spot*. Keluarkan dari perhitungan recall; laporkan terpisah. Rule 100210 hanya menangkap varian query string. |
| B3 | **Cryptography (XV-17)** | Tidak ada peristiwa jaringan/host yang menandakan eksploitasi hash lemah atau kunci tertanam. | Temuan statis via SCA (check 10030–10031), bukan alert. |
| B4 | **Session Flaws (XV-13)** | Deteksi hijacking memerlukan session ID di log. ASIW sengaja tidak mencatat cookie (privasi, PRD 12). | Temuan statis via SCA (check 10010–10012). |
| B5 | **CSRF (XV-16)** | Request CSRF identik dengan request sah; `Referer` kosong bukan bukti serangan. | Rule 100216 level 4 dan **tidak boleh dinaikkan**. T3 (100416) hanya mengonfirmasi password berubah, bukan bahwa itu CSRF. |
| B6 | **IDOR (XV-14) akses tunggal** | Pelanggaran otorisasi hanya dipahami aplikasi; satu akses ke objek orang lain tampak normal. | Hanya enumerasi yang terdeteksi (100314). Tidak ada T3. |
| B7 | **Formula Injection (XV-05) dampak** | Eksekusi terjadi saat korban membuka CSV di spreadsheet, di luar lingkup server. | Hanya penyisipan input terdeteksi (100205). |
| B8 | **XPath Injection (XV-04) tier lanjut** | XML diproses in-process; tidak ada jejak host maupun audit DB. | Maksimal T1. |

### Implikasi perhitungan metrik

Sesuai dokumen mapping Bagian 8, hitung recall pada **dua himpunan**:

1. **Seluruh 19 modul** (cakupan penuh) — angka ini akan selalu < 100% karena B2–B8.
2. **Modul yang secara teoretis dapat dideteksi** (kelas P/H pada katalog mapping) —
   angka ini mengukur kualitas desain deteksi, bukan batas fundamental.

Laporkan juga **tier achieved vs expected** per skenario. Contoh: serangan command
injection seharusnya mencapai T3; jika hanya T1, berarti bukti host (auditd) gagal,
dan itu temuan operasional, bukan batas struktural.

## 2. Batasan alat uji

| # | Batasan | Dampak |
|---|---|---|
| U1 | **`wazuh-logtest` tidak dapat memutar ulang event FIM** | Rule 100407 dan 100410 memakai `<if_sid>554</if_sid>`. Rule 554 dipicu decoder internal `syscheck_new_entry` yang dibangun analysisd dari FIM DB agent, bukan dari baris teks. Akibatnya kedua rule itu **tidak tercakup** harness `tests/run_tests.sh`. |
| U2 | **Rule frekuensi tidak diuji sebagai urutan** | Harness mengirim satu baris per sesi logtest, jadi rule dengan `frequency` (100302, 100308, 100311, 100313, 100314, 100319) tidak terpicu di uji. Yang diverifikasi adalah: ruleset dimuat tanpa error dan rule induknya (`if_matched_sid`) cocok. |
| U3 | **Korelasi lintas sumber tidak diuji end-to-end** | Rule 100501, 100503, 100507 memerlukan dua event berbeda dalam satu timeframe pada state analysisd yang sama. |

### Cara memverifikasi U1–U3 (wajib dilakukan sebelum fase D)

Ketiganya harus diuji **di lingkungan nyata**, bukan di logtest:

```bash
# U1: FIM upload webshell. Jalankan di VM Target.
sudo -u www-data bash -c 'printf "<?php system(\$_GET[0]); ?>\n" \
  > /var/www/html/xvwa/img/uploads/asiw-test-shell.php'
# Di VM Monitoring, dalam <= 30 detik:
sudo grep -E '"id":"(100407|554)"' /var/ossec/logs/alerts/alerts.json | tail -3
# Bersihkan:
sudo rm -f /var/www/html/xvwa/img/uploads/asiw-test-shell.php

# U2: rule frekuensi. Jalankan dari host penyerang lab.
TARGET=192.0.2.124
for i in $(seq 1 8); do
  curl -s "http://$TARGET/xvwa/vulnerabilities/sqli_blind/?item=1%20and%20sleep%281%29" >/dev/null
done
# Harus muncul rule 100302 (T2, level 9):
sudo grep '"id":"100302"' /var/ossec/logs/alerts/alerts.json | tail -1

# U3: korelasi cmdi. Jalankan dari host penyerang lab.
curl -s "http://$TARGET/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
# Harus muncul 100203 (T1), 100403 (T3), lalu 100503 (korelasi, level 14):
sudo grep -E '"id":"(100203|100403|100503)"' /var/ossec/logs/alerts/alerts.json | tail -5
```

Catat hasil ketiga uji ini sebagai bukti verifikasi fase A2.

## 3. Asumsi yang dikodekan ke dalam rule

Nilai-nilai berikut **dipakai keras** di dalam rule/konfigurasi. Jika berbeda pada
VM Target, rule tidak akan cocok dan hasilnya adalah false negative senyap.

| # | Asumsi | Nilai yang dipakai | Cara verifikasi | Yang harus diubah bila berbeda |
|---|---|---|---|---|
| A1 | Document root Apache | `/var/www/html` → XVWA di `/var/www/html/xvwa` | `grep -rh DocumentRoot /etc/apache2/sites-enabled/` | path pada rule 100407/100410, `ossec.conf`, SCA |
| A2 | UID user web | `33` (www-data, Ubuntu) | `id -u www-data` | `euid=33` pada `auditd/asiw-xvwa.rules` |
| A3 | Path biner ping | `/usr/bin/ping` atau `/bin/ping` | `command -v ping` | allowlist pada rule 100403 |
| A4 | URL dasar aplikasi | `/xvwa/` | `curl -I http://TARGET/xvwa/` | semua regex `^/xvwa/` pada rule T1 |
| A5 | Direktori upload | `/xvwa/img/uploads/` | inspeksi `fileupload/home.php` (sudah diverifikasi dari source) | rule 100407, 100507, `ossec.conf` syscheck |
| A6 | Nama database | `xvwa`, user `root` | `config.php` (sudah diverifikasi dari source) | rule 100120, `mariadb/asiw-server-audit.cnf` |
| A7 | IP VM Monitoring | `192.0.2.148` | PRD Bagian 7 | suppression rule 100901 |
| A8 | Domain sah modul redirect | `www.webappsec.org` | source `redirect/home.php` (sudah diverifikasi) | suppression rule 100902 |
| A9 | Protokol VM Target | HTTP (bukan HTTPS) | `curl -I` | bila HTTPS: Suricata tidak melihat body, ModSecurity tetap bisa (Lampiran A5 dokumen mapping) |
| A10 | Zona waktu seluruh VM | UTC, tersinkron NTP | `timedatectl` | korelasi 1005NN gagal bila jam melenceng (FN6) |

## 4. Keputusan desain yang perlu dicatat

| # | Keputusan | Alasan |
|---|---|---|
| D1 | **Tier T2 tidak pernah memakai HTTP 200** | XVWA membalas 200 untuk input normal maupun serangan gagal. Rule bawaan Wazuh 31106 ("A web attack returned code 200") menyesatkan di sini. Lihat dokumen mapping 1.3. |
| D2 | **Rule T1 selalu diikat ke path modul** | Pengendali FP1. Pola global seperti `union select` akan memicu pada pencarian sah. |
| D3 | **Baseline statistik dihitung di backend, bukan Wazuh** | Rule Wazuh tidak menyimpan statistik historis. T2 berbasis ukuran/durasi respons (vs baseline endpoint) dihitung n8n/backend memakai field `resp_bytes` dan `duration_us` dari S2. |
| D4 | **Access log combined tetap dipertahankan** | Mengubah formatnya ke JSON akan mematikan seluruh rule web bawaan 31100–31171. Karena itu dipakai file log kedua. |
| D5 | **Rule 100214 (IDOR) berlevel 0** | Satu akses objek adalah perilaku sah. Rule ini hanya menjadi induk rule frekuensi 100314. |
| D6 | **Suppression hanya menurunkan level, tidak menghapus event** | Dokumen mapping 2.4. Event tetap tersimpan di Indexer untuk evaluasi. |
| D7 | **Host penyerang lab tidak di-suppress** | Dokumen mapping 2.4 melarangnya. Beri tag `lab_attacker` di layer normalisasi agar dapat dibedakan dari insiden nyata. |
| D8 | **ModSecurity wajib DetectionOnly** | PRD 3.2: sistem bukan IPS inline. Blokir akan merusak reproduksibilitas skenario E4–E8. |

## 5. Risiko operasional yang teridentifikasi

| # | Risiko | Mitigasi yang disarankan |
|---|---|---|
| R1 | Rule 100411/100412 (auditd `connect` oleh user web) berpotensi berisik karena koneksi ke MariaDB lokal juga memakai `connect`. | Filter berbasis port tujuan di layer normalisasi, atau turunkan level setelah mengukur laju FP pada baseline E0/E1 selama 24 jam. |
| R2 | Audit DB (S5) mencatat teks query penuh; berdampak kinerja dan privasi. | Dapat diterima di lab karena DB `xvwa` berisi data sintetis. Jangan terapkan pola ini ke DB berisi data nyata. |
| R3 | Skrip Active Response YARA berjalan sebagai root. | Skrip membatasi diri ke path di bawah `/var/www/html/xvwa/` dan menolak path mengandung `..`. Tetap tinjau skrip sebelum deploy. |
| R4 | XVWA terekspos di jaringan kampus (PRD R14). | Batasi akses dengan firewall/segmentasi; jangan ekspos di luar subnet lab. |
| R5 | Volume log S2 meningkat saat skenario serangan. | `CustomLog` sudah dibatasi hanya untuk request `^/xvwa` dengan `SetEnvIf`. Pantau EPS saat E2–E8 (PRD Bagian 12). |

---

## 6. Hasil audit adversarial (31 Oktober 2026)

Ruleset diaudit secara adversarial sebelum dinyatakan siap: 15 kasus trafik sah
diuji untuk mencari false positive, dan ~35 varian payload diuji untuk mencari
evasion. Enam cacat ditemukan dan **sudah diperbaiki**. Dicatat di sini karena
pola kesalahannya relevan bagi siapa pun yang menambah rule di kemudian hari.

### T-1 (KRITIS, diperbaiki) — `\b` gagal setelah persen-encoding

**Gejala.** Pola `\bunion\b` tidak cocok pada `?item=1%20union%20select`.

**Sebab.** Pada `%20union`, karakter sebelum `u` adalah `0`. Digit adalah *word
character*, sehingga **tidak ada word boundary** di situ. Akibatnya seluruh pola
yang memakai `\b` di depan kata kunci gagal pada bentuk URL-encoded, yaitu
bentuk **paling umum** dari serangan nyata (sqlmap, Burp, browser).

Ini adalah false negative **senyap**: rule tetap memuat tanpa error dan uji
dengan payload mentah tetap lulus, sehingga cacat ini lolos dari uji awal.

**Perbaikan.** Batas kiri eksplisit yang juga menerima akhir sekuens persen:

```
LB = (?:\b|%[0-9a-f]{2})
```

Diterapkan ke 8 rule T1 (100201, 100202, 100204, 100206, 100208, 100210, 100211, 100219).

**Bukti.** Sebelum perbaikan `?item=1%20and%20extractvalue(...)` → rule 100101
(level 0, lolos). Sesudah → rule 100201 (level 6). Enam kasus regresi anti-evasion
ditambahkan ke `tests/corpus_positive.tsv`.

### T-2 (TINGGI, diperbaiki) — pola hanya menerima bentuk ter-encode

**Gejala.** Lima payload lolos sepenuhnya:

| Payload | Modul | Sebelum | Sesudah |
|---|---|---|---|
| `?item=1' or '1'='1` (apostrof mentah) | sqli | lolos | 100201 |
| `?item=1%20union/**/select%201` (komentar inline) | sqli | lolos | 100201 |
| `?item=1%2527%20or%201%3D1` (double-encode) | sqli | lolos | 100201 |
| `?item=<script>alert(1)</script>` (tag mentah) | reflected_xss | lolos | 100208 |
| `?name={{7*7}}` (kurawal mentah) | ssti | lolos | 100219 |

**Sebab.** Pola ditulis dengan asumsi klien selalu melakukan percent-encoding.
Apache mencatat URI **apa adanya**; `curl`, `sqlmap`, dan Burp Repeater sering
mengirim karakter mentah.

**Perbaikan.** Setiap karakter kunci kini menerima kedua bentuk, mis.
`(%27|%2527|'|%22|%2522|")` untuk kutip, `(%3C|%253C|\x3c)` untuk `<`,
`(%7B%7B|%257B%257B|\{\{)` untuk `{{`.

### T-3 (SEDANG, diperbaiki) — pelanggaran skema ID

Empat rule memiliki digit `NN` yang tidak sesuai XV-ID-nya, sehingga melanggar
kontrak "backend memetakan lewat tabel, bukan menebak" pada dokumen mapping 7.1.

| Lama | Baru | XV-ID | Keterangan |
|---|---|---|---|
| 100313 | **100332** | XV-12 | varian T2 ke-2 |
| 100404 | **100423** | XV-03 | varian T3 ke-2 |
| 100408 | **100427** | XV-07 | varian T3 ke-2 |
| 100410 | **100431** | XV-11 | varian T3 ke-2 |
| 100214 | **100114** | XV-14 | level 0, bukan T1 → dipindah ke band konteks |

**Akar masalah.** Skema `1003NN` pada dokumen mapping hanya menampung satu rule
per tier per XV-ID. Diperkenalkan konvensi `NN = 20 + XV-ID` untuk varian ke-2
(`40 +` untuk ke-3, `60 +` untuk ke-4), didokumentasikan di header ruleset dan
`docs/rule-reference.md`.

### T-4 (SEDANG, diperbaiki) — rule hantu di dokumentasi

`docs/rule-reference.md` mencantumkan rule **100412** (XV-12 T3, RFI) yang tidak
ada di ruleset.

**Analisis.** Rule itu akan memiliki kondisi **persis sama** dengan 100411
(`if_sid 80700` + `audit.key = asiw_web_connect`). Wazuh memilih satu rule per
event, jadi rule kedua tidak akan pernah menyala. Menghapusnya adalah keputusan
yang benar; dokumentasinya yang salah.

**Perbaikan.** Baris dihapus dari tabel, diganti catatan eksplisit bahwa XV-11
dan XV-12 **berbagi bukti host yang identik**, beserta tabel korelasi yang harus
dipakai backend untuk menentukan `xv_id` yang benar dari alert 100411.

### T-5 (SEDANG, diperbaiki) — log injection via nama berkas

**Gejala.** `agent/yara/asiw-yara.sh` menulis path berkas ke
`/var/log/asiw-yara.log` yang kemudian dibaca logcollector. XVWA menyimpan berkas
unggahan memakai `basename($_FILES['image']['name'])` **tanpa sanitasi**
(`vulnerabilities/fileupload/home.php` baris 68), sehingga nama berkas sepenuhnya
dikendalikan penyerang. Nama berkas yang memuat newline dapat menyuntikkan baris
log palsu, yang berarti penyerang dapat **memalsukan alert atau menyembunyikan
temuan**.

**Perbaikan.** Skrip menolak path yang memuat karakter kendali (`\000-\037`,
`\177`) dan mencatatnya sebagai indikator serangan tersendiri. Rule **100447**
(level 12) dibuat agar penolakan itu menghasilkan alert, bukan hilang tanpa jejak.

**Bukti.** Diuji dengan empat payload: nama ber-newline → ditolak dan dicatat
sebagai `ASIW_Suspicious_Filename`; path traversal → ditolak tanpa output; path
di luar `/var/www/html/xvwa/` → ditolak tanpa output; webshell sah → terdeteksi
`ASIW_Webshell_Generic_PHP`.

Catatan: path **tidak pernah** dieksekusi lewat shell, hanya diteruskan sebagai
argumen ber-tanda kutip ke biner `yara`, jadi tidak ada jalur command injection.

### T-6 (RENDAH, diperbaiki) — harness rapuh pada container baru

Pemeriksaan kesiapan hanya menguji keberadaan biner `wazuh-logtest`, padahal biner
itu ada jauh sebelum `wazuh-analysisd` membuka socket `rule_test`. Pada container
yang benar-benar baru, uji gagal dengan *"error when connecting with
wazuh-analysisd"*. Diganti dengan polling yang benar-benar mengirim log percobaan
sampai `Completed pre-decoding` muncul.

### Yang terbukti BENAR pada audit

| Yang diuji | Hasil |
|---|---|
| 15 kasus trafik sah seluruh modul (termasuk `O'Brien`, `a < b`, harga `-5`, hostname sah, tautan serialisasi UI XVWA, `readme.txt`, `action=view`, akses idor tunggal) | **0 false positive**, semuanya level 0 |
| Allowlist domain sah modul redirect (100902) | berfungsi, menurunkan 100218 ke level 0 |
| Suppression health check VM Monitoring (100901) | berfungsi |
| Suppression reset lab (100903) | berfungsi, DDL turun ke level 3 |
| Baseline `ping`/`sh` modul cmdi tidak memicu 100403 | terbukti, level 0 |
| YARA: 5 contoh berbahaya cocok, 4 contoh sah tidak cocok | **9/9**, 0 false positive |
| Tidak ada rule dengan kondisi identik (saling membayangi) | terbukti, 48 rule diperiksa |
| Konsistensi ID antara ruleset dan `docs/rule-reference.md` | 48/48 cocok, tidak ada selisih |
| Double-encoding LFI, null byte, `....//`, polyglot upload | semuanya terdeteksi |

### Yang TIDAK dapat diverifikasi pada audit ini

Rule berbasis FIM (**100407**, **100431**) dan rule frekuensi/korelasi
(**100302**, **100308**, **100311**, **100332**, **100314**, **100319**,
**100501**, **100503**, **100507**) tidak dapat diuji lewat `wazuh-logtest`
karena alasan pada Bagian 2 (U1–U3). Yang terverifikasi adalah sintaksnya valid
dan ruleset dimuat tanpa error. **Verifikasi fungsionalnya wajib dilakukan di
lingkungan nyata** memakai prosedur pada Bagian 2 sebelum fase D dimulai.


### T-7 (SEDANG, diperbaiki) - pemantauan `connect` auditd membanjiri alert

**Gejala (lapangan, 31 Okt 2026, setup Docker multi-container).** Rule 100411
("Web process initiated an outbound connection") menyala berulang CRITICAL pada
aktivitas normal.

**Sebab.** Aturan auditd `-S connect -F euid=33` menangkap SETIAP koneksi oleh
user web, termasuk koneksi web->MariaDB yang terjadi pada setiap hit halaman.
Pada XVWA dengan container web + DB terpisah, ini berarti banjir alert untuk
aktivitas yang sepenuhnya sah. auditd tidak dapat memfilter berdasarkan alamat
tujuan di level aturan. (Risiko R1 pada Bagian 5 memang sudah memprediksi ini.)

**Perbaikan.** Pemantauan `connect` dinonaktifkan di `agent/auditd/asiw-xvwa.rules`
(dua baris `-S connect` dikomentari). Konfirmasi T3 berbasis host untuk SSRF/RFI
(rule 100411) menjadi tidak aktif; SSRF/RFI tetap terdeteksi lewat T1 (100211/
100212) dan T2 (100311/100313). Pemantauan `execve` (bukti T3 command injection,
rule 100403) TIDAK terpengaruh dan terbukti bekerja dengan baik di container.

**Cara mengaktifkan kembali** (mis. XVWA native dengan DB lokal yang di-allowlist):
buka komentar dua baris `connect` lalu saring koneksi ke IP DB di layer
normalisasi n8n/backend.
