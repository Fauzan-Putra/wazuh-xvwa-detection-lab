# Menulis Custom Detection Rules Wazuh untuk Web Attack — SOC Home Lab dengan XVWA

Tutorial dan paket siap-pakai untuk membangun **deteksi serangan web berbasis
bukti** di SOC home lab-mu, memakai Wazuh sebagai SIEM dan
[XVWA](https://github.com/s4n7h0/xvwa) sebagai aplikasi target yang sengaja rentan.

Fokus repo ini adalah bagian yang paling jarang diajarkan secara tuntas:
**bagaimana menulis custom rule Wazuh yang benar-benar bekerja** — bukan sekadar
menyalin pola regex, tetapi memahami kapan sebuah alert layak disebut "serangan
berhasil", bagaimana menghindari banjir false positive, dan bagaimana
membuktikan rule-mu benar sebelum dipasang.

Bukan tutorial instalasi Wazuh dari nol (dokumentasi resmi sudah bagus untuk
itu). Ini tutorial **tahap setelah Wazuh berjalan**: membuatnya mendeteksi
sesuatu yang berguna.

| | |
|---|---|
| Diuji pada | Wazuh 4.14.8 |
| Aplikasi target | XVWA (`s4n7h0/xvwa`) |
| Jumlah rule | 48 custom rule + decoder |
| Status uji | 100/100 kasus `wazuh-logtest` lulus (58 positif, 42 negatif) + 9/9 kasus YARA |
| Lisensi | MIT |

> **Lab-only.** XVWA memuat kerentanan nyata (eksekusi perintah, upload webshell).
> Jalankan hanya di lingkungan terisolasi. Baca [`SECURITY.md`](SECURITY.md).

---

## Daftar isi

1. [Apa yang akan kamu pelajari](#1-apa-yang-akan-kamu-pelajari)
2. [Arsitektur lab](#2-arsitektur-lab)
3. [Konsep inti: tiga tingkat bukti](#3-konsep-inti-tiga-tingkat-bukti)
4. [Lima pelajaran dari menulis rule ini](#4-lima-pelajaran-dari-menulis-rule-ini)
5. [Jalur cepat: pasang dan coba](#5-jalur-cepat-pasang-dan-coba)
6. [Memahami struktur repo](#6-memahami-struktur-repo)
7. [Menguji rule sebelum dipasang](#7-menguji-rule-sebelum-dipasang)
8. [Latihan: tambah rule-mu sendiri](#8-latihan-tambah-rulemu-sendiri)
9. [Batasan yang harus kamu ketahui](#9-batasan-yang-harus-kamu-ketahui)

---

## 1. Apa yang akan kamu pelajari

Kebanyakan tutorial deteksi berhenti pada "tulis regex yang cocok dengan payload
serangan". Masalahnya, itu menghasilkan SOC yang membanjiri analis dengan alarm
dan tidak bisa membedakan percobaan dari keberhasilan. Repo ini mengajarkan
pendekatan yang lebih matang:

- **Memisahkan percobaan dari keberhasilan.** `' OR 1=1` di URL belum tentu SQLi
  berhasil. Kamu akan belajar membedakannya dengan *evidence tier*.
- **Mengikat deteksi ke konteks, bukan pola global.** Kata `union select` wajar
  muncul di kotak pencarian. Kamu akan belajar mengikat rule ke modul tertentu
  agar nama sah seperti "O'Brien" tidak memicu alarm.
- **Menguji rule secara otomatis** dengan `wazuh-logtest`, lengkap dengan korpus
  positif (serangan) dan negatif (trafik sah).
- **Mengakui batas deteksi** secara jujur, alih-alih mengklaim cakupan 100%.

Setiap keputusan desain pada rule di repo ini ada alasannya, dan alasan itu
ditulis di komentar rule dan di `docs/`. Bacalah — itu bagian paling berharga.

---

## 2. Arsitektur lab

Lab minimum butuh tiga peran. Kamu bisa menjalankan semuanya sebagai VM terpisah,
atau menggabung attacker dan analis di satu mesin.

```
  ┌──────────────┐        serangan HTTP        ┌─────────────────────┐
  │  Attacker    │ ──────────────────────────> │  Target VM          │
  │  (Kali/curl) │                             │  Apache + PHP + XVWA │
  └──────────────┘                             │  + Wazuh Agent      │
                                               │  + auditd + YARA    │
                                               └──────────┬──────────┘
                                                          │ event mentah (1514/tcp)
                                                          ▼
                                               ┌─────────────────────┐
                                               │  Wazuh Manager      │
                                               │                     │
                                               │  >> CUSTOM RULE     │
                                               │     ADA DI SINI <<  │
                                               │  + Dashboard        │
                                               └─────────────────────┘
```

**Poin paling penting untuk pemula:** custom rule **tidak** dipasang di agent.
Agent hanya mengumpulkan log dan mengirim event mentah; seluruh pencocokan rule
terjadi di `wazuh-analysisd` pada Manager. Jadi kalau kamu punya 1 target atau
10 target, rule tetap dipasang **sekali** di Manager.

Yang dikerjakan di sisi target hanyalah membuat agent **menghasilkan** telemetri
yang dibutuhkan rule: log akses web, log error, event auditd, dan hasil YARA.

| Peran | Perangkat lunak | Catatan |
|---|---|---|
| Target | Ubuntu + Apache + PHP + MariaDB + XVWA + Wazuh Agent | yang diserang |
| Manager | Wazuh Manager + Indexer + Dashboard | otak deteksi |
| Attacker | apa saja yang bisa `curl`/`sqlmap`/browser | sumber serangan uji |

---

## 3. Konsep inti: tiga tingkat bukti

Ini fondasi seluruh repo. Alih-alih setiap deteksi berbobot sama, setiap alert
membawa **tingkat bukti** yang menyatakan seberapa yakin kita bahwa serangan
benar-benar terjadi.

| Tier | Nama | Arti | Contoh | Level Wazuh | Notifikasi |
|---|---|---|---|---|---|
| **T1** | Attempt | Pola serangan ada di request. Berhasil atau tidak, belum tahu. | `' OR 1=1--` di parameter | 4–7 (MEDIUM) | tidak |
| **T2** | Probable | T1 + indikator independen. | T1 + pesan error SQL di log | 8–10 (HIGH) | ya |
| **T3** | Confirmed | Bukti dari sisi host efek serangan terjadi. | `id` dieksekusi oleh `www-data`; webshell `.php` muncul di folder upload | ≥ 11 (CRITICAL) | ya + eskalasi |

Mengapa ini penting? Dua alasan praktis:

1. **T1 tidak pernah membangunkan analis tengah malam.** Scanner otomatis
   menghasilkan ribuan T1 per hari. Kalau semuanya CRITICAL, SOC-mu lumpuh.
2. **T3 hampir pasti nyata.** Kalau `www-data` tiba-tiba menjalankan `nc`, itu
   bukan "mungkin serangan" — itu serangan yang sudah berhasil.

### Jebakan klasik: HTTP 200 bukan tanda keberhasilan

Rule bawaan Wazuh menaikkan severity bila serangan membalas HTTP 200. Di XVWA
ini **menyesatkan**: aplikasi membalas 200 untuk input normal maupun payload
yang gagal. Kalau kamu percaya kode status, setiap percobaan akan terlihat
"berhasil". Rule T2 di repo ini memakai bukti lain (error log, bukti DB,
frekuensi) — tidak pernah kode status. Ini kesalahan paling umum pada deteksi
web, dan repo ini sengaja menghindarinya.

Cakupan deteksi per modul XVWA:

| Modul XVWA | Kelas kerentanan | T1 | T2 | T3 |
|---|---|---|---|---|
| sqli | SQL Injection (error-based) | ✓ | ✓ | ✓ |
| sqli_blind | SQL Injection (blind) | ✓ | ✓ | — |
| cmdi | OS Command Injection | ✓ | — | ✓✓ |
| xpath | XPath Injection | ✓ | — | — |
| formula_injection | CSV Formula Injection | ✓ | — | — |
| php_object_injection | PHP Object Injection | ✓ | ✓ | — |
| fileupload | Unrestricted File Upload | ✓ | — | ✓✓✓ |
| reflected_xss | XSS Reflected | ✓ | ✓ | — |
| stored_xss | XSS Stored | ✓ | — | ✓ |
| dom_xss | XSS DOM | ✓ | — | — |
| ssrf_xspa | SSRF / XSPA | ✓ | ✓ | ✓✓ |
| fi | File Inclusion (LFI/RFI) | ✓ | ✓✓ | ✓ |
| idor | IDOR | — | ✓ | — |
| missfunc | Missing Function-Level AC | ✓ | — | ✓ |
| csrf | CSRF | ✓ | — | ✓ |
| redirect | Unvalidated Redirect | ✓ | — | — |
| ssti | Server-Side Template Injection | ✓ | ✓ | — |
| sessionflaws | Session Flaws | SCA | — | — |
| crypto | Cryptography | SCA | — | — |

Dua modul (`sessionflaws`, `crypto`) berkelas statis — tidak ada "peristiwa
serangan" yang bisa dilihat agent, jadi diukur lewat SCA (lihat Pelajaran 5).
Sel kosong lain punya alasan struktural; semua dijelaskan di
[`docs/limitations-and-gaps.md`](docs/limitations-and-gaps.md).

Tabel lengkap `rule.id → tier → kategori`: [`docs/rule-reference.md`](docs/rule-reference.md).

---

## 4. Lima pelajaran dari menulis rule ini

Bagian ini adalah inti edukatif repo. Masing-masing adalah kesalahan nyata yang
ditemukan saat mengembangkan (dan menguji) rule ini.

### Pelajaran 1 — `\b` gagal setelah persen-encoding

Pola `\bunion\b` terlihat benar, tetapi **tidak cocok** pada
`?item=1%20union%20select`. Sebabnya: karakter sebelum `u` adalah `0` (dari
`%20`), dan digit adalah *word character*, jadi tidak ada word boundary di situ.

Ini false negative **senyap**: rule termuat tanpa error, uji dengan payload
mentah lulus, tapi bentuk URL-encoded — yang paling umum dipakai serangan nyata
— lolos tanpa terdeteksi.

Solusi yang dipakai di repo ini: batas kiri eksplisit `(?:\b|%[0-9a-f]{2})`.

### Pelajaran 2 — serangan dikirim mentah maupun ter-encode

Apache mencatat URI **apa adanya**. `curl`, `sqlmap`, dan Burp sering mengirim
karakter mentah (`<script>`, `{{7*7}}`, `'`), bukan bentuk `%3C`. Pola yang hanya
menerima satu bentuk mudah dilewati. Setiap pola di repo ini menerima kedua
bentuk, mis. `(%27|%2527|'|%22|")` untuk kutip.

### Pelajaran 3 — ikat rule ke modul, bukan pola global

Kata `union`, tanda `'`, dan `<` muncul di trafik sah. Nama "O'Brien", pencarian
"a < b", semua wajar. Kalau rule mencari pola itu di mana saja, SOC-mu tenggelam
dalam false positive.

Solusinya: setiap rule T1 diikat ke **path modul** yang relevan, mis.
`^/xvwa/vulnerabilities/sqli/`. Payload SQLi di kotak pencarian modul sqli itu
mencurigakan; tanda `'` di modul lain yang memang menerima teks bebas, tidak.
Repo ini menguji 15 kasus trafik sah dan nol memicu alarm.

### Pelajaran 4 — urutan evaluasi rule mengikuti urutan file, bukan level

Wazuh memuat `ruleset/rules` (bawaan) sebelum `etc/rules` (kustom). Kalau rule
kustommu hanya "bersaudara" dengan rule bawaan yang cocok lebih dulu, rule
bawaan menang dan rule-mu tak pernah jalan. Untuk rule error log, custom rule
di repo ini sengaja menjadi **anak** dari rule bawaan yang cocok (`<if_sid>`),
bukan saudaranya.

### Pelajaran 5 — kerentanan statis bukan peristiwa

Beberapa kelemahan (hash MD5 lemah, cookie tanpa HttpOnly) tidak menghasilkan
"peristiwa serangan" yang bisa dilihat di log. Mencoba membuat alert untuknya
hanya menghasilkan derau. Yang benar: ukur sebagai **kondisi konfigurasi** lewat
SCA (Security Configuration Assessment), simpan sebagai registri kerentanan, dan
pakai untuk memperkaya konteks — bukan sebagai alarm.

---

## 5. Jalur cepat: pasang dan coba

Prasyarat: Wazuh Manager sudah berjalan, dan minimal satu target VM dengan Apache
+ PHP + MariaDB + XVWA + Wazuh Agent sudah terhubung ke Manager.

```bash
git clone https://github.com/<user>/wazuh-xvwa-detection.git
cd wazuh-xvwa-detection

# (opsional) isi nilai spesifik lab-mu; tanpa ini dipakai nilai contoh
cp asiw.env.example asiw.env
nano asiw.env        # minimal: ASIW_MONITOR_IP = IP Wazuh Manager-mu
```

**Di Wazuh Manager (sekali):**

```bash
sudo ./manager/asiw-install-manager.sh
```

Skrip ini memasang decoder + rule, **memvalidasinya dengan `wazuh-logtest`
sebelum me-restart** (krusial — analysisd menolak start bila ada rule salah,
dan itu menghentikan SELURUH deteksi, bukan cuma rule ini), membuat agent group,
memasang konfigurasi telemetri terpusat, lalu me-restart dan memverifikasi.

**Di setiap target VM:**

```bash
sudo ./agent/asiw-install-target.sh --check   # periksa asumsi, tanpa mengubah
sudo ./agent/asiw-install-target.sh           # pasang
```

Skrip target memasang yang tidak bisa dipusatkan (konfigurasi Apache, auditd,
YARA, ModSecurity, audit DB) dan **memverifikasi tiga asumsi** yang dipakai keras
di rule: lokasi XVWA, UID `www-data`, dan path `ping`. Kalau tidak cocok, rule
gagal senyap — jadi skrip menolak lanjut.

**Coba serang (dari attacker, bukan dari target, agar `srcip` benar):**

```bash
TARGET=<ip-target>
curl -s "http://$TARGET/xvwa/vulnerabilities/reflected_xss/?item=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null
curl -s "http://$TARGET/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
```

**Lihat hasilnya di Manager:**

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E '"id":"1002|"id":"1004'
```

Harus muncul rule `100208` (XSS T1) dan, jika command injection berhasil,
`100203` (T1), `100403` (T3), dan `100503` (korelasi).

Panduan lengkap untuk banyak target sekaligus:
[`docs/deployment-3-targets.md`](docs/deployment-3-targets.md).

---

## 6. Memahami struktur repo

```
wazuh-xvwa-detection/
├── decoders/asiw_xvwa_decoders.xml   # [MANAGER] decoder untuk log JSON, DB, YARA
├── rules/asiw_xvwa_rules.xml         # [MANAGER] 48 custom rule — baca komentarnya!
├── manager/
│   ├── asiw-install-manager.sh       # pemasang sisi Manager
│   └── agent.conf-asiw-xvwa          # konfigurasi telemetri terpusat
├── agent/                            # [TARGET] yang membuat agent menghasilkan telemetri
│   ├── asiw-install-target.sh        # pemasang + verifikasi asumsi
│   ├── apache/                       # S2: access log JSON
│   ├── auditd/                       # S6: execve/connect user web (bukti T3)
│   ├── yara/                         # S8: deteksi webshell + active response
│   ├── modsecurity/                  # S4: inspeksi body POST
│   ├── mariadb/                      # S5: audit query (bukti terkuat SQLi)
│   └── sca/                          # S9: registri kerentanan statis
├── tests/
│   ├── run_tests.sh                  # harness wazuh-logtest (otomatis)
│   ├── run_yara_tests.sh             # harness YARA
│   ├── corpus_positive.tsv           # 58 serangan yang HARUS terdeteksi
│   └── corpus_negative.tsv           # 42 trafik sah yang TIDAK boleh beralarm
├── docker/                           # bila XVWA dijalankan via Docker
│   ├── README-docker.md              #   -> panduan khusus Docker
│   ├── asiw-setup-target-docker.sh   #   -> wiring host + container
│   ├── docker-compose.override.yml   #   -> keluarkan log container ke host
│   └── agent.conf-asiw-xvwa-docker   #   -> agent.conf path host
└── docs/
    ├── rule-reference.md             # tabel rule.id -> tier -> kategori
    ├── xvwa-module-inventory.md      # parameter & metode tiap modul (dari source)
    ├── deployment-3-targets.md       # deploy ke banyak target
    └── limitations-and-gaps.md       # batasan jujur + catatan audit
```

Urutan membaca yang disarankan untuk belajar:

1. Bagian 3 dan 4 README ini (konsep).
2. `rules/asiw_xvwa_rules.xml` — baca dari atas; tiap rule punya komentar alasan.
3. `tests/corpus_positive.tsv` dan `corpus_negative.tsv` — lihat apa yang harus
   dan tidak boleh terdeteksi.
4. `docs/limitations-and-gaps.md` Bagian 6 — catatan audit, tempat belajar dari
   kesalahan nyata.

---

## 7. Menguji rule sebelum dipasang

Ini kebiasaan yang membedakan rule amatir dari rule produksi: **jangan pernah
pasang rule tanpa menguji keduanya** — bahwa ia menangkap serangan, dan bahwa
ia tidak menangkap trafik sah.

Repo ini menyertakan harness otomatis yang menjalankan `wazuh-logtest` di dalam
container Wazuh (tidak perlu memasang Wazuh di laptopmu):

```bash
./tests/run_tests.sh        # 58 kasus serangan + 42 kasus trafik sah
./tests/run_yara_tests.sh   # 9 kasus webshell vs berkas sah
```

Keluaran yang diharapkan:

```
Positif : 58 lulus, 0 gagal
Negatif : 42 lulus, 0 gagal
SEMUA UJI LULUS
```

Cara kerja harness: ia membuat container `wazuh/wazuh-manager:4.14.8`, menyalin
decoder + rule-mu, lalu mengalirkan tiap baris korpus melalui `wazuh-logtest` dan
membandingkan rule yang menyala dengan yang diharapkan. Format korpus sederhana:

```
<expected_rule_id><TAB><baris log>     # corpus_positive.tsv
<max_level_diizinkan><TAB><baris log>  # corpus_negative.tsv
```

Kalau kamu menambah rule, tambahkan kasusnya ke korpus dan jalankan harness.
Itu satu-satunya cara tahu rule barumu tidak merusak yang lama.

---

## 8. Latihan: tambah rule-mu sendiri

Cara terbaik belajar adalah menambah satu rule. Misalnya kamu ingin mendeteksi
upaya membaca `/etc/shadow` lewat modul file inclusion dengan severity khusus.

1. **Pahami parameternya.** `docs/xvwa-module-inventory.md` memberitahu modul
   `fi` memakai parameter GET `file`.
2. **Tulis rule**, anak dari rule konteks XVWA, terikat ke path modul:

   ```xml
   <rule id="100512" level="10">
     <if_sid>100101</if_sid>
     <field name="uri" type="pcre2">(?i)^/xvwa/vulnerabilities/fi/.*file(%3D|=).*(%2F|/)etc(%2F|/)shadow</field>
     <description>Percobaan membaca /etc/shadow via file inclusion</description>
     <mitre><id>T1083</id></mitre>
   </rule>
   ```

   (Perhatikan: menerima `/` mentah maupun `%2F` — ingat Pelajaran 2.)
3. **Tambahkan kasus uji** ke `tests/corpus_positive.tsv`:

   ```
   100512	Oct 31 12:00:00 t asiw-xvwa-web: {"remote_ip":"198.51.100.99","method":"GET","uri":"/xvwa/vulnerabilities/fi/?file=../../../../etc/shadow","status":"200"}
   ```

4. **Tambahkan kasus negatif** agar yakin tidak over-match, mis. `file=readme.txt`
   harus tetap level 0.
5. **Jalankan** `./tests/run_tests.sh`. Hijau? Rule-mu siap.

ID rule kustom harus ≥ 100000. Skema penomoran yang dipakai repo ini dijelaskan
di `docs/rule-reference.md`.

---

## 9. Batasan yang harus kamu ketahui

Deteksi yang jujur menyatakan apa yang **tidak** bisa dilihatnya. Beberapa contoh
dari repo ini:

- **Body POST tidak ada di access log Apache.** Modul yang memakai POST (sqli,
  stored_xss, dll) tidak terdeteksi di tier T1 tanpa ModSecurity (S4) atau NIDS
  seperti Suricata. Repo ini memasang ModSecurity `DetectionOnly` untuk menutupnya.
- **DOM XSS varian fragment (`#...`)** tidak pernah dikirim ke server — mustahil
  dideteksi dari sisi server.
- **Rule berbasis FIM dan korelasi** tidak bisa diuji dengan `wazuh-logtest`
  (event FIM dibangun dari database agent, bukan baris teks). Harus diuji di VM
  nyata; prosedurnya di `docs/limitations-and-gaps.md` Bagian 2.

Daftar lengkap, plus catatan audit tempat 6 cacat ditemukan dan diperbaiki, ada
di [`docs/limitations-and-gaps.md`](docs/limitations-and-gaps.md). Itu bacaan
wajib sebelum kamu mengandalkan rule ini untuk hal serius.

---

## Kredit dan rujukan

- [Wazuh documentation](https://documentation.wazuh.com) — ruleset syntax, custom
  rules/decoders, FIM, Active Response, SCA.
- [XVWA oleh s4n7h0](https://github.com/s4n7h0/xvwa) — aplikasi target.
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [MITRE ATT&CK](https://attack.mitre.org)

Repo ini lahir dari proyek SOC home lab multi-hypervisor. Skema penamaan internal
(`asiw`, `XV-01`..`XV-19`) dipertahankan karena konsisten dengan dokumentasi
rule, tetapi tutorialnya berlaku umum untuk SOC home lab mana pun yang memakai
Wazuh + XVWA.

Kontribusi dan laporan evasion/false-positive dipersilakan lewat issue.
