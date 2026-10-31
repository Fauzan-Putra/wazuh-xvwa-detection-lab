# Konfigurasi Sisi Agent (VM Target XVWA)

Semua langkah di sini dijalankan pada **VM Target**: `target1-user` (192.0.2.124),
`target2-user` (192.0.2.143), `target3-user` (192.0.2.162).

Prasyarat: Wazuh Agent 4.14.8 sudah terpasang dan berstatus Active (sudah selesai per
dokumen konsep 9 Oktober 2026), serta XVWA sudah ter-deploy di `/var/www/html/xvwa`.

## Peta berkas

| Berkas | Sumber telemetri | Mengisi tier | Status |
|---|---|---|---|
| `apache/asiw-xvwa-json-log.conf` | S2 access log JSON | T1 (semua modul GET) | **Wajib** |
| `ossec.conf-target.xml` | S1,S2,S3,S6,S7 | semua | **Wajib** |
| `auditd/asiw-xvwa.rules` | S6 auditd | T3 (XV-03, XV-11, XV-12) | **Wajib untuk T3** |
| `yara/asiw-yara.sh` + `yara/asiw-webshell.yar` | S8 YARA via AR | T3 (XV-07) | Disarankan |
| `sca/asiw_xvwa_baseline.yml` | S9 SCA | registri kerentanan statis | Disarankan |
| `modsecurity/asiw-modsecurity.conf` | S4 ModSecurity | T1 untuk modul POST | Opsional (menutup FN1) |
| `mariadb/asiw-server-audit.cnf` | S5 audit DB | T3 (XV-01, XV-09, XV-15, XV-16) | Opsional (bukti terkuat SQLi) |

## Urutan pemasangan

Kerjakan berurutan; tiap langkah punya verifikasi sendiri.

### Langkah 0 — verifikasi asumsi

Dua nilai dipakai keras di dalam rule dan harus dicek dulu:

```bash
# 1. Document root Apache (rule memakai /var/www/html/xvwa)
grep -rh DocumentRoot /etc/apache2/sites-enabled/

# 2. UID user web (aturan auditd memakai euid=33)
id -u www-data

# 3. Path biner ping (allowlist baseline modul cmdi pada rule 100403)
command -v ping
```

Jika hasilnya berbeda dari asumsi, sesuaikan:
- path pada `ossec.conf-target.xml`, `auditd/asiw-xvwa.rules`, dan `sca/asiw_xvwa_baseline.yml`;
- `euid=33` pada `auditd/asiw-xvwa.rules`;
- allowlist `ping` pada rule `100403` di `../rules/asiw_xvwa_rules.xml`.

Catat hasil ketiga perintah ini per VM sebagai bukti reproducibility.

### Langkah 1 — access log JSON (S2)

```bash
sudo cp apache/asiw-xvwa-json-log.conf /etc/apache2/conf-available/
sudo a2enconf asiw-xvwa-json-log
sudo apache2ctl configtest && sudo systemctl reload apache2

# Pastikan log_errors aktif (prasyarat tier T2)
php -r 'echo "log_errors=", ini_get("log_errors"), "\n";'
```

Verifikasi:

```bash
curl -s "http://localhost/xvwa/" > /dev/null
sudo tail -1 /var/log/apache2/xvwa_access_json.log
```

Harus muncul satu baris JSON dengan field `remote_ip`, `method`, `uri`, `status`,
`resp_bytes`, `duration_us`.

### Langkah 2 — auditd (S6)

```bash
sudo apt install -y auditd audispd-plugins
sudo cp auditd/asiw-xvwa.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | grep asiw_web
```

Verifikasi bahwa perilaku baseline modul cmdi memang tercatat:

```bash
curl -s "http://localhost/xvwa/vulnerabilities/cmdi/?target=127.0.0.1" > /dev/null
sudo ausearch -k asiw_web_exec -i | tail -20
```

Harus terlihat `exe=/usr/bin/ping` (atau `/bin/ping`). Inilah baseline yang
di-allowlist rule 100403, sehingga aktivitas sah modul tidak memicu alert.

### Langkah 3 — konfigurasi agent

Gabungkan blok dari `ossec.conf-target.xml` ke `/var/ossec/etc/ossec.conf`
(di dalam `<ossec_config>`). Jangan menduplikasi `<labels>` bila sudah ada.

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%F)
sudo nano /var/ossec/etc/ossec.conf     # tempel blok yang diperlukan
sudo systemctl restart wazuh-agent
sudo tail -30 /var/ossec/logs/ossec.log
```

Verifikasi agent membaca semua sumber log:

```bash
sudo /var/ossec/bin/wazuh-control info
sudo grep -E "Analyzing file|Monitoring" /var/ossec/logs/ossec.log | tail -15
```

Harus muncul `xvwa_access_json.log`, `error.log`, `access.log`, dan `audit.log`.

### Langkah 4 — YARA via Active Response (S8)

```bash
sudo apt install -y yara
sudo mkdir -p /var/ossec/etc/yara/rules
sudo install -o root -g wazuh -m 640 yara/asiw-webshell.yar /var/ossec/etc/yara/rules/
sudo install -o root -g wazuh -m 750 yara/asiw-yara.sh /var/ossec/active-response/bin/
sudo touch /var/log/asiw-yara.log && sudo chmod 640 /var/log/asiw-yara.log
```

Aktifkan blok `<command>` dan `<active-response>` pada `ossec.conf`, tambahkan
localfile untuk hasilnya:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/asiw-yara.log</location>
  <out_format>$(timestamp) $(hostname) asiw-yara: $(log)</out_format>
</localfile>
```

Verifikasi aturan YARA sebelum dipakai:

```bash
yara -w /var/ossec/etc/yara/rules/asiw-webshell.yar /dev/null && echo "sintaks OK"
```

### Langkah 5 — SCA kustom (S9)

```bash
sudo install -o root -g wazuh -m 640 sca/asiw_xvwa_baseline.yml /var/ossec/etc/shared/
# aktifkan blok <sca> pada ossec.conf
sudo systemctl restart wazuh-agent
```

Hasil tampil di Wazuh Dashboard: **Agents → <target> → Security Configuration Assessment**.
Gunakan hasilnya untuk mengisi tabel `asset_vulnerabilities` (lihat dokumen mapping 7.3).

### Langkah 6 (opsional) — ModSecurity (S4)

Diperlukan agar modul yang memakai POST (sqli, sqli_blind, xpath, stored_xss,
ssrf_xspa, fileupload) dapat mencapai tier T1. Tanpa ini, serangan pada modul
tersebut hanya terdeteksi bila mencapai tier T3.

```bash
sudo apt install -y libapache2-mod-security2
sudo a2enmod security2 headers
sudo cp modsecurity/asiw-modsecurity.conf /etc/modsecurity/
echo 'IncludeOptional /etc/modsecurity/asiw-modsecurity.conf' | \
  sudo tee -a /etc/apache2/mods-enabled/security2.conf
sudo apache2ctl configtest && sudo systemctl reload apache2

# WAJIB: pastikan mode DetectionOnly, bukan On
sudo grep -r SecRuleEngine /etc/modsecurity/ /etc/apache2/
```

> **Penting.** Mode harus `DetectionOnly`. PRD ASIW Bagian 3.2 menetapkan sistem ini
> bukan IPS inline. Jika ModSecurity memblokir request, skenario serangan E4–E8
> tidak dapat direproduksi dan data eksperimen menjadi tidak valid.

### Langkah 7 (opsional) — audit MariaDB (S5)

Sumber bukti terkuat untuk SQLi dan satu-satunya konfirmasi stored XSS.

```bash
sudo mysql -e "INSTALL SONAME 'server_audit';"
sudo cp mariadb/asiw-server-audit.cnf /etc/mysql/mariadb.conf.d/99-asiw-audit.cnf
sudo systemctl restart mariadb
sudo mysql -e "SHOW VARIABLES LIKE 'server_audit%';"
sudo chmod 644 /var/log/mysql/server_audit.log
```

Aktifkan localfile `asiw-dbaudit` pada `ossec.conf`, lalu verifikasi:

```bash
curl -s "http://localhost/xvwa/vulnerabilities/idor/?item=3" > /dev/null
sudo tail -3 /var/log/mysql/server_audit.log
```

## Uji ujung-ke-ujung setelah semua terpasang

Jalankan dari host penyerang lab (bukan dari VM Target, agar `srcip` benar):

```bash
TARGET=192.0.2.124

# T1: XSS reflected (GET, terlihat di access log)
curl -s "http://$TARGET/xvwa/vulnerabilities/reflected_xss/?item=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null

# T1: command injection (GET)
curl -s "http://$TARGET/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null

# T1: LFI
curl -s "http://$TARGET/xvwa/vulnerabilities/fi/?file=../../../../etc/passwd" >/dev/null
```

Lalu di VM Monitoring:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | \
  grep -E '"id":"1002|"id":"1003|"id":"1004'
```

Harus muncul rule 100208, 100203, dan 100212. Jika command injection berhasil,
rule 100403 (T3) dan korelasi 100503 juga akan muncul.
