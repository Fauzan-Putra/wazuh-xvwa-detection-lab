# Deployment untuk XVWA yang Berjalan via Docker

Panduan ini untuk kasus XVWA dijalankan sebagai container Docker, bukan native
di host. Berlaku bila struktur lab-mu seperti berikut (contoh nyata):

```
/root/xvwa-lab/
├── docker-compose.yml      # service: web (php:apache), db (mariadb:10.6)
├── Dockerfile              # build image web
└── xvwa/                   # source XVWA, bind-mounted ke container
```

dengan compose:

```yaml
services:
  web:
    build: .
    container_name: xvwa-web
    ports: ["80:80"]
    volumes: ["./xvwa:/var/www/html/xvwa"]
  db:
    image: mariadb:10.6
    container_name: xvwa-db
    environment:
      MYSQL_ROOT_PASSWORD: <password-anda>
      MYSQL_DATABASE: xvwa
    volumes: ["dbdata:/var/lib/mysql"]
```

## Kenapa perlu perlakuan khusus

Wazuh Agent berjalan di **host**, sementara Apache/PHP/MariaDB di **dalam
container**. Agent host tidak melihat ke dalam container secara default. Jadi
telemetri harus "dikeluarkan" ke path host yang dibaca agent.

Kabar baiknya: compose-mu sudah mem-bind `./xvwa` ke host, sehingga **file XVWA
(termasuk folder upload) sudah ada di host** di `/root/xvwa-lab/xvwa`. Itu
membuat FIM dan SCA langsung bisa bekerja. Yang perlu ditambahkan hanya
mengeluarkan **log Apache** dan **log audit MariaDB** dari container.

| Telemetri | Status pada setup Docker | Cara |
|---|---|---|
| S7 FIM upload (T3 webshell) | sudah di host via bind mount | langsung jalan |
| S9 SCA (registri statis) | sudah di host | langsung jalan |
| S2/S3 log web (T1 17 modul) | di dalam container | mount `/var/log/apache2` keluar + suntik conf JSON |
| S5 audit DB (T3 SQLi) | di dalam container | aktifkan server_audit + mount log keluar |
| S6 auditd (T3 cmdi) | kernel host | aturan auditd host, **perlu verifikasi** |
| S4 ModSecurity (T1 POST) | tidak ada di base image | rebuild image (opsional, lihat bawah) |

**Rule di Manager tidak berubah.** Rule FIM memakai substring `/xvwa/img/uploads/`
yang tetap cocok pada path host `/root/xvwa-lab/xvwa/img/uploads/...`.

## Langkah

Asumsi: compose di `/root/xvwa-lab/`. Bila berbeda, set `ASIW_LAB_DIR`.

### 1. Di tiap VM Target — host + wiring container

```bash
sudo git clone https://github.com/<user>/wazuh-xvwa-detection-lab.git /opt/asiw
cd /opt/asiw
sudo ./docker/asiw-setup-target-docker.sh --check   # verifikasi, tanpa ubah
sudo ./docker/asiw-setup-target-docker.sh           # pasang
```

Skrip ini: memasang auditd+yara di host, memasang aturan auditd & YARA dengan
path host, menyalin override + konfigurasi ke `/root/xvwa-lab/`, lalu
`docker compose up -d` untuk membuat ulang container dengan mount log. XVWA
down sesaat saat container dibuat ulang (wajar di lab).

### 2. Di Manager — pasang rule + dorong agent.conf varian Docker

```bash
sudo git clone https://github.com/<user>/wazuh-xvwa-detection-lab.git /opt/asiw
cd /opt/asiw
cp asiw.env.example asiw.env
# isi ASIW_MONITOR_IP (IP Manager) dan ASIW_AGENT_IDS (mis. "001 002")
nano asiw.env

ASIW_DEPLOYMENT=docker sudo -E ./manager/asiw-install-manager.sh
```

`ASIW_DEPLOYMENT=docker` membuat installer mendorong `agent.conf` varian Docker
(path host `/root/xvwa-lab/...`) dan policy SCA varian Docker.

### 3. Verifikasi end-to-end

Dari attacker:

```bash
TARGET=<ip-target>
curl -s "http://$TARGET/xvwa/vulnerabilities/sqli/?item=1%20union%20select%201,2,3" >/dev/null
curl -s "http://$TARGET/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
```

Di target:

```bash
tail -5 /root/xvwa-lab/logs/apache/xvwa_access_json.log
sudo ausearch -k asiw_web_exec -i 2>/dev/null | tail -20
```

Di Manager:

```bash
sudo grep -E '"id":"(100201|100203|100403)"' /var/ossec/logs/alerts/alerts.json | tail
```

## Verifikasi WAJIB: auditd terhadap proses container

Deteksi command injection (T3, rule 100403) bergantung pada apakah auditd host
menangkap `execve` dari dalam container. Ini **harus diuji empiris**, tidak boleh
diasumsikan:

```bash
# dari attacker
curl -s "http://<target>/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
# di target
sudo ausearch -k asiw_web_exec -i 2>/dev/null | tail -30
```

- **Muncul event dengan `comm=id`** → rule 100403 bekerja. Bagus. Rule memakai
  `comm` (basename), jadi robust terhadap path overlay Docker.
- **Tidak muncul event sama sekali** → kemungkinan user-namespace remap aktif
  (uid 33 container tidak = uid 33 host) atau auditd tidak menangkap namespace
  container. Laporkan; rule perlu disesuaikan (mis. filter berdasarkan key saja
  tanpa euid, lalu saring di layer normalisasi).

## ModSecurity (opsional, S4)

Base image `php:apache` tidak memuat ModSecurity, jadi modul yang memakai POST
(sqli, stored_xss, dll) belum tercapai di tier T1. Untuk mengaktifkan, tambahkan
ke `Dockerfile` lab-mu lalu rebuild:

```dockerfile
RUN apt-get update && apt-get install -y libapache2-mod-security2 \
 && a2enmod security2 headers \
 && cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf \
 && sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf
COPY asiw/modsecurity/asiw-modsecurity.conf /etc/modsecurity/asiw-modsecurity.conf
RUN echo 'IncludeOptional /etc/modsecurity/asiw-modsecurity.conf' >> /etc/apache2/mods-enabled/security2.conf
```

Salin `agent/modsecurity/asiw-modsecurity.conf` ke `/root/xvwa-lab/asiw/modsecurity/`,
tambahkan mount `/root/xvwa-lab/logs/apache:/var/log/apache2` (sudah ada dari
override), lalu buka komentar blok S4 pada `docker/agent.conf-asiw-xvwa-docker`
dan jalankan ulang installer Manager. **Pastikan `SecRuleEngine DetectionOnly`**,
bukan `On` (PRD: bukan IPS inline).

## Membatalkan

```bash
cd /root/xvwa-lab
rm -f docker-compose.override.yml      # kembalikan ke compose asli
docker compose up -d                   # buat ulang container tanpa mount ASIW
```
Aturan auditd/YARA di host dan rule di Manager bisa dibiarkan atau dihapus
terpisah; keduanya tidak mengganggu operasi XVWA.
