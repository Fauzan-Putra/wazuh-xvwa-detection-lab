# Panduan Deployment: Manager + 3 VM Target

## Yang dipasang di mana

Ini bagian yang paling sering disalahpahami, jadi diperjelas lebih dulu.

```
                    ┌─────────────────────────────────────────┐
                    │  VM MONITORING  192.0.2.148           │
                    │  (Wazuh Manager)                        │
                    │                                         │
                    │  >> SELURUH CUSTOM RULE ADA DI SINI <<  │
                    │     etc/rules/asiw_xvwa_rules.xml       │
                    │     etc/decoders/asiw_xvwa_decoders.xml │
                    │                                         │
                    │  Konfigurasi terpusat untuk 3 target:   │
                    │     etc/shared/asiw-xvwa-targets/       │
                    │        agent.conf                       │
                    │        asiw_xvwa_baseline.yml           │
                    └──────────────┬──────────────────────────┘
                                   │ event mentah (1514/tcp)
                                   │ konfigurasi (didorong Manager)
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
      ┌──────┴──────┐       ┌──────┴──────┐       ┌──────┴──────┐
      │asiw-target-1│       │asiw-target-2│       │asiw-target-3│
      │ 192.0.2.  │       │ 192.0.2.  │       │ 192.0.2.162│
      │     124     │       │     143     │       │             │
      │ Ubuntu 22.04│       │ Ubuntu 22.04│       │ Ubuntu 24.04│
      │ agent 001   │       │ agent 002   │       │ agent 003   │
      ├─────────────┤       ├─────────────┤       ├─────────────┤
      │ TIDAK ada   │       │ TIDAK ada   │       │ TIDAK ada   │
      │ rule di sini│       │ rule di sini│       │ rule di sini│
      │             │       │             │       │             │
      │ Hanya:      │       │ Hanya:      │       │ Hanya:      │
      │ - Apache cfg│       │ - Apache cfg│       │ - Apache cfg│
      │ - auditd    │       │ - auditd    │       │ - auditd    │
      │ - yara + AR │       │ - yara + AR │       │ - yara + AR │
      └─────────────┘       └─────────────┘       └─────────────┘
```

**Agent tidak pernah mengevaluasi rule.** Agent mengumpulkan log dan mengirim
event mentah; seluruh pencocokan rule terjadi di `wazuh-analysisd` pada Manager.
Jadi custom rule dipasang **satu kali** dan otomatis berlaku untuk ketiga target.

Yang perlu dikerjakan per-VM hanyalah membuat agent **menghasilkan** telemetri
yang dibutuhkan rule.

## Mengapa memakai agent group

Tiga VM Target harus memiliki konfigurasi telemetri **identik**, karena
eksperimen ASIW membandingkan perilaku antar-hypervisor (PRD Bagian 10). Bila
`ossec.conf` diedit manual tiga kali, selisih sekecil apa pun akan mencemari
perbandingan itu, dan sulit dibuktikan bahwa ketiganya benar-benar sama.

Konfigurasi `localfile`, `syscheck`, `sca`, dan `labels` berlabel *Agent Config*
di Wazuh, artinya bisa dipusatkan lewat `agent.conf` pada direktori grup. Manager
mendorongnya ke semua anggota grup otomatis. Satu sumber kebenaran, nol drift,
dan memenuhi kebutuhan reproducibility (PRD Bagian 12).

## Urutan pemasangan

### Tahap 1 — Manager (satu kali)

Salin paket ke VM Monitoring, lalu:

```bash
scp -r wazuh-xvwa-detection monitor-user@192.0.2.148:/tmp/
ssh monitor-user@192.0.2.148
cd /tmp/wazuh-xvwa-detection
sudo ./manager/asiw-install-manager.sh
```

Skrip mengerjakan 8 langkah: backup, pasang decoder+rule, **validasi sebelum
restart**, buat grup `asiw-xvwa-targets`, pasang `agent.conf` terpusat, tambahkan
blok Active Response, masukkan agent 001/002/003 ke grup, restart + verifikasi.

Langkah validasi itu penting: `wazuh-analysisd` **menolak start** bila ada satu
saja kesalahan sintaks rule. Kalau itu terjadi setelah restart, seluruh pemrosesan
alert berhenti, bukan hanya rule ASIW. Skrip memvalidasi dengan `wazuh-logtest`
lebih dulu dan membatalkan diri (serta mengembalikan berkas) bila gagal.

Verifikasi manual:

```bash
sudo /var/ossec/bin/agent_groups -s -g asiw-xvwa-targets
echo probe | sudo /var/ossec/bin/wazuh-logtest     # tidak boleh ada ERROR
```

### Tahap 2 — tiap VM Target (tiga kali)

Jalankan skrip yang sama di ketiga VM:

```bash
# asiw-target-1
scp -r wazuh-xvwa-detection target1-user@192.0.2.124:/tmp/
ssh target1-user@192.0.2.124
cd /tmp/wazuh-xvwa-detection
sudo ./agent/asiw-install-target.sh --check     # periksa dulu, tanpa mengubah
sudo ./agent/asiw-install-target.sh             # baru pasang
```

Ulangi untuk `target2-user@192.0.2.143` dan `target3-user@192.0.2.162`.

Mode `--check` memverifikasi asumsi tanpa mengubah apa pun. Gunakan itu lebih
dulu di setiap VM: lebih baik mengetahui path XVWA berbeda **sebelum** memasang
apa pun.

Skrip bersifat idempoten (aman dijalankan berulang) dan menulis laporan bukti ke
`/root/asiw-target-verification-<host>-<timestamp>.txt`. Simpan ketiga laporan
itu sebagai bukti verifikasi fase A2.

### Tahap 3 — tunggu sinkronisasi grup

Manager mendorong konfigurasi setiap ~10 menit. Untuk mempercepat:

```bash
# di Manager
sudo systemctl restart wazuh-manager
```

Verifikasi di tiap target:

```bash
ls -l /var/ossec/etc/shared/agent.conf
grep -c '<localfile>' /var/ossec/etc/shared/agent.conf   # harus 5
sudo grep -E "Analyzing file|Monitoring" /var/ossec/logs/ossec.log | tail -12
```

Harus terlihat `xvwa_access_json.log`, `error.log`, `access.log`, `audit.log`,
dan `asiw-yara.log`.

## Mengapa asumsi diverifikasi per-VM

Tiga nilai dipakai keras di dalam rule pada Manager. Bila berbeda di suatu VM,
rule **tidak cocok** dan hasilnya false negative **senyap**: tidak ada error,
alert hanya tidak pernah muncul.

| Kode | Asumsi | Nilai | Dampak bila berbeda |
|---|---|---|---|
| A1 | Lokasi XVWA | `/var/www/html/xvwa` | rule 100407/100431/100507 (FIM) tidak pernah cocok |
| A2 | UID `www-data` | `33` | aturan auditd tidak menangkap apa pun → tier T3 mati |
| A3 | Path `ping` | `/usr/bin/ping` atau `/bin/ping` | setiap ping **sah** dari modul cmdi memicu alert CRITICAL palsu |

Skrip memeriksa ketiganya dan **menolak lanjut** bila A1 atau A3 tidak sesuai.
Untuk A2, skrip menyesuaikan diri otomatis (memakai UID nyata pada aturan auditd),
karena rule di Manager memfilter `audit.key`, bukan UID.

## Catatan khusus Ubuntu 24.04 (asiw-target-3)

asiw-target-3 memakai Ubuntu 24.04, dua VM lain 22.04. Perbedaan yang berdampak:

**PHP berbeda versi.** Ubuntu 22.04 default PHP 8.1, Ubuntu 24.04 default PHP 8.3.
Path `php.ini` Apache berbeda (`/etc/php/8.1/apache2/` vs `/etc/php/8.3/apache2/`).
Skrip menanganinya otomatis dengan membaca `PHP_VERSION`.

**Modul crypto XVWA akan fatal error di kedua OS.** `vulnerabilities/crypto/home.php`
memakai `mcrypt_get_iv_size()`, `mcrypt_create_iv()`, dan `mcrypt_encrypt()`.
Fungsi `mcrypt_*` **dihapus di PHP 7.2**, jadi tidak ada di PHP 8.1 maupun 8.3.
Konsekuensinya:

- Modul XV-17 (Cryptography) **tidak dapat dijalankan** di lingkunganmu. Itu
  konsisten dengan dokumen mapping yang sudah mengklasifikasikannya kelas statis
  (hanya diukur SCA), jadi tidak mengubah desain deteksi.
- Tetapi modul itu akan menghasilkan PHP fatal error berulang pada baseline E0/E1.
  Error itu **tidak** memicu rule T2 ASIW (sudah diverifikasi: pola 100301/100306/100312
  mensyaratkan signature error spesifik **dan** path modul yang sesuai), tetapi
  akan memicu rule Apache bawaan. Catat sebagai derau baseline yang diketahui,
  bukan temuan.
- Rekomendasi: jangan sertakan modul crypto dalam skenario serangan, dan catat
  di laporan bahwa XV-17 tidak dapat diuji secara dinamis karena alasan versi PHP.

## Uji ujung-ke-ujung

Jalankan dari **host penyerang lab**, bukan dari VM Target, supaya `srcip` benar:

```bash
for T in 192.0.2.124 192.0.2.143 192.0.2.162; do
  echo "--- $T"
  curl -s "http://$T/xvwa/vulnerabilities/reflected_xss/?item=%3Cscript%3Ealert(1)%3C/script%3E" >/dev/null
  curl -s "http://$T/xvwa/vulnerabilities/cmdi/?target=127.0.0.1%3Bid" >/dev/null
  curl -s "http://$T/xvwa/vulnerabilities/fi/?file=../../../../etc/passwd" >/dev/null
done
```

Di Manager:

```bash
sudo tail -200 /var/ossec/logs/alerts/alerts.json \
  | grep -oE '"id":"100[0-9]{3}"|"name":"Target-[^"]*"' | paste - - | sort | uniq -c
```

Harus muncul rule 100208, 100203, 100212 dari **ketiga** agent. Jika command
injection berhasil, 100403 (T3) dan 100503 (korelasi) juga muncul.

## Apa yang masih harus diputuskan

**1. ModSecurity (S4).** Tanpa ini, modul yang memakai POST (`sqli`, `sqli_blind`,
`xpath`, `stored_xss`, `ssrf_xspa`, `fileupload`) tidak dapat mencapai tier T1,
karena body request tidak ada di access log Apache. Ini batas struktural, bukan
bug. Untuk skenario E4 dan E8 kamu perlu memilih: pasang ModSecurity
`DetectionOnly`, andalkan Suricata (S10), atau terima bahwa modul-modul itu hanya
terdeteksi di tier T3. Pilihan ini memengaruhi angka recall, jadi tetapkan
**sebelum** eksperimen dimulai dan catat alasannya.

**2. Audit MariaDB (S5).** Bukti terkuat untuk SQLi (rule 100401) dan satu-satunya
konfirmasi stored XSS (rule 100409). Tanpa ini, XV-01 berhenti di T2 dan XV-09
tidak punya T3 sama sekali.

Keduanya dinonaktifkan (dikomentari) di `agent.conf`. Untuk mengaktifkan: buka
komentarnya di `manager/agent.conf-asiw-xvwa`, pasang komponennya di ketiga VM
(lihat `agent/README.md` langkah 6 dan 7), lalu jalankan ulang
`asiw-install-manager.sh`.

**3. Verifikasi 11 rule yang belum teruji fungsional.** Rule berbasis FIM dan
rule frekuensi/korelasi tidak dapat diuji lewat `wazuh-logtest`. Prosedur
pengujiannya di lingkungan nyata ada di `limitations-and-gaps.md` Bagian 2.
Wajib dijalankan sebelum fase D.
