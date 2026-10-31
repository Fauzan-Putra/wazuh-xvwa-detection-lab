# Catatan Keamanan dan Lingkup Penggunaan

## Lingkup

Repositori ini memuat **aturan deteksi (detection rules)** untuk Wazuh SIEM.
Isinya bersifat **defensif**: mendeteksi serangan terhadap aplikasi web, bukan
melakukannya. Tidak ada eksploit, payload serangan siap-pakai, maupun perkakas
ofensif di dalamnya.

Korpus uji (`tests/corpus_*.tsv`) memuat **cuplikan baris log** yang
merepresentasikan serangan. Itu adalah data uji untuk memvalidasi aturan, bukan
perkakas untuk menyerang.

## Aplikasi target

Aturan di sini dirancang untuk mendeteksi serangan pada
[XVWA](https://github.com/s4n7h0/xvwa), aplikasi web yang **sengaja dibuat
rentan** untuk pelatihan keamanan.

> **Jangan pernah menjalankan XVWA pada jaringan produksi atau host yang dapat
> dijangkau internet.** XVWA memuat kerentanan nyata yang dapat dieksploitasi,
> termasuk eksekusi perintah dan unggah webshell. Jalankan hanya pada
> lingkungan lab yang terisolasi dan berizin.

## Yang tidak ada di repositori ini

Sesuai PRD proyek Bagian 12 (Privasi) dan 8.9 (FR-X3):

- Tidak ada alamat IP, hostname, atau nama pengguna infrastruktur nyata.
  Seluruh contoh memakai rentang dokumentasi RFC 5737 (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) yang tidak dapat dirutekan.
- Tidak ada kredensial, kunci privat, API key, atau `client.keys` Wazuh.
- Nilai spesifik lingkungan dibaca dari `asiw.env` yang **tidak di-commit**
  (lihat `asiw.env.example`).

Jika kamu melakukan fork dan menyesuaikannya, pastikan `asiw.env` tetap berada
di `.gitignore` sebelum melakukan commit.

## Pertimbangan keamanan saat penerapan

| Hal | Catatan |
|---|---|
| **ModSecurity wajib `DetectionOnly`** | Mode `On` memblokir request. Proyek ini bukan IPS inline (PRD 3.2), dan pemblokiran membuat skenario eksperimen tidak dapat direproduksi. Skrip pemasang memeriksa ini dan berhenti bila menemukan mode blocking. |
| **Skrip Active Response berjalan sebagai root** | `agent/yara/asiw-yara.sh` dieksekusi `wazuh-execd` sebagai root dan menerima path berkas dari payload alert. Nama berkas unggahan sepenuhnya dikendalikan penyerang, sehingga skrip menolak karakter kendali (mencegah log injection), menolak path traversal, dan membatasi pemindaian ke direktori aplikasi. Path tidak pernah dieksekusi lewat shell. Tinjau skrip sebelum menerapkan. |
| **Audit query database** | `agent/mariadb/` mengaktifkan pencatatan teks query penuh. Dapat diterima pada lab berisi data sintetis; **jangan** terapkan pada basis data berisi data nyata atau data pribadi. |
| **Aturan auditd dibatasi pada user web** | Aturan memfilter `euid` user web, bukan memantau seluruh `execve` sistem, agar volume event terkendali dan aktivitas administrator tidak tercampur. |

## Melaporkan masalah

Bila kamu menemukan aturan yang dapat dilewati (evasion), atau pola yang
menimbulkan false positive pada trafik sah, silakan buka issue dengan
menyertakan baris log contoh. Riwayat temuan serupa beserta perbaikannya ada di
`docs/limitations-and-gaps.md` Bagian 6.
