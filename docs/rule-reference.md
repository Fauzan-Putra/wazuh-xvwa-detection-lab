# Referensi Rule ASIW: pemetaan `rule.id` → XV-ID → kategori

Tabel ini adalah **kontrak antara Wazuh dan layer normalisasi (n8n/backend)**.
Sesuai `XVWA_Detection_Mapping_ASIW.md` Bagian 7.1, skema ID dibuat deterministik
supaya backend dapat memetakan `rule.id` ke `xv_id`, `evidence_tier`, dan
`attack_category` lewat tabel, **tanpa menebak dari teks deskripsi**.

Versi ruleset: 1.1 · Diuji pada Wazuh 4.14.8 · **100/100 kasus uji lulus**
(58 positif, 42 negatif).

## Cara membaca ID

```
1 0 0 2 0 1
      │ └─┴── NN
      └────── digit tier: 2=T1, 3=T2, 4=T3, 5=korelasi
```

Pengecualian: `1001xx` = rule konteks, `1009xx` = suppression.

### Konvensi NN

Dokumen mapping 7.1 menetapkan `NN` = nomor XV-ID. Skema itu hanya menampung
**satu** rule per tier per XV-ID, sedangkan beberapa XV-ID memerlukan lebih
dari satu rule pada tier yang sama (contoh: XV-07 T3 perlu deteksi berbasis
ekstensi **dan** berbasis isi/YARA). Karena itu `NN` diperluas:

| Rentang NN | Arti |
|---|---|
| `01`–`19` | rule **kanonik**, `NN` = nomor XV-ID |
| `20 + XV` | varian ke-2 dari XV-ID tersebut |
| `40 + XV` | varian ke-3 |
| `60 + XV` | varian ke-4 |

Contoh: `100427` → tier T3 (digit `4`), `NN=27 = 20+07` → varian ke-2 dari XV-07.

Pemetaan tetap deterministik, tetapi **tabel di bawah adalah acuan tunggal**
bagi backend. Jangan menghitung `xv_id` dari digit tanpa mengecek tabel.

## Tabel lengkap

| rule.id | level | severity_label | xv_id | evidence_tier | attack_category | attack_subcategory | source_type | classification_basis | Sumber data |
|---|---|---|---|---|---|---|---|---|---|
| 100100 | 0 | — | — | — | — | — | host | — | S2 |
| 100101 | 0 | — | — | — | — | — | host | — | S2 |
| 100120 | 0 | — | — | — | — | — | host | — | S5 |
| 100130 | 0 | — | — | — | — | — | host | — | S8 |
| 100140 | 0 | — | — | — | — | — | host | — | S4 |
| 100201 | 6 | MEDIUM | XV-01 | T1 | Web Attack | SQL Injection | host | module_path | S2 |
| 100202 | 6 | MEDIUM | XV-02 | T1 | Web Attack | SQL Injection (Blind) | host | module_path | S2 |
| 100203 | 7 | MEDIUM | XV-03 | T1 | Web Attack | Command Injection | host | module_path | S2 |
| 100204 | 6 | MEDIUM | XV-04 | T1 | Web Attack | XPath Injection | host | module_path | S2 |
| 100205 | 5 | MEDIUM | XV-05 | T1 | Web Attack | Formula Injection | host | module_path | S2 |
| 100206 | 7 | MEDIUM | XV-06 | T1 | Web Attack | Object Injection | host | module_path | S2 |
| 100207 | 4 | LOW | XV-07 | T1 | Web Attack | File Upload | host | module_path | S2 |
| 100208 | 6 | MEDIUM | XV-08 | T1 | Web Attack | XSS (Reflected) | host | module_path | S2 |
| 100209 | 4 | LOW | XV-09 | T1 | Web Attack | XSS (Stored) | host | module_path | S2 |
| 100210 | 5 | MEDIUM | XV-10 | T1 | Web Attack | XSS (DOM) | host | module_path | S2 |
| 100211 | 6 | MEDIUM | XV-11 | T1 | Reconnaissance | SSRF / XSPA | host | module_path | S2 |
| 100212 | 7 | MEDIUM | XV-12 | T1 | Web Attack | Path Traversal / LFI | host | module_path | S2 |
| 100114 | 0 | — | XV-14 | — | — | — | host | module_path | S2 |
| 100215 | 7 | MEDIUM | XV-15 | T1 | Policy Violation | Function-Level Access Control | host | module_path | S2 |
| 100216 | 4 | LOW | XV-16 | T1 | Policy Violation | CSRF | host | module_path | S2 |
| 100218 | 5 | MEDIUM | XV-18 | T1 | Policy Violation | Open Redirect | host | module_path | S2 |
| 100219 | 6 | MEDIUM | XV-19 | T1 | Web Attack | SSTI | host | module_path | S2 |
| 100301 | 9 | HIGH | XV-01 | T2 | Web Attack | SQL Injection | host | payload | S3 |
| 100302 | 9 | HIGH | XV-02 | T2 | Web Attack | SQL Injection (Blind) | correlated | module_path | S2 |
| 100306 | 9 | HIGH | XV-06 | T2 | Web Attack | Object Injection | host | payload | S3 |
| 100308 | 8 | HIGH | XV-08 | T2 | Web Attack | XSS (Reflected) | correlated | module_path | S2 |
| 100311 | 9 | HIGH | XV-11 | T2 | Reconnaissance | Service Scan (via SSRF) | correlated | module_path | S2 |
| 100312 | 9 | HIGH | XV-12 | T2 | Web Attack | Path Traversal / LFI | host | payload | S3 |
| 100332 | 8 | HIGH | XV-12 | T2 | Web Attack | Path Traversal / LFI | correlated | module_path | S2 |
| 100314 | 8 | HIGH | XV-14 | T2 | Reconnaissance | IDOR Enumeration | correlated | module_path | S2 |
| 100319 | 8 | HIGH | XV-19 | T2 | Web Attack | SSTI | correlated | module_path | S2 |
| 100401 | 12 | CRITICAL | XV-01 | T3 | Web Attack | SQL Injection | host | host_evidence | S5 |
| 100403 | 12 | CRITICAL | XV-03 | T3 | Command Execution | Non-baseline Binary | host | host_evidence | S6 |
| 100423 | 13 | CRITICAL | XV-03 | T3 | Command Execution | Interpreter / Reverse Shell | host | host_evidence | S6 |
| 100407 | 12 | CRITICAL | XV-07 | T3 | Web Shell | Executable Upload | host | host_evidence | S7 |
| 100427 | 14 | CRITICAL | XV-07 | T3 | Web Shell | YARA Content Match | host | host_evidence | S8 |
| 100447 | 12 | CRITICAL | XV-07 | T3 | Web Shell | Log-Injection Filename | host | host_evidence | S8 |
| 100409 | 11 | CRITICAL | XV-09 | T3 | Web Attack | XSS (Stored, persisted) | host | host_evidence | S5 |
| 100431 | 11 | CRITICAL | XV-11 | T3 | File Integrity Violation | SSRF Fetch Artifact | host | host_evidence | S7 |
| 100411 | 11 | CRITICAL | XV-11 *(lihat catatan)* | T3 | Suspicious Outbound | Web Process Egress | host | host_evidence | S6 |
| 100415 | 11 | CRITICAL | XV-15 | T3 | Policy Violation | Privileged Delete Executed | host | host_evidence | S5 |
| 100416 | 11 | CRITICAL | XV-16 | T3 | Policy Violation | Credential Change | host | host_evidence | S5 |
| 100501 | 13 | CRITICAL | — | T3 | Brute Force | SSH Login After Brute Force | correlated | host_evidence | auth log |
| 100503 | 14 | CRITICAL | XV-03 | T3 | Command Execution | Confirmed Exploit Chain | correlated | host_evidence | S2+S6 |
| 100507 | 14 | CRITICAL | XV-07 | T3 | Web Shell | Active Web Shell | correlated | host_evidence | S7+S2 |
| 100901 | 0 | — | — | — | — | — | host | — | S2 |
| 100902 | 0 | — | — | — | — | — | host | — | S2 |
| 100903 | 3 | LOW | — | — | — | — | host | — | S5 |

## Field tambahan yang harus dihasilkan backend

Sesuai dokumen mapping Bagian 7.2, backend melengkapi payload PRD 9.1 dengan:

| Field | Cara mengisi |
|---|---|
| `xv_id` | lookup tabel di atas dari `rule.id` |
| `evidence_tier` | digit ke-4 `rule.id` (2→T1, 3→T2, 4→T3) |
| `owasp_2025` | lookup `xv_id` ke katalog mapping Bagian 4 |
| `attack_category` / `attack_subcategory` | kolom tabel di atas |
| `source_type` | kolom tabel di atas |
| `classification_basis` | kolom tabel di atas |
| `classification_note` | isi `payload_context_mismatch` bila pola payload tidak cocok dengan modul sasaran (mapping Bagian 6) |
| `correlation_id` | ID bersama untuk event lintas sumber atas satu serangan |
| `vuln_known` | `true` bila `xv_id` ada di `asset_vulnerabilities` untuk aset itu |

## Rule yang TIDAK ada, dan alasannya

| XV-ID | Mengapa tidak ada rule T1/T2/T3 |
|---|---|
| XV-13 Session Flaws | Kelas statis. Diukur SCA (`sca/asiw_xvwa_baseline.yml` check 10010–10012). Deteksi peristiwa memerlukan hash session ID di log, yang sengaja tidak dicatat karena alasan privasi (lihat S2). |
| XV-17 Cryptography | Kelas statis murni. Diukur SCA check 10030–10031. Tidak ada peristiwa jaringan/host yang menandakan eksploitasi. |
| XV-05 (T2/T3) | Eksploitasi terjadi di sisi korban saat membuka CSV. Server tidak pernah melihatnya. Hanya penyisipan input yang terdeteksi (100205). |
| XV-10 (T3) | Eksekusi sepenuhnya di browser. Varian fragment (`#`) tidak pernah dikirim ke server. |
| XV-04 (T3) | XML diproses di dalam aplikasi; tidak ada jejak host maupun DB. |
| XV-14 (T3) | Pelanggaran otorisasi hanya dipahami aplikasi. Maksimal T2 (perilaku enumerasi). |

## Catatan khusus rule 100411 (XV-11 dan XV-12 berbagi bukti host)

Bukti host untuk SSRF (XV-11) dan RFI (XV-12) **identik**: keduanya terlihat
sebagai syscall `connect` oleh proses web dengan auditd key `asiw_web_connect`.
Tidak ada field pada event auditd yang membedakan "proses web mengambil URL
karena modul ssrf_xspa" dari "karena modul fi".

Rancangan awal memuat dua rule terpisah (100411 untuk XV-11, 100412 untuk
XV-12) dengan kondisi yang persis sama. Itu **cacat**: Wazuh hanya memilih
satu rule per event, sehingga rule kedua tidak akan pernah menyala dan hanya
menimbulkan kebingungan saat audit. Karena itu hanya 100411 yang ada.

Konsekuensi untuk backend: `xv_id` pada alert 100411 **tidak boleh diambil
langsung dari tabel ini**. Backend harus menentukannya lewat korelasi dengan
alert T1 terdekat dari IP yang sama:

| Alert T1 terdekat | `xv_id` yang benar untuk 100411 |
|---|---|
| 100211 (modul ssrf_xspa) | XV-11 |
| 100212 (modul fi, pola RFI `http://`) | XV-12 |
| tidak ada | biarkan `XV-11`, set `classification_note = "egress_source_unknown"` |

## Deviasi level yang disengaja (wajib dibaca)

Dokumen mapping 1.2 menetapkan T1 = level 5–7. Empat rule menyimpang, dan
semuanya **disengaja**:

| rule.id | level | Alasan deviasi |
|---|---|---|
| 100207 | 4 | T1 XV-07 hanya menandai "ada POST ke endpoint upload"; isi berkas tidak terlihat di access log. Dokumen mapping sendiri menyebut T1 XV-07 "lemah". Level 5 akan membuat setiap unggahan gambar sah tampil sebagai MEDIUM. |
| 100209 | 4 | Sama: T1 XV-09 hanya menandai penulisan komentar. Payload ada di body POST (butuh S4/S10). |
| 100216 | 4 | Dokumen mapping XV-16 secara eksplisit melarang sinyal CSRF naik di atas "T1 rendah". Ini **pertentangan di dalam dokumen sumber** (band 5–7 vs larangan menaikkan); larangan spesifik XV-16 dimenangkan karena lebih spesifik. |
| 100114 | 0 | Bukan T1. Akses objek tunggal pada modul idor adalah perilaku sah; rule ini hanya induk bagi rule frekuensi 100314. Karena itu ID-nya dipindahkan ke band konteks `1001xx`. |

## Rentang ID yang masih kosong

Disediakan untuk perluasan tanpa menabrak skema:

- `100102`–`100113`, `100115`–`100119` — rule konteks tambahan
- `100213`, `100217` — T1 untuk XV-13 dan XV-17 (tidak akan dipakai, lihat tabel di atas)
- `100303`–`100305`, `100307`, `100309`, `100310`, `100315`–`100318` — T2 kanonik tambahan
- `100320`–`100331`, `100333`–`100399` — T2 varian tambahan
- `100402`, `100405`, `100406`, `100413`, `100414`, `100417`–`100419` — T3 kanonik tambahan
- `100420`–`100422`, `100424`–`100426`, `100428`–`100430`, `100432`–`100446`, `100448`–`100499` — T3 varian tambahan
- `100502`, `100504`–`100506`, `100508`–`100599` — korelasi tambahan
- `100904`–`100999` — suppression tambahan (wajib berkomentar alasan dan pemilik)
