# Inventaris Modul XVWA (berdasarkan source `s4n7h0/xvwa`)

Sumber: clone `https://github.com/s4n7h0/xvwa`, commit `fb30fa51` (terakhir diubah 2020-09-12).
Diverifikasi dengan membaca `vulnerabilities/<modul>/home.php`, `index.php`, `sidepanel.php`, `config.php`, `login.php`.

## Peta path modul (URL)

| XV-ID | Path URL (root `/xvwa/`) | File utama | Metode + parameter input |
|---|---|---|---|
| XV-01 SQLi (error-based) | `/xvwa/vulnerabilities/sqli/` | `home.php` | **POST** `item` (dropdown kode item, digit), **POST** `search` (teks) |
| XV-02 SQLi (blind) | `/xvwa/vulnerabilities/sqli_blind/` | `home.php` | **POST** `item`, **POST** `search` |
| XV-03 OS Command Injection | `/xvwa/vulnerabilities/cmdi/` | `home.php` | **GET/REQUEST** `target` (dipakai di `shell_exec('ping -c 3 '.$target)` — **GET**, form `method='get'`) |
| XV-04 XPath Injection | `/xvwa/vulnerabilities/xpath/` | `home.php` | **POST** `search` (dipakai di XPath `…[@ID='$input']`), tombol `submit` |
| XV-05 Formula (CSV) Injection | `/xvwa/vulnerabilities/formula_injection/` | `home.php`, `export.php` | **POST** ke `export.php` dengan `action=export`; payload formula disuntikkan lewat pembuatan item (via modul fileupload/SQLi), bukan form ini |
| XV-06 PHP Object Injection | `/xvwa/vulnerabilities/php_object_injection/` | `home.php` | **GET/REQUEST** `r` (string serialisasi PHP, `unserialize($_REQUEST['r'])`) |
| XV-07 Unrestricted File Upload | `/xvwa/vulnerabilities/fileupload/` | `home.php` | **POST multipart** `image` (file) + `item`, `desc`, `categ`, `price`; disimpan ke **`/xvwa/img/uploads/`** (relatif `DOCUMENT_ROOT`) |
| XV-08 XSS Reflected | `/xvwa/vulnerabilities/reflected_xss/` | `home.php` | **GET** `item` (langsung `echo $_GET['item']`) |
| XV-09 XSS Stored | `/xvwa/vulnerabilities/stored_xss/` | `home.php` | **POST** `name`, `msg` (disimpan ke tabel `comments`) |
| XV-10 XSS DOM | `/xvwa/vulnerabilities/dom_xss/` | `home.php` | **GET** `default` dibaca **JavaScript** dari `document.location.href` (sisi klien; server tidak melihat payload) |
| XV-11 SSRF/XSPA | `/xvwa/vulnerabilities/ssrf_xspa/` | `home.php` | **POST** `img_url` (`file_get_contents($_POST['img_url'])`) |
| XV-12 File Inclusion (LFI/RFI) | `/xvwa/vulnerabilities/fi/` | `home.php` | **GET** `file` (`include($file)`) |
| XV-13 Session Flaws | `/xvwa/vulnerabilities/sessionflaws/` | `home.php`, `logout.php` | tidak ada parameter eksploitasi; kelemahan manajemen sesi |
| XV-14 IDOR | `/xvwa/vulnerabilities/idor/` | `home.php` | **GET** `item` (angka `itemid`, dipakai prepared statement tapi tanpa otorisasi per-objek) |
| XV-15 Missing Function-Level AC | `/xvwa/vulnerabilities/missfunc/` | `home.php` | **GET** `item` + **GET** `action` (`view`/`delete`; `delete` hanya disembunyikan di UI, tidak dicek server-side) |
| XV-16 CSRF | `/xvwa/vulnerabilities/csrf/` | `home.php` | **GET** `passwd`, `confirm`, `submit` (ganti password user login; tanpa token anti-CSRF) |
| XV-17 Cryptography | `/xvwa/vulnerabilities/crypto/` | `home.php` | **GET** `item` (demo encoding/encrypt/hash) — kelemahan statis |
| XV-18 Unvalidated Redirects | `/xvwa/vulnerabilities/redirect/redirect.php` | `redirect.php` | **GET** `forward` (URL tujuan `header("Location: ".$forward)`) |
| XV-19 SSTI | `/xvwa/vulnerabilities/ssti/` | `home.php` (dan `ssti.php`) | **GET** `name` (dirender langsung oleh Twig `Twig_Loader_String`) |

## Fakta penting untuk deteksi

- **Direktori upload**: `/xvwa/img/uploads/` (ditulis `move_uploaded_file`). Setup `setup/home.php` juga
  menghapus isi `img/uploads/*` saat reset. → FIM harus memantau `<webroot>/xvwa/img/uploads/` (realtime).
- **SSRF** menulis file hasil unduhan ke `../../img/<rand>img1.jpg` → direktori `/xvwa/img/` juga layak dipantau FIM.
- **cmdi** memakai `ping -c 3` (Linux) atau `ping` (Windows). Perintah baseline sah modul ini = `ping`.
  Anomali = biner lain dieksekusi oleh user web (mis. `id`, `whoami`, `cat`, `nc`, `bash`, `sh -c ...`).
- **sqli / sqli_blind** menggunakan query string concat langsung ke `itemid` dan `LIKE '%…%'`.
  Error-based (sqli) menyalakan `display_errors=1` → pesan error MySQL/mysqli akan muncul di **respons**
  (dan juga ke Apache/PHP error log bila `log_errors` aktif).
- **DB**: `config.php` memakai MySQL/MariaDB, user `root`, db `xvwa`, tabel `comments`, `caffaine`, `users`.
  Modul memakai dua koneksi: `$conn` (mysqli) dan `$conn1` (PDO). → audit DB (MariaDB `server_audit`) bisa
  menangkap query aktual (T3 untuk SQLi & stored XSS).
- **Login**: `login.php` (POST `username`, `password`), sesi `$_SESSION['user']`; kredensial default
  `admin/admin`, `xvwa/xvwa`, `user/user` (md5).
- **Setup/reset**: `/xvwa/setup/` (GET `action=do`) menghapus & membuat ulang tabel serta mengosongkan `img/uploads/`.
- **`php.ini`**: `file_uploads=On`, `allow_url_fopen=on`, `allow_url_include=on` (memungkinkan RFI & SSRF).
- **Akar web**: seluruh URL diawali `/xvwa/` (lihat `sidepanel.php`). Root app `index.php` include `sidepanel.php`.
  `config.php` `$XVWA_WEBROOT = ""` (path relatif). Document root biasanya `/var/www/html` → app di `/var/www/html/xvwa`.

## Bentuk input sah (model positif) per parameter utama

| Modul | Parameter | Bentuk sah (baseline) | Penyimpangan → indikasi |
|---|---|---|---|
| sqli | `item` | `^\d{1,4}$` | karakter non-digit / operator SQL |
| sqli | `search` | teks pendek alfanumerik/spasi | `'`, `"`, `--`, `#`, `/*`, `union`, `select`, `or/and`, `sleep(` |
| sqli_blind | `item`/`search` | sama seperti di atas | `sleep(`, `benchmark(`, `waitfor delay`, pola boolean `and 1=1/1=2` |
| cmdi | `target` | IP/hostname (`^[A-Za-z0-9._-]{1,64}$`) | `;`, `|`, `&&`, `||`, `` ` ``, `$(`, nama perintah |
| xpath | `search` | `^\d{1,4}$` (ID) | `'`, `or`, `//`, `]`, `|`, fungsi XPath |
| php_object_injection | `r` | string serialisasi terbatas (contoh `a:2:{…}` pada tombol) | pola `O:\d+:"`, `__wakeup`, `eval`, base64 panjang |
| fileupload | `image` | ekstensi gambar `.jpg/.jpeg/.png/.gif` | ekstensi eksekutabel `.php/.phtml/.phar/.php5/.php7/.pht`, double ext, MIME mismatch |
| reflected_xss | `item` | teks pendek | `<script`, `on*=` handler, `javascript:`, `<img`, `<svg` |
| stored_xss | `name`/`msg` | teks | tag HTML + event handler |
| ssrf_xspa | `img_url` | URL `http(s)://` gambar | `file://`, `gopher://`, `dict://`, host internal/loopback/metadata |
| fi | `file` | `readme.txt` (satu-satunya yang di-link UI) | `../`, `..%2f`, path absolut, `php://`, `data://`, `expect://`, `http(s)://` (RFI) |
| idor | `item` | `^\d{1,4}$` | enumerasi berurutan cepat dari satu sumber |
| missfunc | `action` | `view` | `delete` oleh sesi non-admin |
| csrf | `passwd`/`confirm` | string | request tanpa/eksternal `Referer` ke endpoint ini |
| redirect | `forward` | `http://www.webappsec.org/` | URL eksternal lain, `//host`, `%2f%2f` |
| ssti | `name` | nama | `{{…}}`, `${…}`, `<%= %>`, `{%…%}`, uji aritmetika `{{7*7}}` |
