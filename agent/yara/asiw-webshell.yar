/*
 * =====================================================================
 * ASIW S8: aturan YARA untuk artefak pascaeksploitasi di direktori
 *          upload XVWA (webshell PHP dan payload sejenis).
 * ---------------------------------------------------------------------
 * Pasang: /var/ossec/etc/yara/rules/asiw-webshell.yar
 * Uji:    yara -w asiw-webshell.yar /var/www/html/xvwa/img/uploads/
 *
 * LINGKUP: aturan ini SENGAJA dibuat sempit (hanya pola webshell yang
 * jelas) agar tidak menandai gambar sah. YARA di sini berfungsi sebagai
 * KONFIRMASI ISI, bukan pengganti FIM berbasis ekstensi (rule 100407).
 * Keduanya saling melengkapi:
 *   - 100407 menangkap shell.php (ekstensi jelas, isi apa pun)
 *   - 100408 menangkap shell.php.jpg / polyglot (isi jelas, ekstensi menipu)
 *
 * BATASAN YANG DIAKUI (XVWA_Detection_Mapping_ASIW.md Bagian 8):
 * webshell yang di-obfuscate berat (eval berlapis, base64 bertingkat,
 * string terenkripsi) dapat lolos. Ini dilaporkan sebagai batas deteksi,
 * bukan dianggap tertutup.
 * =====================================================================
 */

private rule ASIW_Is_PHP_Content
{
    meta:
        description = "Berkas memuat penanda pembuka PHP"
    strings:
        $php_open_long  = "<?php"  nocase
        $php_open_short = "<?="
        $php_open_tag   = "<?"     // paling longgar, dipakai bersama syarat lain
    condition:
        $php_open_long or $php_open_short or $php_open_tag
}

rule ASIW_Webshell_Generic_PHP
{
    meta:
        author      = "Tim ASIW"
        description = "Webshell PHP generik: pembuka PHP + fungsi eksekusi perintah yang menerima input pengguna"
        xv_id       = "XV-07"
        severity    = "critical"
        reference   = "XVWA_Detection_Mapping_ASIW.md XV-07"

    strings:
        // Fungsi eksekusi perintah sistem
        $exec1 = "shell_exec"     nocase
        $exec2 = "passthru"       nocase
        $exec3 = "proc_open"      nocase
        $exec4 = "popen"          nocase
        $exec5 = "pcntl_exec"     nocase
        $exec6 = "system("        nocase
        $exec7 = "exec("          nocase

        // Sumber input yang dikendalikan penyerang
        $src1 = "$_GET"
        $src2 = "$_POST"
        $src3 = "$_REQUEST"
        $src4 = "$_COOKIE"
        $src5 = "php://input"     nocase

    condition:
        ASIW_Is_PHP_Content
        and any of ($exec*)
        and any of ($src*)
}

rule ASIW_Webshell_Eval_Obfuscated
{
    meta:
        author      = "Tim ASIW"
        description = "Webshell PHP dengan eval dan dekode terselubung (base64/gzinflate/rot13)"
        xv_id       = "XV-07"
        severity    = "critical"

    strings:
        $eval1 = "eval("              nocase
        $eval2 = "assert("            nocase
        $eval3 = "create_function"    nocase
        $eval4 = "preg_replace"       nocase   // modifier /e pada PHP lama

        $dec1  = "base64_decode"      nocase
        $dec2  = "gzinflate"          nocase
        $dec3  = "gzuncompress"       nocase
        $dec4  = "str_rot13"          nocase
        $dec5  = "hex2bin"            nocase
        $dec6  = "convert_uudecode"   nocase

    condition:
        ASIW_Is_PHP_Content
        and any of ($eval*)
        and any of ($dec*)
}

rule ASIW_Webshell_Known_Family
{
    meta:
        author      = "Tim ASIW"
        description = "Penanda string keluarga webshell yang dikenal luas"
        xv_id       = "XV-07"
        severity    = "critical"

    strings:
        $s1 = "c99shell"           nocase
        $s2 = "r57shell"           nocase
        $s3 = "WSO "               nocase
        $s4 = "FilesMan"           nocase
        $s5 = "b374k"              nocase
        $s6 = "IndoXploit"         nocase
        $s7 = "Mini Shell"         nocase
        $s8 = "weevely"            nocase
        $s9 = "p0wny"              nocase

    condition:
        any of them
}

rule ASIW_Reverse_Shell_Payload
{
    meta:
        author      = "Tim ASIW"
        description = "Payload reverse shell (PHP atau skrip) yang membuka socket ke host penyerang"
        xv_id       = "XV-03"
        severity    = "critical"

    strings:
        $sock1 = "fsockopen"            nocase
        $sock2 = "socket_create"        nocase
        $sock3 = "stream_socket_client" nocase

        $sh1   = "/bin/sh"
        $sh2   = "/bin/bash"
        $sh3   = "cmd.exe"              nocase

        // Pola reverse shell satu baris yang umum
        $one1  = "bash -i >&"
        $one2  = "nc -e"
        $one3  = "sh -i 2>&1"
        $one4  = "python -c 'import socket"
        $one5  = "pty.spawn"

    condition:
        (any of ($sock*) and any of ($sh*)) or any of ($one*)
}

rule ASIW_Polyglot_Image_With_PHP
{
    meta:
        author      = "Tim ASIW"
        description = "Berkas dengan header gambar sah tetapi memuat kode PHP (polyglot / bypass ekstensi)"
        xv_id       = "XV-07"
        severity    = "critical"

    strings:
        // Magic bytes header gambar
        $jpeg = { FF D8 FF }
        $png  = { 89 50 4E 47 0D 0A 1A 0A }
        $gif  = "GIF8"

        $php  = "<?php" nocase

    condition:
        (($jpeg at 0) or ($png at 0) or ($gif at 0)) and $php
}
