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
    
    # 2. Sử dụng ffuf như là một lựa chọn thay thế
    if command -v ffuf &> /dev/null; then
        echo "[+] Using ffuf for recursive scanning..."
        
        # Quét ban đầu để tìm các thư mục
        ffuf -u $url/FUZZ \
             -w $wordlist \
             -t $THREADS \
             -e .php,.asp,.aspx,.jsp,.html,.txt,.old,.bak \
             -recursion \
             -recursion-depth $depth \
             -v \
             -of html -o "$output_dir/ffuf_recursive.html" \
             -of json -o "$output_dir/ffuf_recursive.json"
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