#!/bin/bash
#
# SSH Vulnerability Scanner
# Script de kiem tra cac lo hong bao mat pho bien trong dich vu SSH
# Tham chieu cac ma CVE tuong ung voi moi lo hong
#

# Mau sac de hien thi
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Hien thi banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                SSH Vulnerability Scanner                   ║"
echo "║          Kiem tra lo hong SSH va ma CVE tuong ung         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Kiem tra cac cong cu can thiet
command -v nmap >/dev/null 2>&1 || { echo -e "${RED}[!] Yeu cau cai dat nmap nhung khong tim thay. Vui long cai dat nmap.${NC}"; exit 1; }
command -v ssh >/dev/null 2>&1 || { echo -e "${RED}[!] Yeu cau cai dat openssh-client nhung khong tim thay.${NC}"; exit 1; }

# Hien thi huong dan su dung
function show_usage {
    echo -e "${BLUE}Cach su dung:${NC}"
    echo -e "  $0 [tuy chon] <target>"
    echo -e ""
    echo -e "${BLUE}Tuy chon:${NC}"
    echo -e "  -h, --help           Hien thi thong tin tro giup nay"
    echo -e "  -p, --port <port>    Chi dinh cong SSH (mac dinh: 22)"
    echo -e "  -t, --timeout <sec>  Thoi gian timeout ket noi (mac dinh: 5)"
    echo -e "  -v, --verbose        Hien thi thong tin chi tiet"
    echo -e "  -o, --output <file>  Xuat ket qua ra file"
    echo -e ""
    echo -e "${BLUE}Vi du:${NC}"
    echo -e "  $0 192.168.1.10"
    echo -e "  $0 -p 2222 192.168.1.10"
    echo -e "  $0 -v -o ssh_scan_results.txt 192.168.1.10"
    echo -e "  $0 --port 2222 --timeout 10 192.168.1.10"
    exit 0
}

# Khoi tao bien
SSH_PORT=22
TIMEOUT=5
VERBOSE=0
OUTPUT_FILE=""
TARGET=""

# Xu ly tham so dau vao
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            else
                echo -e "${RED}[!] Tham so khong hop le: $1${NC}"
                show_usage
            fi
            shift
            ;;
    esac
done

# Kiem tra tham so bat buoc
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}[!] Thieu tham so bat buoc: target${NC}"
    show_usage
fi

# Ham ghi log
log() {
    local level="$1"
    local message="$2"
    local color=""
    
    case "$level" in
        "INFO") color="${BLUE}";;
        "SUCCESS") color="${GREEN}";;
        "WARNING") color="${YELLOW}";;
        "ERROR") color="${RED}";;
        "VULN") color="${MAGENTA}";;
        *) color="${NC}";;
    esac
    
    echo -e "${color}[$level] $message${NC}"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "[$level] $message" >> "$OUTPUT_FILE"
    fi
}

# Ham log chi tiet (chi khi bat che do verbose)
verbose_log() {
    if [[ $VERBOSE -eq 1 ]]; then
        log "DEBUG" "$1"
    fi
}

# Khoi tao file output neu duoc chi dinh
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "SSH Vulnerability Scan Results - $(date)" > "$OUTPUT_FILE"
    echo "Target: $TARGET:$SSH_PORT" >> "$OUTPUT_FILE"
    echo "Scan time: $(date)" >> "$OUTPUT_FILE"
    echo "----------------------------------------" >> "$OUTPUT_FILE"
fi

log "INFO" "Bat dau quet dich vu SSH tai $TARGET:$SSH_PORT"

# Kiem tra xem host co phan hoi khong
ping -c 1 -W 3 "$TARGET" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    log "WARNING" "Host $TARGET khong phan hoi ping. Tiep tuc quet..."
fi

# Kiem tra xem cong SSH co mo khong
verbose_log "Kiem tra cong SSH $SSH_PORT tren $TARGET"
nc -z -w $TIMEOUT "$TARGET" "$SSH_PORT" > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
    log "ERROR" "Cong $SSH_PORT dong hoac bi loc tren $TARGET"
    log "ERROR" "Khong the tiep tuc quet. Hay kiem tra lai host va cong."
    exit 1
fi

log "SUCCESS" "Cong SSH $SSH_PORT dang mo tren $TARGET"

# Lay phien ban SSH
verbose_log "Dang thu thap thong tin phien ban SSH..."
SSH_VERSION=$(timeout $TIMEOUT nmap -p $SSH_PORT -sV --version-all "$TARGET" -oG - 2>/dev/null | grep "open" | grep -oE "SSH-[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?" || echo "Unknown")

if [[ $SSH_VERSION == "Unknown" ]]; then
    # Thu cach khac de lay phien ban SSH
    SSH_VERSION=$(timeout $TIMEOUT nc -w $TIMEOUT "$TARGET" "$SSH_PORT" 2>/dev/null | head -1 | grep -oE "SSH-[0-9]+\.[0-9]+" || echo "Unknown")
fi

if [[ $SSH_VERSION == "Unknown" ]]; then
    log "WARNING" "Khong the xac dinh phien ban SSH"
else
    log "INFO" "Phien ban SSH: $SSH_VERSION"
fi

log "INFO" "Bat dau kiem tra cac lo hong bao mat..."

# Mang luu tru thong tin lo hong
# Format: [Ma lo hong]:[Muc do nghiem trong]:[Phien ban bi anh huong]:[Mo ta]
SSH_VULNS=(
    "CVE-2002-0640:HIGH:SSH 1.x:OpenSSH truoc 3.4 de bi tan cong Bleichenbacher RSA"
    "CVE-2006-5051:HIGH:SSH 1.x, OpenSSH 2.x, 3.x, 4.3:Lo hong nguy hiem trong thuc thi cac phep tinh Diffie-Hellman cho phep tan cong man-in-the-middle"
    "CVE-2008-4109:MEDIUM:OpenSSH 4.7:Lo hong xac thuc X.509 cho phep ke tan cong gia mao chung chi"
    "CVE-2016-0777:HIGH:OpenSSH 5.4-7.1:Lo hong ro ri thong tin tu bo nho thong qua roaming"
    "CVE-2018-15473:MEDIUM:OpenSSH truoc 7.7:Lo hong liet ke nguoi dung (user enumeration) cho phep ke tan cong kiem tra nguoi dung ton tai"
    "CVE-2019-6111:MEDIUM:OpenSSH 7.6p1:Lo hong scp cho phep ghi de file khi tai xuong"
    "CVE-2020-14145:LOW:OpenSSH 5.7-8.3:Lo hong ro ri cau hinh host-key"
    "CVE-2021-28041:HIGH:OpenSSH truoc 8.5p1:Lo hong heap buffer overflow trong xu ly goi sshd"
    "CVE-2023-38408:MEDIUM:OpenSSH 9.3p1:Lo hong logic trong xac thuc GSSAPI cho phep tan cong man-in-the-middle"
)

# Mang ket qua lo hong duoc phat hien
FOUND_VULNS=()

# Kiem tra tung lo hong
for vuln in "${SSH_VULNS[@]}"; do
    IFS=':' read -r cve severity affected_version description <<< "$vuln"
    
    verbose_log "Kiem tra $cve ($affected_version)"
    
    # Kiem tra phien ban SSH co bi anh huong boi lo hong nay khong
    if [[ $SSH_VERSION == "Unknown" ]]; then
        # Neu khong the xac dinh phien ban, thuc hien kiem tra bo sung
        case "$cve" in
            "CVE-2018-15473")
                # Kiem tra lo hong liet ke nguoi dung
                verbose_log "Kiem tra lo hong liet ke nguoi dung (CVE-2018-15473)"
                python3 -c '
import socket, sys, struct, time
host = sys.argv[1]
port = int(sys.argv[2])
timeout = int(sys.argv[3])
user = "root"
sock = socket.socket()
sock.settimeout(timeout)
try:
    sock.connect((host, port))
    msg = sock.recv(1024)
    sock.send(b"SSH-2.0-OpenSSH_7.7\r\n")
    time.sleep(0.2)
    msg = sock.recv(1024)
    packet = struct.pack(">I", len(user) + 29) + b"\\x00\\x00\\x00\\x05" + b"ssh-rsa" + struct.pack(">I", len(user)) + user.encode()
    packet = struct.pack(">I", len(packet)) + packet
    sock.send(packet)
    time.sleep(0.2)
    response = sock.recv(1024)
    if response.find(b"publickey") != -1 or msg.find(b"Protocol mismatch") == -1:
        print("1")
    else:
        print("0")
except Exception as e:
    print("0")
sock.close()
' "$TARGET" "$SSH_PORT" "$TIMEOUT" > /dev/null 2>&1

                if [[ $? -eq 0 ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2016-0777")
                # Kiem tra lo hong roaming
                verbose_log "Kiem tra lo hong roaming (CVE-2016-0777)"
                
                echo "SSH-2.0-OpenSSH_7.1" | nc -w $TIMEOUT "$TARGET" "$SSH_PORT" 2>/dev/null | grep -q "roaming not supported"
                if [[ $? -eq 0 ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            *)
                # Khong the kiem tra lo hong cu the do thieu thong tin phien ban
                verbose_log "Bo qua kiem tra $cve: Khong du thong tin"
                ;;
        esac
    else
        # Kiem tra dua tren phien ban
        case "$cve" in
            "CVE-2002-0640")
                if [[ $SSH_VERSION == *"SSH-1"* ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2006-5051")
                if [[ $SSH_VERSION == *"SSH-1"* ]] || [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_2"* ]] || [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_3"* ]] || [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_4.3"* ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2008-4109")
                if [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_4.7"* ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2016-0777")
                if [[ $SSH_VERSION =~ SSH-2\.0-OpenSSH_([5-6]\.|7\.0|7\.1) ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2018-15473")
                if [[ ! $SSH_VERSION =~ SSH-2\.0-OpenSSH_7\.7p1 ]] && [[ ! $SSH_VERSION =~ SSH-2\.0-OpenSSH_[8-9] ]]; then
                    # Thu xac thuc voi username khong ton tai
                    python3 -c '
import socket, sys, struct, time
host = sys.argv[1]
port = int(sys.argv[2])
timeout = int(sys.argv[3])
user = "nonexistentuser123456789"
sock = socket.socket()
sock.settimeout(timeout)
try:
    sock.connect((host, port))
    msg = sock.recv(1024)
    sock.send(b"SSH-2.0-OpenSSH_7.7\r\n")
    time.sleep(0.2)
    msg = sock.recv(1024)
    packet = struct.pack(">I", len(user) + 29) + b"\\x00\\x00\\x00\\x05" + b"ssh-rsa" + struct.pack(">I", len(user)) + user.encode()
    packet = struct.pack(">I", len(packet)) + packet
    sock.send(packet)
    time.sleep(0.2)
    response = sock.recv(1024)
    if response.find(b"publickey") != -1:
        print("1")
    else:
        print("0")
except Exception as e:
    print("0")
sock.close()
' "$TARGET" "$SSH_PORT" "$TIMEOUT" 2>/dev/null | grep -q "1"
                    if [[ $? -eq 0 ]]; then
                        FOUND_VULNS+=("$cve:$severity:$description")
                    fi
                fi
                ;;
                
            "CVE-2019-6111")
                if [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_7.6"* ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2020-14145")
                if [[ $SSH_VERSION =~ SSH-2\.0-OpenSSH_([5-7]\.|8\.[0-3]) ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2021-28041")
                if [[ ! $SSH_VERSION =~ SSH-2\.0-OpenSSH_8\.5p1 ]] && [[ ! $SSH_VERSION =~ SSH-2\.0-OpenSSH_[9] ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
                
            "CVE-2023-38408")
                if [[ $SSH_VERSION == *"SSH-2.0-OpenSSH_9.3"* ]]; then
                    FOUND_VULNS+=("$cve:$severity:$description")
                fi
                ;;
        esac
    fi
done

# Kiem tra cau hinh SSH
log "INFO" "Kiem tra cau hinh SSH..."

# Kiem tra xem SSH cho phep dang nhap bang mat khau khong
if timeout $TIMEOUT nmap --script ssh-auth-methods -p $SSH_PORT "$TARGET" -oG - 2>/dev/null | grep -q "password"; then
    log "WARNING" "May chu cho phep xac thuc bang mat khau (khuyen nghi: chi su dung xac thuc khoa)"
fi

# Kiem tra xem SSH su dung phien ban 1 khong (khong an toan)
if timeout $TIMEOUT nmap --script ssh2-enum-algos -p $SSH_PORT "$TARGET" -oG - 2>/dev/null | grep -q "SSH-1"; then
    log "ERROR" "May chu ho tro giao thuc SSH v1 (khong an toan, nen vo hieu hoa)"
    FOUND_VULNS+=("CONFIG:HIGH:Ho tro SSH v1:Giao thuc SSH v1 da bi loi thoi va khong an toan")
fi

# Kiem tra cac thuat toan ma hoa yeu
if timeout $TIMEOUT nmap --script ssh2-enum-algos -p $SSH_PORT "$TARGET" -oG - 2>/dev/null | grep -iE "arcfour|3des|blowfish|cast128"; then
    log "WARNING" "May chu ho tro cac thuat toan ma hoa yeu (arcfour, 3des, blowfish, cast128)"
    FOUND_VULNS+=("CONFIG:MEDIUM:Thuat toan ma hoa yeu:Su dung cac thuat toan ma hoa yeu (arcfour, 3des, blowfish, cast128)")
fi

# Hien thi ket qua
echo -e "\n${CYAN}═════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}              KET QUA KIEM TRA LO HONG                   ${NC}"
echo -e "${CYAN}═════════════════════════════════════════════════════════${NC}"

if [[ ${#FOUND_VULNS[@]} -eq 0 ]]; then
    log "SUCCESS" "Khong phat hien lo hong bao mat da biet trong dich vu SSH"
else
    log "VULN" "Phat hien ${#FOUND_VULNS[@]} lo hong bao mat:"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "\nDanh sach lo hong duoc phat hien:" >> "$OUTPUT_FILE"
    fi
    
    # Hien thi cac lo hong phat hien duoc theo muc do nghiem trong
    for severity in "HIGH" "MEDIUM" "LOW"; do
        for vuln in "${FOUND_VULNS[@]}"; do
            IFS=':' read -r cve current_severity description <<< "$vuln"
            
            if [[ "$current_severity" == "$severity" ]]; then
                case "$severity" in
                    "HIGH") color="${RED}";;
                    "MEDIUM") color="${YELLOW}";;
                    "LOW") color="${BLUE}";;
                    *) color="${NC}";;
                esac
                
                echo -e "${color}[$severity] $cve: $description${NC}"
                
                if [[ -n "$OUTPUT_FILE" ]]; then
                    echo "[$severity] $cve: $description" >> "$OUTPUT_FILE"
                fi
                
                # Hien thi thong tin tham khao cho lo hong
                echo -e "    Tham khao: https://nvd.nist.gov/vuln/detail/$cve"
                
                if [[ -n "$OUTPUT_FILE" ]]; then
                    echo "    Tham khao: https://nvd.nist.gov/vuln/detail/$cve" >> "$OUTPUT_FILE"
                fi
            fi
        done
    done
    
    # Hien thi cac lo hong cau hinh
    for vuln in "${FOUND_VULNS[@]}"; do
        IFS=':' read -r cve current_severity description <<< "$vuln"
        
        if [[ "$cve" == "CONFIG" ]]; then
            case "$current_severity" in
                "HIGH") color="${RED}";;
                "MEDIUM") color="${YELLOW}";;
                "LOW") color="${BLUE}";;
                *) color="${NC}";;
            esac
            
            echo -e "${color}[$current_severity] Loi cau hinh: $description${NC}"
            
            if [[ -n "$OUTPUT_FILE" ]]; then
                echo "[$current_severity] Loi cau hinh: $description" >> "$OUTPUT_FILE"
            fi
        fi
    done
    
    # Hien thi khuyen nghi
    echo -e "\n${CYAN}Khuyen nghi:${NC}"
    echo -e "  - Cap nhat OpenSSH len phien ban moi nhat"
    echo -e "  - Cau hinh SSH theo tieu chuan bao mat: tat SSHv1, chi su dung xac thuc khoa"
    echo -e "  - Vo hieu hoa cac thuat toan ma hoa yeu"
    echo -e "  - Su dung tuong lua han che dia chi IP duoc phep truy cap SSH"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "\nKhuyen nghi:" >> "$OUTPUT_FILE"
        echo "  - Cap nhat OpenSSH len phien ban moi nhat" >> "$OUTPUT_FILE"
        echo "  - Cau hinh SSH theo tieu chuan bao mat: tat SSHv1, chi su dung xac thuc khoa" >> "$OUTPUT_FILE"
        echo "  - Vo hieu hoa cac thuat toan ma hoa yeu" >> "$OUTPUT_FILE"
        echo "  - Su dung tuong lua han che dia chi IP duoc phep truy cap SSH" >> "$OUTPUT_FILE"
    fi
fi

echo -e "\n${CYAN}═════════════════════════════════════════════════════════${NC}"

# Ket thuc
if [[ -n "$OUTPUT_FILE" ]]; then
    log "INFO" "Ket qua da duoc luu vao file: $OUTPUT_FILE"
fi

log "INFO" "Qua trinh quet hoan tat"