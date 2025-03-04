<#
.SYNOPSIS
    Enhanced PowerShell Credential Finder for OSCP
.DESCRIPTION
    Công cụ tìm kiếm nâng cao cho các credentials và thông tin nhạy cảm trong hệ thống.
    Tìm kiếm trong files, Registry, Credential Manager, và các nguồn khác.
.PARAMETER SearchPath
    Đường dẫn thư mục gốc để quét (mặc định là C:\)
.PARAMETER FileExtensions
    Danh sách các đuôi tệp cần quét
.PARAMETER Keywords
    Danh sách từ khóa cần tìm kiếm
.PARAMETER OutputFile
    File xuất kết quả (mặc định là trong thư mục Temp với timestamp)
.PARAMETER IncludeRegistry
    Nếu được đặt, sẽ quét Registry tìm credentials
.PARAMETER IncludeCredentialManager
    Nếu được đặt, sẽ quét Windows Credential Manager
.PARAMETER Thorough
    Nếu được đặt, sẽ thực hiện quét kỹ lưỡng hơn (tốn thời gian hơn)
.EXAMPLE
    .\Enhanced-CredentialFinder.ps1 -SearchPath "C:\Users" -Thorough -IncludeRegistry -IncludeCredentialManager
#>

param(
    # Đường dẫn thư mục gốc để quét (mặc định là C:\)
    [string]$SearchPath = "C:\",
    
    # Danh sách các đuôi tệp cần quét (mở rộng so với script gốc)
    [string[]]$FileExtensions = @(
        "*.txt", "*.log", "*.conf", "*.ini", "*.config", "*.xml", "*.json", "*.yml", "*.yaml",
        "*.properties", "*.cfg", "*.env", "*.cnf", "*.php", "*.aspx", "*.asp", "*.jsp", "*.js",
        "*.py", "*.rb", "*.bak", "*.old", "*.backup", "*.sql", "*.db", "*.sqlite", "*.mdb",
        "*.pem", "*.key", "*.ppk", "*.pfx", "*.p12", "*.ps1", "*.bat", "*.cmd"
    ),
    
    # Danh sách từ khóa cần tìm kiếm (mở rộng so với script gốc)
    [string[]]$Keywords = @(
        "password:", "oscp{", "pwd:", "pass:", "passwd:", "username:", "user:", "administrator:", 
        "admin:", "root:", "secret:", "login:", "credentials:", "private_key:", "secret_key:",
        "api_key:", "auth:", "token:", "connectionString:", "connectionstring:", "DB_PASSWORD:",
        "DATABASE_PASSWORD", "APIKEY", "API_TOKEN", "SECRET_TOKEN", "AWS_SECRET", "AWS_KEY",
        "AZURE_PASSWORD", "SSH_PRIVATE", "RSA PRIVATE", "PASSWORD=", "PWD=", "DB_PASS", 
        "DBPASS", "PASSW=", "apitoken", "api_secret", "client_secret", "oauth"
    ),
    
    # File xuất kết quả với timestamp
    [string]$OutputFile = "$env:TEMP\CredScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    
    # Quét Registry
    [switch]$IncludeRegistry = $true,
    
    # Quét Credential Manager
    [switch]$IncludeCredentialManager = $true,
    
    # Quét kỹ lưỡng hơn (tốn thời gian hơn)
    [switch]$Thorough = $false
)

function Write-Banner {
    $banner = @"
 _____              _       _   _       _   _____ _           _           
/  __ \            | |     | | (_)     | | |  ___(_)         | |          
| /  \/ _ __  _   _| |_ __ | |_ _  __ _| | | |_   _ _ __   __| | ___ _ __ 
| |    | '_ \| | | | __/ _\| __| |/ _\ | | |  _| | | '_ \ / _\ |/ _ \ '__|
| \__/\| |_) | |_| | || (_|| |_| | (_| | | | |   | | | | | (_| |  __/ |   
 \____/| .__/ \__, |\__\__/ \__|_|\__,_|_| \_|   |_|_| |_|\__,_|\___|_|   
       | |     __/ |                      Enhanced for OSCP               
       |_|    |___/                                                       
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "Developed for OSCP Exam Scenarios" -ForegroundColor Yellow
    Write-Host "======================================================`n"
}

Write-Banner

# Kiểm tra quyền admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin) {
    Write-Warning "Script không chạy với quyền admin. Một số tính năng có thể sẽ bị hạn chế."
    Write-Host "Khuyến nghị: Chạy lại script với quyền Administrator để có kết quả tốt nhất.`n" -ForegroundColor Yellow
}

# Sử dụng thêm một file log chi tiết để dễ dàng phân tích
$LogFile = [System.IO.Path]::GetDirectoryName($OutputFile) + "\CredScan_Detail_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Initialize log file
"Enhanced Credential Finder for OSCP - $(Get-Date)`n" | Out-File -FilePath $LogFile
"Search Path: $SearchPath" | Out-File -FilePath $LogFile -Append
"Keywords: $($Keywords -join ', ')" | Out-File -FilePath $LogFile -Append
"File Extensions: $($FileExtensions -join ', ')" | Out-File -FilePath $LogFile -Append
"Registry Scan: $IncludeRegistry" | Out-File -FilePath $LogFile -Append
"Credential Manager Scan: $IncludeCredentialManager" | Out-File -FilePath $LogFile -Append
"Thorough Scan: $Thorough" | Out-File -FilePath $LogFile -Append
"======================================================`n" | Out-File -FilePath $LogFile -Append

Write-Host "Bắt đầu quét trong thư mục: $SearchPath" -ForegroundColor Cyan
Write-Host "Tìm kiếm các từ khóa: $($Keywords -join ', ')" -ForegroundColor Cyan
Write-Host "Kết quả sẽ được lưu vào file: $OutputFile" -ForegroundColor Cyan
Write-Host "Log chi tiết: $LogFile" -ForegroundColor Cyan
Write-Host "--------------------------------------------`n"

# Mảng chứa kết quả
$results = @()

# Danh sách thư mục quan trọng để tập trung quét
$ImportantPaths = @(
    "$env:SystemRoot\System32\config",
    "$env:SystemRoot\Repair",
    "$env:SystemRoot\Panther",
    "$env:SystemRoot\System32\inetsrv",
    "$env:ProgramFiles\Microsoft SQL Server",
    "${env:ProgramFiles(x86)}\Microsoft SQL Server",
    "$env:ProgramData",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:SystemDrive\inetpub",
    "$env:SystemDrive\xampp",
    "$env:SystemDrive\wamp",
    "$env:SystemDrive\wamp64",
    "$env:USERPROFILE\.ssh",
    "$env:USERPROFILE\.aws",
    "$env:USERPROFILE\.config"
)

function Find-CredentialsInFiles {
    param (
        [string]$Path,
        [string[]]$Extensions,
        [string[]]$KeywordList,
        [bool]$IsPriorityPath = $false
    )
    
    Write-Host "Đang quét trong $Path..." -ForegroundColor Yellow
    "Scanning directory: $Path" | Out-File -FilePath $LogFile -Append
    
    foreach ($extension in $Extensions) {
        try {
            $searchParams = @{
                Path = $Path
                Filter = $extension
                Recurse = $true
                ErrorAction = "SilentlyContinue"
            }
            
            # Nếu Thorough mode thì chúng ta cũng tìm cả file ẩn
            if ($Thorough) {
                $searchParams.Add("Force", $true)
                "Including hidden files in search for $extension" | Out-File -FilePath $LogFile -Append
            }
            
            # Thêm độ ưu tiên cho các thư mục quan trọng
            if ($IsPriorityPath) {
                Write-Host "  Đang quét các file $extension - Thư mục ưu tiên" -ForegroundColor Yellow
                "Scanning priority files with extension $extension" | Out-File -FilePath $LogFile -Append
            }
            else {
                Write-Host "  Đang quét các file $extension" -ForegroundColor Yellow
            }
            
            # Lấy danh sách các tệp có đuôi tương ứng
            Get-ChildItem @searchParams | ForEach-Object {
                $file = $_
                try {
                    # Tìm kiếm các dòng chứa từ khóa
                    $matches = Select-String -Path $file.FullName -Pattern ($KeywordList -join "|") -ErrorAction SilentlyContinue
                    if ($matches) {
                        foreach ($match in $matches) {
                            $context = $match.Line.Trim()
                            
                            # Kiểm tra nếu context quá dài, cắt bớt để đảm bảo readable
                            if ($context.Length -gt 150) {
                                $context = $context.Substring(0, 147) + "..."
                            }
                            
                            $outputLine = "[+] File: $($file.FullName)"
                            $outputLine += "`n    Line $($match.LineNumber): $context"
                            
                            # Xác định loại credential
                            $credType = "Unknown"
                            foreach ($keyword in $KeywordList) {
                                if ($context -match $keyword) {
                                    $credType = $keyword
                                    break
                                }
                            }
                            
                            # Thêm phân loại dựa trên loại tệp
                            $importance = "Medium"
                            $fileExt = $file.Extension.ToLower()
                            
                            if ($fileExt -match "\.key|\.pem|\.ppk|\.pfx|\.p12") {
                                $importance = "HIGH"
                            }
                            elseif ($context -match "password|passwd|root|admin|secret|connectionstring|private" -and
                                    ($fileExt -match "\.conf|\.ini|\.xml|\.config|\.env")) {
                                $importance = "HIGH"
                            }
                            elseif ($IsPriorityPath) {
                                $importance = "HIGH"
                            }
                            
                            $outputLine += "`n    [Type: $credType | Importance: $importance]`n"
                            
                            # Hiển thị ngay kết quả tìm thấy với màu sắc dựa trên mức độ quan trọng
                            if ($importance -eq "HIGH") {
                                Write-Host $outputLine -ForegroundColor Red
                            } else {
                                Write-Host $outputLine -ForegroundColor Green
                            }
                            
                            # Lưu kết quả vào mảng và log
                            $results += $outputLine
                            $outputLine | Out-File -FilePath $LogFile -Append
                        }
                    }
                }
                catch {
                    "Error reading file: $($file.FullName). Error: $_" | Out-File -FilePath $LogFile -Append
                }
            }
        }
        catch {
            "Error scanning with extension $extension in $Path. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
}

function Find-CredentialsInRegistry {
    Write-Host "`n[*] Đang quét Registry tìm credentials..." -ForegroundColor Yellow
    "[*] Scanning Registry for credentials" | Out-File -FilePath $LogFile -Append
    
    # Danh sách các khóa Registry thường chứa credentials
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP",
        "HKCU:\Software\TightVNC\Server",
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKCU:\Software\SimonTatham\PuTTY\Sessions",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\ORL\WinVNC3\Password",
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies",
        "HKCU:\Software\Microsoft\FTP",
        "HKCU:\Software\Microsoft\Windows Messaging Subsystem\Profiles",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon",
        "HKCU:\Software\Microsoft\Protected Storage System Provider"
    )
    
    # Danh sách các tên khóa phổ biến chứa thông tin nhạy cảm
    $SensitiveKeyNames = @(
        "password", "pwd", "passwd", "credentials", "username", "user", 
        "apikey", "connectionstring", "secret", "key", "login", "token",
        "auth", "authenticate", "DefaultPassword", "DefaultUser", "AutoLogon",
        "DefaultDomainName", "pass", "cred", "accountpassword"
    )
    
    # Quét từng khóa Registry
    foreach ($regPath in $RegistryPaths) {
        Write-Host "  Đang kiểm tra: $regPath" -ForegroundColor Yellow
        "Checking Registry Path: $regPath" | Out-File -FilePath $LogFile -Append
        
        try {
            # Thử đọc giá trị của khóa Registry
            if (Test-Path $regPath) {
                $properties = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                # Kiểm tra mỗi thuộc tính
                foreach ($property in $properties.PSObject.Properties) {
                    $propertyName = $property.Name
                    $propertyValue = $property.Value
                    
                    # Chỉ xử lý các thuộc tính không phải là phương thức của PSObject
                    if ($propertyName -ne "PSPath" -and $propertyName -ne "PSParentPath" -and 
                        $propertyName -ne "PSChildName" -and $propertyName -ne "PSDrive" -and 
                        $propertyName -ne "PSProvider") {
                        
                        # Chuyển đổi giá trị thành chuỗi để kiểm tra
                        $valueAsString = "$propertyValue"
                        
                        # Phân loại mức độ quan trọng
                        $importance = "MEDIUM"
                        
                        # Kiểm tra nếu tên thuộc tính chứa từ khóa nhạy cảm
                        foreach ($keyword in $SensitiveKeyNames) {
                            if ($propertyName -match $keyword) {
                                $importance = "HIGH"
                                break
                            }
                        }
                        
                        # Hiển thị tất cả các khóa có giá trị khác rỗng
                        if ($valueAsString.Trim() -ne "") {
                            $outputLine = "[+] Registry: $regPath"
                            $outputLine += "`n    Key: $propertyName"
                            
                            # Có thể là binary data hoặc dữ liệu khác, cố gắng hiển thị hợp lý
                            if ($valueAsString.Length -gt 150) {
                                $valueAsString = $valueAsString.Substring(0, 147) + "..."
                            }
                            
                            $outputLine += "`n    Value: $valueAsString"
                            $outputLine += "`n    [Type: Registry | Importance: $importance]`n"
                            
                            # Hiển thị kết quả với màu sắc tương ứng
                            if ($importance -eq "HIGH") {
                                Write-Host $outputLine -ForegroundColor Red
                            } else {
                                Write-Host $outputLine -ForegroundColor Yellow
                            }
                            
                            # Lưu kết quả
                            $results += $outputLine
                            $outputLine | Out-File -FilePath $LogFile -Append
                        }
                    }
                }
                
                # Nếu ở chế độ Thorough, quét các khóa con một cách đệ quy
                if ($Thorough) {
                    "Scanning subkeys of $regPath (Thorough mode)" | Out-File -FilePath $LogFile -Append
                    
                    # Lấy danh sách tất cả các khóa con
                    $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                    
                    foreach ($subKey in $subKeys) {
                        # Gọi đệ quy để kiểm tra các khóa con
                        $registryPath = $subKey.PSPath
                        Write-Host "    Đang kiểm tra khóa con: $registryPath" -ForegroundColor Yellow
                        "Checking Registry Subkey: $registryPath" | Out-File -FilePath $LogFile -Append
                        
                        try {
                            $subProperties = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
                            
                            # Kiểm tra mỗi thuộc tính
                            foreach ($property in $subProperties.PSObject.Properties) {
                                $propertyName = $property.Name
                                $propertyValue = $property.Value
                                
                                # Chỉ xử lý các thuộc tính không phải là phương thức của PSObject
                                if ($propertyName -ne "PSPath" -and $propertyName -ne "PSParentPath" -and 
                                    $propertyName -ne "PSChildName" -and $propertyName -ne "PSDrive" -and 
                                    $propertyName -ne "PSProvider") {
                                    
                                    # Chuyển đổi giá trị thành chuỗi để kiểm tra
                                    $valueAsString = "$propertyValue"
                                    
                                    # Phân loại mức độ quan trọng
                                    $importance = "MEDIUM"
                                    
                                    # Kiểm tra nếu tên thuộc tính chứa từ khóa nhạy cảm
                                    foreach ($keyword in $SensitiveKeyNames) {
                                        if ($propertyName -match $keyword) {
                                            $importance = "HIGH"
                                            break
                                        }
                                    }
                                    
                                    # Hiển thị tất cả các khóa có giá trị khác rỗng
                                    if ($valueAsString.Trim() -ne "") {
                                        $outputLine = "[+] Registry Subkey: $registryPath"
                                        $outputLine += "`n    Key: $propertyName"
                                        
                                        # Cắt ngắn giá trị nếu quá dài
                                        if ($valueAsString.Length -gt 150) {
                                            $valueAsString = $valueAsString.Substring(0, 147) + "..."
                                        }
                                        
                                        $outputLine += "`n    Value: $valueAsString"
                                        $outputLine += "`n    [Type: Registry Subkey | Importance: $importance]`n"
                                        
                                        # Hiển thị kết quả với màu sắc tương ứng
                                        if ($importance -eq "HIGH") {
                                            Write-Host $outputLine -ForegroundColor Red
                                        } else {
                                            Write-Host $outputLine -ForegroundColor Yellow
                                        }
                                        
                                        # Lưu kết quả
                                        $results += $outputLine
                                        $outputLine | Out-File -FilePath $LogFile -Append
                                    }
                                }
                            }
                        }
                        catch {
                            "Error accessing registry subkey: $registryPath. Error: $_" | Out-File -FilePath $LogFile -Append
                        }
                    }
                }
            }
            else {
                "Registry path not found: $regPath" | Out-File -FilePath $LogFile -Append
            }
        }
        catch {
            "Error accessing registry: $regPath. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
    
    # Tìm kiếm thêm các khóa liên quan đến AutoLogon
    try {
        $autoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if (Test-Path $autoLogonPath) {
            $autoLogonProps = Get-ItemProperty -Path $autoLogonPath -ErrorAction SilentlyContinue
            
            # Kiểm tra cụ thể cho AutoLogon
            if ($autoLogonProps.AutoAdminLogon -eq "1") {
                $outputLine = "[+] Windows AutoLogon Detected!"
                $outputLine += "`n    Registry: $autoLogonPath"
                
                if ($autoLogonProps.DefaultUserName) {
                    $outputLine += "`n    Username: $($autoLogonProps.DefaultUserName)"
                }
                
                if ($autoLogonProps.DefaultPassword) {
                    $outputLine += "`n    Password: $($autoLogonProps.DefaultPassword)"
                }
                
                if ($autoLogonProps.DefaultDomainName) {
                    $outputLine += "`n    Domain: $($autoLogonProps.DefaultDomainName)"
                }
                
                $outputLine += "`n    [Type: AutoLogon | Importance: HIGH]`n"
                
                # Hiển thị kết quả
                Write-Host $outputLine -ForegroundColor Red
                
                # Lưu kết quả
                $results += $outputLine
                $outputLine | Out-File -FilePath $LogFile -Append
            }
        }
    }
    catch {
        "Error checking AutoLogon: $_" | Out-File -FilePath $LogFile -Append
    }
}

function Find-CredentialsInCredentialManager {
    Write-Host "`n[*] Đang quét Windows Credential Manager..." -ForegroundColor Yellow
    "[*] Scanning Windows Credential Manager" | Out-File -FilePath $LogFile -Append
    
    try {
        # Sử dụng cmdkey để liệt kê các credentials đã lưu
        $credList = cmdkey /list
        
        if ($credList) {
            $outputLine = "[+] Windows Credential Manager entries:"
            $outputLine += "`n$($credList | Out-String)"
            $outputLine += "`n    [Type: Windows Credential Manager | Importance: HIGH]`n"
            
            # Hiển thị kết quả
            Write-Host $outputLine -ForegroundColor Red
            
            # Lưu kết quả
            $results += $outputLine
            $outputLine | Out-File -FilePath $LogFile -Append
        }
        else {
            Write-Host "  Không tìm thấy credentials trong Windows Credential Manager." -ForegroundColor Yellow
            "No credentials found in Windows Credential Manager" | Out-File -FilePath $LogFile -Append
        }
    }
    catch {
        "Error accessing Windows Credential Manager. Error: $_" | Out-File -FilePath $LogFile -Append
    }
    
    # Kiểm tra thêm WinVault nếu trong chế độ Thorough 
    if ($Thorough) {
        Write-Host "  Đang kiểm tra Windows Vault (PowerShell 5.1+)..." -ForegroundColor Yellow
        "[*] Checking Windows Vault (PowerShell 5.1+)" | Out-File -FilePath $LogFile -Append
        
        try {
            # Kiểm tra nếu Windows có hỗ trợ cmdlet Vault
            if (Get-Command -Name "Get-VaultCredential" -ErrorAction SilentlyContinue) {
                $vaultCreds = Get-VaultCredential
                
                if ($vaultCreds) {
                    $outputLine = "[+] Windows Vault credentials found:"
                    $outputLine += "`n$($vaultCreds | Format-List | Out-String)"
                    $outputLine += "`n    [Type: Windows Vault | Importance: HIGH]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Red
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
                else {
                    "No credentials found in Windows Vault" | Out-File -FilePath $LogFile -Append
                }
            }
            else {
                "Get-VaultCredential cmdlet not available on this system" | Out-File -FilePath $LogFile -Append
            }
        }
        catch {
            "Error accessing Windows Vault. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
}

function Find-SQLServerInstances {
    Write-Host "`n[*] Tìm kiếm SQL Server instances..." -ForegroundColor Yellow
    "[*] Searching for SQL Server instances" | Out-File -FilePath $LogFile -Append
    
    # Kiểm tra nếu SQL Server được cài đặt thông qua Registry
    try {
        $sqlInstances = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
        
        if ($sqlInstances -ne $null) {
            $outputLine = "[+] SQL Server Instances found:"
            $outputLine += "`n    Instances: $($sqlInstances.PSObject.Properties.Name -join ', ')"
            $outputLine += "`n    [Type: SQL Server | Importance: HIGH]`n"
            
            # Hiển thị kết quả
            Write-Host $outputLine -ForegroundColor Red
            
            # Lưu kết quả
            $results += $outputLine
            $outputLine | Out-File -FilePath $LogFile -Append
            
            # Tìm kiếm thêm các file config SQL
            Write-Host "  Đang tìm kiếm các file cấu hình SQL Server..." -ForegroundColor Yellow
            "[*] Searching for SQL Server config files" | Out-File -FilePath $LogFile -Append
            
            $sqlPaths = @(
                "$env:ProgramFiles\Microsoft SQL Server",
                "${env:ProgramFiles(x86)}\Microsoft SQL Server"
            )
            
            foreach ($sqlPath in $sqlPaths) {
                if (Test-Path $sqlPath) {
                    # Tìm các file config
                    $configFiles = Get-ChildItem -Path $sqlPath -Recurse -Include "*.ini", "*.config" -ErrorAction SilentlyContinue
                    
                    foreach ($file in $configFiles) {
                        $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
                        
                        if ($content -match "password|pwd|user|login|credentials|connection") {
                            $outputLine = "[+] SQL Server Config File: $($file.FullName)"
                            $outputLine += "`n    Contains potential credentials"
                            $outputLine += "`n    [Type: SQL Config | Importance: HIGH]`n"
                            
                            # Hiển thị kết quả
                            Write-Host $outputLine -ForegroundColor Red
                            
                            # Lưu kết quả
                            $results += $outputLine
                            $outputLine | Out-File -FilePath $LogFile -Append
                        }
                    }
                }
            }
        }
        else {
            "[*] No SQL Server instances found in registry" | Out-File -FilePath $LogFile -Append
        }
    }
    catch {
        "Error checking SQL Server instances. Error: $_" | Out-File -FilePath $LogFile -Append
    }
}

function Find-WebConfigs {
    Write-Host "`n[*] Tìm kiếm các file web.config chứa connection strings..." -ForegroundColor Yellow
    "[*] Searching for web.config files with connection strings" | Out-File -FilePath $LogFile -Append
    
    $webPaths = @(
        "$env:SystemDrive\inetpub",
        "$env:SystemDrive\xampp",
        "$env:SystemDrive\wamp",
        "$env:SystemDrive\wamp64",
        "$env:ProgramFiles\IIS Express",
        "$env:SystemDrive\websites",
        "$env:SystemDrive\wwwroot"
    )
    
    foreach ($webPath in $webPaths) {
        if (Test-Path $webPath) {
            Write-Host "  Đang quét $webPath tìm web.config..." -ForegroundColor Yellow
            "[*] Scanning $webPath for web.config files" | Out-File -FilePath $LogFile -Append
            
            $webConfigs = Get-ChildItem -Path $webPath -Recurse -Include "web.config", "app.config", "appsettings.json" -ErrorAction SilentlyContinue
            
            foreach ($config in $webConfigs) {
                $content = Get-Content -Path $config.FullName -ErrorAction SilentlyContinue
                
                if ($content -match "connectionString|password|user|credentials|authentication") {
                    $outputLine = "[+] Web Config File: $($config.FullName)"
                    $outputLine += "`n    Contains connection strings or credentials"
                    
                    # Extract the specific connection string lines
                    $matches = Select-String -Path $config.FullName -Pattern "connectionString|password|user id|credentials|authentication" -ErrorAction SilentlyContinue
                    if ($matches) {
                        $outputLine += "`n    Matching lines:"
                        foreach ($match in $matches) {
                            $line = $match.Line.Trim()
                            if ($line.Length -gt 150) {
                                $line = $line.Substring(0, 147) + "..."
                            }
                            $outputLine += "`n      Line $($match.LineNumber): $line"
                        }
                    }
                    
                    $outputLine += "`n    [Type: Web Config | Importance: HIGH]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Red
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
            }
        }
    }
}

function Find-SSHKeys {
    Write-Host "`n[*] Tìm kiếm SSH Keys và certificates..." -ForegroundColor Yellow
    "[*] Searching for SSH Keys and certificates" | Out-File -FilePath $LogFile -Append
    
    $sshPaths = @(
        "$env:USERPROFILE\.ssh",
        "C:\Users\*\.ssh",
        "$env:ProgramData\ssh",
        "C:\Program Files\Git\.ssh"
    )
    
    $keyExtensions = @("*.pem", "*.key", "*.ppk", "*.p12", "*.pfx", "*.cer", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
    
    foreach ($sshPath in $sshPaths) {
        # Sử dụng Resolve-Path với wildcards và xử lý lỗi
        try {
            $paths = Resolve-Path -Path $sshPath -ErrorAction SilentlyContinue | Where-Object { Test-Path $_.Path }
            
            foreach ($path in $paths) {
                Write-Host "  Đang kiểm tra thư mục: $($path.Path)" -ForegroundColor Yellow
                "[*] Checking SSH directory: $($path.Path)" | Out-File -FilePath $LogFile -Append
                
                foreach ($ext in $keyExtensions) {
                    $keys = Get-ChildItem -Path $path.Path -Filter $ext -Force -ErrorAction SilentlyContinue
                    
                    foreach ($key in $keys) {
                        $outputLine = "[+] SSH Key/Certificate found: $($key.FullName)"
                        $outputLine += "`n    File size: $($key.Length) bytes"
                        $outputLine += "`n    Last modified: $($key.LastWriteTime)"
                        
                        # Check if it's a private key
                        $content = Get-Content -Path $key.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content -match "PRIVATE KEY|RSA PRIVATE|BEGIN DSA|BEGIN EC") {
                            $outputLine += "`n    [Contains PRIVATE KEY]"
                        }
                        
                        $outputLine += "`n    [Type: SSH/Certificate | Importance: HIGH]`n"
                        
                        # Hiển thị kết quả
                        Write-Host $outputLine -ForegroundColor Red
                        
                        # Lưu kết quả
                        $results += $outputLine
                        $outputLine | Out-File -FilePath $LogFile -Append
                    }
                }
            }
        }
        catch {
            "Error accessing SSH path: $sshPath. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
}

function Find-BrowserData {
    Write-Host "`n[*] Tìm kiếm dữ liệu trình duyệt (Chrome, Firefox, Edge)..." -ForegroundColor Yellow
    "[*] Searching for browser data" | Out-File -FilePath $LogFile -Append
    
    # Chrome
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
        "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default"
    )
    
    # Edge
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
        "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default"
    )
    
    # Firefox
    $firefoxPaths = @(
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles"
    )
    
    # Check Chrome
    foreach ($chromePath in $chromePaths) {
        try {
            $paths = Resolve-Path -Path $chromePath -ErrorAction SilentlyContinue | Where-Object { Test-Path $_.Path }
            
            foreach ($path in $paths) {
                Write-Host "  Đang kiểm tra Chrome profile: $($path.Path)" -ForegroundColor Yellow
                "[*] Checking Chrome profile: $($path.Path)" | Out-File -FilePath $LogFile -Append
                
                # Check Login Data
                $loginDataPath = Join-Path -Path $path.Path -ChildPath "Login Data"
                if (Test-Path $loginDataPath) {
                    $outputLine = "[+] Chrome Login Data found: $loginDataPath"
                    $outputLine += "`n    [Type: Browser Credentials | Importance: HIGH]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Red
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
                
                # Check Web Data
                $webDataPath = Join-Path -Path $path.Path -ChildPath "Web Data"
                if (Test-Path $webDataPath) {
                    $outputLine = "[+] Chrome Web Data found: $webDataPath"
                    $outputLine += "`n    [Type: Browser Data | Importance: MEDIUM]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Yellow
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
                
                # Check Cookies
                $cookiesPath = Join-Path -Path $path.Path -ChildPath "Cookies"
                if (Test-Path $cookiesPath) {
                    $outputLine = "[+] Chrome Cookies found: $cookiesPath"
                    $outputLine += "`n    [Type: Browser Cookies | Importance: MEDIUM]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Yellow
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
            }
        }
        catch {
            "Error accessing Chrome path: $chromePath. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
    
    # Check Edge
    foreach ($edgePath in $edgePaths) {
        try {
            $paths = Resolve-Path -Path $edgePath -ErrorAction SilentlyContinue | Where-Object { Test-Path $_.Path }
            
            foreach ($path in $paths) {
                Write-Host "  Đang kiểm tra Edge profile: $($path.Path)" -ForegroundColor Yellow
                "[*] Checking Edge profile: $($path.Path)" | Out-File -FilePath $LogFile -Append
                
                # Check Login Data
                $loginDataPath = Join-Path -Path $path.Path -ChildPath "Login Data"
                if (Test-Path $loginDataPath) {
                    $outputLine = "[+] Edge Login Data found: $loginDataPath"
                    $outputLine += "`n    [Type: Browser Credentials | Importance: HIGH]`n"
                    
                    # Hiển thị kết quả
                    Write-Host $outputLine -ForegroundColor Red
                    
                    # Lưu kết quả
                    $results += $outputLine
                    $outputLine | Out-File -FilePath $LogFile -Append
                }
            }
        }
        catch {
            "Error accessing Edge path: $edgePath. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
    
    # Check Firefox
    foreach ($firefoxPath in $firefoxPaths) {
        try {
            $paths = Resolve-Path -Path $firefoxPath -ErrorAction SilentlyContinue | Where-Object { Test-Path $_.Path }
            
            foreach ($path in $paths) {
                Write-Host "  Đang kiểm tra Firefox profiles: $($path.Path)" -ForegroundColor Yellow
                "[*] Checking Firefox profiles: $($path.Path)" | Out-File -FilePath $LogFile -Append
                
                # Get all profile directories
                $profileDirs = Get-ChildItem -Path $path.Path -Directory -ErrorAction SilentlyContinue
                
                foreach ($profileDir in $profileDirs) {
                    # Check logins.json
                    $loginsPath = Join-Path -Path $profileDir.FullName -ChildPath "logins.json"
                    if (Test-Path $loginsPath) {
                        $outputLine = "[+] Firefox Logins found: $loginsPath"
                        $outputLine += "`n    [Type: Browser Credentials | Importance: HIGH]`n"
                        
                        # Hiển thị kết quả
                        Write-Host $outputLine -ForegroundColor Red
                        
                        # Lưu kết quả
                        $results += $outputLine
                        $outputLine | Out-File -FilePath $LogFile -Append
                    }
                    
                    # Check key4.db (password database)
                    $keyDbPath = Join-Path -Path $profileDir.FullName -ChildPath "key4.db"
                    if (Test-Path $keyDbPath) {
                        $outputLine = "[+] Firefox Key Database found: $keyDbPath"
                        $outputLine += "`n    [Type: Browser Credentials | Importance: HIGH]`n"
                        
                        # Hiển thị kết quả
                        Write-Host $outputLine -ForegroundColor Red
                        
                        # Lưu kết quả
                        $results += $outputLine
                        $outputLine | Out-File -FilePath $LogFile -Append
                    }
                }
            }
        }
        catch {
            "Error accessing Firefox path: $firefoxPath. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    }
}

# Main execution flow
# ------------------

# First scan regular files in main path
Write-Host "`n[+] STARTING FILE SYSTEM SCAN" -ForegroundColor Cyan
"[+] STARTING FILE SYSTEM SCAN" | Out-File -FilePath $LogFile -Append

Find-CredentialsInFiles -Path $SearchPath -Extensions $FileExtensions -KeywordList $Keywords

# Scan important directories with high priority
Write-Host "`n[+] SCANNING HIGH-PRIORITY DIRECTORIES" -ForegroundColor Cyan
"[+] SCANNING HIGH-PRIORITY DIRECTORIES" | Out-File -FilePath $LogFile -Append

foreach ($path in $ImportantPaths) {
    if (Test-Path $path) {
        Find-CredentialsInFiles -Path $path -Extensions $FileExtensions -KeywordList $Keywords -IsPriorityPath $true
    }
}

# Registry scan if enabled
if ($IncludeRegistry) {
    Write-Host "`n[+] STARTING REGISTRY SCAN" -ForegroundColor Cyan
    "[+] STARTING REGISTRY SCAN" | Out-File -FilePath $LogFile -Append
    Find-CredentialsInRegistry
}

# Credential Manager scan if enabled
if ($IncludeCredentialManager) {
    Write-Host "`n[+] STARTING CREDENTIAL MANAGER SCAN" -ForegroundColor Cyan
    "[+] STARTING CREDENTIAL MANAGER SCAN" | Out-File -FilePath $LogFile -Append
    Find-CredentialsInCredentialManager
}

# Web config files scan
Write-Host "`n[+] SCANNING WEB CONFIG FILES" -ForegroundColor Cyan
"[+] SCANNING WEB CONFIG FILES" | Out-File -FilePath $LogFile -Append
Find-WebConfigs

# SSH keys and certificates scan
Write-Host "`n[+] SCANNING FOR SSH KEYS AND CERTIFICATES" -ForegroundColor Cyan
"[+] SCANNING FOR SSH KEYS AND CERTIFICATES" | Out-File -FilePath $LogFile -Append
Find-SSHKeys

# SQL Server instances scan
Write-Host "`n[+] SCANNING FOR SQL SERVER INSTANCES" -ForegroundColor Cyan
"[+] SCANNING FOR SQL SERVER INSTANCES" | Out-File -FilePath $LogFile -Append
Find-SQLServerInstances

# Browser data scan
Write-Host "`n[+] SCANNING BROWSER DATA" -ForegroundColor Cyan
"[+] SCANNING BROWSER DATA" | Out-File -FilePath $LogFile -Append
Find-BrowserData

# Summary and results
Write-Host "`n[+] SCAN COMPLETED!" -ForegroundColor Green
"[+] SCAN COMPLETED!" | Out-File -FilePath $LogFile -Append

$totalFindings = $results.Count

Write-Host "`n====== SUMMARY ======" -ForegroundColor Cyan
Write-Host "Total credential findings: $totalFindings" -ForegroundColor Yellow
Write-Host "Results saved to: $OutputFile" -ForegroundColor Yellow
Write-Host "Detailed logs saved to: $LogFile" -ForegroundColor Yellow
Write-Host "======================" -ForegroundColor Cyan

"====== SUMMARY ======" | Out-File -FilePath $LogFile -Append
"Total credential findings: $totalFindings" | Out-File -FilePath $LogFile -Append
"Results saved to: $OutputFile" | Out-File -FilePath $LogFile -Append
"======================" | Out-File -FilePath $LogFile -Append

# Export results to file
if ($results.Count -gt 0) {
    # Create a header for the output file
    "Enhanced Credential Finder Results - $(Get-Date)" | Out-File -FilePath $OutputFile -Encoding UTF8
    "Target: $SearchPath" | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    "============================================================`n" | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    
    # Add all results
    $results | Out-File -FilePath $OutputFile -Append -Encoding UTF8
    
    Write-Host "`n[*] Results have been saved to: $OutputFile" -ForegroundColor Green
} else {
    Write-Host "`n[-] No credentials were found matching the specified criteria." -ForegroundColor Red
    "No credentials were found matching the specified criteria." | Out-File -FilePath $OutputFile -Encoding UTF8
}

# Provide additional guidance
Write-Host "`n[*] Scan completed. Remember to check the following manually:" -ForegroundColor Yellow
Write-Host "  - Look for hardcoded credentials in custom applications" -ForegroundColor Yellow
Write-Host "  - Check Group Policy preferences for credentials" -ForegroundColor Yellow
Write-Host "  - Review found connection strings for sensitive data" -ForegroundColor Yellow
Write-Host "  - Investigate browser data files using specialized tools" -ForegroundColor Yellow

# Clean-up
[System.GC]::Collect()