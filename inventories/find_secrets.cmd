@echo off
setlocal enabledelayedexpansion

echo =====================================================
echo TIM KIEM CREDENTIALS TRONG HE THONG
echo =====================================================
echo.

:: Tao thu muc ket qua
set "output_dir=%TEMP%\credential_finder_results"
set "log_file=%output_dir%\credential_scan_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log"
set "log_file=%log_file: =0%"

if not exist "%output_dir%" mkdir "%output_dir%"

echo [+] Bat dau tim kiem credentials vao: %date% %time% > "%log_file%"
echo [+] Ket qua se duoc luu tai: %log_file%
echo.

:: Danh sach dinh dang file can tim kiem
set "file_types=conf ini txt xml json config properties cfg env yaml yml cnf log ini php jsp asp aspx py rb js html htm db sql sqlite mdb bak old backup"

:: Danh sach tu khoa can tim kiem
set "keywords=password: Password: pwd: Pwd: pass: Pass: passwd: Passwd: username: Username: user: User: administrator: Administrator: admin: Admin: root: Root: secret: Secret: login: Login: credentials: Credentials: private_key: Private_Key: secret_key: Secret_Key: api_key: Api_Key: auth: Auth: token: Token: connectionString: ConnectionString: db_password: DB_Password: DatabasePassword:"

:: Chuyen keywords thanh file tam thoi
set "keywords_file=%TEMP%\cred_finder_keywords.txt"
(for %%k in (%keywords%) do echo %%k) > "%keywords_file%"

echo [+] KIEM TRA CAC FILE CONFIGURATION
echo [+] KIEM TRA CAC FILE CONFIGURATION >> "%log_file%"
echo. >> "%log_file%"

:: Lay danh sach tat ca cac o dia
for /f "tokens=1" %%i in ('wmic logicaldisk get deviceid ^| findstr :') do (
    set "drive=%%i"
    if exist "!drive!\" (
        echo Dang quet o dia !drive!...
        echo [+] Dang quet o dia !drive!... >> "%log_file%"
        
        :: Tim kiem tren moi o dia cho moi dinh dang file
        for %%t in (%file_types%) do (
            echo Dang tim kiem trong cac file .%%t tren !drive!...
            echo [+] Tim kiem trong cac file .%%t tren !drive!... >> "%log_file%"
            
            :: Tim kiem trong cac file co chua keywords
            for /f "delims=" %%a in ('dir "!drive!\*.%%t" /s /b 2^>nul') do (
                findstr /i /g:"%keywords_file%" "%%a" >nul 2>&1
                if not errorlevel 1 (
                    echo [+] FOUND CREDENTIALS trong file: %%a
                    echo [+] FOUND CREDENTIALS trong file: %%a >> "%log_file%"
                    echo    Noi dung:
                    echo    Noi dung: >> "%log_file%"
                    echo    ----------------------------------------------
                    echo    ---------------------------------------------- >> "%log_file%"
                    
                    for /f "tokens=1* delims=:" %%p in ('findstr /i /n /g:"%keywords_file%" "%%a" 2^>nul') do (
                        echo    Line %%p: %%q
                        echo    Line %%p: %%q >> "%log_file%"
                    )
                    
                    echo    ----------------------------------------------
                    echo    ---------------------------------------------- >> "%log_file%"
                    echo.
                    echo. >> "%log_file%"
                )
            )
        )
    ) else (
        echo O dia !drive! khong ton tai hoac khong the truy cap, dang bo qua...
        echo [-] O dia !drive! khong ton tai hoac khong the truy cap, dang bo qua... >> "%log_file%"
    )
)

:: Tim kiem cac thu muc quan trong
echo.
echo [+] TIM KIEM TRONG CAC THU MUC QUAN TRONG
echo [+] TIM KIEM TRONG CAC THU MUC QUAN TRONG >> "%log_file%"
echo. >> "%log_file%"

:: Danh sach thu muc quan trong
set "important_paths=C:\inetpub,C:\xampp,C:\wamp,C:\wamp64,C:\Program Files,C:\Program Files (x86),C:\ProgramData,C:\Windows\System32\config,C:\Windows\Panther,C:\WINDOWS\repair,C:\Documents and Settings,C:\Users\Administrator,C:\Users\Public,C:\AppServ"

for %%p in (%important_paths%) do (
    set "current_path=%%p"
    if exist "!current_path!" (
        echo Dang quet thu muc !current_path!...
        echo [+] Dang quet thu muc !current_path!... >> "%log_file%"
        
        :: Tim kiem trong moi dinh dang file
        for %%t in (%file_types%) do (
            for /f "delims=" %%a in ('dir "!current_path!\*.%%t" /s /b 2^>nul') do (
                findstr /i /g:"%keywords_file%" "%%a" >nul 2>&1
                if not errorlevel 1 (
                    echo [+] FOUND CREDENTIALS trong file: %%a
                    echo [+] FOUND CREDENTIALS trong file: %%a >> "%log_file%"
                    echo    Noi dung:
                    echo    Noi dung: >> "%log_file%"
                    echo    ----------------------------------------------
                    echo    ---------------------------------------------- >> "%log_file%"
                    
                    for /f "tokens=1* delims=:" %%p in ('findstr /i /n /g:"%keywords_file%" "%%a" 2^>nul') do (
                        echo    Line %%p: %%q
                        echo    Line %%p: %%q >> "%log_file%"
                    )
                    
                    echo    ----------------------------------------------
                    echo    ---------------------------------------------- >> "%log_file%"
                    echo.
                    echo. >> "%log_file%"
                )
            )
        )
    ) else (
        echo Thu muc !current_path! khong ton tai hoac khong the truy cap, dang bo qua...
        echo [-] Thu muc !current_path! khong ton tai hoac khong the truy cap... >> "%log_file%"
    )
)

:: Tim kiem trong cac thu muc home cua tung user
echo.
echo [+] TIM KIEM TRONG THU MUC HOME CUA CAC USER
echo [+] TIM KIEM TRONG THU MUC HOME CUA CAC USER >> "%log_file%"
echo. >> "%log_file%"

if exist "C:\Users\" (
    for /d %%u in (C:\Users\*) do (
        echo Dang quet thu muc cua user: %%~nxu
        echo [+] Dang quet thu muc cua user: %%~nxu >> "%log_file%"
        
        :: Tim kiem trong cac thu muc phổ biến
        set "user_paths=Desktop,Documents,Downloads,.ssh,.config,.aws,AppData\Roaming,AppData\Local"
        
        for %%p in (%user_paths%) do (
            if exist "%%u\%%p" (
                for %%t in (%file_types%) do (
                    for /f "delims=" %%a in ('dir "%%u\%%p\*.%%t" /s /b 2^>nul') do (
                        findstr /i /g:"%keywords_file%" "%%a" >nul 2>&1
                        if not errorlevel 1 (
                            echo [+] FOUND CREDENTIALS trong file: %%a
                            echo [+] FOUND CREDENTIALS trong file: %%a >> "%log_file%"
                            echo    Noi dung:
                            echo    Noi dung: >> "%log_file%"
                            echo    ----------------------------------------------
                            echo    ---------------------------------------------- >> "%log_file%"
                            
                            for /f "tokens=1* delims=:" %%p in ('findstr /i /n /g:"%keywords_file%" "%%a" 2^>nul') do (
                                echo    Line %%p: %%q
                                echo    Line %%p: %%q >> "%log_file%"
                            )
                            
                            echo    ----------------------------------------------
                            echo    ---------------------------------------------- >> "%log_file%"
                            echo.
                            echo. >> "%log_file%"
                        )
                    )
                )
            )
        )
    )
)

echo.
echo [+] TIM KIEM CREDENTIALS TRONG REGISTRY
echo [+] TIM KIEM CREDENTIALS TRONG REGISTRY >> "%log_file%"
echo. >> "%log_file%"

:: Luu các khóa registry vào file tạm thời
set "reg_tmp=%output_dir%\reg_dump.txt"

:: Danh sách các khóa registry cần kiểm tra
set "reg_keys=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon,HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU,HKLM\SYSTEM\CurrentControlSet\Services\SNMP,HKCU\Software\TightVNC\Server,HKLM\SOFTWARE\RealVNC\WinVNC4,HKCU\Software\SimonTatham\PuTTY\Sessions,HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall,HKCU\Software\ORL\WinVNC3\Password,HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce,HKCU\Software\Microsoft\Windows\CurrentVersion\Run,HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce,HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer,HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings,HKLM\SYSTEM\CurrentControlSet\Services\SNMP,HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

:: Export và kiểm tra từng khóa registry
for %%k in (%reg_keys%) do (
    echo Dang kiem tra Registry Key: %%k
    echo [+] Dang kiem tra Registry Key: %%k >> "%log_file%"
    
    reg export "%%k" "%reg_tmp%" /y >nul 2>&1
    if exist "%reg_tmp%" (
        findstr /i "password pwd passwd credentials username apikey connectionstring" "%reg_tmp%" >nul 2>&1
        if not errorlevel 1 (
            echo [+] FOUND POTENTIAL CREDENTIALS trong registry key: %%k
            echo [+] FOUND POTENTIAL CREDENTIALS trong registry key: %%k >> "%log_file%"
            echo    Noi dung:
            echo    Noi dung: >> "%log_file%"
            echo    ----------------------------------------------
            echo    ---------------------------------------------- >> "%log_file%"
            
            findstr /i "password pwd passwd credentials username apikey connectionstring" "%reg_tmp%" >> "%log_file%"
            findstr /i "password pwd passwd credentials username apikey connectionstring" "%reg_tmp%"
            
            echo    ----------------------------------------------
            echo    ---------------------------------------------- >> "%log_file%"
            echo.
            echo. >> "%log_file%"
        )
    )
)

:: Kiểm tra các mật khẩu lưu trong Credential Manager
echo.
echo [+] KIEM TRA CREDENTIAL MANAGER
echo [+] KIEM TRA CREDENTIAL MANAGER >> "%log_file%"
echo. >> "%log_file%"

:: Tạo file tạm chứa các lệnh PowerShell
set "ps_script=%TEMP%\get_creds.ps1"

echo try { > "%ps_script%"
echo   $output = cmdkey /list ^| Out-String >> "%ps_script%"
echo   if ($output -match "Currently stored credentials:") { >> "%ps_script%"
echo     Write-Output "[+] Credentials found in Windows Credential Manager:" >> "%ps_script%"
echo     Write-Output $output >> "%ps_script%"
echo   } else { >> "%ps_script%"
echo     Write-Output "[-] No credentials found in Windows Credential Manager" >> "%ps_script%"
echo   } >> "%ps_script%"
echo } catch { >> "%ps_script%"
echo   Write-Output "[-] Error accessing Windows Credential Manager: $_" >> "%ps_script%"
echo } >> "%ps_script%"

powershell -ExecutionPolicy Bypass -File "%ps_script%" > "%output_dir%\credman_results.txt" 2>&1

type "%output_dir%\credman_results.txt"
type "%output_dir%\credman_results.txt" >> "%log_file%"

:: Quét các file web.config trong thư mục web
echo.
echo [+] KIEM TRA CAC FILE WEB.CONFIG
echo [+] KIEM TRA CAC FILE WEB.CONFIG >> "%log_file%"
echo. >> "%log_file%"

set "web_paths=C:\inetpub\wwwroot,C:\xampp\htdocs,C:\wamp\www,C:\wamp64\www,C:\AppServ\www,C:\Users\Public,C:\Program Files\IIS Express"

for %%p in (%web_paths%) do (
    if exist "%%p" (
        echo Dang kiem tra thu muc web: %%p
        echo [+] Dang kiem tra thu muc web: %%p >> "%log_file%"
        
        for /f "delims=" %%a in ('dir "%%p\web.config" /s /b 2^>nul') do (
            echo [+] FOUND WEB.CONFIG: %%a
            echo [+] FOUND WEB.CONFIG: %%a >> "%log_file%"
            echo    Dang kiem tra noi dung...
            echo    Dang kiem tra noi dung... >> "%log_file%"
            
            findstr /i "connectionString password credentials authentication" "%%a" >nul 2>&1
            if not errorlevel 1 (
                echo    [+] FOUND CONNECTION STRINGS hoac CREDENTIALS trong file: %%a
                echo    [+] FOUND CONNECTION STRINGS hoac CREDENTIALS trong file: %%a >> "%log_file%"
                echo    Noi dung:
                echo    Noi dung: >> "%log_file%"
                echo    ----------------------------------------------
                echo    ---------------------------------------------- >> "%log_file%"
                
                findstr /i "connectionString password credentials authentication" "%%a" >> "%log_file%"
                findstr /i "connectionString password credentials authentication" "%%a"
                
                echo    ----------------------------------------------
                echo    ---------------------------------------------- >> "%log_file%"
                echo.
                echo. >> "%log_file%"
            )
        )
    )
)

:: Tìm tất cả các file có chứa Private Key
echo.
echo [+] TIM KIEM CAC PRIVATE KEY
echo [+] TIM KIEM CAC PRIVATE KEY >> "%log_file%"
echo. >> "%log_file%"

set "key_exts=pem key ppk pfx p12 cert"

for %%e in (%key_exts%) do (
    echo Dang tim kiem cac file .%%e...
    echo [+] Dang tim kiem cac file .%%e... >> "%log_file%"
    
    for /f "delims=" %%a in ('dir "C:\*.%%e" /s /b 2^>nul') do (
        echo [+] FOUND POTENTIAL PRIVATE KEY: %%a
        echo [+] FOUND POTENTIAL PRIVATE KEY: %%a >> "%log_file%"
        echo. >> "%log_file%"
    )
)

:: Tìm kiếm thông tin SQL Server
echo.
echo [+] TIM KIEM THONG TIN SQL SERVER
echo [+] TIM KIEM THONG TIN SQL SERVER >> "%log_file%"
echo. >> "%log_file%"

reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" >nul 2>&1
if not errorlevel 1 (
    echo [+] SQL Server duoc cai dat tren he thong
    echo [+] SQL Server duoc cai dat tren he thong >> "%log_file%"
    
    :: Export SQL Server registry keys
    reg export "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" "%output_dir%\sql_server_reg.txt" /y >nul 2>&1
    echo [+] Thong tin SQL Server duoc luu trong: %output_dir%\sql_server_reg.txt
    echo [+] Thong tin SQL Server duoc luu trong: %output_dir%\sql_server_reg.txt >> "%log_file%"
    
    :: Tìm kiếm các file liên quan đến SQL Server
    dir "C:\Program Files\Microsoft SQL Server\*.ini" /s /b 2>nul >> "%output_dir%\sql_config_files.txt"
    dir "C:\Program Files\Microsoft SQL Server\*.config" /s /b 2>nul >> "%output_dir%\sql_config_files.txt"
    dir "C:\Program Files (x86)\Microsoft SQL Server\*.ini" /s /b 2>nul >> "%output_dir%\sql_config_files.txt"
    dir "C:\Program Files (x86)\Microsoft SQL Server\*.config" /s /b 2>nul >> "%output_dir%\sql_config_files.txt"
    
    echo [+] Danh sach cac file cau hinh SQL Server duoc luu trong: %output_dir%\sql_config_files.txt
    echo [+] Danh sach cac file cau hinh SQL Server duoc luu trong: %output_dir%\sql_config_files.txt >> "%log_file%"
)

:: Dọn dẹp các file tạm
del "%keywords_file%" 2>nul
del "%reg_tmp%" 2>nul
del "%ps_script%" 2>nul

echo.
echo [+] TIM KIEM HOAN TAT!
echo [+] TIM KIEM HOAN TAT! >> "%log_file%"
echo [+] Ket qua day du da duoc luu trong: %log_file%
echo.

pause