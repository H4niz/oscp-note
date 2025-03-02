@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo SCRIPT TIM KIEM PROOF.TXT VA LOCAL.TXT
echo ==========================================
echo.
echo Dang tim kiem tren tat ca cac o dia...
echo.

:: Lay danh sach tat ca cac o dia
for /f "tokens=1,2" %%i in ('wmic logicaldisk get deviceid^, volumename ^| findstr :') do (
    set "drive=%%i"
    echo Dang quet o dia !drive!...
    
    :: Tim va doc proof.txt
    for /f "tokens=*" %%a in ('dir !drive!\proof.txt /b /s 2^>nul') do (
        echo.
        echo [+] FOUND PROOF.TXT: %%a
        echo [+] NOI DUNG PROOF.TXT:
        echo ===================
        type "%%a"
        echo ===================
        echo.
    )
    
    :: Tim va doc local.txt
    for /f "tokens=*" %%a in ('dir !drive!\local.txt /b /s 2^>nul') do (
        echo.
        echo [+] FOUND LOCAL.TXT: %%a
        echo [+] NOI DUNG LOCAL.TXT:
        echo ===================
        type "%%a"
        echo ===================
        echo.
    )
)

:: Tim trong cac thu muc quan trong
echo Dang tim kiem trong cac thu muc thuong dung...
set "common_paths=C:\Users C:\Documents and Settings C:\ C:\Windows C:\inetpub C:\xampp C:\wamp"

for %%p in (%common_paths%) do (
    if exist "%%p" (
        echo Dang quet %%p...
        
        :: Tim va doc proof.txt
        for /f "tokens=*" %%a in ('dir "%%p\proof.txt" /b /s 2^>nul') do (
            echo.
            echo [+] FOUND PROOF.TXT: %%a
            echo [+] NOI DUNG PROOF.TXT:
            echo ===================
            type "%%a"
            echo ===================
            echo.
        )
        
        :: Tim va doc local.txt
        for /f "tokens=*" %%a in ('dir "%%p\local.txt" /b /s 2^>nul') do (
            echo.
            echo [+] FOUND LOCAL.TXT: %%a
            echo [+] NOI DUNG LOCAL.TXT:
            echo ===================
            type "%%a"
            echo ===================
            echo.
        )
    )
)

echo.
echo Tim kiem hoan tat!
echo.

pause