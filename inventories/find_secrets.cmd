@echo off
setlocal enabledelayedexpansion

echo =====================================================
echo TIM KIEM MAT KHAU TRONG CAC TEP TIN CONFIGURATION
echo =====================================================
echo.

:: Danh sach dinh dang file can tim kiem
set "file_types=conf ini txt xml json config properties cfg env yaml yml cnf log"

:: Lay danh sach tat ca cac o dia
for /f "tokens=1" %%i in ('wmic logicaldisk get deviceid ^| findstr :') do (
    set "drive=%%i"
    if exist "!drive!\" (
        echo Dang quet o dia !drive!...
        
        :: Tim kiem tren moi o dia cho moi dinh dang file
        for %%t in (%file_types%) do (
            echo Dang tim kiem trong cac file .%%t tren !drive!...
            
            :: Tim kiem trong cac file co chua "password:" hoac "Password:"
            for /f "delims=" %%a in ('dir "!drive!\*.%%t" /s /b 2^>nul') do (
                findstr /i "password: Password:" "%%a" >nul 2>&1
                if not errorlevel 1 (
                    echo [+] FOUND PASSWORD trong file: %%a
                    echo    Noi dung:
                    echo    ------------------------------------------
                    findstr /i "password: Password:" "%%a" 2>nul
                    echo    ------------------------------------------
                    echo.
                )
            )
        )
    ) else (
        echo O dia !drive! khong ton tai hoac khong the truy cap, dang bo qua...
    )
)

:: Tim kiem trong cac thu muc quan trong
echo Dang tim kiem trong cac thu muc thuong duoc quan tam...

:: Danh sach thu muc quan trong
set paths_to_check=C:\Users,C:\wamp64

:: Duyet qua tung thu muc
for %%p in (%paths_to_check%) do (
    set "current_path=%%p"
    if exist "!current_path!" (
        echo Dang quet thu muc !current_path!...
        
        :: Tim kiem trong moi dinh dang file
        for %%t in (%file_types%) do (
            for /f "delims=" %%a in ('dir "!current_path!\*.%%t" /s /b 2^>nul') do (
                findstr /i "password: Password:" "%%a" >nul 2>&1
                if not errorlevel 1 (
                    echo [+] FOUND PASSWORD trong file: %%a
                    echo    Noi dung:
                    echo    ------------------------------------------
                    findstr /i "password: Password:" "%%a" 2>nul
                    echo    ------------------------------------------
                    echo.
                )
            )
        )
    ) else (
        echo Thu muc !current_path! khong ton tai hoac khong the truy cap, dang bo qua...
    )
)

:: Tim kiem trong cac thu muc home cua tung user
echo Dang tim kiem trong thu muc home cua cac user...
if exist "C:\Users\" (
    for /d %%u in (C:\Users\*) do (
        echo Dang quet thu muc cua user: %%~nxu
        
        for %%t in (%file_types%) do (
            for /f "delims=" %%a in ('dir "%%u\*.%%t" /s /b 2^>nul') do (
                findstr /i "password: Password:" "%%a" >nul 2>&1
                if not errorlevel 1 (
                    echo [+] FOUND PASSWORD trong file: %%a
                    echo    Noi dung:
                    echo    ------------------------------------------
                    findstr /i "password: Password:" "%%a" 2>nul
                    echo    ------------------------------------------
                    echo.
                )
            )
        )
    )
)

echo.
echo Tim kiem hoan tat!
echo.

pause