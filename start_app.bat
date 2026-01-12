@echo off
chcp 65001 >nul 2>&1
title Şifreleme Uygulaması
color 0A

REM Batch dosyasının dizinine geç
cd /d "%~dp0"

REM app.py kontrolü
if not exist app.py (
    echo [HATA] app.py bulunamadi!
    echo Dizin: %CD%
    pause
    exit /b 1
)

echo ========================================
echo   Şifreleme Uygulaması
echo ========================================
echo.

REM Python kontrolü
where python >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadi!
    pause
    exit /b 1
)

echo Python: 
python --version
echo.

REM Kütüphane kontrolü ve kurulumu
echo Kütüphaneler kontrol ediliyor...
python -c "import flask; import sys; sys.exit(0)" 2>nul || (
    echo Flask yükleniyor...
    python -m pip install -r requirements.txt --quiet
)

python -c "from Crypto.Cipher import AES; import sys; sys.exit(0)" 2>nul || (
    echo PyCryptodome yükleniyor...
    python -m pip install pycryptodome --quiet
)

echo.
echo Uygulama başlatılıyor...
echo Tarayıcı açılacak: http://127.0.0.1:5000
echo Durdurmak için: Ctrl+C
echo.
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000 2>nul
python app.py
if errorlevel 1 (
    echo.
    echo [HATA] Bir sorun oluştu!
    pause
)

