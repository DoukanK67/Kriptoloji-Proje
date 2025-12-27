@echo off
title Şifreleme Uygulaması
color 0A

echo ========================================
echo   Şifreleme Uygulaması Başlatılıyor...
echo ========================================
echo.

REM Proje dizinine geç
cd /d "%~dp0"

REM Python'un kurulu olup olmadığını kontrol et
python --version >nul 2>&1
if errorlevel 1 (
    echo [HATA] Python bulunamadı!
    echo Lütfen Python'u yükleyin ve PATH'e ekleyin.
    pause
    exit /b 1
)

echo Python bulundu: 
python --version
echo.

REM Gerekli kütüphanelerin kurulu olup olmadığını kontrol et (isteğe bağlı)
echo Gerekli kütüphaneler kontrol ediliyor...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [UYARI] Flask bulunamadı. Kütüphaneler yükleniyor...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [HATA] Kütüphaneler yüklenemedi!
        pause
        exit /b 1
    )
)

python -c "from Crypto.Cipher import AES" >nul 2>&1
if errorlevel 1 (
    echo [UYARI] PyCryptodome bulunamadı. Yükleniyor...
    python -m pip install pycryptodome
)

echo.
echo ========================================
echo   Uygulama başlatılıyor...
echo   Tarayıcınız otomatik olarak açılacak.
echo   Durdurmak için Ctrl+C tuşlarına basın.
echo ========================================
echo.

REM Uygulamayı başlat ve tarayıcıyı aç
start http://127.0.0.1:5000
python app.py

REM Uygulama kapanınca pencereyi kapatma (hata görmek için)
if errorlevel 1 (
    echo.
    echo [HATA] Uygulama bir hata ile kapandı!
    pause
)

