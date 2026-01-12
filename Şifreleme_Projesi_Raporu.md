# ŞİFRELEME UYGULAMASI PROJESİ RAPORU

**Öğrenci Adı Soyadı:** Doğukan Kılınç  
**Okul Numarası:** 436553  
**Tarih:** 27/12/2024

---

## 1. GİRİŞ

Bu rapor, Python Flask framework kullanılarak geliştirilmiş kapsamlı bir şifreleme uygulaması projesini açıklamaktadır. Proje, hem klasik hem de modern şifreleme algoritmalarını içeren, web tabanlı bir şifreleme ve deşifreleme platformu olarak tasarlanmıştır. Uygulama, kullanıcılara çoklu şifreleme algoritması seçenekleri sunarak, hem eğitim amaçlı hem de pratik kullanım için esnek bir çözüm sağlamaktadır.

## 2. PROJE TANIMI VE AMAÇ

Bu proje, çeşitli şifreleme algoritmalarını tek bir platform altında toplayan kapsamlı bir web uygulamasıdır. Projenin temel amacı:

- Klasik şifreleme algoritmalarının (Sezar, Vigenere, Playfair vb.) uygulanması ve gösterilmesi
- Modern şifreleme standartlarının (AES, DES, RSA, DSA, ECC) entegre edilmesi
- Hem kütüphaneli hem de kütüphanesiz (manuel) implementasyon seçeneklerinin sunulması
- Algoritmaların performans analizinin yapılabilmesi için çalışma zamanı ölçümü
- Kullanıcı dostu bir web arayüzü ile kolay erişim sağlanması

## 3. KULLANILAN TEKNOLOJİLER

Proje geliştirme sürecinde aşağıdaki teknolojiler ve kütüphaneler kullanılmıştır:

### 3.1 Programlama Dili ve Framework

**Python 3.x**  
Programlama dili olarak Python tercih edilmiştir. Python'un zengin kütüphane ekosistemi ve okunabilir syntax'ı proje geliştirmeyi kolaylaştırmıştır.

**Flask Framework**  
Web uygulaması geliştirmek için Flask framework kullanılmıştır. Flask, hafif ve esnek yapısı sayesinde hızlı geliştirme imkanı sağlamıştır.

### 3.2 Şifreleme Kütüphaneleri

**PyCryptodome**  
Modern şifreleme algoritmaları (AES, DES, RSA, DSA, ECC) için PyCryptodome kütüphanesi kullanılmıştır. Bu kütüphane, endüstri standardı şifreleme işlemlerini güvenli bir şekilde gerçekleştirmektedir.

### 3.3 Web Teknolojileri

**HTML, CSS, JavaScript**  
Kullanıcı arayüzü için modern web teknolojileri kullanılmıştır. Responsive tasarım ile farklı ekran boyutlarına uyum sağlanmıştır.

**Jinja2 Template Engine**  
Flask ile entegre şablon motoru kullanılmıştır. Dinamik içerik oluşturma ve form yönetimi için kullanılmıştır.

## 4. UYGULANAN ŞİFRELEME ALGORİTMALARI

Proje, toplamda 14 farklı şifreleme algoritmasını içermektedir. Bu algoritmalar klasik ve modern olmak üzere iki kategoriye ayrılabilir:

### 4.1 Klasik Şifreleme Algoritmaları

#### 4.1.1 Sezar Şifrelemesi
Alfabedeki her harfi belirli bir kaydırma değeri kadar kaydırarak şifreleme yapar. En basit ve en eski şifreleme yöntemlerinden biridir.

#### 4.1.2 Rail Fence Şifrelemesi
Metni zikzak bir desenle katmanlara yerleştirip farklı sırada okuyarak şifreler. Transpozisyon tabanlı bir şifreleme yöntemidir.

#### 4.1.3 Vigenere Şifrelemesi
Anahtar kelime kullanarak her harfi farklı kaydırma değerleriyle şifreler. Sezar şifrelemesinin gelişmiş bir versiyonudur.

#### 4.1.4 Vernam Şifrelemesi (One-Time Pad)
XOR işlemi kullanarak karakter bazlı şifreleme yapar. Teorik olarak kırılamaz bir şifreleme yöntemidir.

#### 4.1.5 Playfair Şifrelemesi
5x5 matris kullanarak çift harfler halinde şifreleme yapar. İkinci Dünya Savaşı'nda kullanılmış bir şifreleme yöntemidir.

#### 4.1.6 Route Şifrelemesi
Metni bir grid'e yerleştirip spiral rotada okuyarak şifreler. Transpozisyon tabanlı bir yöntemdir.

#### 4.1.7 Affine Şifrelemesi
Matematiksel formül (ax+b) mod 26 kullanarak şifreleme yapar. Doğrusal dönüşüm tabanlı bir yöntemdir.

#### 4.1.8 Hill Cipher
Matris çarpımı kullanarak blok şifreleme yapar. Lineer cebir prensiplerine dayanır.

#### 4.1.9 Columnar Transposition
Metni sütunlara yerleştirip anahtara göre sıralayarak şifreler. Transpozisyon tabanlı bir yöntemdir.

### 4.2 Modern Şifreleme Algoritmaları

#### 4.2.1 AES (Advanced Encryption Standard)
Modern simetrik şifreleme standardı. Hem kütüphaneli (PyCryptodome) hem de manuel implementasyon içerir. 128, 192 ve 256 bit anahtar boyutlarını destekler. Günümüzde en yaygın kullanılan şifreleme standardıdır.

#### 4.2.2 DES (Data Encryption Standard)
Klasik simetrik şifreleme algoritması. Kütüphaneli ve manuel versiyonları mevcuttur. 56 bit anahtar kullanır ve günümüzde güvenliği yetersiz kabul edilir.

#### 4.2.3 RSA (Rivest-Shamir-Adleman)
Asimetrik şifreleme algoritması. Sadece kütüphaneli versiyon kullanılmaktadır. Public/private key çifti ile çalışır. 512-4096 bit anahtar boyutlarını destekler. Dijital imza ve şifreleme için kullanılır.

#### 4.2.4 DSA (Digital Signature Algorithm)
Dijital imza algoritması. İmza oluşturma ve doğrulama işlemleri için kullanılır. Hem kütüphaneli hem de kütüphanesiz versiyonları mevcuttur. 1024, 2048 ve 3072 bit anahtar boyutlarını destekler.

#### 4.2.5 ECC (Elliptic Curve Cryptography)
Modern eliptik eğri kriptografisi. Yüksek güvenlik sağlar ve daha küçük anahtar boyutları kullanır. P-192, P-224, P-256, P-384, P-521 ve secp256k1 eğrilerini destekler.

## 5. PROJE YAPISI

Proje, modüler bir yapıda organize edilmiştir. Ana bileşenler şunlardır:

### 5.1 Ana Dosyalar

**app.py**  
Ana Flask uygulaması ve tüm şifreleme algoritmalarının implementasyonları bu dosyada bulunur. Toplam 2235 satır kod içermektedir. Tüm şifreleme fonksiyonları, form işleme mantığı ve API endpoint'leri bu dosyada yer almaktadır.

**templates/index.html**  
Web kullanıcı arayüzü şablonu. Tüm form alanları ve JavaScript fonksiyonları içerir. Dinamik içerik için Jinja2 template syntax kullanılmıştır.

**static/style.css**  
Uygulamanın görsel stillerini içeren CSS dosyası. Modern ve responsive tasarım prensipleri uygulanmıştır.

**requirements.txt**  
Projenin Python bağımlılıklarını listeleyen dosya. Flask ve PyCryptodome gibi gerekli kütüphaneler burada tanımlanmıştır.

**run.bat**  
Windows ortamında uygulamayı başlatmak için batch script dosyası. Otomatik kütüphane kontrolü ve kurulumu yapar.

### 5.2 Kod Organizasyonu

Kod, şifreleme algoritmalarına göre bölümlere ayrılmıştır:
- Klasik algoritmalar (Sezar, Vigenere, vb.)
- Modern simetrik algoritmalar (AES, DES)
- Modern asimetrik algoritmalar (RSA, DSA, ECC)
- Form işleme ve state yönetimi
- API endpoint'leri

## 6. PROJE ÖZELLİKLERİ

### 6.1 Çoklu Algoritma Desteği
Tek bir platform altında 14 farklı şifreleme algoritması sunulmaktadır. Bu, kullanıcılara farklı güvenlik ihtiyaçları için esneklik sağlar.

### 6.2 Kütüphaneli ve Kütüphanesiz Seçenekler
Modern algoritmalar için hem profesyonel kütüphane implementasyonları hem de eğitim amaçlı manuel implementasyonlar sunulmaktadır. Bu sayede kullanıcılar hem gerçek dünya uygulamalarını hem de algoritmaların nasıl çalıştığını anlayabilir.

### 6.3 Performans Analizi
AES, DES, RSA, DSA ve ECC algoritmaları için çalışma zamanı ölçümü yapılmaktadır. Bu özellik, farklı algoritmaların performanslarını karşılaştırmak için kullanılabilir.

### 6.4 Kullanıcı Dostu Arayüz
Modern ve responsive web arayüzü ile kolay kullanım sağlanmaktadır. Algoritma seçimine göre dinamik olarak form alanları gösterilir.

### 6.5 Otomatik Anahtar Üretimi
RSA, DSA ve ECC için otomatik anahtar çifti oluşturma özelliği bulunmaktadır. AJAX kullanılarak sayfa yenilenmeden anahtar üretimi yapılır.

### 6.6 Asimetrik Şifreleme Desteği
RSA ve ECC ile public/private key tabanlı şifreleme ve deşifreleme işlemleri yapılabilmektedir. Bu, güvenli veri iletimi için kritik öneme sahiptir.

### 6.7 Dijital İmza Desteği
DSA algoritması ile dijital imza oluşturma ve doğrulama işlemleri yapılabilmektedir. Bu, veri bütünlüğü ve kimlik doğrulama için önemlidir.

## 7. UYGULAMANIN KULLANIMI

Uygulama kullanımı oldukça basittir:

1. **Uygulama başlatma:**  
   run.bat dosyasına çift tıklayarak veya terminalden "python app.py" komutu ile uygulama başlatılır. Uygulama http://127.0.0.1:5000 adresinde çalışır.

2. **Algoritma seçimi:**  
   Web arayüzünden istenen şifreleme algoritması dropdown menüsünden seçilir.

3. **Parametre girme:**  
   Seçilen algoritmaya göre gerekli parametreler (anahtar, kaydırma değeri, eğri tipi vb.) girilir. Bazı algoritmalar için otomatik anahtar üretme butonu kullanılabilir.

4. **Mod seçimi:**  
   Şifreleme veya deşifreleme modu radio butonları ile seçilir.

5. **İşlem yapma:**  
   "Çalıştır" butonuna basılarak işlem gerçekleştirilir.

6. **Sonuç görüntüleme:**  
   İşlem sonucu ve performans bilgileri (çalışma süresi) ekranda gösterilir. Sonuç panoya kopyalanabilir.

## 8. GÜVENLİK VE PERFORMANS

### 8.1 Güvenlik Özellikleri

- Modern algoritmalar için endüstri standardı kütüphaneler kullanılmıştır
- Asimetrik şifreleme ile güvenli anahtar yönetimi sağlanmıştır
- Dijital imza desteği ile veri bütünlüğü korunmaktadır
- Manuel implementasyonlar eğitim amaçlıdır ve üretim ortamında kullanılmamalıdır

### 8.2 Performans Özellikleri

- Çalışma zamanı ölçümü ile algoritma performansları karşılaştırılabilir
- Kütüphaneli versiyonlar optimize edilmiş kod kullanır
- Asenkron anahtar üretimi ile kullanıcı deneyimi iyileştirilmiştir

## 9. SONUÇ VE DEĞERLENDİRME

Bu proje, şifreleme algoritmalarının teorik bilgisini pratik bir uygulama ile birleştiren kapsamlı bir çalışmadır. Proje sayesinde:

- Klasik şifreleme algoritmalarının nasıl çalıştığı pratik olarak gösterilmiştir
- Modern şifreleme standartlarının kullanımı öğrenilmiştir
- Hem kütüphaneli hem de kütüphanesiz implementasyonların farkları anlaşılmıştır
- Web uygulaması geliştirme süreçleri uygulanmıştır
- Performans analizi ve optimizasyon konularında deneyim kazanılmıştır
- Asimetrik şifreleme ve dijital imza kavramları pratik olarak uygulanmıştır

Proje, eğitim amaçlı olmanın yanı sıra, gerçek dünya uygulamalarında kullanılabilecek bir yapıya sahiptir. Modern şifreleme algoritmalarının kütüphaneli versiyonları profesyonel kullanım için uygundur. Klasik algoritmalar ise kriptografi eğitimi ve tarihsel anlayış için değerlidir.

### 9.1 Gelecek Geliştirmeler

Projenin gelecekte geliştirilebileceği alanlar:
- Daha fazla şifreleme algoritması eklenebilir
- Dosya şifreleme desteği eklenebilir
- Toplu işlem desteği eklenebilir
- API endpoint'leri genişletilebilir
- Veritabanı entegrasyonu yapılabilir

---

**Rapor Hazırlayan:** Doğukan Kılınç  
**Okul Numarası:** 436553  
**Tarih:** 27/12/2024

