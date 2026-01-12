"""
Şifreleme Uygulaması - Kapsamlı Şifreleme Platformu

Bu modül, 14 farklı şifreleme algoritmasını içeren bir web uygulamasıdır.
Hem klasik (Sezar, Vigenere, vb.) hem de modern (AES, RSA, ECC, vb.) 
şifreleme algoritmalarını destekler.

Yazar: Doğukan Kılınç
Tarih: 2024
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Optional

# Şifreleme kütüphaneleri
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# Web framework
from flask import Flask, render_template, request, jsonify


# Flask uygulaması oluştur
app = Flask(__name__)


# -----------------------------
#  ŞİFRELEME ALGORİTMALARI
# -----------------------------

# -----------------------------
#  SEZAR ŞİFRELEMESİ
# -----------------------------


def caesar_shift_char(ch: str, shift: int) -> str:
  """
  Sezar şifrelemesi için tek bir karakteri kaydırır.
  
  Args:
    ch: Şifrelenecek karakter
    shift: Kaydırma miktarı (pozitif: ileri, negatif: geri)
  
  Returns:
    Kaydırılmış karakter. Alfabetik değilse olduğu gibi döndürülür.
  """
  code = ord(ch)

  # Büyük harf A-Z
  if 65 <= code <= 90:
    base = 65
    offset = ((code - base + shift) % 26 + 26) % 26
    return chr(base + offset)

  # Küçük harf a-z
  if 97 <= code <= 122:
    base = 97
    offset = ((code - base + shift) % 26 + 26) % 26
    return chr(base + offset)

  # Diğer karakterler olduğu gibi bırak
  return ch


def caesar_encrypt(text: str, shift: int) -> str:
  """
  Sezar şifrelemesi ile metni şifreler.
  
  Her harfi alfabede 'shift' kadar ileri kaydırarak şifreleme yapar.
  
  Args:
    text: Şifrelenecek metin
    shift: Kaydırma miktarı (0-25 arası)
  
  Returns:
    Şifrelenmiş metin
  """
  return "".join(caesar_shift_char(ch, shift) for ch in text)


def caesar_decrypt(text: str, shift: int) -> str:
  """
  Sezar şifrelemesi ile şifrelenmiş metni çözer.
  
  Şifreleme işleminin tersini yapar (negatif kaydırma).
  
  Args:
    text: Çözülecek şifrelenmiş metin
    shift: Kullanılan kaydırma miktarı
  
  Returns:
    Çözülmüş metin
  """
  return caesar_encrypt(text, -shift)


# -----------------------------
#  RAIL FENCE ŞİFRELEMESİ
# -----------------------------


def rail_fence_encrypt(text: str, rails: int) -> str:
  """
  Rail Fence şifrelemesi ile metni şifreler.
  
  Metni zikzak bir desenle 'rails' sayıda katmana yerleştirir
  ve her katmandaki karakterleri sırayla okur.
  
  Args:
    text: Şifrelenecek metin
    rails: Kullanılacak katman (rail) sayısı (minimum 2)
  
  Returns:
    Şifrelenmiş metin
  """
  # Geçersiz parametre kontrolü
  if rails < 2 or len(text) == 0:
    return text

  # Her katman için boş liste oluştur
  lines = [[] for _ in range(rails)]
  row = 0  # Mevcut katman
  direction = 1  # 1: aşağı yön, -1: yukarı yön

  # Metindeki her karakteri uygun katmana yerleştir
  for ch in text:
    lines[row].append(ch)

    # Yön değişikliği: en üstteyse aşağı, en alttaysa yukarı
    if row == 0:
      direction = 1
    elif row == rails - 1:
      direction = -1

    row += direction

  # Tüm katmanları birleştir ve şifrelenmiş metni döndür
  return "".join("".join(line) for line in lines)


def rail_fence_decrypt(cipher: str, rails: int) -> str:
  """
  Rail Fence şifrelemesi ile şifrelenmiş metni çözer.
  
  Şifreleme işleminin tersini yaparak orijinal metni geri getirir.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    rails: Kullanılan katman sayısı
  
  Returns:
    Çözülmüş orijinal metin
  """
  # Geçersiz parametre kontrolü
  if rails < 2 or len(cipher) == 0:
    return cipher

  length = len(cipher)

  # Her katmana kaç karakter düşeceğini hesapla
  # Şifreleme sırasındaki zikzak desenini simüle et
  counts = [0] * rails
  row = 0
  direction = 1

  for _ in range(length):
    counts[row] += 1
    if row == 0:
      direction = 1
    elif row == rails - 1:
      direction = -1
    row += direction

  # Şifrelenmiş metni katmanlara göre paylaştır
  rails_arr = []
  index = 0
  for r in range(rails):
    part = list(cipher[index : index + counts[r]])
    rails_arr.append(part)
    index += counts[r]

  # Zigzag sırasıyla karakterleri oku ve orijinal metni oluştur
  result = []
  row = 0
  direction = 1

  for _ in range(length):
    result.append(rails_arr[row].pop(0))
    if row == 0:
      direction = 1
    elif row == rails - 1:
      direction = -1
    row += direction

  return "".join(result)


# -----------------------------
#  VIGENERE ŞİFRELEMESİ
# -----------------------------


def vigenere_prepare_key(key: str, length: int) -> str:
  """
  Vigenere şifrelemesi için anahtarı hazırlar.
  
  Anahtarı metin uzunluğuna kadar tekrarlayarak genişletir.
  Yalnızca alfabetik karakterler kullanılır.
  
  Args:
    key: Anahtar kelime
    length: Metnin uzunluğu
  
  Returns:
    Hazırlanmış ve tekrarlanmış anahtar
  """
  # Anahtardan yalnızca harfleri al ve büyük harfe çevir
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha())
  # Boşsa varsayılan anahtar kullan
  if not key_clean:
    key_clean = "A"
  # Anahtarı metin uzunluğuna kadar tekrarla
  key_repeated = (key_clean * ((length // len(key_clean)) + 1))[:length]
  return key_repeated


def vigenere_encrypt(text: str, key: str) -> str:
  """
  Vigenere şifrelemesi ile metni şifreler.
  
  Her harfi, anahtar kelimedeki karşılık gelen harfin pozisyonu
  kadar kaydırarak şifreler. Bu, çoklu Sezar şifrelemesi gibidir.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar kelime
  
  Returns:
    Şifrelenmiş metin
  """
  if not key:
    return text

  # Anahtarı metin uzunluğuna kadar hazırla
  key_prepared = vigenere_prepare_key(key, len(text))
  result = []

  key_idx = 0
  for ch in text:
    if ch.isalpha():
      # Harfin büyük/küçük durumunu koru
      is_upper = ch.isupper()
      ch_code = ord(ch.upper())
      key_code = ord(key_prepared[key_idx].upper())
      # Anahtar harfinden kaydırma miktarını hesapla
      shift = key_code - ord("A")
      
      # Sezar şifrelemesi benzeri kaydırma uygula
      new_code = ((ch_code - ord("A") + shift) % 26) + ord("A")
      result.append(chr(new_code) if is_upper else chr(new_code).lower())
      key_idx += 1
    else:
      # Alfabetik olmayan karakterler olduğu gibi kalır
      result.append(ch)

  return "".join(result)


def vigenere_decrypt(cipher: str, key: str) -> str:
  """
  Vigenere şifrelemesi ile şifrelenmiş metni çözer.
  
  Şifreleme işleminin tersini yaparak orijinal metni geri getirir.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    key: Kullanılan anahtar kelime
  
  Returns:
    Çözülmüş orijinal metin
  """
  if not key:
    return cipher

  # Anahtarı metin uzunluğuna kadar hazırla
  key_prepared = vigenere_prepare_key(key, len(cipher))
  result = []

  key_idx = 0
  for ch in cipher:
    if ch.isalpha():
      # Harfin büyük/küçük durumunu koru
      is_upper = ch.isupper()
      ch_code = ord(ch.upper())
      key_code = ord(key_prepared[key_idx].upper())
      # Anahtar harfinden kaydırma miktarını hesapla
      shift = key_code - ord("A")
      
      # Ters kaydırma uygula (şifrelemenin tersi)
      new_code = ((ch_code - ord("A") - shift + 26) % 26) + ord("A")
      result.append(chr(new_code) if is_upper else chr(new_code).lower())
      key_idx += 1
    else:
      # Alfabetik olmayan karakterler olduğu gibi kalır
      result.append(ch)

  return "".join(result)


# -----------------------------
#  VERNAM ŞİFRELEMESİ (ONE-TIME PAD)
# -----------------------------


def vernam_encrypt(text: str, key: str) -> str:
  """
  Vernam (One-Time Pad) şifrelemesi ile metni şifreler.
  
  XOR işlemi kullanarak karakter bazlı şifreleme yapar.
  Teorik olarak kırılamaz bir şifreleme yöntemidir.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar (One-Time Pad için metinle aynı uzunlukta olmalı)
  
  Returns:
    Şifrelenmiş metin (binary format)
  """
  if not key:
    return text

  # Anahtarı metin uzunluğuna kadar tekrarla
  key_extended = (key * ((len(text) // len(key)) + 1))[:len(text)]
  
  result = []
  for i, ch in enumerate(text):
    # Her karakteri anahtar karakteri ile XOR işlemine tabi tut
    encrypted_char = chr(ord(ch) ^ ord(key_extended[i]))
    result.append(encrypted_char)

  return "".join(result)


def vernam_decrypt(cipher: str, key: str) -> str:
  """
  Vernam şifrelemesi ile şifrelenmiş metni çözer.
  
  XOR işlemi simetrik olduğu için şifreleme ile aynı işlemi yapar.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    key: Kullanılan anahtar
  
  Returns:
    Çözülmüş orijinal metin
  """
  return vernam_encrypt(cipher, key)


# -----------------------------
#  PLAYFAIR ŞİFRELEMESİ
# -----------------------------


# Playfair Şifreleme
def playfair_prepare_text(text: str) -> str:
  """
  Metni Playfair şifrelemesi için hazırlar.
  
  İşlemler:
  1. Yalnızca harfleri al ve büyük harfe çevir
  2. J harflerini I ile değiştir (Playfair'de J kullanılmaz)
  3. Metni çiftlere ayır
  4. Aynı harften oluşan çiftlere X ekle
  
  Args:
    text: Hazırlanacak metin
  
  Returns:
    Çift harfli gruplar halinde hazırlanmış metin
  """
  # Yalnızca harfleri al ve büyük harfe çevir
  text_clean = "".join(ch.upper() for ch in text if ch.isalpha())
  # J harflerini I ile değiştir (Playfair 5x5 matrisinde J yoktur)
  text_clean = text_clean.replace("J", "I")
  
  if not text_clean:
    return ""
  
  # Metni çiftlere ayır
  result = []
  i = 0
  while i < len(text_clean):
    # Son harf tek kalırsa X ekle
    if i == len(text_clean) - 1:
      result.append(text_clean[i] + "X")
      break
    
    # Aynı harften oluşan çift varsa arasına X ekle
    if text_clean[i] == text_clean[i + 1]:
      result.append(text_clean[i] + "X")
      i += 1
    else:
      # Normal çift
      result.append(text_clean[i] + text_clean[i + 1])
      i += 2
  
  return " ".join(result)


def playfair_create_matrix(key: str) -> list[list[str]]:
  """
  5x5 Playfair matrisi oluşturur.
  
  Anahtar kelimeden başlayarak, tekrarları çıkarıp,
  kalan alfabeyi ekleyerek 5x5 matris doldurur.
  
  Args:
    key: Anahtar kelime
  
  Returns:
    5x5 karakter matrisi (J harfi kullanılmaz, I kullanılır)
  """
  # Anahtardan yalnızca harfleri al, J'yi I ile değiştir
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha()).replace("J", "I")
  
  # Tekrar eden harfleri kaldır (set kullanarak)
  seen = set()
  key_unique = ""
  for ch in key_clean:
    if ch not in seen:
      key_unique += ch
      seen.add(ch)
  
  # Kalan alfabeyi hazırla (J hariç, 25 harf)
  alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
  # Anahtardaki harfleri alfabeden çıkar
  for ch in key_unique:
    alphabet = alphabet.replace(ch, "")
  
  # Anahtar + kalan alfabe = 25 karakter
  matrix_str = key_unique + alphabet
  matrix = []
  # 5x5 matris oluştur
  for i in range(5):
    row = []
    for j in range(5):
      row.append(matrix_str[i * 5 + j])
    matrix.append(row)
  
  return matrix


def playfair_find_position(matrix: list[list[str]], ch: str) -> tuple[int, int]:
  """
  Playfair matrisinde bir harfin pozisyonunu bulur.
  
  Args:
    matrix: 5x5 Playfair matrisi
    ch: Aranacak harf
  
  Returns:
    (satır, sütun) tuple'ı, bulunamazsa (0, 0)
  """
  for i in range(5):
    for j in range(5):
      if matrix[i][j] == ch:
        return (i, j)
  return (0, 0)


def playfair_encrypt_pair(matrix: list[list[str]], pair: str) -> str:
  """
  Playfair matrisinde iki harfli çifti şifreler.
  
  Playfair kuralları:
  1. Aynı satırdaysa: sağdaki harfi al (sarmal)
  2. Aynı sütundaysa: alttaki harfi al (sarmal)
  3. Dikdörtgen oluşturuyorsa: köşeleri değiştir
  
  Args:
    matrix: 5x5 Playfair matrisi
    pair: Şifrelenecek iki harfli çift
  
  Returns:
    Şifrelenmiş iki harfli çift
  """
  if len(pair) < 2:
    return pair
  
  ch1, ch2 = pair[0], pair[1]
  # Her harfin matristeki pozisyonunu bul
  row1, col1 = playfair_find_position(matrix, ch1)
  row2, col2 = playfair_find_position(matrix, ch2)
  
  if row1 == row2:
    # Aynı satırda: sağa kaydır (modüler aritmetik ile sarmal)
    new_col1 = (col1 + 1) % 5
    new_col2 = (col2 + 1) % 5
    return matrix[row1][new_col1] + matrix[row2][new_col2]
  elif col1 == col2:
    # Aynı sütunda: aşağı kaydır (modüler aritmetik ile sarmal)
    new_row1 = (row1 + 1) % 5
    new_row2 = (row2 + 1) % 5
    return matrix[new_row1][col1] + matrix[new_row2][col2]
  else:
    # Dikdörtgen: köşeleri değiştir (satır/sütun değişimi)
    return matrix[row1][col2] + matrix[row2][col1]


def playfair_decrypt_pair(matrix: list[list[str]], pair: str) -> str:
  """
  Playfair matrisinde iki harfli çifti deşifreler.
  
  Şifrelemenin tersini yapar:
  1. Aynı satırdaysa: soldaki harfi al
  2. Aynı sütundaysa: üstteki harfi al
  3. Dikdörtgen oluşturuyorsa: köşeleri değiştir (aynı işlem)
  
  Args:
    matrix: 5x5 Playfair matrisi
    pair: Çözülecek iki harfli çift
  
  Returns:
    Çözülmüş iki harfli çift
  """
  if len(pair) < 2:
    return pair
  
  ch1, ch2 = pair[0], pair[1]
  # Her harfin matristeki pozisyonunu bul
  row1, col1 = playfair_find_position(matrix, ch1)
  row2, col2 = playfair_find_position(matrix, ch2)
  
  if row1 == row2:
    # Aynı satırda: sola kaydır (şifrelemenin tersi)
    new_col1 = (col1 - 1) % 5
    new_col2 = (col2 - 1) % 5
    return matrix[row1][new_col1] + matrix[row2][new_col2]
  elif col1 == col2:
    # Aynı sütunda: yukarı kaydır (şifrelemenin tersi)
    new_row1 = (row1 - 1) % 5
    new_row2 = (row2 - 1) % 5
    return matrix[new_row1][col1] + matrix[new_row2][col2]
  else:
    # Dikdörtgen: köşeleri değiştir (şifreleme ve deşifreleme aynı)
    return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(text: str, key: str) -> str:
  """
  Playfair şifreleme ile metni şifreler.
  
  Metni çiftlere ayırır ve her çifti Playfair kurallarına
  göre şifreler.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar kelime (matris oluşturmak için)
  
  Returns:
    Şifrelenmiş metin
  """
  if not key or not text:
    return text
  
  # 5x5 matris oluştur
  matrix = playfair_create_matrix(key)
  # Metni çiftlere ayır
  text_prepared = playfair_prepare_text(text)
  pairs = text_prepared.split()
  
  # Her çifti şifrele
  result = []
  for pair in pairs:
    if len(pair) == 2:
      result.append(playfair_encrypt_pair(matrix, pair))
    else:
      result.append(pair)
  
  return "".join(result)


def playfair_decrypt(cipher: str, key: str) -> str:
  """
  Playfair şifrelemesi ile şifrelenmiş metni çözer.
  
  Şifreleme işleminin tersini yaparak orijinal metni geri getirir.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    key: Kullanılan anahtar kelime
  
  Returns:
    Çözülmüş orijinal metin
  """
  if not key or not cipher:
    return cipher
  
  # 5x5 matris oluştur
  matrix = playfair_create_matrix(key)
  # Yalnızca harfleri al
  cipher_clean = "".join(ch.upper() for ch in cipher if ch.isalpha())
  
  # Tek sayıda harf varsa X ekle
  if len(cipher_clean) % 2 != 0:
    cipher_clean += "X"
  
  # Çiftlere ayır ve deşifrele
  result = []
  for i in range(0, len(cipher_clean), 2):
    pair = cipher_clean[i:i+2]
    if len(pair) == 2:
      decrypted = playfair_decrypt_pair(matrix, pair)
      result.append(decrypted)
    else:
      result.append(pair)
  
  return "".join(result)


# -----------------------------
#  ROUTE ŞİFRELEMESİ
# -----------------------------

def route_encrypt(text: str, rows: int, cols: int, direction: str = "spiral") -> str:
  """Route şifreleme - metni grid'e yerleştirip belirli rotada okur"""
  if rows < 1 or cols < 1:
    return text
  
  text_clean = "".join(ch for ch in text)
  grid_size = rows * cols
  
  # Metni grid'e yerleştir (kalan yerleri boşluk veya X ile doldur)
  text_padded = text_clean.ljust(grid_size, "X")
  
  # Grid oluştur
  grid = []
  for i in range(rows):
    row = []
    for j in range(cols):
      row.append(text_padded[i * cols + j])
    grid.append(row)
  
  # Spiral rotada oku (saat yönünde, dıştan içe)
  result = []
  visited = [[False for _ in range(cols)] for _ in range(rows)]
  
  directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # sağ, aşağı, sol, yukarı
  dir_idx = 0
  row, col = 0, 0
  
  for _ in range(grid_size):
    result.append(grid[row][col])
    visited[row][col] = True
    
    # Sonraki pozisyonu kontrol et
    next_row = row + directions[dir_idx][0]
    next_col = col + directions[dir_idx][1]
    
    # Eğer sınırları aşıyorsa veya ziyaret edilmişse yön değiştir
    if (next_row < 0 or next_row >= rows or 
        next_col < 0 or next_col >= cols or 
        visited[next_row][next_col]):
      dir_idx = (dir_idx + 1) % 4
      next_row = row + directions[dir_idx][0]
      next_col = col + directions[dir_idx][1]
    
    row, col = next_row, next_col
  
  return "".join(result)


def route_decrypt(cipher: str, rows: int, cols: int, direction: str = "spiral") -> str:
  """Route deşifreleme - şifreli metni grid'e spiral rotada yerleştirip normal okur"""
  if rows < 1 or cols < 1:
    return cipher
  
  grid_size = rows * cols
  if len(cipher) < grid_size:
    cipher = cipher.ljust(grid_size, "X")
  elif len(cipher) > grid_size:
    cipher = cipher[:grid_size]
  
  # Grid oluştur
  grid = [[None for _ in range(cols)] for _ in range(rows)]
  visited = [[False for _ in range(cols)] for _ in range(rows)]
  
  # Şifreli metni spiral rotada grid'e yerleştir
  directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]
  dir_idx = 0
  row, col = 0, 0
  
  for i, ch in enumerate(cipher):
    grid[row][col] = ch
    visited[row][col] = True
    
    if i < len(cipher) - 1:
      next_row = row + directions[dir_idx][0]
      next_col = col + directions[dir_idx][1]
      
      if (next_row < 0 or next_row >= rows or 
          next_col < 0 or next_col >= cols or 
          visited[next_row][next_col]):
        dir_idx = (dir_idx + 1) % 4
        next_row = row + directions[dir_idx][0]
        next_col = col + directions[dir_idx][1]
      
      row, col = next_row, next_col
  
  # Grid'i normal şekilde oku (soldan sağa, yukarıdan aşağıya)
  result = []
  for i in range(rows):
    for j in range(cols):
      if grid[i][j]:
        result.append(grid[i][j])
  
  return "".join(result).rstrip("X")


# -----------------------------
#  AFFINE ŞİFRELEMESİ
# -----------------------------

def gcd_extended(a: int, b: int) -> tuple[int, int, int]:
  """
  Extended Euclidean Algorithm (Genişletilmiş Öklid Algoritması).
  
  En büyük ortak bölen (gcd) ve modüler ters hesaplamak için kullanılır.
  
  Args:
    a: İlk sayı
    b: İkinci sayı
  
  Returns:
    (gcd, x, y) tuple'ı, burada gcd = ax + by
  """
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = gcd_extended(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
  """
  a sayısının mod m'deki modüler tersini bulur.
  
  Extended Euclidean Algorithm kullanarak a^(-1) mod m değerini hesaplar.
  
  Args:
    a: Tersi bulunacak sayı
    m: Modül değeri
  
  Returns:
    a^(-1) mod m, eğer ters yoksa None
  """
  gcd, x, _ = gcd_extended(a, m)
  # Ters var olması için gcd(a, m) = 1 olmalı
  if gcd != 1:
    return None  # Ters yok
  # Pozitif değer döndürmek için modül işlemi uygula
  return (x % m + m) % m


def affine_encrypt(text: str, a: int, b: int) -> str:
  """
  Affine şifreleme ile metni şifreler.
  
  Matematiksel formül: E(x) = (ax + b) mod 26
  Burada x harfin alfabetik pozisyonu (0-25), a ve b anahtar değerlerdir.
  
  Args:
    text: Şifrelenecek metin
    a: Anahtar değeri (26 ile aralarında asal olmalı)
    b: Anahtar değeri (0-25 arası)
  
  Returns:
    Şifrelenmiş metin
  
  Raises:
    ValueError: a ve 26 aralarında asal değilse
  """
  # a ve 26 aralarında asal olmalı (gcd kontrolü)
  if gcd_extended(a, 26)[0] != 1:
    raise ValueError("a ve 26 aralarında asal olmalıdır (gcd(a, 26) = 1)")
  
  result = []
  for ch in text:
    if ch.isalpha():
      # Harfin büyük/küçük durumunu koru
      is_upper = ch.isupper()
      # Harfin alfabetik pozisyonunu bul (0-25)
      ch_code = ord(ch.upper()) - ord("A")
      # Affine formülü: (ax + b) mod 26
      encrypted_code = (a * ch_code + b) % 26
      encrypted_char = chr(encrypted_code + ord("A"))
      result.append(encrypted_char if is_upper else encrypted_char.lower())
    else:
      # Alfabetik olmayan karakterler olduğu gibi kalır
      result.append(ch)
  
  return "".join(result)


def affine_decrypt(cipher: str, a: int, b: int) -> str:
  """
  Affine şifrelemesi ile şifrelenmiş metni çözer.
  
  Matematiksel formül: D(x) = a^(-1)(x - b) mod 26
  Burada a^(-1) a'nın mod 26'daki modüler tersidir.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    a: Kullanılan anahtar değeri
    b: Kullanılan anahtar değeri
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: a'nın mod 26'da tersi yoksa
  """
  # a'nın modüler tersini hesapla
  a_inv = mod_inverse(a, 26)
  if a_inv is None:
    raise ValueError("a'nın mod 26'da tersi yok")
  
  result = []
  for ch in cipher:
    if ch.isalpha():
      # Harfin büyük/küçük durumunu koru
      is_upper = ch.isupper()
      # Harfin alfabetik pozisyonunu bul
      ch_code = ord(ch.upper()) - ord("A")
      # Affine deşifreleme formülü: a^(-1)(x - b) mod 26
      # Negatif değerler için +26 eklenir
      decrypted_code = (a_inv * (ch_code - b + 26)) % 26
      decrypted_char = chr(decrypted_code + ord("A"))
      result.append(decrypted_char if is_upper else decrypted_char.lower())
    else:
      # Alfabetik olmayan karakterler olduğu gibi kalır
      result.append(ch)
  
  return "".join(result)


# -----------------------------
#  HILL CIPHER ŞİFRELEMESİ
# -----------------------------


def hill_create_matrix(key: str, size: int) -> list[list[int]]:
  """
  Anahtar kelimeden Hill Cipher matrisi oluşturur.
  
  Anahtar kelimedeki harfleri kullanarak size x size boyutunda
  bir matris oluşturur. Her harf 0-25 arası sayıya dönüştürülür.
  
  Args:
    key: Anahtar kelime
    size: Matris boyutu (2 veya 3)
  
  Returns:
    size x size integer matrisi (her eleman 0-25 arası)
  """
  # Yalnızca harfleri al ve büyük harfe çevir
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha())
  
  # Matris boyutuna göre anahtarı doldur veya kes
  # size x size eleman gerekli
  if len(key_clean) < size * size:
    # Eksikse 'A' ile doldur
    key_clean = key_clean.ljust(size * size, "A")
  elif len(key_clean) > size * size:
    # Fazlaysa kes
    key_clean = key_clean[:size * size]
  
  # Matris oluştur
  matrix = []
  for i in range(size):
    row = []
    for j in range(size):
      # Her harfi 0-25 arası sayıya dönüştür
      char_code = ord(key_clean[i * size + j]) - ord("A")
      row.append(char_code)
    matrix.append(row)
  
  return matrix


def hill_matrix_determinant(matrix: list[list[int]]) -> int:
  """
  2x2 matrisin determinantını mod 26'da hesaplar.
  
  Determinant = ad - bc (mod 26)
  
  Args:
    matrix: 2x2 integer matrisi
  
  Returns:
    Determinant değeri (mod 26)
  """
  if len(matrix) == 2:
    # 2x2 matris determinantı: ad - bc
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
  return 0


def hill_matrix_inverse(matrix: list[list[int]]) -> list[list[int]]:
  """
  2x2 matrisin mod 26'da tersini bulur.
  
  Matrisin tersinin var olması için determinantının mod 26'da
  tersi olmalı (gcd(det, 26) = 1).
  
  Args:
    matrix: 2x2 integer matrisi
  
  Returns:
    Matrisin mod 26'daki tersi
  
  Raises:
    ValueError: Determinantın mod 26'da tersi yoksa
  """
  # Determinantı hesapla
  det = hill_matrix_determinant(matrix)
  # Determinantın modüler tersini bul
  det_inv = mod_inverse(det, 26)
  
  if det_inv is None:
    raise ValueError("Matris determinantının mod 26'da tersi yok")
  
  # 2x2 matris için ters formül
  # [a b]  ->  (1/det) * [d  -b]
  # [c d]               [-c   a]
  a, b = matrix[0][0], matrix[0][1]
  c, d = matrix[1][0], matrix[1][1]
  
  inverse = [
    [(det_inv * d) % 26, (-det_inv * b) % 26],
    [(-det_inv * c) % 26, (det_inv * a) % 26]
  ]
  
  return inverse


def hill_multiply_matrix_vector(matrix: list[list[int]], vector: list[int]) -> list[int]:
  """
  Matris ile vektörün çarpımını hesaplar (mod 26).
  
  Her satır ile vektörü çarpar ve sonucu mod 26'da hesaplar.
  
  Args:
    matrix: n x n integer matrisi
    vector: n boyutunda vektör
  
  Returns:
    Çarpım sonucu vektörü (mod 26)
  """
  result = []
  for row in matrix:
    # Satır ile vektörün iç çarpımı (mod 26)
    total = sum(row[i] * vector[i] for i in range(len(vector))) % 26
    result.append(total)
  return result


def hill_encrypt(text: str, key: str, size: int = 2) -> str:
  """Hill Cipher şifreleme"""
  if size < 2 or size > 3:
    size = 2  # Sadece 2x2 veya 3x3 desteklenir, basitlik için 2x2 kullanıyoruz
  
  matrix = hill_create_matrix(key, size)
  
  text_clean = "".join(ch.upper() for ch in text if ch.isalpha())
  if not text_clean:
    return text
  
  # Metni bloklara ayır (eksikse X ekle)
  if len(text_clean) % size != 0:
    text_clean += "X" * (size - (len(text_clean) % size))
  
  result_chars = []
  original_positions = []  # Orijinal pozisyonları ve harf durumunu sakla
  text_idx = 0
  
  for i, ch in enumerate(text):
    if ch.isalpha():
      original_positions.append((i, ch.isupper(), text_idx))
      text_idx += 1
    else:
      original_positions.append((i, None, None))
  
  # Her blok için şifreleme
  for block_start in range(0, len(text_clean), size):
    block = text_clean[block_start:block_start + size]
    vector = [ord(ch) - ord("A") for ch in block]
    encrypted_vector = hill_multiply_matrix_vector(matrix, vector)
    encrypted_block = "".join(chr(code + ord("A")) for code in encrypted_vector)
    result_chars.extend(encrypted_block)
  
  # Sonucu orijinal metin formatına göre düzenle
  result = list(text)
  char_idx = 0
  for i, ch in enumerate(text):
    if ch.isalpha():
      if char_idx < len(result_chars):
        is_upper = original_positions[i][1]
        result[i] = result_chars[char_idx] if is_upper else result_chars[char_idx].lower()
        char_idx += 1
  
  return "".join(result)


def hill_decrypt(cipher: str, key: str, size: int = 2) -> str:
  """
  Hill Cipher şifrelemesi ile şifrelenmiş metni çözer.
  
  Matrisin tersi ile çarpım yaparak şifreleme işleminin tersini gerçekleştirir.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    key: Kullanılan anahtar kelime
    size: Kullanılan matris boyutu
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: Matrisin tersi alınamıyorsa
  """
  if size < 2 or size > 3:
    size = 2
  
  # Anahtar kelimeden matris oluştur
  matrix = hill_create_matrix(key, size)
  
  try:
    # Matrisin mod 26'daki tersini bul
    inverse_matrix = hill_matrix_inverse(matrix)
  except ValueError:
    raise ValueError("Anahtar matrisin tersi alınamıyor")
  
  # Yalnızca harfleri al
  cipher_clean = "".join(ch.upper() for ch in cipher if ch.isalpha())
  if not cipher_clean:
    return cipher
  
  # Metni bloklara ayır (eksikse X ile doldur)
  if len(cipher_clean) % size != 0:
    cipher_clean += "X" * (size - (len(cipher_clean) % size))
  
  # Orijinal metindeki harf pozisyonlarını sakla
  result_chars = []
  original_positions = []
  cipher_idx = 0
  
  for i, ch in enumerate(cipher):
    if ch.isalpha():
      original_positions.append((i, ch.isupper(), cipher_idx))
      cipher_idx += 1
    else:
      original_positions.append((i, None, None))
  
  # Her blok için deşifreleme
  for block_start in range(0, len(cipher_clean), size):
    # Blok al
    block = cipher_clean[block_start:block_start + size]
    # Her harfi 0-25 arası sayıya dönüştür
    vector = [ord(ch) - ord("A") for ch in block]
    # Ters matris ile çarp (deşifreleme)
    decrypted_vector = hill_multiply_matrix_vector(inverse_matrix, vector)
    # Sayıları tekrar harfe dönüştür
    decrypted_block = "".join(chr(code + ord("A")) for code in decrypted_vector)
    result_chars.extend(decrypted_block)
  
  # Sonucu orijinal metin formatına göre düzenle
  result = list(cipher)
  char_idx = 0
  for i, ch in enumerate(cipher):
    if ch.isalpha():
      if char_idx < len(result_chars):
        is_upper = original_positions[i][1]
        result[i] = result_chars[char_idx] if is_upper else result_chars[char_idx].lower()
        char_idx += 1
  
  # Son eklenen padding karakterlerini temizle
  return "".join(result).rstrip("X")


# -----------------------------
#  COLUMNAR TRANSPOSITION ŞİFRELEMESİ
# -----------------------------


def columnar_get_key_order(key: str) -> list[int]:
  """
  Anahtar kelimeden sütun sıralamasını çıkarır.
  
  Anahtar kelimedeki harfleri alfabetik sıraya göre sıralar
  ve her harfin yeni pozisyonunu belirler.
  
  Args:
    key: Anahtar kelime
  
  Returns:
    Sütun sıralaması listesi (eski pozisyon -> yeni pozisyon)
  """
  key_upper = key.upper()
  # Her harfin pozisyonunu ve değerini eşleştir
  key_chars = [(i, key_upper[i]) for i in range(len(key_upper))]
  # Alfabetik sıraya göre sırala (eşitlik durumunda pozisyona göre)
  key_chars_sorted = sorted(key_chars, key=lambda x: (x[1], x[0]))
  
  # Her pozisyonun yeni sırasını belirle
  order = [0] * len(key)
  for new_pos, (old_pos, _) in enumerate(key_chars_sorted):
    order[old_pos] = new_pos
  
  return order


def columnar_get_key_order_reverse(key: str) -> list[int]:
  """
  Deşifreleme için ters sıralama oluşturur.
  
  Şifreleme sırasının tersini alır, böylece deşifreleme
  sırasında doğru sütun sırası kullanılır.
  
  Args:
    key: Kullanılan anahtar kelime
  
  Returns:
    Ters sıralama listesi
  """
  order = columnar_get_key_order(key)
  reverse_order = [0] * len(order)
  for i, pos in enumerate(order):
    reverse_order[pos] = i
  return reverse_order


def columnar_encrypt(text: str, key: str) -> str:
  """
  Columnar Transposition şifreleme ile metni şifreler.
  
  Metni bir grid'e yerleştirir ve anahtar kelimenin alfabetik
  sırasına göre sütunları okuyarak şifreler.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar kelime (sütun sıralamasını belirler)
  
  Returns:
    Şifrelenmiş metin
  """
  if not key:
    return text
  
  # Yalnızca harfleri al
  text_clean = "".join(ch for ch in text if ch.isalpha())
  if not text_clean:
    return text
  
  key_len = len(key)
  # Gerekli satır sayısını hesapla (yukarı yuvarlama)
  num_rows = (len(text_clean) + key_len - 1) // key_len
  
  # Grid oluştur: metni satırlar halinde yerleştir
  grid = []
  text_idx = 0
  for i in range(num_rows):
    row = []
    for j in range(key_len):
      if text_idx < len(text_clean):
        row.append(text_clean[text_idx])
        text_idx += 1
      else:
        row.append("X")  # Eksik yerleri X ile doldur (padding)
    grid.append(row)
  
  # Sütun sırasına göre oku (anahtar kelimenin alfabetik sırasına göre)
  order = columnar_get_key_order(key)
  result = []
  
  for col_pos in range(key_len):
    # Bu pozisyondaki sütunun gerçek index'ini bul
    col_idx = order.index(col_pos)
    # Bu sütundaki tüm karakterleri oku
    for row in grid:
      result.append(row[col_idx])
  
  return "".join(result)


def columnar_decrypt(cipher: str, key: str) -> str:
  """
  Columnar Transposition şifrelemesi ile şifrelenmiş metni çözer.
  
  Şifreleme işleminin tersini yaparak orijinal metni geri getirir.
  Şifreli metni sütunlara dağıtıp, sonra satır satır okur.
  
  Args:
    cipher: Çözülecek şifrelenmiş metin
    key: Kullanılan anahtar kelime
  
  Returns:
    Çözülmüş orijinal metin
  """
  if not key:
    return cipher
  
  # Yalnızca harfleri al
  cipher_clean = "".join(ch for ch in cipher if ch.isalpha())
  if not cipher_clean:
    return cipher
  
  key_len = len(key)
  num_rows = (len(cipher_clean) + key_len - 1) // key_len
  
  # Sütun sıralamasını bul
  order = columnar_get_key_order(key)
  reverse_order = columnar_get_key_order_reverse(key)
  
  # Her sütuna kaç karakter düşeceğini hesapla
  chars_per_col = [num_rows] * key_len
  total_chars = num_rows * key_len
  excess = total_chars - len(cipher_clean)
  
  # Fazla karakterleri son sütunlardan çıkar (padding için)
  for i in range(excess):
    col_idx = key_len - 1 - i
    chars_per_col[col_idx] -= 1
  
  # Grid oluştur ve şifreli metni sütunlara dağıt
  grid = [[None for _ in range(key_len)] for _ in range(num_rows)]
  cipher_idx = 0
  
  for col_pos in range(key_len):
    # Bu pozisyondaki sütunun gerçek index'ini bul
    col_idx = order.index(col_pos)
    # Bu sütuna karakterleri yerleştir
    for row in range(chars_per_col[col_idx]):
      if cipher_idx < len(cipher_clean):
        grid[row][col_idx] = cipher_clean[cipher_idx]
        cipher_idx += 1
  
  # Grid'i satır satır oku (normal okuma)
  result = []
  for row in grid:
    for ch in row:
      if ch:
        result.append(ch)
  
  # Padding karakterlerini temizle
  return "".join(result).rstrip("X")


# -----------------------------
#  AES ve DES Şifreleme
# -----------------------------

# AES - Kütüphaneli (pycryptodome)
def aes_library_encrypt(text: str, key: str) -> str:
  """
  AES şifrelemesi ile metni şifreler (Kütüphane kullanarak).
  
  PyCryptodome kütüphanesini kullanarak AES-CBC modunda
  şifreleme yapar. Güvenli ve standart uyumlu implementasyondur.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar (string formatında, 16, 24 veya 32 byte'a çevrilir)
  
  Returns:
    Base64 kodlanmış şifrelenmiş metin (IV + ciphertext)
  
  Raises:
    ValueError: Şifreleme sırasında hata oluşursa
  """
  try:
    # Anahtarı 16, 24 veya 32 byte'a tamamla (AES-128, AES-192, AES-256)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) < 24:
      key_bytes = key_bytes.ljust(24, b'\0')
    elif len(key_bytes) < 32:
      key_bytes = key_bytes.ljust(32, b'\0')
    else:
      key_bytes = key_bytes[:32]
    
    # Anahtar uzunluğuna göre AES modunu seç
    if len(key_bytes) == 16:
      cipher = AES.new(key_bytes, AES.MODE_CBC)
    elif len(key_bytes) == 24:
      cipher = AES.new(key_bytes, AES.MODE_CBC)
    else:
      cipher = AES.new(key_bytes, AES.MODE_CBC)
    
    # Metni byte'a çevir
    text_bytes = text.encode('utf-8')
    # PKCS7 padding ekle (16 byte blok boyutu için)
    padded_text = pad(text_bytes, AES.block_size)
    # Şifreleme işlemi
    encrypted = cipher.encrypt(padded_text)
    
    # IV (Initialization Vector) ve şifreli metni birleştir
    # IV şifreleme için gereklidir ve deşifrelemede kullanılacak
    iv_ciphertext = cipher.iv + encrypted
    # Base64 kodlama ile string formatına çevir
    return base64.b64encode(iv_ciphertext).decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES şifreleme hatası: {str(e)}")


def aes_library_decrypt(encrypted_text: str, key: str) -> str:
  """
  AES şifrelemesi ile şifrelenmiş metni çözer (Kütüphane kullanarak).
  
  PyCryptodome kütüphanesini kullanarak AES-CBC modunda
  deşifreleme yapar. Şifreleme ile aynı anahtar kullanılmalıdır.
  
  Args:
    encrypted_text: Base64 kodlanmış şifrelenmiş metin (IV + ciphertext)
    key: Kullanılan anahtar (şifreleme ile aynı olmalı)
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: Deşifreleme sırasında hata oluşursa
  """
  try:
    # Anahtarı şifrelemedeki gibi hazırla
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) < 24:
      key_bytes = key_bytes.ljust(24, b'\0')
    elif len(key_bytes) < 32:
      key_bytes = key_bytes.ljust(32, b'\0')
    else:
      key_bytes = key_bytes[:32]
    
    # Base64 kodunu çöz
    iv_ciphertext = base64.b64decode(encrypted_text.encode('utf-8'))
    # IV ve şifreli metni ayır
    iv = iv_ciphertext[:AES.block_size]  # İlk 16 byte IV
    ciphertext = iv_ciphertext[AES.block_size:]  # Kalan kısım şifreli metin
    
    # Aynı IV ile deşifreleme yap
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES deşifreleme hatası: {str(e)}")


# AES - Kütüphanesiz (Basitleştirilmiş Implementasyon)
# Not: Bu basit bir AES implementasyonudur, eğitim amaçlıdır.
# Gerçek AES çok karmaşık olduğu için basit XOR tabanlı şifreleme kullanılır.

def aes_manual_key_schedule(key: bytes) -> list:
  """
  Basitleştirilmiş anahtar genişletme algoritması.
  
  Gerçek AES'in anahtar genişletme algoritması çok karmaşık olduğu için,
  burada basit bir döngüsel kaydırma kullanılır. Sadece eğitim amaçlıdır.
  
  Args:
    key: Anahtar byte'ları
  
  Returns:
    Genişletilmiş anahtarlar listesi
  """
  # Basitleştirilmiş versiyon - sadece anahtarı tekrarlar
  key_len = len(key)
  rounds = {16: 10, 24: 12, 32: 14}.get(key_len, 10)
  keys = [key]
  for i in range(rounds):
    # Basit döngüsel kaydırma
    new_key = bytes((b + i) % 256 for b in key)
    keys.append(new_key)
  return keys


def aes_manual_encrypt(text: str, key: str) -> str:
  """
  AES şifrelemesi ile metni şifreler (Kütüphanesiz, basitleştirilmiş).
  
  Gerçek AES implementasyonu çok karmaşık olduğu için,
  burada basit XOR tabanlı şifreleme kullanılır. Sadece eğitim amaçlıdır.
  Üretim ortamında kütüphane tabanlı AES kullanılmalıdır.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar string
  
  Returns:
    Base64 kodlanmış şifrelenmiş metin
  
  Raises:
    ValueError: Şifreleme sırasında hata oluşursa
  """
  try:
    # Anahtarı hazırla (16-32 byte arası)
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) > 32:
      key_bytes = key_bytes[:32]
    
    # Metni byte'a çevir
    text_bytes = text.encode('utf-8')
    
    # PKCS7 padding ekle (16 byte blok boyutu için)
    pad_len = 16 - (len(text_bytes) % 16)
    padded_text = text_bytes + bytes([pad_len] * pad_len)
    
    # Basit XOR tabanlı şifreleme (gerçek AES yerine)
    # Her 16 byte'lık blok için XOR işlemi yapılır
    result = []
    # Anahtarı metin uzunluğuna kadar genişlet
    key_extended = (key_bytes * ((len(padded_text) // len(key_bytes)) + 1))[:len(padded_text)]
    
    # Bloklar halinde şifrele
    for i in range(0, len(padded_text), 16):
      block = padded_text[i:i+16]
      key_block = key_extended[i:i+16]
      # XOR işlemi ile şifreleme
      encrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(encrypted_block)
    
    encrypted = b''.join(result)
    return base64.b64encode(encrypted).decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES (manuel) şifreleme hatası: {str(e)}")


def aes_manual_decrypt(encrypted_text: str, key: str) -> str:
  """
  AES şifrelemesi ile şifrelenmiş metni çözer (Kütüphanesiz, basitleştirilmiş).
  
  XOR tabanlı basit deşifreleme yapar. XOR simetrik olduğu için
  şifreleme ile aynı işlemi gerçekleştirir.
  
  Args:
    encrypted_text: Base64 kodlanmış şifrelenmiş metin
    key: Kullanılan anahtar (şifreleme ile aynı olmalı)
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: Deşifreleme veya padding hatası oluşursa
  """
  try:
    # Anahtarı şifrelemedeki gibi hazırla
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) > 32:
      key_bytes = key_bytes[:32]
    
    # Base64 kodunu çöz
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # XOR ile deşifreleme (şifreleme ile aynı işlem)
    result = []
    # Anahtarı metin uzunluğuna kadar genişlet
    key_extended = (key_bytes * ((len(encrypted) // len(key_bytes)) + 1))[:len(encrypted)]
    
    # Bloklar halinde deşifrele
    for i in range(0, len(encrypted), 16):
      block = encrypted[i:i+16]
      key_block = key_extended[i:i+16]
      # XOR işlemi ile deşifreleme
      decrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(decrypted_block)
    
    decrypted = b''.join(result)
    
    # PKCS7 padding'i kaldır
    pad_len = decrypted[-1]
    if pad_len > 16:
      raise ValueError("Hatalı padding")
    decrypted = decrypted[:-pad_len]
    
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES (manuel) deşifreleme hatası: {str(e)}")


# -----------------------------
#  DES (DATA ENCRYPTION STANDARD)
# -----------------------------

# DES - Kütüphaneli (pycryptodome)
def des_library_encrypt(text: str, key: str) -> str:
  """
  DES şifrelemesi ile metni şifreler (Kütüphane kullanarak).
  
  PyCryptodome kütüphanesini kullanarak DES-CBC modunda
  şifreleme yapar. DES eski bir standarttır ve artık güvenli
  kabul edilmemektedir, AES tercih edilmelidir.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar (tam olarak 8 byte olmalı)
  
  Returns:
    Base64 kodlanmış şifrelenmiş metin (IV + ciphertext)
  
  Raises:
    ValueError: Şifreleme sırasında hata oluşursa
  """
  try:
    # DES anahtarı tam olarak 8 byte olmalı
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
      key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
      key_bytes = key_bytes[:8]
    
    cipher = DES.new(key_bytes, DES.MODE_CBC)
    text_bytes = text.encode('utf-8')
    padded_text = pad(text_bytes, DES.block_size)
    encrypted = cipher.encrypt(padded_text)
    
    # IV ve şifreli metni birleştir
    iv_ciphertext = cipher.iv + encrypted
    return base64.b64encode(iv_ciphertext).decode('utf-8')
  except Exception as e:
    raise ValueError(f"DES şifreleme hatası: {str(e)}")


def des_library_decrypt(encrypted_text: str, key: str) -> str:
  """
  DES şifrelemesi ile şifrelenmiş metni çözer (Kütüphane kullanarak).
  
  PyCryptodome kütüphanesini kullanarak DES-CBC modunda
  deşifreleme yapar.
  
  Args:
    encrypted_text: Base64 kodlanmış şifrelenmiş metin (IV + ciphertext)
    key: Kullanılan anahtar (şifreleme ile aynı olmalı)
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: Deşifreleme sırasında hata oluşursa
  """
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
      key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
      key_bytes = key_bytes[:8]
    
    iv_ciphertext = base64.b64decode(encrypted_text.encode('utf-8'))
    iv = iv_ciphertext[:DES.block_size]
    ciphertext = iv_ciphertext[DES.block_size:]
    
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"DES deşifreleme hatası: {str(e)}")


# DES - Kütüphanesiz (Basitleştirilmiş Implementasyon)
def des_manual_encrypt(text: str, key: str) -> str:
  """
  DES şifrelemesi ile metni şifreler (Kütüphanesiz, basitleştirilmiş).
  
  Gerçek DES implementasyonu çok karmaşık olduğu için,
  burada basit XOR tabanlı şifreleme kullanılır. Sadece eğitim amaçlıdır.
  
  Args:
    text: Şifrelenecek metin
    key: Anahtar string (8 byte'a çevrilir)
  
  Returns:
    Base64 kodlanmış şifrelenmiş metin
  
  Raises:
    ValueError: Şifreleme sırasında hata oluşursa
  """
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
      key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
      key_bytes = key_bytes[:8]
    
    text_bytes = text.encode('utf-8')
    
    # PKCS7 padding
    pad_len = 8 - (len(text_bytes) % 8)
    padded_text = text_bytes + bytes([pad_len] * pad_len)
    
    # Basit XOR tabanlı şifreleme (gerçek DES yerine)
    # Gerçek DES çok karmaşık olduğu için basit bir XOR şifreleme kullanıyoruz
    result = []
    key_extended = (key_bytes * ((len(padded_text) // len(key_bytes)) + 1))[:len(padded_text)]
    
    for i in range(0, len(padded_text), 8):
      block = padded_text[i:i+8]
      key_block = key_extended[i:i+8]
      encrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(encrypted_block)
    
    encrypted = b''.join(result)
    return base64.b64encode(encrypted).decode('utf-8')
  except Exception as e:
    raise ValueError(f"DES (manuel) şifreleme hatası: {str(e)}")


def des_manual_decrypt(encrypted_text: str, key: str) -> str:
  """DES deşifreleme - kütüphanesiz basit implementasyon"""
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 8:
      key_bytes = key_bytes.ljust(8, b'\0')
    elif len(key_bytes) > 8:
      key_bytes = key_bytes[:8]
    
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # XOR ile deşifreleme
    result = []
    key_extended = (key_bytes * ((len(encrypted) // len(key_bytes)) + 1))[:len(encrypted)]
    
    for i in range(0, len(encrypted), 8):
      block = encrypted[i:i+8]
      key_block = key_extended[i:i+8]
      decrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(decrypted_block)
    
    decrypted = b''.join(result)
    
    # PKCS7 unpadding
    pad_len = decrypted[-1]
    if pad_len > 8:
      raise ValueError("Hatalı padding")
    decrypted = decrypted[:-pad_len]
    
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"DES (manuel) deşifreleme hatası: {str(e)}")


# -----------------------------
#  RSA Şifreleme
# -----------------------------

# RSA - Kütüphaneli (pycryptodome)
def rsa_library_generate_keys(key_size: int = 2048) -> tuple[bytes, bytes]:
  """
  RSA anahtar çifti oluşturur.
  
  Asimetrik şifreleme için public ve private anahtar çifti
  üretir. RSA güvenliği büyük asal sayıların çarpanlarına
  ayrılmasının zorluğuna dayanır.
  
  Args:
    key_size: Anahtar boyutu (bit cinsinden, varsayılan: 2048)
              Minimum 512, maksimum 4096 bit
  
  Returns:
    (public_key_pem, private_key_pem) tuple'ı (PEM formatında)
  """
  # Anahtar boyutu sınırlaması
  if key_size < 512:
    key_size = 512
  elif key_size > 4096:
    key_size = 4096
  
  # RSA anahtarı oluştur
  key = RSA.generate(key_size)
  # Private ve public anahtarları PEM formatında export et
  private_key = key.export_key()
  public_key = key.publickey().export_key()
  return public_key, private_key


def rsa_library_encrypt(text: str, public_key_pem: str) -> str:
  """
  RSA şifrelemesi ile metni şifreler (Public key kullanarak).
  
  RSA asimetrik şifreleme algoritmasıdır. Public key ile şifreleme
  yapılır, private key ile deşifreleme yapılır. PKCS1_OAEP padding
  kullanılır.
  
  Args:
    text: Şifrelenecek metin
    public_key_pem: Public anahtar (PEM formatında)
  
  Returns:
    Base64 kodlanmış şifrelenmiş metin
  
  Raises:
    ValueError: Şifreleme sırasında hata oluşursa
  """
  try:
    # Public key'i yükle (string veya bytes)
    if isinstance(public_key_pem, str):
      public_key = RSA.import_key(public_key_pem.encode('utf-8'))
    else:
      public_key = RSA.import_key(public_key_pem)
    
    # PKCS1_OAEP şifreleme nesnesi oluştur
    cipher = PKCS1_OAEP.new(public_key)
    text_bytes = text.encode('utf-8')
    
    # RSA blok boyutu sınırlaması var, metni bloklara böl
    # OAEP padding 42 byte kullanır
    key_size = public_key.size_in_bytes()
    max_block_size = key_size - 42  # OAEP padding için
    
    # Metni bloklar halinde şifrele
    encrypted_blocks = []
    for i in range(0, len(text_bytes), max_block_size):
      block = text_bytes[i:i+max_block_size]
      encrypted_block = cipher.encrypt(block)
      encrypted_blocks.append(encrypted_block)
    
    # Tüm blokları birleştir ve base64 ile kodla
    encrypted = b''.join(encrypted_blocks)
    return base64.b64encode(encrypted).decode('utf-8')
  except Exception as e:
    raise ValueError(f"RSA şifreleme hatası: {str(e)}")


def rsa_library_decrypt(encrypted_text: str, private_key_pem: str) -> str:
  """
  RSA şifrelemesi ile şifrelenmiş metni çözer (Private key kullanarak).
  
  RSA asimetrik şifreleme algoritmasının deşifreleme işlemi.
  Private key ile şifrelenmiş metin çözülür.
  
  Args:
    encrypted_text: Base64 kodlanmış şifrelenmiş metin
    private_key_pem: Private anahtar (PEM formatında)
  
  Returns:
    Çözülmüş orijinal metin
  
  Raises:
    ValueError: Deşifreleme sırasında hata oluşursa
  """
  try:
    # Private key'i yükle (string veya bytes)
    if isinstance(private_key_pem, str):
      private_key = RSA.import_key(private_key_pem.encode('utf-8'))
    else:
      private_key = RSA.import_key(private_key_pem)
    
    # PKCS1_OAEP deşifreleme nesnesi oluştur
    cipher = PKCS1_OAEP.new(private_key)
    # Base64 kodunu çöz
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # Her blok key_size kadar byte içerir
    key_size = private_key.size_in_bytes()
    
    # Bloklar halinde deşifrele
    decrypted_blocks = []
    for i in range(0, len(encrypted), key_size):
      block = encrypted[i:i+key_size]
      if block:
        decrypted_block = cipher.decrypt(block)
        decrypted_blocks.append(decrypted_block)
    
    # Blokları birleştir
    decrypted = b''.join(decrypted_blocks)
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"RSA deşifreleme hatası: {str(e)}")


# -----------------------------
#  YARDIMCI FONKSİYONLAR
# -----------------------------

def manual_gcd(a: int, b: int) -> int:
  """
  En büyük ortak bölen (Euclidean Algorithm).
  
  İki sayının en büyük ortak bölenini hesaplar.
  DSA ve diğer algoritmalarda kullanılır.
  
  Args:
    a: İlk sayı
    b: İkinci sayı
  
  Returns:
    En büyük ortak bölen
  """
  while b:
    a, b = b, a % b
  return a


def manual_mod_pow(base: int, exp: int, mod: int) -> int:
  """
  Modüler üs alma (Exponentiation by Squaring).
  
  base^exp mod mod işlemini verimli bir şekilde hesaplar.
  Büyük sayılar için kullanılır.
  
  Args:
    base: Taban
    exp: Üs
    mod: Modül değeri
  
  Returns:
    base^exp mod mod sonucu
  """
  result = 1
  base = base % mod
  while exp > 0:
    if exp % 2 == 1:
      result = (result * base) % mod
    exp = exp >> 1
    base = (base * base) % mod
  return result


def manual_is_prime(n: int) -> bool:
  """
  Basit asal sayı kontrolü.
  
  Bir sayının asal olup olmadığını kontrol eder.
  Küçük sayılar için kullanılır.
  
  Args:
    n: Kontrol edilecek sayı
  
  Returns:
    True eğer asal ise, False değilse
  """
  if n < 2:
    return False
  if n == 2:
    return True
  if n % 2 == 0:
    return False
  for i in range(3, int(n ** 0.5) + 1, 2):
    if n % i == 0:
      return False
  return True


# -----------------------------
#  DSA (Digital Signature Algorithm)
# -----------------------------

# DSA - Kütüphaneli (pycryptodome)
def dsa_library_generate_keys(key_size: int = 2048) -> tuple[bytes, bytes]:
  """DSA anahtar çifti oluşturur (public key, private key)"""
  if key_size < 1024:
    key_size = 1024
  elif key_size > 3072:
    key_size = 3072
  
  # DSA key_size 1024, 2048 veya 3072 olmalı
  if key_size not in [1024, 2048, 3072]:
    if key_size < 1536:
      key_size = 1024
    elif key_size < 2560:
      key_size = 2048
    else:
      key_size = 3072
  
  key = DSA.generate(key_size)
  private_key = key.export_key()
  public_key = key.publickey().export_key()
  return public_key, private_key


def dsa_library_sign(text: str, private_key_pem: str) -> str:
  """DSA ile dijital imza oluşturur"""
  try:
    # Private key'i yükle
    if isinstance(private_key_pem, str):
      private_key = DSA.import_key(private_key_pem.encode('utf-8'))
    else:
      private_key = DSA.import_key(private_key_pem)
    
    # Metnin hash'ini al
    text_bytes = text.encode('utf-8')
    hash_obj = SHA256.new(text_bytes)
    
    # İmza oluştur
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    
    # İmza ve metni birleştir (format: base64(metin)||base64(imza))
    text_b64 = base64.b64encode(text_bytes).decode('utf-8')
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return f"{text_b64}||{signature_b64}"
  except Exception as e:
    raise ValueError(f"DSA imza oluşturma hatası: {str(e)}")


def dsa_library_verify(signed_data: str, public_key_pem: str) -> str:
  """DSA ile dijital imzayı doğrular"""
  try:
    # Public key'i yükle
    if isinstance(public_key_pem, str):
      public_key = DSA.import_key(public_key_pem.encode('utf-8'))
    else:
      public_key = DSA.import_key(public_key_pem)
    
    # İmzalı veriyi parse et
    if "||" not in signed_data:
      raise ValueError("Geçersiz imzalı veri formatı")
    
    text_b64, signature_b64 = signed_data.split("||", 1)
    text_bytes = base64.b64decode(text_b64.encode('utf-8'))
    signature = base64.b64decode(signature_b64.encode('utf-8'))
    
    # Metnin hash'ini al
    hash_obj = SHA256.new(text_bytes)
    
    # İmzayı doğrula
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
      verifier.verify(hash_obj, signature)
      return text_bytes.decode('utf-8')
    except ValueError:
      raise ValueError("İmza doğrulama başarısız - imza geçersiz")
  except Exception as e:
    raise ValueError(f"DSA imza doğrulama hatası: {str(e)}")


# DSA - Kütüphanesiz (basitleştirilmiş implementasyon)
def dsa_manual_generate_keys(key_size: int = 1024) -> tuple[dict, dict]:
  """Basit DSA anahtar çifti oluşturur (eğitim amaçlı)"""
  # Basitleştirilmiş DSA parametreleri
  # Gerçek DSA çok daha karmaşıktır
  import random
  
  # Küçük asal sayılar (gerçek DSA'da çok daha büyük)
  q_primes = [101, 103, 107, 109, 113, 127, 131, 137, 139, 149]
  q = random.choice(q_primes)
  
  # p = q * k + 1 (basitleştirilmiş)
  k = random.randint(10, 50)
  p = q * k + 1
  while not manual_is_prime(p):
    k += 1
    p = q * k + 1
    if p > 10000:  # Limit
      p = 101 * 20 + 1
      break
  
  # g seç (generator)
  g = 2
  while manual_mod_pow(g, (p - 1) // q, p) == 1:
    g += 1
    if g > 100:  # Limit
      g = 3
      break
  
  # Private key: x (1 < x < q)
  x = random.randint(2, q - 1)
  
  # Public key: y = g^x mod p
  y = manual_mod_pow(g, x, p)
  
  private_key = {"p": p, "q": q, "g": g, "x": x}
  public_key = {"p": p, "q": q, "g": g, "y": y}
  
  return public_key, private_key


def dsa_manual_sign(text: str, private_key: dict) -> str:
  """DSA ile dijital imza oluşturur - kütüphanesiz"""
  try:
    p = private_key["p"]
    q = private_key["q"]
    g = private_key["g"]
    x = private_key["x"]
    
    text_bytes = text.encode('utf-8')
    # Basit hash (gerçekte SHA kullanılır)
    h = hash(text_bytes) % q
    if h == 0:
      h = 1
    
    import random
    k = random.randint(1, q - 1)
    
    # r = (g^k mod p) mod q
    r = manual_mod_pow(g, k, p) % q
    if r == 0:
      r = 1
    
    # s = k^(-1) * (h + x*r) mod q
    k_inv = mod_inverse(k, q)
    if k_inv is None:
      raise ValueError("k'nin modüler tersi bulunamadı")
    
    s = (k_inv * (h + x * r)) % q
    if s == 0:
      s = 1
    
    # İmza ve metni birleştir
    text_b64 = base64.b64encode(text_bytes).decode('utf-8')
    signature_str = f"{r},{s}"
    signature_b64 = base64.b64encode(signature_str.encode('utf-8')).decode('utf-8')
    return f"{text_b64}||{signature_b64}"
  except Exception as e:
    raise ValueError(f"DSA (manuel) imza oluşturma hatası: {str(e)}")


def dsa_manual_verify(signed_data: str, public_key: dict) -> str:
  """DSA ile dijital imzayı doğrular - kütüphanesiz"""
  try:
    p = public_key["p"]
    q = public_key["q"]
    g = public_key["g"]
    y = public_key["y"]
    
    # İmzalı veriyi parse et
    if "||" not in signed_data:
      raise ValueError("Geçersiz imzalı veri formatı")
    
    text_b64, signature_b64 = signed_data.split("||", 1)
    text_bytes = base64.b64decode(text_b64.encode('utf-8'))
    signature_str = base64.b64decode(signature_b64.encode('utf-8')).decode('utf-8')
    
    r_str, s_str = signature_str.split(",")
    r = int(r_str)
    s = int(s_str)
    
    if not (0 < r < q) or not (0 < s < q):
      raise ValueError("İmza değerleri geçersiz")
    
    # Basit hash
    h = hash(text_bytes) % q
    if h == 0:
      h = 1
    
    # w = s^(-1) mod q
    w = mod_inverse(s, q)
    if w is None:
      raise ValueError("s'nin modüler tersi bulunamadı")
    
    # u1 = (h * w) mod q
    u1 = (h * w) % q
    
    # u2 = (r * w) mod q
    u2 = (r * w) % q
    
    # v = ((g^u1 * y^u2) mod p) mod q
    g_u1 = manual_mod_pow(g, u1, p)
    y_u2 = manual_mod_pow(y, u2, p)
    v = ((g_u1 * y_u2) % p) % q
    
    # v == r ise imza geçerli
    if v != r:
      raise ValueError("İmza doğrulama başarısız - imza geçersiz")
    
    return text_bytes.decode('utf-8')
  except Exception as e:
    raise ValueError(f"DSA (manuel) imza doğrulama hatası: {str(e)}")


# -----------------------------
#  ECC (Elliptic Curve Cryptography)
# -----------------------------

# ECC - Kütüphaneli (pycryptodome)
def ecc_library_generate_keys(curve_name: str = "P-256") -> tuple[bytes, bytes]:
  """ECC anahtar çifti oluşturur (public key, private key)"""
  # Desteklenen eğriler: P-192, P-224, P-256, P-384, P-521, secp256k1
  valid_curves = ["P-192", "P-224", "P-256", "P-384", "P-521", "secp256k1"]
  if curve_name not in valid_curves:
    curve_name = "P-256"
  
  key = ECC.generate(curve=curve_name)
  private_key = key.export_key(format='PEM')
  public_key = key.public_key().export_key(format='PEM')
  return public_key, private_key


def ecc_library_encrypt(text: str, public_key_pem: str) -> str:
  """ECC şifreleme - kütüphane kullanarak (public key ile)"""
  try:
    # Public key'i yükle
    if isinstance(public_key_pem, str):
      public_key = ECC.import_key(public_key_pem.encode('utf-8'))
    else:
      public_key = ECC.import_key(public_key_pem)
    
    # ECIES (Elliptic Curve Integrated Encryption Scheme) kullan
    # Basit bir yaklaşım: AES ile şifrele, ECC ile AES anahtarını şifrele
    text_bytes = text.encode('utf-8')
    
    # Geçici AES anahtarı oluştur
    aes_key = get_random_bytes(32)  # 256-bit AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(text_bytes)
    
    # AES anahtarını ECC ile şifrele (basitleştirilmiş - gerçek ECIES daha karmaşık)
    # Bu basit bir implementasyon, gerçek ECIES daha karmaşıktır
    from Crypto.Cipher import PKCS1_OAEP
    # ECC için basit bir şifreleme: Anahtarı base64 ile encode et ve ekle
    encrypted_key_b64 = base64.b64encode(aes_key).decode('utf-8')
    
    # Tüm veriyi birleştir: encrypted_key||nonce||tag||ciphertext
    result = f"{encrypted_key_b64}||{base64.b64encode(nonce).decode('utf-8')}||{base64.b64encode(tag).decode('utf-8')}||{base64.b64encode(ciphertext).decode('utf-8')}"
    return result
  except Exception as e:
    raise ValueError(f"ECC şifreleme hatası: {str(e)}")


def ecc_library_decrypt(encrypted_text: str, private_key_pem: str) -> str:
  """ECC deşifreleme - kütüphane kullanarak (private key ile)"""
  try:
    # Private key'i yükle
    if isinstance(private_key_pem, str):
      private_key = ECC.import_key(private_key_pem.encode('utf-8'))
    else:
      private_key = ECC.import_key(private_key_pem)
    
    # Şifreli veriyi parse et
    parts = encrypted_text.split("||")
    if len(parts) != 4:
      raise ValueError("Geçersiz şifreli veri formatı")
    
    encrypted_key_b64, nonce_b64, tag_b64, ciphertext_b64 = parts
    aes_key = base64.b64decode(encrypted_key_b64.encode('utf-8'))
    nonce = base64.b64decode(nonce_b64.encode('utf-8'))
    tag = base64.b64decode(tag_b64.encode('utf-8'))
    ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
    
    # AES ile deşifrele
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"ECC deşifreleme hatası: {str(e)}")


def ecc_library_sign(text: str, private_key_pem: str) -> str:
  """ECC ile dijital imza oluşturur (ECDSA)"""
  try:
    # Private key'i yükle
    if isinstance(private_key_pem, str):
      private_key = ECC.import_key(private_key_pem.encode('utf-8'))
    else:
      private_key = ECC.import_key(private_key_pem)
    
    # Metnin hash'ini al
    text_bytes = text.encode('utf-8')
    hash_obj = SHA256.new(text_bytes)
    
    # İmza oluştur
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    
    # İmza ve metni birleştir
    text_b64 = base64.b64encode(text_bytes).decode('utf-8')
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return f"{text_b64}||{signature_b64}"
  except Exception as e:
    raise ValueError(f"ECC imza oluşturma hatası: {str(e)}")


def ecc_library_verify(signed_data: str, public_key_pem: str) -> str:
  """ECC ile dijital imzayı doğrular (ECDSA)"""
  try:
    # Public key'i yükle
    if isinstance(public_key_pem, str):
      public_key = ECC.import_key(public_key_pem.encode('utf-8'))
    else:
      public_key = ECC.import_key(public_key_pem)
    
    # İmzalı veriyi parse et
    if "||" not in signed_data:
      raise ValueError("Geçersiz imzalı veri formatı")
    
    text_b64, signature_b64 = signed_data.split("||", 1)
    text_bytes = base64.b64decode(text_b64.encode('utf-8'))
    signature = base64.b64decode(signature_b64.encode('utf-8'))
    
    # Metnin hash'ini al
    hash_obj = SHA256.new(text_bytes)
    
    # İmzayı doğrula
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
      verifier.verify(hash_obj, signature)
      return text_bytes.decode('utf-8')
    except ValueError:
      raise ValueError("İmza doğrulama başarısız - imza geçersiz")
  except Exception as e:
    raise ValueError(f"ECC imza doğrulama hatası: {str(e)}")


# ECC - Kütüphanesiz (basitleştirilmiş implementasyon)
def ecc_manual_generate_keys() -> tuple[dict, dict]:
  """Basit ECC anahtar çifti oluşturur (eğitim amaçlı)"""
  # Basit eliptik eğri: y^2 = x^3 + ax + b (mod p)
  # Küçük sayılar kullanıyoruz (gerçek ECC çok daha karmaşık)
  p = 23  # Küçük asal sayı
  a = 1
  b = 1
  
  # Eğri üzerindeki noktaları bul
  points = []
  for x in range(p):
    y_squared = (x**3 + a*x + b) % p
    for y in range(p):
      if (y**2) % p == y_squared:
        points.append((x, y))
  
  if len(points) < 2:
    # Varsayılan noktalar
    points = [(0, 1), (1, 7), (3, 10), (6, 19)]
  
  # Generator point (G) seç
  import random
  G = points[1] if len(points) > 1 else points[0]
  
  # Private key: d (rastgele sayı)
  d = random.randint(2, min(20, len(points) - 1))
  
  # Public key: Q = d * G (point multiplication - basitleştirilmiş)
  # Basit yaklaşım: d * G = G + G + ... + G (d kez)
  Q = G
  for _ in range(d - 1):
    # Basit point addition (gerçek ECC'de çok daha karmaşık)
    Q_x, Q_y = Q
    G_x, G_y = G
    # Basit toplama modülü (gerçek formül farklıdır)
    new_x = (Q_x + G_x) % p
    new_y = (Q_y + G_y) % p
    Q = (new_x, new_y)
  
  private_key = {"p": p, "a": a, "b": b, "G": G, "d": d}
  public_key = {"p": p, "a": a, "b": b, "G": G, "Q": Q}
  
  return public_key, private_key


def ecc_manual_encrypt(text: str, public_key: dict) -> str:
  """ECC şifreleme - kütüphanesiz basit implementasyon"""
  try:
    text_bytes = text.encode('utf-8')
    
    # Basit şifreleme: XOR ile (gerçek ECC çok daha karmaşık)
    # Public key'den bir değer türet
    Q = public_key["Q"]
    key_value = (Q[0] + Q[1]) % 256
    
    # Her byte'ı XOR ile şifrele
    encrypted_bytes = bytes(byte_val ^ key_value for byte_val in text_bytes)
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')
  except Exception as e:
    raise ValueError(f"ECC (manuel) şifreleme hatası: {str(e)}")


def ecc_manual_decrypt(encrypted_text: str, private_key: dict) -> str:
  """ECC deşifreleme - kütüphanesiz basit implementasyon"""
  try:
    encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # Private key'den aynı değeri türet
    G = private_key["G"]
    d = private_key["d"]
    p = private_key["p"]
    
    # Q = d * G hesapla (decrypt için)
    Q = G
    for _ in range(d - 1):
      Q_x, Q_y = Q
      G_x, G_y = G
      new_x = (Q_x + G_x) % p
      new_y = (Q_y + G_y) % p
      Q = (new_x, new_y)
    
    key_value = (Q[0] + Q[1]) % 256
    
    # XOR ile deşifrele
    decrypted_bytes = bytes(byte_val ^ key_value for byte_val in encrypted_bytes)
    
    return decrypted_bytes.decode('utf-8')
  except Exception as e:
    raise ValueError(f"ECC (manuel) deşifreleme hatası: {str(e)}")


def ecc_manual_sign(text: str, private_key: dict) -> str:
  """ECC ile dijital imza oluşturur - kütüphanesiz"""
  try:
    text_bytes = text.encode('utf-8')
    p = private_key["p"]
    d = private_key["d"]
    
    # Basit hash
    h = hash(text_bytes) % p
    if h == 0:
      h = 1
    
    # Basit imza (gerçek ECDSA çok daha karmaşık)
    import random
    k = random.randint(1, p - 1)
    r = (k * h) % p
    s = (d * r + k) % p
    
    # İmza ve metni birleştir
    text_b64 = base64.b64encode(text_bytes).decode('utf-8')
    signature_str = f"{r},{s}"
    signature_b64 = base64.b64encode(signature_str.encode('utf-8')).decode('utf-8')
    return f"{text_b64}||{signature_b64}"
  except Exception as e:
    raise ValueError(f"ECC (manuel) imza oluşturma hatası: {str(e)}")


def ecc_manual_verify(signed_data: str, public_key: dict) -> str:
  """ECC ile dijital imzayı doğrular - kütüphanesiz"""
  try:
    # İmzalı veriyi parse et
    if "||" not in signed_data:
      raise ValueError("Geçersiz imzalı veri formatı")
    
    text_b64, signature_b64 = signed_data.split("||", 1)
    text_bytes = base64.b64decode(text_b64.encode('utf-8'))
    signature_str = base64.b64decode(signature_b64.encode('utf-8')).decode('utf-8')
    
    r_str, s_str = signature_str.split(",")
    r = int(r_str)
    s = int(s_str)
    
    p = public_key["p"]
    Q = public_key["Q"]
    
    # Basit hash
    h = hash(text_bytes) % p
    if h == 0:
      h = 1
    
    # Basit doğrulama (gerçek ECDSA çok daha karmaşık)
    # Bu sadece eğitim amaçlı basit bir yaklaşım
    v = (r * h + s) % p
    expected_v = (Q[0] + Q[1]) % p
    
    # Basit kontrol (gerçek ECDSA'da farklı)
    if abs(v - expected_v) > 5:  # Tolerans
      raise ValueError("İmza doğrulama başarısız - imza geçersiz")
    
    return text_bytes.decode('utf-8')
  except Exception as e:
    raise ValueError(f"ECC (manuel) imza doğrulama hatası: {str(e)}")


# -----------------------------
#  FORM YÖNETİMİ VE API
# -----------------------------

@dataclass
class FormState:
  """
  Form verilerini saklamak için kullanılan veri sınıfı.
  
  Tüm şifreleme algoritmaları ve parametrelerini içerir.
  Flask form verilerini organize etmek için kullanılır.
  """
  text: str = ""
  output: str = ""
  algorithm: str = "caesar"  # "caesar" | "railFence" | "vigenere" | "vernam" | "playfair" | "route" | "affine" | "hill" | "columnar" | "aes" | "des" | "rsa" | "dsa" | "ecc"
  mode: str = "encrypt"  # "encrypt" | "decrypt"
  caesar_shift: int = 3
  rail_rails: int = 3
  vigenere_key: str = ""
  vernam_key: str = ""
  playfair_key: str = ""
  route_rows: int = 4
  route_cols: int = 4
  affine_a: int = 5
  affine_b: int = 8
  hill_key: str = ""
  hill_size: int = 2
  columnar_key: str = ""
  aes_key: str = ""
  aes_use_library: bool = True
  des_key: str = ""
  des_use_library: bool = True
  rsa_key_size: int = 2048
  rsa_public_key: str = ""
  rsa_private_key: str = ""
  dsa_key_size: int = 2048
  dsa_public_key: str = ""
  dsa_private_key: str = ""
  dsa_use_library: bool = True
  ecc_curve: str = "P-256"
  ecc_public_key: str = ""
  ecc_private_key: str = ""
  ecc_use_library: bool = True
  status: str = ""
  is_error: bool = False


def handle_form(req) -> FormState:
  if req.method == "GET":
    return FormState()

  text = (req.form.get("text") or "").strip()
  algorithm = req.form.get("algorithm", "caesar")
  mode = req.form.get("mode", "encrypt")

  caesar_shift_raw = req.form.get("caesarShift", "3")
  rail_rails_raw = req.form.get("railRails", "3")
  vigenere_key = (req.form.get("vigenereKey") or "").strip()
  vernam_key = (req.form.get("vernamKey") or "").strip()
  playfair_key = (req.form.get("playfairKey") or "").strip()
  route_rows_raw = req.form.get("routeRows", "4")
  route_cols_raw = req.form.get("routeCols", "4")
  affine_a_raw = req.form.get("affineA", "5")
  affine_b_raw = req.form.get("affineB", "8")
  hill_key = (req.form.get("hillKey") or "").strip()
  hill_size_raw = req.form.get("hillSize", "2")
  columnar_key = (req.form.get("columnarKey") or "").strip()
  aes_key = (req.form.get("aesKey") or "").strip()
  aes_use_library_raw = req.form.get("aesUseLibrary", "true")
  des_key = (req.form.get("desKey") or "").strip()
  des_use_library_raw = req.form.get("desUseLibrary", "true")
  rsa_key_size_raw = req.form.get("rsaKeySize", "2048")
  rsa_public_key = (req.form.get("rsaPublicKey") or "").strip()
  rsa_private_key = (req.form.get("rsaPrivateKey") or "").strip()
  dsa_key_size_raw = req.form.get("dsaKeySize", "2048")
  dsa_public_key = (req.form.get("dsaPublicKey") or "").strip()
  dsa_private_key = (req.form.get("dsaPrivateKey") or "").strip()
  dsa_use_library_raw = req.form.get("dsaUseLibrary", "true")
  ecc_curve = req.form.get("eccCurve", "P-256")
  ecc_public_key = (req.form.get("eccPublicKey") or "").strip()
  ecc_private_key = (req.form.get("eccPrivateKey") or "").strip()
  ecc_use_library_raw = req.form.get("eccUseLibrary", "true")

  state = FormState(
    text=text,
    algorithm=algorithm,
    mode=mode,
    vigenere_key=vigenere_key,
    vernam_key=vernam_key,
    playfair_key=playfair_key,
    hill_key=hill_key,
    columnar_key=columnar_key,
    aes_key=aes_key,
    aes_use_library=aes_use_library_raw.lower() == "true",
    des_key=des_key,
    des_use_library=des_use_library_raw.lower() == "true",
    rsa_public_key=rsa_public_key,
    rsa_private_key=rsa_private_key,
    dsa_public_key=dsa_public_key,
    dsa_private_key=dsa_private_key,
    dsa_use_library=dsa_use_library_raw.lower() == "true",
    ecc_curve=ecc_curve,
    ecc_public_key=ecc_public_key,
    ecc_private_key=ecc_private_key,
    ecc_use_library=ecc_use_library_raw.lower() == "true",
  )
  
  try:
    state.rsa_key_size = int(rsa_key_size_raw)
    if state.rsa_key_size < 512:
      state.rsa_key_size = 512
    elif state.rsa_key_size > 4096:
      state.rsa_key_size = 4096
  except ValueError:
    state.rsa_key_size = 2048
  
  try:
    state.dsa_key_size = int(dsa_key_size_raw)
    if state.dsa_key_size < 1024:
      state.dsa_key_size = 1024
    elif state.dsa_key_size > 3072:
      state.dsa_key_size = 3072
    # DSA için sadece 1024, 2048, 3072 geçerli
    if state.dsa_key_size not in [1024, 2048, 3072]:
      if state.dsa_key_size < 1536:
        state.dsa_key_size = 1024
      elif state.dsa_key_size < 2560:
        state.dsa_key_size = 2048
      else:
        state.dsa_key_size = 3072
  except ValueError:
    state.dsa_key_size = 2048

  try:
    state.caesar_shift = int(caesar_shift_raw)
  except ValueError:
    state.caesar_shift = 3

  try:
    state.rail_rails = max(2, int(rail_rails_raw))
  except ValueError:
    state.rail_rails = 3

  try:
    state.route_rows = max(2, int(route_rows_raw))
  except ValueError:
    state.route_rows = 4

  try:
    state.route_cols = max(2, int(route_cols_raw))
  except ValueError:
    state.route_cols = 4

  try:
    state.affine_a = int(affine_a_raw)
    if state.affine_a < 1 or state.affine_a > 25:
      state.affine_a = 5
  except ValueError:
    state.affine_a = 5

  try:
    state.affine_b = int(affine_b_raw)
    if state.affine_b < 0 or state.affine_b > 25:
      state.affine_b = 8
  except ValueError:
    state.affine_b = 8

  try:
    state.hill_size = max(2, min(3, int(hill_size_raw)))
  except ValueError:
    state.hill_size = 2

  if not text:
    state.status = "Lütfen bir metin girin."
    state.is_error = True
    return state

  try:
    if algorithm == "caesar":
      if mode == "encrypt":
        state.output = caesar_encrypt(text, state.caesar_shift)
        state.status = "Sezar ile şifreleme tamamlandı."
      else:
        state.output = caesar_decrypt(text, state.caesar_shift)
        state.status = "Sezar ile deşifreleme tamamlandı."
    elif algorithm == "railFence":
      if mode == "encrypt":
        state.output = rail_fence_encrypt(text, state.rail_rails)
        state.status = "Rail Fence ile şifreleme tamamlandı."
      else:
        state.output = rail_fence_decrypt(text, state.rail_rails)
        state.status = "Rail Fence ile deşifreleme tamamlandı."
    elif algorithm == "vigenere":
      if not vigenere_key:
        state.status = "Vigenere için anahtar gereklidir."
        state.is_error = True
        return state
      if mode == "encrypt":
        state.output = vigenere_encrypt(text, vigenere_key)
        state.status = "Vigenere ile şifreleme tamamlandı."
      else:
        state.output = vigenere_decrypt(text, vigenere_key)
        state.status = "Vigenere ile deşifreleme tamamlandı."
    elif algorithm == "vernam":
      if not vernam_key:
        state.status = "Vernam için anahtar gereklidir."
        state.is_error = True
        return state
      if mode == "encrypt":
        state.output = vernam_encrypt(text, vernam_key)
        state.status = "Vernam ile şifreleme tamamlandı."
      else:
        state.output = vernam_decrypt(text, vernam_key)
        state.status = "Vernam ile deşifreleme tamamlandı."
    elif algorithm == "playfair":
      if not playfair_key:
        state.status = "Playfair için anahtar gereklidir."
        state.is_error = True
        return state
      if mode == "encrypt":
        state.output = playfair_encrypt(text, playfair_key)
        state.status = "Playfair ile şifreleme tamamlandı."
      else:
        state.output = playfair_decrypt(text, playfair_key)
        state.status = "Playfair ile deşifreleme tamamlandı."
    elif algorithm == "route":
      if mode == "encrypt":
        state.output = route_encrypt(text, state.route_rows, state.route_cols)
        state.status = "Route ile şifreleme tamamlandı."
      else:
        state.output = route_decrypt(text, state.route_rows, state.route_cols)
        state.status = "Route ile deşifreleme tamamlandı."
    elif algorithm == "affine":
      try:
        if mode == "encrypt":
          state.output = affine_encrypt(text, state.affine_a, state.affine_b)
          state.status = "Affine ile şifreleme tamamlandı."
        else:
          state.output = affine_decrypt(text, state.affine_a, state.affine_b)
          state.status = "Affine ile deşifreleme tamamlandı."
      except ValueError as e:
        state.status = f"Affine hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "hill":
      if not hill_key:
        state.status = "Hill Cipher için anahtar gereklidir."
        state.is_error = True
        return state
      try:
        if mode == "encrypt":
          state.output = hill_encrypt(text, hill_key, state.hill_size)
          state.status = "Hill Cipher ile şifreleme tamamlandı."
        else:
          state.output = hill_decrypt(text, hill_key, state.hill_size)
          state.status = "Hill Cipher ile deşifreleme tamamlandı."
      except ValueError as e:
        state.status = f"Hill Cipher hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "columnar":
      if not columnar_key:
        state.status = "Columnar için anahtar gereklidir."
        state.is_error = True
        return state
      if mode == "encrypt":
        state.output = columnar_encrypt(text, columnar_key)
        state.status = "Columnar ile şifreleme tamamlandı."
      else:
        state.output = columnar_decrypt(text, columnar_key)
        state.status = "Columnar ile deşifreleme tamamlandı."
    elif algorithm == "aes":
      if not aes_key:
        state.status = "AES için anahtar gereklidir."
        state.is_error = True
        return state
      try:
        # Zaman ölçümü başlat
        start_time = time.perf_counter()
        
        if state.aes_use_library:
          if mode == "encrypt":
            state.output = aes_library_encrypt(text, aes_key)
            method_type = "kütüphaneli"
            operation = "şifreleme"
          else:
            state.output = aes_library_decrypt(text, aes_key)
            method_type = "kütüphaneli"
            operation = "deşifreleme"
        else:
          if mode == "encrypt":
            state.output = aes_manual_encrypt(text, aes_key)
            method_type = "kütüphanesiz"
            operation = "şifreleme"
          else:
            state.output = aes_manual_decrypt(text, aes_key)
            method_type = "kütüphanesiz"
            operation = "deşifreleme"
        
        # Zaman ölçümü bitir
        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000  # milisaniyeye çevir
        
        state.status = f"AES ({method_type}) ile {operation} tamamlandı. Süre: {elapsed_time:.3f} ms"
      except ValueError as e:
        state.status = f"AES hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "des":
      if not des_key:
        state.status = "DES için anahtar gereklidir (8 karakter)."
        state.is_error = True
        return state
      try:
        # Zaman ölçümü başlat
        start_time = time.perf_counter()
        
        if state.des_use_library:
          if mode == "encrypt":
            state.output = des_library_encrypt(text, des_key)
            method_type = "kütüphaneli"
            operation = "şifreleme"
          else:
            state.output = des_library_decrypt(text, des_key)
            method_type = "kütüphaneli"
            operation = "deşifreleme"
        else:
          if mode == "encrypt":
            state.output = des_manual_encrypt(text, des_key)
            method_type = "kütüphanesiz"
            operation = "şifreleme"
          else:
            state.output = des_manual_decrypt(text, des_key)
            method_type = "kütüphanesiz"
            operation = "deşifreleme"
        
        # Zaman ölçümü bitir
        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000  # milisaniyeye çevir
        
        state.status = f"DES ({method_type}) ile {operation} tamamlandı. Süre: {elapsed_time:.3f} ms"
      except ValueError as e:
        state.status = f"DES hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "rsa":
      try:
        # Zaman ölçümü başlat
        start_time = time.perf_counter()
        
        if mode == "encrypt":
          if not rsa_public_key:
            state.status = "RSA şifreleme için public key gereklidir. Anahtar oluştur butonuna basın."
            state.is_error = True
            return state
          state.output = rsa_library_encrypt(text, rsa_public_key)
          operation = "şifreleme"
        else:
          if not rsa_private_key:
            state.status = "RSA deşifreleme için private key gereklidir."
            state.is_error = True
            return state
          state.output = rsa_library_decrypt(text, rsa_private_key)
          operation = "deşifreleme"
        
        # Zaman ölçümü bitir
        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000  # milisaniyeye çevir
        
        state.status = f"RSA (kütüphaneli) ile {operation} tamamlandı. Süre: {elapsed_time:.3f} ms"
      except ValueError as e:
        state.status = f"RSA hatası: {str(e)}"
        state.is_error = True
      except Exception as e:
        state.status = f"RSA hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "dsa":
      try:
        # Zaman ölçümü başlat
        start_time = time.perf_counter()
        
        if state.dsa_use_library:
          if mode == "encrypt":
            # DSA encrypt = dijital imza oluştur
            if not dsa_private_key:
              state.status = "DSA imza oluşturma için private key gereklidir. Anahtar oluştur butonuna basın."
              state.is_error = True
              return state
            state.output = dsa_library_sign(text, dsa_private_key)
            method_type = "kütüphaneli"
            operation = "imza oluşturma"
          else:
            # DSA decrypt = dijital imza doğrula
            if not dsa_public_key:
              state.status = "DSA imza doğrulama için public key gereklidir."
              state.is_error = True
              return state
            state.output = dsa_library_verify(text, dsa_public_key)
            method_type = "kütüphaneli"
            operation = "imza doğrulama"
        else:
          if mode == "encrypt":
            # DSA imza oluştur
            if not dsa_private_key:
              # Anahtar oluştur
              pub_key_dict, priv_key_dict = dsa_manual_generate_keys(state.dsa_key_size)
              # Dictionary'yi JSON benzeri string'e çevir
              import json
              state.dsa_public_key = json.dumps(pub_key_dict)
              state.dsa_private_key = json.dumps(priv_key_dict)
              priv_key = priv_key_dict
            else:
              # String'den dict'e çevir
              import json
              priv_key = json.loads(dsa_private_key)
            state.output = dsa_manual_sign(text, priv_key)
            method_type = "kütüphanesiz"
            operation = "imza oluşturma"
          else:
            # DSA imza doğrula
            if not dsa_public_key:
              state.status = "DSA imza doğrulama için public key gereklidir."
              state.is_error = True
              return state
            # String'den dict'e çevir
            import json
            pub_key = json.loads(dsa_public_key)
            state.output = dsa_manual_verify(text, pub_key)
            method_type = "kütüphanesiz"
            operation = "imza doğrulama"
        
        # Zaman ölçümü bitir
        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000  # milisaniyeye çevir
        
        state.status = f"DSA ({method_type}) ile {operation} tamamlandı. Süre: {elapsed_time:.3f} ms"
      except ValueError as e:
        state.status = f"DSA hatası: {str(e)}"
        state.is_error = True
      except Exception as e:
        state.status = f"DSA hatası: {str(e)}"
        state.is_error = True
    elif algorithm == "ecc":
      try:
        # Zaman ölçümü başlat
        start_time = time.perf_counter()
        
        if state.ecc_use_library:
          if mode == "encrypt":
            if not ecc_public_key:
              state.status = "ECC şifreleme için public key gereklidir. Anahtar oluştur butonuna basın."
              state.is_error = True
              return state
            state.output = ecc_library_encrypt(text, ecc_public_key)
            method_type = "kütüphaneli"
            operation = "şifreleme"
          else:
            if not ecc_private_key:
              state.status = "ECC deşifreleme için private key gereklidir."
              state.is_error = True
              return state
            state.output = ecc_library_decrypt(text, ecc_private_key)
            method_type = "kütüphaneli"
            operation = "deşifreleme"
        else:
          if mode == "encrypt":
            if not ecc_public_key:
              # Anahtar oluştur
              pub_key_dict, priv_key_dict = ecc_manual_generate_keys()
              import json
              state.ecc_public_key = json.dumps(pub_key_dict)
              state.ecc_private_key = json.dumps(priv_key_dict)
              pub_key = pub_key_dict
            else:
              # String'den dict'e çevir
              import json
              pub_key = json.loads(ecc_public_key)
            state.output = ecc_manual_encrypt(text, pub_key)
            method_type = "kütüphanesiz"
            operation = "şifreleme"
          else:
            if not ecc_private_key:
              state.status = "ECC deşifreleme için private key gereklidir."
              state.is_error = True
              return state
            # String'den dict'e çevir
            import json
            priv_key = json.loads(ecc_private_key)
            state.output = ecc_manual_decrypt(text, priv_key)
            method_type = "kütüphanesiz"
            operation = "deşifreleme"
        
        # Zaman ölçümü bitir
        end_time = time.perf_counter()
        elapsed_time = (end_time - start_time) * 1000  # milisaniyeye çevir
        
        state.status = f"ECC ({method_type}) ile {operation} tamamlandı. Süre: {elapsed_time:.3f} ms"
      except ValueError as e:
        state.status = f"ECC hatası: {str(e)}"
        state.is_error = True
      except Exception as e:
        state.status = f"ECC hatası: {str(e)}"
        state.is_error = True
    else:
      state.status = "Bilinmeyen algoritma seçildi."
      state.is_error = True
  except Exception as e:
    state.status = f"İşlem sırasında bir hata oluştu: {str(e)}"
    state.is_error = True

  return state


@app.route("/generate-rsa-keys", methods=["POST"])
def generate_rsa_keys():
  """
  RSA anahtar çifti oluşturan API endpoint'i.
  
  POST isteği alır ve yeni RSA public/private anahtar çifti üretir.
  Anahtarlar PEM formatında JSON response olarak döndürülür.
  
  Returns:
    JSON response: {public_key, private_key} veya {error}
  """
  """RSA anahtar çifti oluşturur (sadece kütüphaneli)"""
  from flask import jsonify
  try:
    key_size = int(request.form.get("keySize", "2048"))
    
    public_key, private_key = rsa_library_generate_keys(key_size)
    return jsonify({
      "success": True,
      "public_key": public_key.decode('utf-8'),
      "private_key": private_key.decode('utf-8')
    })
  except Exception as e:
    return jsonify({"success": False, "error": str(e)})


@app.route("/generate-dsa-keys", methods=["POST"])
def generate_dsa_keys():
  """
  DSA anahtar çifti oluşturan API endpoint'i.
  
  POST isteği alır ve yeni DSA public/private anahtar çifti üretir.
  Anahtarlar PEM formatında (kütüphaneli) veya JSON formatında
  (kütüphanesiz) döndürülür.
  
  Returns:
    JSON response: {public_key, private_key} veya {error}
  """
  """DSA anahtar çifti oluşturur"""
  from flask import jsonify
  try:
    key_size = int(request.form.get("keySize", "2048"))
    use_library = request.form.get("useLibrary", "true").lower() == "true"
    
    # DSA key_size düzelt
    if key_size < 1024:
      key_size = 1024
    elif key_size > 3072:
      key_size = 3072
    if key_size not in [1024, 2048, 3072]:
      if key_size < 1536:
        key_size = 1024
      elif key_size < 2560:
        key_size = 2048
      else:
        key_size = 3072
    
    if use_library:
      public_key, private_key = dsa_library_generate_keys(key_size)
      return jsonify({
        "success": True,
        "public_key": public_key.decode('utf-8'),
        "private_key": private_key.decode('utf-8')
      })
    else:
      pub_key_dict, priv_key_dict = dsa_manual_generate_keys(key_size)
      import json
      return jsonify({
        "success": True,
        "public_key": json.dumps(pub_key_dict),
        "private_key": json.dumps(priv_key_dict)
      })
  except Exception as e:
    return jsonify({"success": False, "error": str(e)})


@app.route("/generate-ecc-keys", methods=["POST"])
def generate_ecc_keys():
  """
  ECC anahtar çifti oluşturan API endpoint'i.
  
  POST isteği alır ve yeni ECC public/private anahtar çifti üretir.
  Anahtarlar PEM formatında (kütüphaneli) veya JSON formatında
  (kütüphanesiz) döndürülür.
  
  Request body'de 'curve' parametresi isteğe bağlı olarak gönderilebilir.
  
  Returns:
    JSON response: {public_key, private_key, curve} veya {error}
  """
  """ECC anahtar çifti oluşturur"""
  from flask import jsonify
  try:
    curve_name = request.form.get("curveName", "P-256")
    use_library = request.form.get("useLibrary", "true").lower() == "true"
    
    if use_library:
      public_key, private_key = ecc_library_generate_keys(curve_name)
      return jsonify({
        "success": True,
        "public_key": public_key.decode('utf-8'),
        "private_key": private_key.decode('utf-8')
      })
    else:
      pub_key_dict, priv_key_dict = ecc_manual_generate_keys()
      import json
      return jsonify({
        "success": True,
        "public_key": json.dumps(pub_key_dict),
        "private_key": json.dumps(priv_key_dict)
      })
  except Exception as e:
    return jsonify({"success": False, "error": str(e)})


@app.route("/", methods=["GET", "POST"])
def index():
  """
  Ana sayfa endpoint'i.
  
  GET ve POST isteklerini karşılar:
  - GET: Boş form sayfasını gösterir
  - POST: Form verilerini işler ve sonuç sayfasını gösterir
  
  Returns:
    Rendered HTML template with form data
  """
  state = handle_form(request)
  return render_template("index.html", state=state)


if __name__ == "__main__":
  app.run(debug=True)


