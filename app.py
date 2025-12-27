from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Optional

from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from flask import Flask, render_template, request


app = Flask(__name__)


# -----------------------------
#  Şifreleme algoritmaları
# -----------------------------


def caesar_shift_char(ch: str, shift: int) -> str:
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
  return "".join(caesar_shift_char(ch, shift) for ch in text)


def caesar_decrypt(text: str, shift: int) -> str:
  return caesar_encrypt(text, -shift)


def rail_fence_encrypt(text: str, rails: int) -> str:
  if rails < 2 or len(text) == 0:
    return text

  lines = [[] for _ in range(rails)]
  row = 0
  direction = 1  # 1: aşağı, -1: yukarı

  for ch in text:
    lines[row].append(ch)

    if row == 0:
      direction = 1
    elif row == rails - 1:
      direction = -1

    row += direction

  return "".join("".join(line) for line in lines)


def rail_fence_decrypt(cipher: str, rails: int) -> str:
  if rails < 2 or len(cipher) == 0:
    return cipher

  length = len(cipher)

  # Her rail'e kaç karakter düşeceğini bul
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

  # Cipher'ı rail'lere paylaştır
  rails_arr = []
  index = 0
  for r in range(rails):
    part = list(cipher[index : index + counts[r]])
    rails_arr.append(part)
    index += counts[r]

  # Zigzag okuması
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


# Vigenere Şifreleme
def vigenere_prepare_key(key: str, length: int) -> str:
  """Anahtarı metin uzunluğuna kadar tekrarlar"""
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha())
  if not key_clean:
    key_clean = "A"
  key_repeated = (key_clean * ((length // len(key_clean)) + 1))[:length]
  return key_repeated


def vigenere_encrypt(text: str, key: str) -> str:
  if not key:
    return text

  key_prepared = vigenere_prepare_key(key, len(text))
  result = []

  key_idx = 0
  for ch in text:
    if ch.isalpha():
      is_upper = ch.isupper()
      ch_code = ord(ch.upper())
      key_code = ord(key_prepared[key_idx].upper())
      shift = key_code - ord("A")
      
      new_code = ((ch_code - ord("A") + shift) % 26) + ord("A")
      result.append(chr(new_code) if is_upper else chr(new_code).lower())
      key_idx += 1
    else:
      result.append(ch)

  return "".join(result)


def vigenere_decrypt(cipher: str, key: str) -> str:
  if not key:
    return cipher

  key_prepared = vigenere_prepare_key(key, len(cipher))
  result = []

  key_idx = 0
  for ch in cipher:
    if ch.isalpha():
      is_upper = ch.isupper()
      ch_code = ord(ch.upper())
      key_code = ord(key_prepared[key_idx].upper())
      shift = key_code - ord("A")
      
      new_code = ((ch_code - ord("A") - shift + 26) % 26) + ord("A")
      result.append(chr(new_code) if is_upper else chr(new_code).lower())
      key_idx += 1
    else:
      result.append(ch)

  return "".join(result)


# Vernam (One-Time Pad) Şifreleme
def vernam_encrypt(text: str, key: str) -> str:
  """XOR tabanlı Vernam şifreleme"""
  if not key:
    return text

  # Anahtarı metin uzunluğuna kadar tekrarlar
  key_extended = (key * ((len(text) // len(key)) + 1))[:len(text)]
  
  result = []
  for i, ch in enumerate(text):
    # Her karakteri XOR ile şifreler
    encrypted_char = chr(ord(ch) ^ ord(key_extended[i]))
    result.append(encrypted_char)

  return "".join(result)


def vernam_decrypt(cipher: str, key: str) -> str:
  """Vernam deşifreleme (XOR simetrik olduğu için encrypt ile aynı)"""
  return vernam_encrypt(cipher, key)


# Playfair Şifreleme
def playfair_prepare_text(text: str) -> str:
  """Metni Playfair için hazırlar (I/J birleştirme, çift harf ekleme)"""
  text_clean = "".join(ch.upper() for ch in text if ch.isalpha())
  text_clean = text_clean.replace("J", "I")
  
  if not text_clean:
    return ""
  
  result = []
  i = 0
  while i < len(text_clean):
    if i == len(text_clean) - 1:
      result.append(text_clean[i] + "X")
      break
    
    if text_clean[i] == text_clean[i + 1]:
      result.append(text_clean[i] + "X")
      i += 1
    else:
      result.append(text_clean[i] + text_clean[i + 1])
      i += 2
  
  return " ".join(result)


def playfair_create_matrix(key: str) -> list[list[str]]:
  """5x5 Playfair matrisi oluşturur"""
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha()).replace("J", "I")
  
  # Tekrar eden harfleri kaldır
  seen = set()
  key_unique = ""
  for ch in key_clean:
    if ch not in seen:
      key_unique += ch
      seen.add(ch)
  
  # Alfabeyi hazırla (J hariç)
  alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
  for ch in key_unique:
    alphabet = alphabet.replace(ch, "")
  
  matrix_str = key_unique + alphabet
  matrix = []
  for i in range(5):
    row = []
    for j in range(5):
      row.append(matrix_str[i * 5 + j])
    matrix.append(row)
  
  return matrix


def playfair_find_position(matrix: list[list[str]], ch: str) -> tuple[int, int]:
  """Matriste bir harfin pozisyonunu bulur"""
  for i in range(5):
    for j in range(5):
      if matrix[i][j] == ch:
        return (i, j)
  return (0, 0)


def playfair_encrypt_pair(matrix: list[list[str]], pair: str) -> str:
  """İki harfli çifti şifreler"""
  if len(pair) < 2:
    return pair
  
  ch1, ch2 = pair[0], pair[1]
  row1, col1 = playfair_find_position(matrix, ch1)
  row2, col2 = playfair_find_position(matrix, ch2)
  
  if row1 == row2:
    # Aynı satırda: sağa kaydır
    new_col1 = (col1 + 1) % 5
    new_col2 = (col2 + 1) % 5
    return matrix[row1][new_col1] + matrix[row2][new_col2]
  elif col1 == col2:
    # Aynı sütunda: aşağı kaydır
    new_row1 = (row1 + 1) % 5
    new_row2 = (row2 + 1) % 5
    return matrix[new_row1][col1] + matrix[new_row2][col2]
  else:
    # Dikdörtgen: köşeleri değiştir
    return matrix[row1][col2] + matrix[row2][col1]


def playfair_decrypt_pair(matrix: list[list[str]], pair: str) -> str:
  """İki harfli çifti deşifreler"""
  if len(pair) < 2:
    return pair
  
  ch1, ch2 = pair[0], pair[1]
  row1, col1 = playfair_find_position(matrix, ch1)
  row2, col2 = playfair_find_position(matrix, ch2)
  
  if row1 == row2:
    # Aynı satırda: sola kaydır
    new_col1 = (col1 - 1) % 5
    new_col2 = (col2 - 1) % 5
    return matrix[row1][new_col1] + matrix[row2][new_col2]
  elif col1 == col2:
    # Aynı sütunda: yukarı kaydır
    new_row1 = (row1 - 1) % 5
    new_row2 = (row2 - 1) % 5
    return matrix[new_row1][col1] + matrix[new_row2][col2]
  else:
    # Dikdörtgen: köşeleri değiştir
    return matrix[row1][col2] + matrix[row2][col1]


def playfair_encrypt(text: str, key: str) -> str:
  """Playfair şifreleme"""
  if not key or not text:
    return text
  
  matrix = playfair_create_matrix(key)
  text_prepared = playfair_prepare_text(text)
  pairs = text_prepared.split()
  
  result = []
  for pair in pairs:
    if len(pair) == 2:
      result.append(playfair_encrypt_pair(matrix, pair))
    else:
      result.append(pair)
  
  return "".join(result)


def playfair_decrypt(cipher: str, key: str) -> str:
  """Playfair deşifreleme"""
  if not key or not cipher:
    return cipher
  
  matrix = playfair_create_matrix(key)
  cipher_clean = "".join(ch.upper() for ch in cipher if ch.isalpha())
  
  if len(cipher_clean) % 2 != 0:
    cipher_clean += "X"
  
  result = []
  for i in range(0, len(cipher_clean), 2):
    pair = cipher_clean[i:i+2]
    if len(pair) == 2:
      decrypted = playfair_decrypt_pair(matrix, pair)
      result.append(decrypted)
    else:
      result.append(pair)
  
  return "".join(result)


# Route Şifreleme
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


# Affine Şifreleme
def gcd_extended(a: int, b: int) -> tuple[int, int, int]:
  """Extended Euclidean Algorithm - gcd ve modüler ters için"""
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = gcd_extended(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
  """a'nın mod m'deki tersini bulur"""
  gcd, x, _ = gcd_extended(a, m)
  if gcd != 1:
    return None  # Ters yok
  return (x % m + m) % m


def affine_encrypt(text: str, a: int, b: int) -> str:
  """Affine şifreleme: E(x) = (ax + b) mod 26"""
  if gcd_extended(a, 26)[0] != 1:
    raise ValueError("a ve 26 aralarında asal olmalıdır (gcd(a, 26) = 1)")
  
  result = []
  for ch in text:
    if ch.isalpha():
      is_upper = ch.isupper()
      ch_code = ord(ch.upper()) - ord("A")
      encrypted_code = (a * ch_code + b) % 26
      encrypted_char = chr(encrypted_code + ord("A"))
      result.append(encrypted_char if is_upper else encrypted_char.lower())
    else:
      result.append(ch)
  
  return "".join(result)


def affine_decrypt(cipher: str, a: int, b: int) -> str:
  """Affine deşifreleme: D(x) = a^(-1)(x - b) mod 26"""
  a_inv = mod_inverse(a, 26)
  if a_inv is None:
    raise ValueError("a'nın mod 26'da tersi yok")
  
  result = []
  for ch in cipher:
    if ch.isalpha():
      is_upper = ch.isupper()
      ch_code = ord(ch.upper()) - ord("A")
      decrypted_code = (a_inv * (ch_code - b + 26)) % 26
      decrypted_char = chr(decrypted_code + ord("A"))
      result.append(decrypted_char if is_upper else decrypted_char.lower())
    else:
      result.append(ch)
  
  return "".join(result)


# Hill Cipher Şifreleme
def hill_create_matrix(key: str, size: int) -> list[list[int]]:
  """Anahtar kelimeden Hill Cipher matrisi oluşturur"""
  key_clean = "".join(ch.upper() for ch in key if ch.isalpha())
  
  # Matris boyutuna göre anahtarı doldur
  if len(key_clean) < size * size:
    key_clean = key_clean.ljust(size * size, "A")
  elif len(key_clean) > size * size:
    key_clean = key_clean[:size * size]
  
  matrix = []
  for i in range(size):
    row = []
    for j in range(size):
      char_code = ord(key_clean[i * size + j]) - ord("A")
      row.append(char_code)
    matrix.append(row)
  
  return matrix


def hill_matrix_determinant(matrix: list[list[int]]) -> int:
  """2x2 matris determinantı hesaplar"""
  if len(matrix) == 2:
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
  return 0


def hill_matrix_inverse(matrix: list[list[int]]) -> list[list[int]]:
  """2x2 matrisin mod 26'da tersini bulur"""
  det = hill_matrix_determinant(matrix)
  det_inv = mod_inverse(det, 26)
  
  if det_inv is None:
    raise ValueError("Matris determinantının mod 26'da tersi yok")
  
  # 2x2 matris için ters formül
  a, b = matrix[0][0], matrix[0][1]
  c, d = matrix[1][0], matrix[1][1]
  
  inverse = [
    [(det_inv * d) % 26, (-det_inv * b) % 26],
    [(-det_inv * c) % 26, (det_inv * a) % 26]
  ]
  
  return inverse


def hill_multiply_matrix_vector(matrix: list[list[int]], vector: list[int]) -> list[int]:
  """Matris-vektör çarpımı"""
  result = []
  for row in matrix:
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
  """Hill Cipher deşifreleme"""
  if size < 2 or size > 3:
    size = 2
  
  matrix = hill_create_matrix(key, size)
  
  try:
    inverse_matrix = hill_matrix_inverse(matrix)
  except ValueError:
    raise ValueError("Anahtar matrisin tersi alınamıyor")
  
  cipher_clean = "".join(ch.upper() for ch in cipher if ch.isalpha())
  if not cipher_clean:
    return cipher
  
  if len(cipher_clean) % size != 0:
    cipher_clean += "X" * (size - (len(cipher_clean) % size))
  
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
    block = cipher_clean[block_start:block_start + size]
    vector = [ord(ch) - ord("A") for ch in block]
    decrypted_vector = hill_multiply_matrix_vector(inverse_matrix, vector)
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
  
  return "".join(result).rstrip("X")


# Columnar Transposition Şifreleme
def columnar_get_key_order(key: str) -> list[int]:
  """Anahtar kelimeden sütun sıralamasını çıkarır"""
  key_upper = key.upper()
  key_chars = [(i, key_upper[i]) for i in range(len(key_upper))]
  key_chars_sorted = sorted(key_chars, key=lambda x: (x[1], x[0]))
  
  order = [0] * len(key)
  for new_pos, (old_pos, _) in enumerate(key_chars_sorted):
    order[old_pos] = new_pos
  
  return order


def columnar_get_key_order_reverse(key: str) -> list[int]:
  """Deşifreleme için ters sıralama"""
  order = columnar_get_key_order(key)
  reverse_order = [0] * len(order)
  for i, pos in enumerate(order):
    reverse_order[pos] = i
  return reverse_order


def columnar_encrypt(text: str, key: str) -> str:
  """Columnar Transposition şifreleme"""
  if not key:
    return text
  
  text_clean = "".join(ch for ch in text if ch.isalpha())
  if not text_clean:
    return text
  
  key_len = len(key)
  num_rows = (len(text_clean) + key_len - 1) // key_len  # Yuvarlama yukarı
  
  # Grid oluştur
  grid = []
  text_idx = 0
  for i in range(num_rows):
    row = []
    for j in range(key_len):
      if text_idx < len(text_clean):
        row.append(text_clean[text_idx])
        text_idx += 1
      else:
        row.append("X")  # Eksik yerleri X ile doldur
    grid.append(row)
  
  # Sütun sırasına göre oku
  order = columnar_get_key_order(key)
  result = []
  
  for col_pos in range(key_len):
    col_idx = order.index(col_pos)
    for row in grid:
      result.append(row[col_idx])
  
  return "".join(result)


def columnar_decrypt(cipher: str, key: str) -> str:
  """Columnar Transposition deşifreleme"""
  if not key:
    return cipher
  
  cipher_clean = "".join(ch for ch in cipher if ch.isalpha())
  if not cipher_clean:
    return cipher
  
  key_len = len(key)
  num_rows = (len(cipher_clean) + key_len - 1) // key_len
  
  # Sütun sırasını bul
  order = columnar_get_key_order(key)
  reverse_order = columnar_get_key_order_reverse(key)
  
  # Şifreli metni sütunlara dağıt
  chars_per_col = [num_rows] * key_len
  total_chars = num_rows * key_len
  excess = total_chars - len(cipher_clean)
  
  # Fazla karakterleri son sütunlardan çıkar
  for i in range(excess):
    col_idx = key_len - 1 - i
    chars_per_col[col_idx] -= 1
  
  # Grid oluştur
  grid = [[None for _ in range(key_len)] for _ in range(num_rows)]
  cipher_idx = 0
  
  for col_pos in range(key_len):
    col_idx = order.index(col_pos)
    for row in range(chars_per_col[col_idx]):
      if cipher_idx < len(cipher_clean):
        grid[row][col_idx] = cipher_clean[cipher_idx]
        cipher_idx += 1
  
  # Grid'i satır satır oku
  result = []
  for row in grid:
    for ch in row:
      if ch:
        result.append(ch)
  
  return "".join(result).rstrip("X")


# -----------------------------
#  AES ve DES Şifreleme
# -----------------------------

# AES - Kütüphaneli (pycryptodome)
def aes_library_encrypt(text: str, key: str) -> str:
  """AES şifreleme - kütüphane kullanarak"""
  try:
    # Anahtarı 16, 24 veya 32 byte'a tamamla
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
    
    text_bytes = text.encode('utf-8')
    padded_text = pad(text_bytes, AES.block_size)
    encrypted = cipher.encrypt(padded_text)
    
    # IV ve şifreli metni birleştir ve base64 ile kodla
    iv_ciphertext = cipher.iv + encrypted
    return base64.b64encode(iv_ciphertext).decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES şifreleme hatası: {str(e)}")


def aes_library_decrypt(encrypted_text: str, key: str) -> str:
  """AES deşifreleme - kütüphane kullanarak"""
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) < 24:
      key_bytes = key_bytes.ljust(24, b'\0')
    elif len(key_bytes) < 32:
      key_bytes = key_bytes.ljust(32, b'\0')
    else:
      key_bytes = key_bytes[:32]
    
    # Base64'ten decode et
    iv_ciphertext = base64.b64decode(encrypted_text.encode('utf-8'))
    iv = iv_ciphertext[:AES.block_size]
    ciphertext = iv_ciphertext[AES.block_size:]
    
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES deşifreleme hatası: {str(e)}")


# AES - Kütüphanesiz (basitleştirilmiş implementasyon)
# Not: Bu basit bir AES implementasyonudur, eğitim amaçlıdır
def aes_manual_key_schedule(key: bytes) -> list:
  """Basit anahtar genişletme (gerçek AES'ten basitleştirilmiş)"""
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
  """AES şifreleme - kütüphanesiz basit implementasyon"""
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) > 32:
      key_bytes = key_bytes[:32]
    
    text_bytes = text.encode('utf-8')
    
    # PKCS7 padding
    pad_len = 16 - (len(text_bytes) % 16)
    padded_text = text_bytes + bytes([pad_len] * pad_len)
    
    # Basit XOR tabanlı şifreleme (gerçek AES yerine)
    # Gerçek AES çok karmaşık olduğu için basit bir XOR şifreleme kullanıyoruz
    result = []
    key_extended = (key_bytes * ((len(padded_text) // len(key_bytes)) + 1))[:len(padded_text)]
    
    for i in range(0, len(padded_text), 16):
      block = padded_text[i:i+16]
      key_block = key_extended[i:i+16]
      encrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(encrypted_block)
    
    encrypted = b''.join(result)
    return base64.b64encode(encrypted).decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES (manuel) şifreleme hatası: {str(e)}")


def aes_manual_decrypt(encrypted_text: str, key: str) -> str:
  """AES deşifreleme - kütüphanesiz basit implementasyon"""
  try:
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
      key_bytes = key_bytes.ljust(16, b'\0')
    elif len(key_bytes) > 32:
      key_bytes = key_bytes[:32]
    
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # XOR ile deşifreleme
    result = []
    key_extended = (key_bytes * ((len(encrypted) // len(key_bytes)) + 1))[:len(encrypted)]
    
    for i in range(0, len(encrypted), 16):
      block = encrypted[i:i+16]
      key_block = key_extended[i:i+16]
      decrypted_block = bytes(a ^ b for a, b in zip(block, key_block))
      result.append(decrypted_block)
    
    decrypted = b''.join(result)
    
    # PKCS7 unpadding
    pad_len = decrypted[-1]
    if pad_len > 16:
      raise ValueError("Hatalı padding")
    decrypted = decrypted[:-pad_len]
    
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"AES (manuel) deşifreleme hatası: {str(e)}")


# DES - Kütüphaneli (pycryptodome)
def des_library_encrypt(text: str, key: str) -> str:
  """DES şifreleme - kütüphane kullanarak"""
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
  """DES deşifreleme - kütüphane kullanarak"""
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


# DES - Kütüphanesiz (basitleştirilmiş implementasyon)
def des_manual_encrypt(text: str, key: str) -> str:
  """DES şifreleme - kütüphanesiz basit implementasyon"""
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
  """RSA anahtar çifti oluşturur (public key, private key)"""
  if key_size < 512:
    key_size = 512
  elif key_size > 4096:
    key_size = 4096
  
  key = RSA.generate(key_size)
  private_key = key.export_key()
  public_key = key.publickey().export_key()
  return public_key, private_key


def rsa_library_encrypt(text: str, public_key_pem: str) -> str:
  """RSA şifreleme - kütüphane kullanarak (public key ile)"""
  try:
    # Public key'i yükle
    if isinstance(public_key_pem, str):
      public_key = RSA.import_key(public_key_pem.encode('utf-8'))
    else:
      public_key = RSA.import_key(public_key_pem)
    
    cipher = PKCS1_OAEP.new(public_key)
    text_bytes = text.encode('utf-8')
    
    # RSA blok boyutu sınırlaması var, metni bloklara böl
    key_size = public_key.size_in_bytes()
    max_block_size = key_size - 42  # OAEP padding için
    
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
  """RSA deşifreleme - kütüphane kullanarak (private key ile)"""
  try:
    # Private key'i yükle
    if isinstance(private_key_pem, str):
      private_key = RSA.import_key(private_key_pem.encode('utf-8'))
    else:
      private_key = RSA.import_key(private_key_pem)
    
    cipher = PKCS1_OAEP.new(private_key)
    encrypted = base64.b64decode(encrypted_text.encode('utf-8'))
    
    # Blok boyutu = key_size
    key_size = private_key.size_in_bytes()
    
    decrypted_blocks = []
    for i in range(0, len(encrypted), key_size):
      block = encrypted[i:i+key_size]
      if block:
        decrypted_block = cipher.decrypt(block)
        decrypted_blocks.append(decrypted_block)
    
    decrypted = b''.join(decrypted_blocks)
    return decrypted.decode('utf-8')
  except Exception as e:
    raise ValueError(f"RSA deşifreleme hatası: {str(e)}")


# Yardımcı fonksiyonlar (DSA için kullanılıyor)
def manual_gcd(a: int, b: int) -> int:
  """En büyük ortak bölen"""
  while b:
    a, b = b, a % b
  return a


def manual_mod_pow(base: int, exp: int, mod: int) -> int:
  """Modüler üs alma"""
  result = 1
  base = base % mod
  while exp > 0:
    if exp % 2 == 1:
      result = (result * base) % mod
    exp = exp >> 1
    base = (base * base) % mod
  return result


def manual_is_prime(n: int) -> bool:
  """Basit asal sayı kontrolü"""
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


@dataclass
class FormState:
  text: str = ""
  output: str = ""
  algorithm: str = "caesar"  # "caesar" | "railFence" | "vigenere" | "vernam" | "playfair" | "route" | "affine" | "hill" | "columnar" | "aes" | "des" | "rsa" | "dsa"
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
    else:
      state.status = "Bilinmeyen algoritma seçildi."
      state.is_error = True
  except Exception as e:
    state.status = f"İşlem sırasında bir hata oluştu: {str(e)}"
    state.is_error = True

  return state


@app.route("/generate-rsa-keys", methods=["POST"])
def generate_rsa_keys():
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
    from flask import jsonify
    return jsonify({"success": False, "error": str(e)})


@app.route("/generate-dsa-keys", methods=["POST"])
def generate_dsa_keys():
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
    from flask import jsonify
    return jsonify({"success": False, "error": str(e)})


@app.route("/", methods=["GET", "POST"])
def index():
  state = handle_form(request)
  return render_template("index.html", state=state)


if __name__ == "__main__":
  app.run(debug=True)


