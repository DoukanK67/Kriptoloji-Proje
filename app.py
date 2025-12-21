from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

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


@dataclass
class FormState:
  text: str = ""
  output: str = ""
  algorithm: str = "caesar"  # "caesar" | "railFence" | "vigenere" | "vernam" | "playfair" | "route" | "affine" | "hill" | "columnar"
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

  state = FormState(
    text=text,
    algorithm=algorithm,
    mode=mode,
    vigenere_key=vigenere_key,
    vernam_key=vernam_key,
    playfair_key=playfair_key,
    hill_key=hill_key,
    columnar_key=columnar_key,
  )

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
    else:
      state.status = "Bilinmeyen algoritma seçildi."
      state.is_error = True
  except Exception as e:
    state.status = f"İşlem sırasında bir hata oluştu: {str(e)}"
    state.is_error = True

  return state


@app.route("/", methods=["GET", "POST"])
def index():
  state = handle_form(request)
  return render_template("index.html", state=state)


if __name__ == "__main__":
  app.run(debug=True)


