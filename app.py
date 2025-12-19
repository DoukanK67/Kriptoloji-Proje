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


@dataclass
class FormState:
  text: str = ""
  output: str = ""
  algorithm: str = "caesar"  # "caesar" | "railFence" | "vigenere" | "vernam" | "playfair" | "route"
  mode: str = "encrypt"  # "encrypt" | "decrypt"
  caesar_shift: int = 3
  rail_rails: int = 3
  vigenere_key: str = ""
  vernam_key: str = ""
  playfair_key: str = ""
  route_rows: int = 4
  route_cols: int = 4
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

  state = FormState(
    text=text,
    algorithm=algorithm,
    mode=mode,
    vigenere_key=vigenere_key,
    vernam_key=vernam_key,
    playfair_key=playfair_key,
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


