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


@dataclass
class FormState:
  text: str = ""
  output: str = ""
  algorithm: str = "caesar"  # "caesar" | "railFence"
  mode: str = "encrypt"  # "encrypt" | "decrypt"
  caesar_shift: int = 3
  rail_rails: int = 3
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

  state = FormState(
    text=text,
    algorithm=algorithm,
    mode=mode,
  )

  try:
    state.caesar_shift = int(caesar_shift_raw)
  except ValueError:
    state.caesar_shift = 3

  try:
    state.rail_rails = max(2, int(rail_rails_raw))
  except ValueError:
    state.rail_rails = 3

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
    else:
      state.status = "Bilinmeyen algoritma seçildi."
      state.is_error = True
  except Exception:
    state.status = "İşlem sırasında bir hata oluştu."
    state.is_error = True

  return state


@app.route("/", methods=["GET", "POST"])
def index():
  state = handle_form(request)
  return render_template("index.html", state=state)


if __name__ == "__main__":
  app.run(debug=True)


