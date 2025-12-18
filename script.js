// Basit yardımcılar
const $ = (id) => document.getElementById(id);

// Sezar Şifrelemesi (sadece İngilizce alfabetik karakterler için)
function caesarShiftChar(ch, shift) {
  const code = ch.charCodeAt(0);

  // Büyük harf A-Z
  if (code >= 65 && code <= 90) {
    const base = 65;
    const offset = ((code - base + shift) % 26 + 26) % 26;
    return String.fromCharCode(base + offset);
  }

  // Küçük harf a-z
  if (code >= 97 && code <= 122) {
    const base = 97;
    const offset = ((code - base + shift) % 26 + 26) % 26;
    return String.fromCharCode(base + offset);
  }

  // Diğer karakterler olduğu gibi bırak
  return ch;
}

function caesarEncrypt(text, shift) {
  return text
    .split("")
    .map((ch) => caesarShiftChar(ch, shift))
    .join("");
}

function caesarDecrypt(text, shift) {
  return caesarEncrypt(text, -shift);
}

// Rail Fence Şifreleme
function railFenceEncrypt(text, rails) {
  if (rails < 2 || text.length === 0) return text;

  const lines = Array.from({ length: rails }, () => []);
  let row = 0;
  let dir = 1; // 1: aşağı, -1: yukarı

  for (const ch of text) {
    lines[row].push(ch);

    if (row === 0) dir = 1;
    else if (row === rails - 1) dir = -1;

    row += dir;
  }

  return lines.map((line) => line.join("")).join("");
}

function railFenceDecrypt(cipher, rails) {
  if (rails < 2 || cipher.length === 0) return cipher;

  const len = cipher.length;

  // Her bir rail'in kaç karakter alacağını bul
  const counts = Array(rails).fill(0);
  let row = 0;
  let dir = 1;

  for (let i = 0; i < len; i++) {
    counts[row]++;
    if (row === 0) dir = 1;
    else if (row === rails - 1) dir = -1;
    row += dir;
  }

  // Cipher'ı rail'lere dağıt
  const railsArr = [];
  let index = 0;
  for (let r = 0; r < rails; r++) {
    railsArr[r] = cipher.slice(index, index + counts[r]).split("");
    index += counts[r];
  }

  // Zigzag sıraya göre karakterleri oku
  const result = [];
  row = 0;
  dir = 1;

  for (let i = 0; i < len; i++) {
    result.push(railsArr[row].shift());
    if (row === 0) dir = 1;
    else if (row === rails - 1) dir = -1;
    row += dir;
  }

  return result.join("");
}

// UI bağlantıları
function updateOptionsVisibility() {
  const algorithm = $("algorithm").value;
  $("caesarOptions").classList.toggle("hidden", algorithm !== "caesar");
  $("railFenceOptions").classList.toggle("hidden", algorithm !== "railFence");
}

function getSelectedMode() {
  const radios = document.querySelectorAll('input[name="mode"]');
  for (const r of radios) {
    if (r.checked) return r.value;
  }
  return "encrypt";
}

function setStatus(message, isError = false) {
  const el = $("status");
  el.textContent = message;
  el.style.color = isError ? "#f87171" : "#9ca3af";
}

function run() {
  const text = $("inputText").value;
  const algorithm = $("algorithm").value;
  const mode = getSelectedMode();

  if (!text) {
    setStatus("Lütfen bir metin girin.", true);
    $("outputText").value = "";
    return;
  }

  try {
    let result = "";

    if (algorithm === "caesar") {
      const shift = parseInt($("caesarShift").value, 10) || 0;
      result = mode === "encrypt" ? caesarEncrypt(text, shift) : caesarDecrypt(text, shift);
    } else if (algorithm === "railFence") {
      let rails = parseInt($("railFenceRails").value, 10) || 2;
      if (rails < 2) rails = 2;
      result = mode === "encrypt" ? railFenceEncrypt(text, rails) : railFenceDecrypt(text, rails);
    }

    $("outputText").value = result;
    setStatus(
      mode === "encrypt" ? "Şifreleme tamamlandı." : "Deşifreleme tamamlandı.",
      false
    );
  } catch (e) {
    console.error(e);
    setStatus("İşlem sırasında bir hata oluştu.", true);
  }
}

function clearAll() {
  $("inputText").value = "";
  $("outputText").value = "";
  setStatus("");
}

function copyOutput() {
  const out = $("outputText").value;
  if (!out) {
    setStatus("Kopyalanacak çıktı yok.", true);
    return;
  }
  navigator.clipboard
    .writeText(out)
    .then(() => setStatus("Çıktı panoya kopyalandı."))
    .catch(() => setStatus("Kopyalama başarısız oldu.", true));
}

// Event bağlama
document.addEventListener("DOMContentLoaded", () => {
  $("algorithm").addEventListener("change", updateOptionsVisibility);
  $("runBtn").addEventListener("click", run);
  $("clearBtn").addEventListener("click", clearAll);
  $("copyBtn").addEventListener("click", copyOutput);
});


