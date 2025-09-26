# jangan lupa install flask numpy dulu ye
# pip install flask numpy

from flask import Flask, request, render_template_string, send_file
from io import BytesIO
import numpy as np
import string

app = Flask(__name__)
app.secret_key = 'change-this-for-prod'

# == Konstanta alfabet ==
ALPHABET = string.ascii_uppercase
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for i, c in enumerate(ALPHABET)}

# == Utilities ==
def sanitize_letters(text):
    return ''.join([c for c in text.upper() if 'A' <= c <= 'Z'])

def chunk5(text):
    return ' '.join([text[i:i+5] for i in range(0, len(text), 5)])

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f'Modular inverse for {a} mod {m} does not exist')
    return x % m

# == Shift (Caesar) ==
def shift_encrypt_text(text, key):
    k = int(key) % 26
    return ''.join(I2A[(A2I[ch.upper()] + k) % 26] if ch.isalpha() else ch for ch in text)

def shift_decrypt_text(text, key):
    return shift_encrypt_text(text, -int(key))

def shift_letters_only(text, key):
    k = int(key) % 26
    s = sanitize_letters(text)
    return ''.join(I2A[(A2I[c] + k) % 26] for c in s)

# == Substitution ==
def build_subst_maps(key26):
    key26 = sanitize_letters(key26)
    if len(key26) != 26 or len(set(key26)) != 26:
        raise ValueError('Substitution key must be 26 unique letters')
    enc_map = {ALPHABET[i]: key26[i] for i in range(26)}
    dec_map = {v: k for k, v in enc_map.items()}
    return enc_map, dec_map

def subst_encrypt_text(text, key26):
    enc_map, _ = build_subst_maps(key26)
    return ''.join(enc_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in text)

def subst_decrypt_text(text, key26):
    _, dec_map = build_subst_maps(key26)
    return ''.join(dec_map.get(ch.upper(), ch) if ch.isalpha() else ch for ch in text)

def subst_letters_only(text, key26):
    enc_map, _ = build_subst_maps(key26)
    s = sanitize_letters(text)
    return ''.join(enc_map[c] for c in s)

# == Affine ==
def affine_encrypt_text(text, a, b):
    a, b = int(a), int(b)
    if egcd(a, 26)[0] != 1:
        raise ValueError('a must be coprime with 26 for Affine cipher')
    return ''.join(I2A[(a * A2I[ch.upper()] + b) % 26] if ch.isalpha() else ch for ch in text)

def affine_decrypt_text(text, a, b):
    a, b = int(a), int(b)
    inv = modinv(a, 26)
    return ''.join(I2A[(inv * (A2I[ch.upper()] - b)) % 26] if ch.isalpha() else ch for ch in text)

def affine_letters_only(text, a, b):
    a, b = int(a), int(b)
    if egcd(a, 26)[0] != 1:
        raise ValueError('a must be coprime with 26 for Affine cipher')
    s = sanitize_letters(text)
    return ''.join(I2A[(a * A2I[c] + b) % 26] for c in s)

# == Vigenere ==
def vigenere_encrypt_text(text, key):
    key = sanitize_letters(key)
    res, ki = '', 0
    for ch in text:
        if ch.isalpha():
            k = A2I[key[ki % len(key)]]
            res += I2A[(A2I[ch.upper()] + k) % 26]
            ki += 1
        else:
            res += ch
    return res

def vigenere_decrypt_text(text, key):
    key = sanitize_letters(key)
    res, ki = '', 0
    for ch in text:
        if ch.isalpha():
            k = A2I[key[ki % len(key)]]
            res += I2A[(A2I[ch.upper()] - k) % 26]
            ki += 1
        else:
            res += ch
    return res

def vigenere_letters_only(text, key):
    key = sanitize_letters(key)
    s = sanitize_letters(text)
    return ''.join(I2A[(A2I[ch] + A2I[key[i % len(key)]]) % 26] for i, ch in enumerate(s))

# == Hill ==
def hill_prepare_blocks(s, k):
    while len(s) % k != 0:
        s += 'X'
    nums = [A2I[c] for c in s]
    return [nums[i:i+k] for i in range(0, len(nums), k)]

def hill_encrypt_letters_only(text, key_numbers):
    nums = [int(x) % 26 for x in key_numbers]
    n = int(round(len(nums) ** 0.5))
    K = np.array(nums).reshape((n, n))
    s = sanitize_letters(text)
    blocks = hill_prepare_blocks(s, n)
    res = ''
    for b in blocks:
        prod = K.dot(np.array(b)) % 26
        res += ''.join(I2A[int(x)] for x in prod)
    return res

def hill_decrypt_letters_only(text, key_numbers):
    nums = [int(x) % 26 for x in key_numbers]
    n = int(round(len(nums) ** 0.5))
    K = np.array(nums).reshape((n, n))
    det = int(round(np.linalg.det(K))) % 26
    inv_det = modinv(det, 26)
    adj = np.round(np.linalg.inv(K) * det).astype(int) % 26
    Kinv = (inv_det * adj) % 26
    s = sanitize_letters(text)
    blocks = hill_prepare_blocks(s, n)
    res = ''
    for b in blocks:
        prod = Kinv.dot(np.array(b)) % 26
        res += ''.join(I2A[int(x)] for x in prod)
    return res

# == Permutation ==
def permutation_encrypt_letters_only(text, perm):
    perm = [int(x) for x in perm]
    k = len(perm)
    s = sanitize_letters(text)
    while len(s) % k != 0:
        s += 'X'
    res = ''
    for i in range(0, len(s), k):
        block = list(s[i:i+k])
        cipher_block = ''.join(block[pi] for pi in perm)
        res += cipher_block
    return res

def permutation_decrypt_letters_only(text, perm):
    perm = [int(x) for x in perm]
    k = len(perm)
    inv = [0] * k
    for i, p in enumerate(perm):
        inv[p] = i
    s = sanitize_letters(text)
    res = ''
    for i in range(0, len(s), k):
        block = list(s[i:i+k])
        plain_block = ''.join(block[inv[j]] for j in range(k))
        res += plain_block
    return res

# == Playfair (5x5 klasik, I=J digabung) ==
def build_playfair_table(key):
    key = sanitize_letters(key).replace("J", "I")
    seen = []
    for c in key:
        if c not in seen:
            seen.append(c)
    for c in ALPHABET:
        if c == 'J':  # skip J
            continue
        if c not in seen:
            seen.append(c)
    table = [seen[i * 5:(i + 1) * 5] for i in range(5)]
    return table

def playfair_process(text, key, decrypt=False):
    tbl = build_playfair_table(key)
    pos = {tbl[r][c]: (r, c) for r in range(5) for c in range(5)}
    s = sanitize_letters(text).replace("J", "I")
    pairs, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    res = ''
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            if not decrypt:
                res += tbl[ra][(ca + 1) % 5] + tbl[rb][(cb + 1) % 5]
            else:
                res += tbl[ra][(ca - 1) % 5] + tbl[rb][(cb - 1) % 5]
        elif ca == cb:
            if not decrypt:
                res += tbl[(ra + 1) % 5][ca] + tbl[(rb + 1) % 5][cb]
            else:
                res += tbl[(ra - 1) % 5][ca] + tbl[(rb - 1) % 5][cb]
        else:
            res += tbl[ra][cb] + tbl[rb][ca]
    return res

# == OTP ==
def otp_encrypt(text, key_stream):
    s = sanitize_letters(text)
    ks = sanitize_letters(key_stream)
    if len(ks) < len(s):
        raise ValueError('Key stream shorter than text')
    return ''.join(I2A[(A2I[s[i]] + A2I[ks[i]]) % 26] for i in range(len(s)))

def otp_decrypt(text, key_stream):
    s = sanitize_letters(text)
    ks = sanitize_letters(key_stream)
    if len(ks) < len(s):
        raise ValueError('Key stream shorter than text')
    return ''.join(I2A[(A2I[s[i]] - A2I[ks[i]]) % 26] for i in range(len(s)))

# == Flask UI ==
TEMPLATE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Web Cipher Project Kriptografi ARA</title>
  <style>
    body{font-family: system-ui; padding:20px; max-width:1100px; margin:auto}
    textarea{width:100%; height:160px}
    input[type=text], input[type=file], select{width:100%; padding:6px}
    .row{display:flex; gap:20px}
    .col{flex:1}
    .panel{border:1px solid #ddd; padding:12px; border-radius:8px; margin-bottom:12px}
    label{font-weight:600}
    button{padding:8px 12px; border-radius:6px}
    .error{color:crimson}
    .note{color:#555; font-size:0.9em}
  </style>
</head>
<body>
  <h1>Web Cipher Project Kriptografi ARA</h1>
  <div class="panel">
    <form method="post" action="/process" enctype="multipart/form-data">
      <div class="row">
        <div class="col">
          <label>Input mode</label>
          <select name="input_mode" id="input_mode">
            <option value="text">Typed text</option>
            <option value="file">Upload file (Shift only)</option>
          </select>

          <div id="text_input">
            <label>Plaintext / Ciphertext</label>
            <textarea name="text">{{ request_text or '' }}</textarea>
          </div>

          <div id="file_input">
            <label>Choose file</label>
            <input type="file" name="file">
          </div>

          <label>Cipher</label>
          <select name="cipher">
            <option value="Shift">Shift (Caesar)</option>
            <option value="Substitution">Substitution</option>
            <option value="Affine">Affine</option>
            <option value="Vigenere">Vigenere</option>
            <option value="Hill">Hill</option>
            <option value="Permutation">Permutation</option>
            <option value="Playfair">Playfair</option>
            <option value="One-time-pad">One-time-pad</option>
          </select>

          <label>Operation</label>
          <select name="op">
            <option value="enc">Encrypt</option>
            <option value="dec">Decrypt</option>
          </select>

          <label>Key / Parameters</label>
          <input type="text" name="key">

          <label>OTP key file (optional)</label>
          <input type="file" name="otp_keyfile">

          <label>Display mode</label>
          <select name="display_mode">
            <option value="preserve">Preserve</option>
            <option value="letters_only">Letters only</option>
            <option value="group5">Group of 5</option>
          </select>

          <br><br>
          <button type="submit">Process</button>
        </div>
        <div class="col">
          <label>Result</label>
          {% if error %}
            <p class="error">{{ error }}</p>
          {% endif %}
          <textarea readonly>{{ result or '' }}</textarea>
        </div>
      </div>
    </form>
  </div>

  <script>
    const inputMode = document.getElementById('input_mode');
    const textInput = document.getElementById('text_input');
    const fileInput = document.getElementById('file_input');
    function updateMode(){
      if(inputMode.value==='file'){
        textInput.style.display='none'; fileInput.style.display='block';
      } else {textInput.style.display='block'; fileInput.style.display='none';}
    }
    inputMode.addEventListener('change', updateMode);
    updateMode();
  </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(TEMPLATE, result=None, error=None, request_text='')

@app.route('/process', methods=['POST'])
def process():
    input_mode = request.form.get('input_mode')
    cipher = request.form.get('cipher')
    op = request.form.get('op')
    key = request.form.get('key') or ''
    display_mode = request.form.get('display_mode')
    uploaded = request.files.get('file')
    otp_keyfile = request.files.get('otp_keyfile')

    result_text, error = '', None
    request_text = request.form.get('text') or ''

    try:
        # File mode (Shift only)
        if input_mode == 'file' and uploaded and uploaded.filename:
            data = uploaded.read()
            filename = uploaded.filename
            if cipher != 'Shift':
                raise ValueError('File mode only supports Shift (byte-wise)')
            if not key:
                raise ValueError('Shift key required for file mode')
            k = int(key) % 256
            out = bytes((b + k) % 256 for b in data) if op == 'enc' else bytes((b - k) % 256 for b in data)
            bio = BytesIO(out)
            return send_file(bio, as_attachment=True, download_name=filename + '.dat')

        text = request_text

        # == Proses Cipher ==
        if cipher == 'Shift':
            result_text = shift_letters_only(text, key or '0') if display_mode != 'preserve' else (
                shift_encrypt_text(text, key) if op == 'enc' else shift_decrypt_text(text, key))
        elif cipher == 'Substitution':
            result_text = subst_letters_only(text, key) if display_mode != 'preserve' else (
                subst_encrypt_text(text, key) if op == 'enc' else subst_decrypt_text(text, key))
        elif cipher == 'Affine':
            a, b = key.split(',', 1)
            result_text = affine_letters_only(text, a, b) if display_mode != 'preserve' else (
                affine_encrypt_text(text, a, b) if op == 'enc' else affine_decrypt_text(text, a, b))
        elif cipher == 'Vigenere':
            result_text = vigenere_letters_only(text, key) if display_mode != 'preserve' else (
                vigenere_encrypt_text(text, key) if op == 'enc' else vigenere_decrypt_text(text, key))
        elif cipher == 'Hill':
            nums = [x.strip() for x in key.split(',') if x.strip()]
            result_text = hill_encrypt_letters_only(text, nums) if op == 'enc' else hill_decrypt_letters_only(text, nums)
        elif cipher == 'Permutation':
            perm = [x.strip() for x in key.split(',') if x.strip()]
            result_text = permutation_encrypt_letters_only(text, perm) if op == 'enc' else permutation_decrypt_letters_only(text, perm)
        elif cipher == 'Playfair':
            result_text = playfair_process(text, key, decrypt=(op=='dec'))
        elif cipher == 'One-time-pad':
            keydata = otp_keyfile.read().decode('utf-8') if (otp_keyfile and otp_keyfile.filename) else key
            result_text = otp_encrypt(text, keydata) if op == 'enc' else otp_decrypt(text, keydata)
        else:
            raise ValueError('Unknown cipher')

        if display_mode == 'letters_only':
            result_text = sanitize_letters(result_text)
        elif display_mode == 'group5':
            result_text = chunk5(sanitize_letters(result_text))

    except Exception as e:
        error = str(e)

    return render_template_string(TEMPLATE, result=result_text, error=error, request_text=request_text)

if __name__ == '__main__':
    app.run(debug=True)
