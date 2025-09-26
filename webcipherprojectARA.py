#jangan lupa install flask numpy dulu ye

from flask import Flask, request, render_template_string, send_file
from io import BytesIO
import numpy as np
import string
import base64

app = Flask(__name__)
app.secret_key = 'change-this-for-prod'

ALPHABET = string.ascii_uppercase
A2I = {c: i for i, c in enumerate(ALPHABET)}
I2A = {i: c for i, c in enumerate(ALPHABET)}

#==Utilities==

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

#==ciper ciperan==

# Shift
def shift_char(ch, k):
    if ch.isupper():
        return chr((ord(ch) - ord('A') + k) % 26 + ord('A'))
    else:
        return chr((ord(ch) - ord('a') + k) % 26 + ord('a'))

def shift_encrypt_text(text, key):
    k = int(key) % 26
    return ''.join(shift_char(ch, k) if ch.isalpha() else ch for ch in text)

def shift_decrypt_text(text, key):
    return shift_encrypt_text(text, -int(key))

def shift_letters_only(text, key):
    k = int(key) % 26
    s = sanitize_letters(text)
    return ''.join(I2A[(A2I[c] + k) % 26] for c in s)

# Substitution
def build_subst_maps(key26):
    key26 = sanitize_letters(key26)
    if len(key26) != 26 or len(set(key26)) != 26:
        raise ValueError('Substitution key must be 26 unique letters')
    enc_map = {ALPHABET[i]: key26[i] for i in range(26)}
    dec_map = {v: k for k, v in enc_map.items()}
    return enc_map, dec_map

def subst_encrypt_text(text, key26):
    enc_map, _ = build_subst_maps(key26)
    res = ''
    for ch in text:
        if ch.isalpha():
            if ch.isupper():
                res += enc_map[ch]
            else:
                res += enc_map[ch.upper()].lower()
        else:
            res += ch
    return res

def subst_decrypt_text(text, key26):
    _, dec_map = build_subst_maps(key26)
    res = ''
    for ch in text:
        if ch.isalpha():
            if ch.isupper():
                res += dec_map[ch]
            else:
                res += dec_map[ch.upper()].lower()
        else:
            res += ch
    return res

def subst_letters_only(text, key26):
    enc_map, _ = build_subst_maps(key26)
    s = sanitize_letters(text)
    return ''.join(enc_map[c] for c in s)

# Affine
def affine_encrypt_text(text, a, b):
    a = int(a); b = int(b)
    if egcd(a, 26)[0] != 1:
        raise ValueError('a must be coprime with 26 for Affine cipher')
    res = ''
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = (A2I[ch.upper()]
                 if ch.isupper() else A2I[ch.upper()])
            y = (a * A2I[ch.upper()] + b) % 26
            res += chr(y + base) if ch.isupper() else chr(y + ord('a'))
        else:
            res += ch
    return res

def affine_decrypt_text(text, a, b):
    a = int(a); b = int(b)
    inv = modinv(a, 26)
    res = ''
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = (inv * (A2I[ch.upper()] - b)) % 26
            res += chr(x + base) if ch.isupper() else chr(x + ord('a'))
        else:
            res += ch
    return res

def affine_letters_only(text, a, b):
    a = int(a); b = int(b)
    if egcd(a, 26)[0] != 1:
        raise ValueError('a must be coprime with 26 for Affine cipher')
    s = sanitize_letters(text)
    return ''.join(I2A[(a * A2I[c] + b) % 26] for c in s)

# Vigenere
def vigenere_encrypt_text(text, key):
    key = sanitize_letters(key)
    if not key:
        return text
    res = ''
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = A2I[key[ki % len(key)]]
            base = ord('A') if ch.isupper() else ord('a')
            y = (A2I[ch.upper()] + k) % 26
            res += chr(y + base)
            ki += 1
        else:
            res += ch
    return res

def vigenere_decrypt_text(text, key):
    key = sanitize_letters(key)
    if not key:
        return text
    res = ''
    ki = 0
    for ch in text:
        if ch.isalpha():
            k = A2I[key[ki % len(key)]]
            x = (A2I[ch.upper()] - k) % 26
            base = ord('A') if ch.isupper() else ord('a')
            res += chr(x + base)
            ki += 1
        else:
            res += ch
    return res

def vigenere_letters_only(text, key):
    key = sanitize_letters(key)
    if not key:
        return sanitize_letters(text)
    s = sanitize_letters(text)
    res = ''
    for i,ch in enumerate(s):
        k = A2I[key[i % len(key)]]
        res += I2A[(A2I[ch] + k) % 26]
    return res

# Hill cipher

def hill_prepare_blocks(s, k):
    while len(s) % k != 0:
        s += 'X'
    nums = [A2I[c] for c in s]
    blocks = [nums[i:i+k] for i in range(0, len(nums), k)]
    return blocks

def hill_encrypt_letters_only(text, key_numbers):
    nums = [int(x) % 26 for x in key_numbers]
    n = int(round(len(nums) ** 0.5))
    if n * n != len(nums):
        raise ValueError('Hill key must contain n*n numbers')
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
    if n * n != len(nums):
        raise ValueError('Hill key must contain n*n numbers')
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

# Permutation 
def permutation_encrypt_letters_only(text, perm):
    perm = [int(x) for x in perm]
    k = len(perm)
    if sorted(perm) != list(range(k)):
        raise ValueError('Permutation must be indices 0..k-1')
    s = sanitize_letters(text)
    while len(s) % k != 0:
        s += 'X'
    res = ''
    for i in range(0, len(s), k):
        block = list(s[i:i+k])
        cipher_block = [''] * k
        for j, pi in enumerate(perm):
            cipher_block[j] = block[pi]
        res += ''.join(cipher_block)
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
        plain_block = [''] * k
        for j in range(k):
            plain_block[inv[j]] = block[j]
        res += ''.join(plain_block)
    return res

# Playfair (kita baka pake kotak persegi panjang 2x13 biar 26 huruf bisa pas)
def build_playfair_table(key, rows=2, cols=13):
    key = sanitize_letters(key)
    seen = []
    for c in key:
        if c not in seen:
            seen.append(c)
    for c in ALPHABET:
        if c not in seen:
            seen.append(c)
    table = [seen[i * cols:(i + 1) * cols] for i in range(rows)]
    return table

def playfair_letters_only(text, key, rows=2, cols=13):
    tbl = build_playfair_table(key, rows, cols)
    pos = {}
    for r in range(rows):
        for c in range(cols):
            pos[tbl[r][c]] = (r, c)
    s = sanitize_letters(text)
    pairs = []
    i = 0
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
            res += tbl[ra][(ca + 1) % cols]
            res += tbl[rb][(cb + 1) % cols]
        elif ca == cb:
            res += tbl[(ra + 1) % rows][ca]
            res += tbl[(rb + 1) % rows][cb]
        else:
            res += tbl[ra][cb]
            res += tbl[rb][ca]
    return res

# One time pad (HURUF DOANG)

def otp_letters_only(text, key_stream):
    s = sanitize_letters(text)
    ks = sanitize_letters(key_stream)
    if len(ks) < len(s):
        raise ValueError('Key stream shorter than text; provide a longer key file or key')
    res = ''
    for i, ch in enumerate(s):
        res += I2A[(A2I[ch] + A2I[ks[i]]) % 26]
    return res

#==UI FLASKNYA==
TEMPLATE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Web Cipher Project Kriptograpi ARA</title>
  <style>
    body{font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Arial; padding:20px; max-width:1100px; margin:auto}
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
  <h1>Web Cipher Project Kriptograpi ARA</h1>
  <div class="panel">
    <form method="post" action="/process" enctype="multipart/form-data">
      <div class="row">
        <div class="col">
          <label>Input mode</label>
          <select name="input_mode" id="input_mode">
            <option value="text">Typed text</option>
            <option value="file">Upload file (binary allowed)</option>
          </select>

          <div id="text_input">
            <label>Plaintext / Ciphertext (type here)</label>
            <textarea name="text">{{ request_text or '' }}</textarea>
          </div>

          <div id="file_input">
            <label>Choose file to process</label>
            <input type="file" name="file">
            <p class="note">When encrypting a file, we store original filename inside the resulting .dat so you can restore extension on decryption.</p>
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
          <input type="text" name="key" placeholder="Shift: number. Substitution: 26-letter map. Affine: a,b. Vigenere: text. Hill: comma numbers (n*n). Permutation: comma indices. Playfair: text. OTP: paste key or upload file">

          <label>OTP key file (for One-time-pad)</label>
          <input type="file" name="otp_keyfile">

          <label>Display mode</label>
          <select name="display_mode">
            <option value="preserve">Preserve non-letters & case (default where supported)</option>
            <option value="letters_only">Letters only (A–Z uppercase, drop others)</option>
            <option value="group5">Group into 5-letter groups (letters only, uppercase)</option>
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

          {% if download_link %}
            <p><a href="{{ download_link }}">Download resulting file</a></p>
          {% endif %}

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
    return render_template_string(TEMPLATE, result=None, error=None, download_link=None, request_text='')

@app.route('/process', methods=['POST'])
def process():
    input_mode = request.form.get('input_mode')
    cipher = request.form.get('cipher')
    op = request.form.get('op')
    key = request.form.get('key') or ''
    display_mode = request.form.get('display_mode')
    uploaded = request.files.get('file')
    otp_keyfile = request.files.get('otp_keyfile')

    result_text = ''
    error = None
    download_link = None
    request_text = request.form.get('text') or ''

    try:
        if input_mode == 'file' and uploaded and uploaded.filename:
            data = uploaded.read()
            filename = uploaded.filename
            if cipher == 'Shift':
                if not key:
                    raise ValueError('For file-mode Shift: supply numeric key')
                k = int(key) % 256
                if op == 'enc':
                    out = bytes((b + k) % 256 for b in data)
                else:
                    out = bytes((b - k) % 256 for b in data)
                bio = BytesIO()
                name_bytes = filename.encode('utf-8')
                bio.write(len(name_bytes).to_bytes(4, 'big'))
                bio.write(name_bytes)
                bio.write(out)
                bio.seek(0)
                return send_file(bio, as_attachment=True, download_name=filename + '.dat')
            else:
                raise ValueError('File-mode currently supports only Shift (byte-wise) in this demo. For typed text use other ciphers.')

        text = request_text

        def finalize_letters_only(txt):
            if display_mode == 'group5':
                return chunk5(sanitize_letters(txt))
            return sanitize_letters(txt)

        if cipher == 'Shift':
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = shift_letters_only(text, key or '0')
                else: result_text = shift_letters_only(text, -int(key) if key else 0)
                if display_mode == 'group5': result_text = chunk5(result_text)
            else:
                if not key:
                    key = '0'
                if op == 'enc': result_text = shift_encrypt_text(text, key)
                else: result_text = shift_decrypt_text(text, key)

        elif cipher == 'Substitution':
            if not key:
                raise ValueError('Substitution requires a 26-letter key map')
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = subst_letters_only(text, key)
                else: result_text = subst_letters_only(text, key) 
                if display_mode == 'group5': result_text = chunk5(result_text)
            else:
                if op == 'enc': result_text = subst_encrypt_text(text, key)
                else: result_text = subst_decrypt_text(text, key)

        elif cipher == 'Affine':
            if ',' not in key:
                raise ValueError('Affine key must be two integers a,b separated by comma')
            a_s, b_s = key.split(',', 1)
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = affine_letters_only(text, int(a_s), int(b_s))
                else: result_text = affine_letters_only(text, int(a_s), int(b_s)) 
            else:
                if op == 'enc': result_text = affine_encrypt_text(text, int(a_s), int(b_s))
                else: result_text = affine_decrypt_text(text, int(a_s), int(b_s))

        elif cipher == 'Vigenere':
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = vigenere_letters_only(text, key)
                else: result_text = vigenere_letters_only(text, key) 
            else:
                if op == 'enc': result_text = vigenere_encrypt_text(text, key)
                else: result_text = vigenere_decrypt_text(text, key)

        elif cipher == 'Hill':
            nums = [x.strip() for x in key.split(',') if x.strip() != '']
            if not nums:
                raise ValueError('Hill requires comma-separated numbers for the key matrix (n*n numbers).')
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = hill_encrypt_letters_only(text, nums)
                else: result_text = hill_decrypt_letters_only(text, nums)
                if display_mode == 'group5': result_text = chunk5(result_text)
            else:
                enc = hill_encrypt_letters_only(text, nums) if op == 'enc' else hill_decrypt_letters_only(text, nums)
                letters = list(enc)
                out = ''
                li = 0
                for ch in text:
                    if ch.isalpha():
                        c = letters[li]
                        out += c.lower() if ch.islower() else c
                        li += 1
                    else:
                        out += ch
                result_text = out

        elif cipher == 'Permutation':
            perm = [x.strip() for x in key.split(',') if x.strip() != '']
            if not perm:
                raise ValueError('Permutation requires comma indices like 2,0,1')
            if display_mode == 'letters_only' or display_mode == 'group5':
                if op == 'enc': result_text = permutation_encrypt_letters_only(text, perm)
                else: result_text = permutation_decrypt_letters_only(text, perm)
                if display_mode == 'group5': result_text = chunk5(result_text)
            else:
                enc = permutation_encrypt_letters_only(text, perm) if op == 'enc' else permutation_decrypt_letters_only(text, perm)
                letters = list(enc)
                out = ''
                li = 0
                for ch in text:
                    if ch.isalpha():
                        c = letters[li]
                        out += c.lower() if ch.islower() else c
                        li += 1
                    else:
                        out += ch
                result_text = out

        elif cipher == 'Playfair':
            if display_mode != 'letters_only' and display_mode != 'group5':
                pass
            if op == 'enc':
                result_text = playfair_letters_only(text, key)
            else:
                raise ValueError('Playfair decryption not implemented in this demo (request if needed)')
            if display_mode == 'group5': result_text = chunk5(result_text)

        elif cipher == 'One-time-pad':
            keydata = ''
            if otp_keyfile and otp_keyfile.filename:
                keydata = otp_keyfile.read().decode('utf-8')
            else:
                keydata = key
            if not keydata:
                raise ValueError('Provide OTP key via uploaded file or paste key text')
            if op == 'enc':
                result_text = otp_letters_only(text, keydata)
            else:
                s = sanitize_letters(text)
                ks = sanitize_letters(keydata)
                if len(ks) < len(s):
                    raise ValueError('OTP key shorter than text')
                res = ''
                for i, ch in enumerate(s):
                    res += I2A[(A2I[ch] - A2I[ks[i]]) % 26]
                result_text = res
            if display_mode == 'group5': result_text = chunk5(result_text)

        else:
            raise ValueError('Cipher not supported')

        return render_template_string(TEMPLATE, result=result_text, error=None, download_link=download_link, request_text=request_text)

    except Exception as e:
        return render_template_string(TEMPLATE, result=None, error=str(e), download_link=None, request_text=request_text)

if __name__ == '__main__':
    app.run(debug=True)
