# cipher_combined.py
"""
Two-stage classical cipher:
  - Stage A: Vigenere substitution (key length >= 10)
  - Stage B: Columnar transposition (pad with 'X' to fill matrix)
Includes:
  - encrypt(plaintext, kv, kc)
  - decrypt(ciphertext, kv, kc)
  - attack_frequency(ciphertext, max_cols=8)
  - attack_known_plaintext(known_plaintext, known_ciphertext, max_cols=8)
"""

import math
import itertools
from collections import Counter

ENGLISH_FREQ = {
    'A': 8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,
    'H':6.094,'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,
    'O':7.507,'P':1.929,'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,
    'V':0.978,'W':2.360,'X':0.150,'Y':1.974,'Z':0.074
}

def normalize_text(s):
    """Keep only A-Z uppercase letters."""
    return ''.join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

# -----------------------
# Vigenere functions
# -----------------------
def vigenere_encrypt(pt, key):
    key_nums = [ord(k)-65 for k in key.upper()]
    L = len(key_nums)
    ct_chars = []
    for i, ch in enumerate(pt):
        p = ord(ch) - 65
        k = key_nums[i % L]
        c = (p + k) % 26
        ct_chars.append(chr(c + 65))
    return ''.join(ct_chars)

def vigenere_decrypt(ct, key):
    key_nums = [ord(k)-65 for k in key.upper()]
    L = len(key_nums)
    pt_chars = []
    for i, ch in enumerate(ct):
        c = ord(ch) - 65
        k = key_nums[i % L]
        p = (c - k + 26) % 26
        pt_chars.append(chr(p + 65))
    return ''.join(pt_chars)

# -----------------------
# Columnar functions
# -----------------------
def column_order_from_key(key):
    """
    Return list of original column indices in the order columns are read.
    Example: key = "ZEBRA" -> sorted list [('A',4),('B',2),...] -> return [4,2,...]
    """
    enumerated = list(enumerate(key))
    sorted_pairs = sorted(enumerated, key=lambda x: (x[1], x[0]))
    return [idx for idx, ch in sorted_pairs]

def encrypt(plaintext, kv, kc):
    """
    Full two-stage encryption.
    - plaintext: string (any chars, will be normalized to A-Z)
    - kv: Vigenere key string (>=10 letters)
    - kc: columnar key string (distinctness not required; ordering by char then index)
    Returns ciphertext string (A-Z).
    """
    pt = normalize_text(plaintext)
    if len(kv) < 10:
        raise ValueError("Vigenere key must be at least 10 characters.")
    if len(kc) < 2:
        raise ValueError("Column key must have length >= 2.")
    # Stage A
    intermediate = vigenere_encrypt(pt, kv)
    # Stage B: columnar transposition
    Lc = len(kc)
    rows = math.ceil(len(intermediate) / Lc)
    pad_len = rows * Lc - len(intermediate)
    intermediate_padded = intermediate + 'X' * pad_len
    # build matrix row-wise
    matrix = [list(intermediate_padded[i*Lc:(i+1)*Lc]) for i in range(rows)]
    order = column_order_from_key(kc)
    ciphertext = []
    for col_index in order:
        for r in range(rows):
            ciphertext.append(matrix[r][col_index])
    return ''.join(ciphertext)

def decrypt(ciphertext, kv, kc):
    """
    Full two-stage decryption.
    - ciphertext: string (A-Z)
    - kv: Vigenere key string (>=10 letters)
    - kc: columnar key string
    Returns plaintext string (A-Z).
    """
    if len(kv) < 10:
        raise ValueError("Vigenere key must be at least 10 characters.")
    ct = normalize_text(ciphertext)
    Lc = len(kc)
    rows = math.ceil(len(ct) / Lc)
    order = column_order_from_key(kc)  # sorted order -> original indices
    # split ciphertext into Lc columns each of length rows
    cols = []
    pos = 0
    for _ in range(Lc):
        cols.append(list(ct[pos:pos+rows]))
        pos += rows
    # place these columns back into original column positions
    matrix = [[''] * Lc for _ in range(rows)]
    for sorted_idx, orig_col in enumerate(order):
        col = cols[sorted_idx]
        for r in range(rows):
            matrix[r][orig_col] = col[r] if r < len(col) else ''
    intermediate = ''.join(''.join(row) for row in matrix).rstrip('X')
    plaintext = vigenere_decrypt(intermediate, kv)
    return plaintext

# -----------------------
# Analysis helpers
# -----------------------
def chi_squared_score(text):
    """Chi-squared statistic against English letter frequencies (lower is better)."""
    N = len(text)
    if N == 0:
        return float('inf')
    counts = Counter(text)
    score = 0.0
    for ch in ENGLISH_FREQ:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * N / 100.0
        if expected > 0:
            score += ((observed - expected)**2) / expected
    return score

def attempt_undo_transposition(ct, cols):
    """
    Split ct into `cols` segments assuming equal column heights (padding used).
    For small cols, try all permutations and reconstruct row-wise text.
    Returns list of (perm, reconstructed_text).
    """
    L = cols
    rows = math.ceil(len(ct) / L)
    # create segments in read-order
    segs = [ct[i*rows:(i+1)*rows] for i in range(L)]
    results = []
    if L > 8:
        return results  # avoid huge permutation space
    for perm in itertools.permutations(range(L)):
        # perm: mapping from sorted-order position -> original column index
        matrix = [[''] * L for _ in range(rows)]
        for sorted_pos, orig_col in enumerate(perm):
            seg = segs[sorted_pos]
            for r in range(len(seg)):
                matrix[r][orig_col] = seg[r]
        reconstructed = ''.join(''.join(row) for row in matrix).rstrip('X')
        results.append((perm, reconstructed))
    return results

# -----------------------
# Attack functions
# -----------------------
def attack_frequency(ciphertext, max_cols=8, kv_maxlen=20):
    """
    Blind frequency-based attack.
    - Try column counts 2..max_cols (but only permute if <=8)
    - For each reconstructed candidate, try vigenere key lengths up to kv_maxlen
      and pick best shifts per key-position by chi-squared on each subsequence.
    Returns top candidate dicts sorted by chi score.
    """
    best_candidates = []
    ct = normalize_text(ciphertext)
    n = len(ct)
    for cols in range(2, min(max_cols+1, n)):
        undo_results = attempt_undo_transposition(ct, cols)
        for perm, candidate in undo_results:
            # try key lengths
            for kl in range(1, min(kv_maxlen, len(candidate)) + 1):
                key_shifts = []
                # determine best shift for each key position
                for pos in range(kl):
                    subseq = candidate[pos::kl]
                    best_shift = 0
                    best_score = float('inf')
                    for shift in range(26):
                        dec = ''.join(chr(((ord(ch)-65 - shift) % 26) + 65) for ch in subseq)
                        score = chi_squared_score(dec)
                        if score < best_score:
                            best_score = score
                            best_shift = shift
                    key_shifts.append(best_shift)
                key = ''.join(chr(s + 65) for s in key_shifts)
                dec_full = vigenere_decrypt(candidate, key)
                final_score = chi_squared_score(dec_full)
                best_candidates.append({
                    'cols': cols,
                    'perm': perm,
                    'key_len': kl,
                    'key': key,
                    'plaintext_candidate': dec_full,
                    'score': final_score
                })
    best_candidates.sort(key=lambda x: x['score'])
    return best_candidates[:10]

def attack_known_plaintext(known_pt, known_ct, max_cols=8):
    """
    Known plaintext attack.
    - known_pt: a plaintext fragment (will be normalized)
    - known_ct: corresponding ciphertext fragment (same alignment)
    Returns possible candidates with recovered column permutation and Vigenere key.
    """
    kp = normalize_text(known_pt)
    kc = normalize_text(known_ct)
    results = []
    n = len(kc)
    for cols in range(2, min(max_cols+1, n)):
        rows = math.ceil(len(kc) / cols)
        segs = [kc[i*rows:(i+1)*rows] for i in range(cols)]
        if cols > 8:
            continue
        for perm in itertools.permutations(range(cols)):
            matrix = [[''] * cols for _ in range(rows)]
            for sorted_pos, orig_col in enumerate(perm):
                seg = segs[sorted_pos]
                for r in range(len(seg)):
                    matrix[r][orig_col] = seg[r]
            intermediate = ''.join(''.join(row) for row in matrix).rstrip('X')
            if len(intermediate) < len(kp):
                continue
            # derive shifts that map kp -> intermediate prefix
            derived_shifts = []
            for i, ch in enumerate(kp):
                c = ord(intermediate[i]) - 65
                p = ord(ch) - 65
                shift = (c - p) % 26
                derived_shifts.append(shift)
            # find minimal repeating period for shifts
            for key_len in range(1, len(derived_shifts) + 1):
                ok = True
                for i in range(len(derived_shifts)):
                    if derived_shifts[i] != derived_shifts[i % key_len]:
                        ok = False
                        break
                if ok:
                    key = ''.join(chr(s + 65) for s in derived_shifts[:key_len])
                    dec_full = vigenere_decrypt(intermediate, key)
                    if dec_full.startswith(kp):
                        results.append({
                            'cols': cols,
                            'perm': perm,
                            'key_len': key_len,
                            'kv_key': key,
                            'intermediate': intermediate,
                            'plaintext_full_candidate': dec_full
                        })
                    break
    return results

# -----------------------
# Example / quick test
# -----------------------
def example_run():
    plaintext = "THIS IS M.Musab Saleem"
    kv = "LONGERKEYABC"   # must be >= 10
    kc = "ZEBRAFOXTROT"   # column key
    ct = encrypt(plaintext, kv, kc)
    dec = decrypt(ct, kv, kc)
    return plaintext, kv, kc, ct, dec

if __name__ == "__main__":
    pt, kv, kc, ct, dec = example_run()
    print("Plaintext:", pt)
    print("Vig key:", kv, "Col key:", kc)
    print("Ciphertext:", ct)
    print("Decrypted:", dec)
