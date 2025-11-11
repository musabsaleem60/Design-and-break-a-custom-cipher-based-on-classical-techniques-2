# Final Report — Custom Classical Cipher (Vigenère + Columnar Transposition)

## 1. Executive Summary
This project implements a **two-stage classical cipher** that combines the **Vigenère cipher** for substitution and **Columnar Transposition** for permutation.  
Encryption first applies Vigenère (key length ≥ 10) and then Columnar Transposition to increase diffusion.  
Two cryptanalysis approaches are provided:  
- **Frequency Analysis Attack** (blind attack using chi-squared test)  
- **Known Plaintext Attack** (when part of plaintext and ciphertext are known).

---

## 2. Cipher Design Overview
- **Stage 1:** Vigenère cipher substitutes plaintext letters using key K_v.  
  Formula: `C_i = (P_i + K_j) mod 26`  
- **Stage 2:** Columnar Transposition arranges intermediate text in a grid based on key K_c and reads columns in key order.  
  Padding with 'X' ensures a full rectangular matrix.

Decryption reverses both stages.

---

## 3. Algorithm Summary
1. Convert plaintext to uppercase (A–Z only).  
2. Encrypt with Vigenère key K_v (≥10 letters).  
3. Arrange output into matrix using K_c columns.  
4. Read columns in sorted key order to get ciphertext.  
5. Reverse process for decryption.

---

## 4. Attack Techniques

### 4.1 Frequency Analysis Attack
- Brute-forces small column permutations (≤8).  
- For each, applies per-position frequency-based key guessing.  
- Uses **chi-squared scoring** to test English-likeness.

### 4.2 Known Plaintext Attack
- Given aligned plaintext and ciphertext samples.  
- Brute-forces transposition permutations (≤8 columns).  
- Derives repeating Vigenère key shifts from known text.

---

## 5. Complexity Analysis

| Operation | Time Complexity | Notes |
|------------|----------------|-------|
| Vigenère Encryption/Decryption | O(n) | Linear per character |
| Columnar Transposition | O(n) | Write + read matrix |
| Frequency Analysis Attack | O(L_c! × K × n) | Heavy for L_c > 8 |
| Known Plaintext Attack | O(L_c! × m) | Feasible for small keys |

Where n = message length, L_c = number of columns, and K = Vigenère key length.

---

## 6. Security Discussion
**Strengths**
- Substitution + permutation increases confusion and diffusion.
- Key space: `26^L_v × L_c!` possible combinations.
- Resistant to simple monoalphabetic frequency analysis.

**Weaknesses**
- Known plaintext exposes direct Vigenère shifts.  
- Brute-force feasible for small L_c (≤8).  
- No randomness across messages (deterministic).

---

## 7. Expected Experimental Results
- **Frequency Attack:** Works for ≤7 columns and message length ≥200.  
- **Known-Plaintext Attack:** Recovers Vigenère key and partial plaintext quickly for small columns.  
- **Encryption/Decryption Speed:** Linear in message length (O(n)).

---

## 8. Recommendations for Improvement
1. Use **irregular column padding** instead of equal lengths.  
2. Add **autokey Vigenère** for non-repeating key pattern.  
3. Apply **double transposition** for higher diffusion.  
4. Use **random IV-based permutation** to vary output.

---

## 9. Deliverables Checklist
- ✅ `cipher_combined.py` – implementation  
- ✅ `README.md` – setup & usage instructions  
- ✅ `report.md` – this file  
- ✅ Optional test output (`example_run.txt`)  

---

## 10. Conclusion
The combination of **Vigenère** and **Columnar Transposition** offers greater complexity than single-stage classical ciphers like Caesar or Shift.  
While stronger against casual analysis, it remains vulnerable to known-plaintext and small-key brute-force attacks.  
This implementation meets CT-486 project requirements and demonstrates both design and cryptanalysis of a custom cipher.

---

**Author:** Musab Saleem (musabsaleem60)  
**Course:** CT-486 — Network and Information Security
