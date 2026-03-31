# ElGamal Cryptosystem — Java Demo

A fully commented, educational Java implementation of the **ElGamal public-key encryption scheme** over the cyclic group **Z\*p**. Alice and Bob communicate over a TCP socket; every cryptographic step is printed with detailed traces so you can follow along with the math in real time.

---

## What This Demonstrates

| Concept | Where it appears |
|---|---|
| Cyclic groups Z\*p | Bob chooses prime `p` and primitive root `α` |
| Discrete Logarithm Problem (DLP) | Bob's private key `d` is hidden inside `β = αᵈ mod p` |
| Diffie–Hellman Key Exchange | Alice and Bob derive the same `kM` without ever transmitting it |
| ElGamal encryption | Per-character: `y = x · kM mod p` |
| ElGamal decryption | `x = y · kM⁻¹ mod p` |
| Square-and-Multiply | Used for every modular exponentiation, with a full bit-by-bit trace |
| Fermat's Little Theorem | Bob computes `kM⁻¹ = kM^(p−2) mod p` in a single exponentiation |
| Probabilistic encryption | Same character → different ciphertext every run (fresh random `i` each time) |

---

## Project Structure

```
.
├── Alice.java   # Sender — connects to Bob, encrypts message, sends ciphertext pairs (kE, y)
└── Bob.java     # Receiver — generates keys, listens for Alice, decrypts each character
```

---

## How It Works

```
Bob publishes:  p (prime),  α (generator of Z*p),  β = αᵈ mod p

Alice, per character x:
  1. Pick fresh random ephemeral key  i
  2. kE = αⁱ  mod p          ← sent to Bob
  3. kM = βⁱ  mod p          ← shared secret, never sent
  4. y  = x · kM mod p       ← ciphertext
  5. Send (kE, y) to Bob

Bob, per ciphertext pair (kE, y):
  1. kM    = kE^d      mod p  ← same value Alice computed
  2. kM⁻¹  = kM^(p−2) mod p  ← Fermat's Little Theorem
  3. x     = y · kM⁻¹ mod p  ← recovered plaintext
```

The shared secret works because exponents commute:  
**Alice:** `β^i = (α^d)^i = α^(d·i)`  
**Bob:** `kE^d = (α^i)^d = α^(i·d)`

---

## Requirements

- **Java 9+** (uses `BigInteger.TWO`; swap for `new BigInteger("2")` for Java 8)
- No external dependencies

---

## Running

Bob must be started first — he opens the server socket and waits for Alice.

**Terminal 1 — Bob (receiver):**
```bash
javac Bob.java
java Bob
```

Bob will prompt you to use the defaults (`p = 257`, `α = 3`) or enter custom parameters.

**Terminal 2 — Alice (sender):**
```bash
javac Alice.java
java Alice
```

Alice will prompt you for the plaintext message, then connect to Bob on `localhost:9090`.

---

## Default Parameters

| Parameter | Value | Reason |
|---|---|---|
| `p` | `257` | Smallest prime above 255; all ASCII values (1–255) fit in Z\*p |
| `α` | `3` | Primitive root mod 257 (generator of the full group) |
| Port | `9090` | Hardcoded in both files; change `PORT` in both to use another |

You can supply your own `p` and `α` when Bob prompts for `custom`. Bob validates primality with Miller–Rabin (30 rounds, false-positive probability ≈ 10⁻¹⁸) and warns you if `p` is not prime.

---

## Sample Output

```
  ElGamal Encryption - BOB (Receiver)
  d = 43   binary: (101011)_2
  beta = 110

  ElGamal Encryption - ALICE (Sender)
  Enter message to encrypt: hey i am remas

  Character 1 / 14   'h'   x = 104 (ASCII)
  [A] i = 224
  [B] kE = 253
  [C] kM = 193   (shared secret, never transmitted)
  [D] y  = 26
  [E] Sent (kE=253, y=26)

  ...

  >>> DONE - Decrypted Message
  "hey i am remas"
```

---

## Security Notes

This is a **teaching tool**, not a production implementation. Notable limitations:

- **Small prime.** `p = 257` is 9 bits. Real ElGamal requires p ≥ 1024 bits to resist the index-calculus attack.
- **Character-by-character encryption.** Encrypting one ASCII byte at a time is inefficient and leaks message length. Real systems encrypt padded blocks.
- **No authentication.** There is no certificate or MAC; the public key `(p, α, β)` is trusted blindly, leaving the protocol open to a man-in-the-middle attack.
- **Ephemeral key i.** The code correctly generates a fresh `i` per character using `SecureRandom`. Reusing `i` is catastrophic: an attacker who knows any plaintext can recover the masking key and decrypt all messages encrypted with that `i`.
- **Malleability.** Schoolbook ElGamal is multiplicatively malleable — an attacker can scale the ciphertext `y` to scale the decrypted value. Real deployments add padding (e.g. DHIES/ECIES).

---

## Key Concepts Reference

- **Discrete Logarithm Problem:** Given `α`, `β`, `p`, find `d` such that `αᵈ ≡ β mod p`. Hard for large `p`.
- **Square-and-Multiply:** Efficient modular exponentiation in O(log e) multiplications by scanning the binary representation of the exponent.
- **Fermat's Little Theorem:** For prime `p` and any `a` not divisible by `p`: `a^(p−1) ≡ 1 mod p`, so `a⁻¹ ≡ a^(p−2) mod p`.
- **Probabilistic encryption:** Encrypting the same message twice gives different ciphertexts because `i` is re-randomised each time.

---

## References

- Paar, C. & Pelzl, J. — *Understanding Cryptography*, Chapter 8: Public-Key Cryptosystems Based on the Discrete Logarithm Problem
- Elgamal, T. (1985) — *A public key cryptosystem and a signature scheme based on discrete logarithms*, IEEE Transactions on Information Theory
