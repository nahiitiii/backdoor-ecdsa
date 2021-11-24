# Backdoored ECDSA signatures

This is a proof of concept implementation of backdoored ECDSA signatures. There are many ways to backdoor signatures; this is a very simple and rough example. The basic idea is to cook the ECDSA nonce (aka ephemeral key) in a way that an attacker can recover a few bits from the public `r` value -- without significantly increasing signing time.

The code here leaks a few bits from a secret on each signature. After enough signatures are collected (even if computed under different keys), this full secret is recovered. This secret does not need to be the long-term signing private key, it can be something else. We do not require synchronizing the subliminal sender/receiver -- the implementation is resistant to loss of some signatures. The current implementation mimics the behavior of a deterministic ECDSA signatures in case it helps your cover-up narrative 🕵

A simplified description is this: name `k` the secret ECDSA nonce. (The x-coordinate `r` of `k*G` is part of the signature.) Pick `k` as the product of a small value `s` (to be leaked) times a long, secret scalar `b` (known to the backdoor designer), `k=s*b`. It's very easy to recover `b` from `k*G` by solving a degenerate discrete log. There're some details left out in this explanation (how to deal with synchronization; how to combine bits from different signatures; how to make sure that only the intended thief can steal the long term secret, ...) but that's the basic idea. The whole thing can be vastly improved 🤡

This is a more detailed description:
 - Notation: `(r,s)` is the ECDSA signature, `k` is the secret ECDSA per-signing secret nonce. The signer and the backdoor designer share a secret scalar `b`. The signer wants to leak a value S.
 - The basic version (easier to explain) works like this: emit a few signatures where the nonces `k` are chosen as `k := b*s_i` where `s_i` are a small integers (say, 1 < `s_i` < 2^16). The `s_i` are just "chunks" of S (each `s_i` is just a few bits of S).
 - Then the backdoor designer, upon collecting enough signature pairs `(r,s)`, recovers the corresponding `s_i` by just sweeping over every value, one by one. Since the backdoor designer knows `b`, this is easy.
 - We can improve several aspects of this basic version:
   - First, instead of `s_i` be just chunks of S, we set `s_i` to be the result of a vector-matrix multiplication over GF(2) `s_i := S*[M]`. Here `[M]` is a public matrix constructed from the message being signed `m`, with dimensions chosen so that `s_i` is only a few bits long. To reconstruct S from `s_i`, the backdoor designer just solves a linear system of equations over GF(2). The advantage here is that this method is resistant to loss of some `s_i`, and the order in which `s_i` are recovered does not matter. Also, the backdoor designer gets immediate feedback on how many bits are still to be guessed from S!
   - Second, instead of repeating `b` over and over for different signatures, we use a per-message secret `b_i := h(b, m)` where `h` is a hash function and `m` is the message being signed. The backdoor designer can still reconstruct `b_i` and use this to loop over possible values for `s_i`.

Some concrete figures: the code right can be used to leak a ~256-bit secret S in about 12 signatures by leaking 20 bits per signature. Recovering each `s_i` takes about 18 seconds in the dumbest implementation ever on a standard laptop.

## TODO

- [ ] Implementation of the nonce generation in a real language
- [ ] Better efficiency: leak more bits per signature.
- [ ] Leak a public-key encrypted secret, so that if `b` is eventually revealed, S can't be recovered from signatures. Here we'd need a public-key scheme with very compact ciphertext -- can we do better than ECIES?
- [ ] Good cover story. This is a fun exercise in creative writing, and there are good examples to learn from 😉