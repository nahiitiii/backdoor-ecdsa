# Backdoored ECDSA signatures

This is a proof of concept implementation of backdoored ECDSA signatures. There are many ways to backdoor signatures; this is a very simple and rough example. The basic idea is to cook the ECDSA nonce (aka ephemeral key) in a way that an attacker can recover a few bits from the public `r` value -- without significantly increasing signing time.

The code here leaks a few bits from a long-term secret on each signature. After enough signatures are collected (even computed under different keys), the full long-term secret is recovered (without the need of synchronizing the subliminal sender/receiver). The current implementation mimics the behavior of a deterministic ECDSA signatures in case it helps your cover-up narrative 🕵

A simplified description is this: name `k` the secret ECDSA nonce. (The x-coordinate `r` of `k*G` is part of the signature.) Pick `k` as the product of a small value `s` (to be leaked) times a long, secret scalar `b` (known to the backdoor designer), `k=s*b`. It's very easy to recover `b` from `k*G` by solving a pathological discrete log. There're some details left out in this explanation (how to deal with synchronization; how to combine bits from different signatures; how to make sure that only the intended thief can steal the long term secret, ...) but that's the basic idea. The whole thing can be vastly improved 🤡

## TODO

- [ ] Implementation of the nonce generation in a real language
- [ ] Good cover story. This is a fun exercise in creative writing, and there are good examples to learn from 😉