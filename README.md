# wedding-photos

Encrypted image files for the password-protected gallery at
https://thenetsuiteguy.com/wedding. Everything under `p/` is AES-256-GCM
ciphertext; the page decrypts it in the browser once the password is entered.

## Rebuilding

```bash
npm install
WEDDING_PW=... npm run build -- "<folder of original photos>"
```

Re-running skips photos that are already built. To change the password,
delete `p/` and build again with the new one.
