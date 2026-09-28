# Cipher — crypto service companion

Open **index.html** in a modern browser. The complete app, CryptoJS 4.2.0, and its MIT license are embedded in this one file. No installation, CDN, or network access is required.

The interface follows `src/core/services/crypto.service.ts`:

- **Encrypt:** follows `encryptRequest()` → `requestEncryption()`: `Utf8.parse(key)`, `Hex.parse(iv)`, AES-CBC, PKCS#7, and raw Hex ciphertext output.
- **Decrypt:** follows `responseDecryption()`: Hex ciphertext converted to Base64 for CryptoJS, AES-CBC / PKCS#7, UTF-8 decoding, and `JSON.parse`. The app pretty-prints the decoded JSON rather than displaying the service status wrapper. Non-JSON plaintext fails just as it does in the service.
- **AES key:** defaults to the supplied editable key, with Text (UTF-8) selected. Use the decoded session key, not its transport Base64 representation. Standard 16-, 24-, and 32-byte keys are accepted, including AES-192. Hex key input is an optional extension; select Text to match the service.
- **AES IV:** defaults to the supplied editable IV. Required: 32 Hex characters (16 bytes). Keep it with the ciphertext; it is not bundled into the output.
- **Generate AES key:** creates a 32-character UTF-8 key from 24 random bytes encoded as Base64. These characters are used literally by the service, not Base64-decoded again.
- **Generate IV:** creates 16 random bytes encoded as Hex. Use a fresh IV for each new encryption with the same key.

## Session API response

Select **Session API**, paste the complete session response JSON, and click **Decrypt session response**. The app Base64-decodes `data.options.aesKey` and `data.options.aesIV`, then decrypts `data.promotionStatus` by default. The field selector also supports `playerPhone`, `playerEmail`, `playerTier`, `playerAddress`, and `playerStatus`; an empty/null field produces a clear error.

Manual key and IV inputs are hidden and ignored in this mode. Switching tabs preserves each input draft and leaves your manual credentials intact. Only the selected field's decoded JSON is output. Session content is processed locally and URLs in the response are never fetched. JSON code fences and the invalid Markdown `\_` escape commonly introduced by copied chat text are accepted; other malformed JSON is rejected.

Key and IV edits are preserved when switching modes; reloading restores the defaults embedded in the HTML. Messages and edits are not saved. Only the theme preference is stored separately.

Raw CBC matches the existing service and does not provide an authentication tag. Input is limited to 2 MiB. AES1 bundles are no longer the UI format; encryption always returns raw Hex.

Trilogy's session service Base64-decodes `options.aesKey` and `options.aesIV` before the crypto service uses them. Use the decoded values from the same session as the encrypted response.

The UI has no passphrase or Advanced settings section. It retains compact desktop/mobile layouts, key visibility, generation buttons, clipboard feedback, and light/dark themes.

Run checks with Node 22 or later from the repository root:

```sh
node --test aes-tool/crypto.test.js
```

Compatibility tests execute the actual TypeScript service functions with session/logging dependencies stubbed, compare encrypted output byte-for-byte, and verify decryption in both directions for all three key lengths.
