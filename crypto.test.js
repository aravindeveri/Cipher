import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createCipheriv } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import serviceCryptoJS from 'crypto-js';
import ts from 'typescript';

// Test the crypto implementation embedded in the delivered single-file app.
const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const compatibilitySource = html.match(/<script id="aes-compat">([\s\S]*?)<\/script>/)?.[1];
assert.ok(compatibilitySource, 'AES-192 compatibility library is embedded');
const compatibilityContext = {};
runInNewContext(compatibilitySource, compatibilityContext);
globalThis.CryptoJS = compatibilityContext.CryptoJS;
const script = html.match(/<script type="module" id="cipher-app">([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'The application script is embedded in the HTML');
assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+rel="stylesheet"/i);
const cryptoCode = script.split('// UI CONTROLLER')[0];
const { encryptText, decryptText, generateKey, generateHex, keyAsHex, encryptRequest, responseDecryption, decryptSessionResponse } = await import(`data:text/javascript;base64,${Buffer.from(cryptoCode).toString('base64')}`);

const secret = 'correct horse battery staple 🔐';
const message = 'Hello, 世界! 🔐\nTabs\tand trailing spaces  ';
for (const mode of ['AES-GCM', 'AES-CBC']) {
  for (const bits of [128, 256]) {
    for (const encoding of ['b64', 'hex']) {
      test(`${mode} ${bits} ${encoding} preserves Unicode and whitespace`, async () => {
        const encrypted = await encryptText(message, secret, { mode, bits, encoding });
        const decrypted = await decryptText(encrypted.text, secret);
        assert.equal(decrypted.text, message);
        assert.equal(decrypted.mode, mode);
        assert.equal(decrypted.bits, bits);
      });
    }
  }
  test(`${mode} rejects wrong keys and tampering; accepts original manual IV`, async () => {
    const encrypted = await encryptText(message, secret, { mode });
    await assert.rejects(decryptText(encrypted.text, 'wrong'), /Decryption failed/);
    const envelope = JSON.parse(Buffer.from(encrypted.text.split('.')[2], 'base64').toString());
    const iv = Buffer.from(envelope.iv, 'base64').toString('hex');
    assert.equal((await decryptText(encrypted.text, secret, iv)).text, message);
    await assert.rejects(decryptText(encrypted.text, secret, '00'.repeat(iv.length / 2)), /Decryption failed/);
    const changed = { ...envelope, data: (envelope.data[0] === 'A' ? 'B' : 'A') + envelope.data.slice(1) };
    await assert.rejects(decryptText(`AES1.b64.${Buffer.from(JSON.stringify(changed)).toString('base64')}`, secret), /Decryption failed/);
    const second = await encryptText(message, secret, { mode });
    assert.notEqual(second.text, encrypted.text);
    assert.notEqual(second.iv, encrypted.iv);
  });
}
test('rejects invalid inputs and produces 256-bit random passphrases', async () => {
  for (const value of ['garbage', 'AES1.b64.!!!', 'AES1.hex.abc', 'AES1.b64.bnVsbA==']) {
    await assert.rejects(decryptText(value, secret), /Invalid|Unsupported/);
  }
  await assert.rejects(encryptText('', secret), /Enter/);
  await assert.rejects(encryptText(message, ''), /Enter/);
  await assert.rejects(encryptText('x'.repeat(2 * 1024 * 1024 + 1), secret), /2 MB/);
  const key = generateKey();
  assert.equal(Buffer.from(key, 'base64').length, 32);
  assert.notEqual(key, generateKey());
});

for (const mode of ['AES-GCM', 'AES-CBC']) {
  for (const bits of [128, 256]) {
    test(`${mode} ${bits} imports raw AES key and uses supplied IV`, async () => {
      const rawKey = generateHex(bits / 8);
      const ivHex = generateHex(mode === 'AES-GCM' ? 12 : 16);
      const encrypted = await encryptText(message, '', { mode, bits, rawKey, ivHex });
      assert.equal((await decryptText(encrypted.text, '', ivHex, rawKey)).text, message);
      assert.equal((await decryptText(encrypted.text, '', '', rawKey)).text, message);
      const p = JSON.parse(Buffer.from(encrypted.text.split('.')[2], 'base64').toString());
      assert.equal(p.keyType, 'raw');
      assert.equal(p.iterations, 0);
      assert.equal(Buffer.from(p.iv, 'base64').toString('hex'), ivHex);
      // Independent decryption confirms the entered key bytes are used directly.
      const key = await crypto.subtle.importKey('raw', Buffer.from(rawKey, 'hex'), mode, false, ['decrypt']);
      const algorithm = { name: mode, iv: Buffer.from(ivHex, 'hex') };
      if (mode === 'AES-GCM') {
        algorithm.tagLength = 128;
        const { v, mode: name, bits: size, iterations, salt, iv, keyType } = p;
        algorithm.additionalData = new TextEncoder().encode(JSON.stringify({ v, mode: name, bits: size, iterations, salt, iv, keyType }));
      }
      assert.equal(new TextDecoder().decode(await crypto.subtle.decrypt(algorithm, key, Buffer.from(p.data, 'base64'))), message);
      await assert.rejects(decryptText(encrypted.text, '', '', generateHex(bits / 8)), /Decryption failed/);
      await assert.rejects(decryptText(encrypted.text, 'passphrase'), /original raw AES key/);
      await assert.rejects(decryptText(encrypted.text, '', '00'.repeat(ivHex.length / 2), rawKey), /Decryption failed/);
      const changed = { ...p, data: (p.data[0] === 'A' ? 'B' : 'A') + p.data.slice(1) };
      await assert.rejects(decryptText(`AES1.b64.${Buffer.from(JSON.stringify(changed)).toString('base64')}`, '', '', rawKey), /Decryption failed/);
    });
  }
}

test('validates raw key and IV fields; passphrase mode accepts a manual IV', async () => {
  const rawKey = generateHex(32);
  await assert.rejects(encryptText(message, '', { rawKey: 'zz' }), /Invalid Hex/);
  await assert.rejects(encryptText(message, '', { rawKey: generateHex(16) }), /64 Hex/);
  await assert.rejects(encryptText(message, '', { rawKey, ivHex: generateHex(16) }), /24 Hex/);
  await assert.rejects(encryptText(message, '', { mode: 'AES-CBC', rawKey, ivHex: generateHex(12) }), /32 Hex/);
  const ivHex = generateHex(12);
  const encrypted = await encryptText(message, secret, { ivHex });
  assert.equal(Buffer.from(encrypted.iv, 'base64').toString('hex'), ivHex);
  assert.equal((await decryptText(encrypted.text, secret)).text, message);
  await assert.rejects(decryptText(encrypted.text, secret, '', rawKey), /AES-key-only interface/);
  const randomIV = await encryptText(message, '', { rawKey, encoding: 'hex' });
  assert.equal((await decryptText(randomIV.text, '', '', rawKey)).text, message);
});

for (const bits of [128, 192, 256]) {
  test(`raw AES-${bits}-CBC accepts UTF-8 and Hex keys from an independent implementation`, async () => {
    const key = 'test'.repeat(bits / 32);
    const iv = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
    const cipher = createCipheriv(`aes-${bits}-cbc`, Buffer.from(key), iv);
    const ciphertext = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]).toString('hex');
    const auto = await decryptText(ciphertext, '', iv.toString('hex'), key);
    assert.equal(auto.text, message);
    assert.equal(auto.bits, bits);
    assert.equal(auto.authenticated, false);
    assert.equal((await decryptText(ciphertext, '', iv.toString('hex'), key, 'utf8')).text, message);
    assert.equal((await decryptText(ciphertext.toUpperCase().match(/.{1,32}/g).join('\n'), '', iv.toString('hex'), Buffer.from(key).toString('hex'), 'hex')).text, message);
    await assert.rejects(decryptText(ciphertext, '', '', key), /requires the original AES IV/);
    await assert.rejects(decryptText(ciphertext, '', '00', key), /16-byte IV/);
    await assert.rejects(decryptText(ciphertext.slice(2), '', iv.toString('hex'), key), /complete 16-byte blocks/);
    await assert.rejects(decryptText(ciphertext, '', iv.toString('hex'), 'short'), /16, 24, or 32 bytes/);
  });
}

test('text keys preserve whitespace, and 192-bit GCM bundles remain compatible', async () => {
  const key = ' ' + 'k'.repeat(22) + ' ';
  const hex = keyAsHex(key, 'utf8');
  assert.equal(hex, Buffer.from(key).toString('hex'));
  const encrypted = await encryptText(message, '', { rawKey: hex, bits: 192 });
  assert.equal((await decryptText(encrypted.text, '', '', key, 'utf8')).text, message);
  assert.equal((await decryptText(encrypted.text, '', '', hex)).text, message);
});

test('AES-192-CBC works when the browser rejects all native 192-bit AES keys', async () => {
  let unsupportedImports = 0;
  const limitedCrypto = {
    getRandomValues: crypto.getRandomValues.bind(crypto),
    subtle: new Proxy(crypto.subtle, {
      get(target, name) {
        if (name === 'importKey') return (...args) => {
          const algorithm = typeof args[2] === 'string' ? args[2] : args[2].name;
          if (args[0] === 'raw' && args[1].byteLength === 24 && algorithm.startsWith('AES')) {
            unsupportedImports++;
            throw new DOMException('192-bit AES keys are not supported', 'NotSupportedError');
          }
          return target.importKey(...args);
        };
        return typeof target[name] === 'function' ? target[name].bind(target) : target[name];
      }
    })
  };
  const api = runInNewContext(cryptoCode.replace(/\bexport /g, '') + '\n({ encryptText, decryptText });', {
    crypto: limitedCrypto, CryptoJS, TextEncoder, TextDecoder, btoa, atob
  });
  const key = 'example-key-192-bit-long';
  assert.equal(Buffer.byteLength(key), 24);
  const rawKey = Buffer.from(key).toString('hex');
  const iv = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const cipher = createCipheriv('aes-192-cbc', Buffer.from(key), iv);
  const ciphertext = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]).toString('hex');
  assert.equal((await api.decryptText(ciphertext, '', iv.toString('hex'), key)).text, message);
  const bundle = await api.encryptText(message, '', { mode: 'AES-CBC', bits: 192, rawKey });
  assert.equal((await api.decryptText(bundle.text, '', '', rawKey)).text, message);
  await assert.rejects(api.decryptText(ciphertext, '', iv.toString('hex'), 'x'.repeat(24)), /decryption failed/);
  // Reject malformed padding explicitly; CryptoJS's default unpad is permissive.
  const invalidPadding = createCipheriv('aes-192-cbc', Buffer.from(key), iv);
  invalidPadding.setAutoPadding(false);
  const malformed = Buffer.concat([invalidPadding.update(Buffer.alloc(32)), invalidPadding.final()]).toString('hex');
  await assert.rejects(api.decryptText(malformed, '', iv.toString('hex'), key), /decryption failed/);
  assert.equal(unsupportedImports, 0, '192-bit CBC never calls the unsupported native import');
});

// Execute the actual TypeScript service with its network/session dependencies stubbed.
// This checks compatibility against the user's named functions, not a reimplementation.
const sharedSessionData = {};
const serviceSource = await readFile(new URL('../src/core/services/crypto.service.ts', import.meta.url), 'utf8');
const compiledService = ts.transpileModule(serviceSource + '\nexport { responseDecryption };', {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 }
}).outputText;
const serviceContext = {
  exports: {},
  require(name) {
    if (name === 'crypto-js') return serviceCryptoJS;
    if (name === './shared.service') return { sharedSessionData };
    if (name === './logger.service') return { loggerService() {} };
    if (name === './utility.service') return { generateTrilogyErrorResponse(error) { return { status: { statusCode: 400 }, error }; } };
    if (name === '../model/const/messages') return { ERROR_MESSAGES: {}, ErrorCode: {}, LogMessages: {}, Messages: {} };
    throw new Error(`Unexpected dependency: ${name}`);
  }
};
runInNewContext(compiledService, serviceContext);

for (const length of [16, 24, 32]) {
  test(`UI operations match actual crypto service with ${length * 8}-bit UTF-8 keys`, async () => {
    const key = 'test'.repeat(length / 4);
    const iv = '00112233445566778899aabbccddeeff';
    Object.assign(sharedSessionData, { aesKey: key, aesIv: iv });
    const original = { message: 'Hello 世界 🔐', count: 42, enabled: true, items: [null, 'x'] };
    const json = JSON.stringify(original);
    const serviceEncrypted = await serviceContext.exports.encryptRequest(json);
    assert.equal(serviceEncrypted.status.statusCode, 200);
    const appEncrypted = encryptRequest(json, key, iv);
    assert.equal(appEncrypted.text, serviceEncrypted.data);
    const serviceDecrypted = await serviceContext.exports.responseDecryption(appEncrypted.text);
    assert.equal(serviceDecrypted.status.statusCode, 200);
    assert.deepEqual(JSON.parse(JSON.stringify(serviceDecrypted.data)), original);
    assert.deepEqual(responseDecryption(serviceEncrypted.data, key, iv).data, original);
    assert.deepEqual(responseDecryption(serviceEncrypted.data, Buffer.from(key).toString('hex'), iv, 'hex').data, original);
    const notJson = encryptRequest('plain text that is not JSON', key, iv).text;
    assert.notEqual((await serviceContext.exports.responseDecryption(notJson)).status.statusCode, 200);
    assert.throws(() => responseDecryption(notJson, key, iv), /UTF-8 JSON/);
  });
}

function sessionFixture(length = 24) {
  const key = 'test'.repeat(length / 4);
  const iv = '00112233445566778899aabbccddeeff';
  const promotion = { enabled: true, offers: [{ name: 'Sample 世界', id: 7 }] };
  const encrypt = value => serviceCryptoJS.AES.encrypt(JSON.stringify(value), serviceCryptoJS.enc.Utf8.parse(key), {
    iv: serviceCryptoJS.enc.Hex.parse(iv), mode: serviceCryptoJS.mode.CBC, padding: serviceCryptoJS.pad.Pkcs7
  }).ciphertext.toString(serviceCryptoJS.enc.Hex);
  return {
    promotion,
    response: {
      data: {
        token: 'DEVICE_TOKEN',
        baseUrl: '[https://example.invalid](https://example.invalid)',
        promotionStatus: encrypt(promotion), playerPhone: encrypt('555-0100'), playerAddress: '', playerStatus: null,
        options: { aesKey: Buffer.from(key).toString('base64'), aesIV: Buffer.from(iv).toString('base64') }
      }, status: { statusCode: '200' }
    }
  };
}

for (const length of [16, 24, 32]) {
  test(`session response automatically decodes ${length * 8}-bit credentials and selected field`, () => {
    const { response, promotion } = sessionFixture(length);
    const original = JSON.stringify(response);
    const result = decryptSessionResponse(original);
    assert.deepEqual(result.data, promotion);
    assert.equal(result.bits, length * 8);
    assert.equal(result.field, 'promotionStatus');
    assert.equal(decryptSessionResponse(original, 'playerPhone').data, '555-0100');
    assert.equal(JSON.stringify(response), original);
  });
}

test('session response supports JSON code fences and copied Markdown underscore escaping', () => {
  const { response, promotion } = sessionFixture();
  response.data.path = 'folder\\_file';
  const raw = JSON.stringify(response);
  assert.deepEqual(decryptSessionResponse('```json\n' + raw + '\n```').data, promotion);
  const copied = raw.replace('DEVICE_TOKEN', 'DEVICE\\_TOKEN');
  const result = decryptSessionResponse(copied);
  assert.equal(result.normalized, true);
  assert.deepEqual(result.data, promotion);
  assert.equal(decryptSessionResponse(raw).normalized, false);
});

test('session response reports invalid JSON, credentials, empty fields, and bad ciphertext', () => {
  assert.throws(() => decryptSessionResponse('bad JSON'), /Invalid session JSON/);
  for (const value of ['null', '{}', '{"data":[]}']) assert.throws(() => decryptSessionResponse(value), /Missing data.options/);
  const { response } = sessionFixture();
  const check = () => decryptSessionResponse(JSON.stringify(response));
  assert.throws(() => decryptSessionResponse(JSON.stringify(response), '__proto__'), /Unsupported/);
  assert.throws(() => decryptSessionResponse(JSON.stringify(response), 'playerAddress'), /empty/);
  assert.throws(() => decryptSessionResponse(JSON.stringify(response), 'playerStatus'), /null/);
  const key = response.data.options.aesKey;
  delete response.data.options.aesKey;
  assert.throws(check, /Missing data.options.aesKey/);
  response.data.options.aesKey = '!';
  assert.throws(check, /aesKey must be valid Base64/);
  response.data.options.aesKey = key;
  response.data.options.aesIV = Buffer.from('wrong').toString('base64');
  assert.throws(check, /data.promotionStatus:.*32 Hex/);
  response.data.options.aesIV = Buffer.from('00112233445566778899aabbccddeeff').toString('base64');
  response.data.promotionStatus = 'invalid';
  assert.throws(check, /data.promotionStatus:.*raw Hex/);
});
