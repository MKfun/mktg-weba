import bigInt from 'big-integer';

import {
  generateRandomBytes,
  modExp,
  readBigIntFromBuffer,
  readBufferFromBigInt,
  sha1,
} from '../Helpers';

export const SERVER_KEYS = [
    {
        fingerprint: bigInt('-2834260219237205393'),
        n: bigInt('b3810a84447043f34b790c0fe338977c4e76f1c68c320d16bc508703ce26cfc85dac9c1e8400707b6082e8c5a3027394ca25a4f336525cd1c3da010edcffb0785bddf6ea14e67d7ce877230679ba9698ba6a797650dcd10eb0441f3b5f67462eae429d8e13afc622438b6e15b36daaa18c3f7422055ca163026078b8b5b2311375de1b25d03d7b572cab73f9ca2e8d7235fccc27504105bf34eb666c767ba1801b31bac8d1d2f4f21be3f16add1207b45d055bcd3213a9dc163419ca1a9a7263839fbcc5366d4d5978cf34bfe0c55eff61dbde43a0fba97df5bf78b3ca26a68d6671042ca504319b5759f0adda665820a45265fdc0fa29c245653804fec79971',16),
        e: 65537
    }
].reduce((acc, { fingerprint, ...keyInfo }) => {
  acc.set(fingerprint.toString(), keyInfo);
  return acc;
}, new Map<string, { n: bigInt.BigInteger; e: number }>());

/**
 * Encrypts the given data known the fingerprint to be used
 * in the way Telegram requires us to do so (sha1(data) + data + padding)

 * @param fingerprint the fingerprint of the RSA key.
 * @param data the data to be encrypted.
 * @returns {Buffer|*|undefined} the cipher text, or undefined if no key matching this fingerprint is found.
 */
export async function encrypt(fingerprint: bigInt.BigInteger, data: Buffer) {
  const key = SERVER_KEYS.get(fingerprint.toString());
  if (!key) {
    return undefined;
  }

  // len(sha1.digest) is always 20, so we're left with 255 - 20 - x padding
  const rand = generateRandomBytes(235 - data.length);

  const toEncrypt = Buffer.concat([await sha1(data), data, rand]);

  // rsa module rsa.encrypt adds 11 bits for padding which we don't want
  // rsa module uses rsa.transform.bytes2int(to_encrypt), easier way:
  const payload = readBigIntFromBuffer(toEncrypt, false);
  const encrypted = modExp(payload, bigInt(key.e), key.n);
  // rsa module uses transform.int2bytes(encrypted, keylength), easier:
  return readBufferFromBigInt(encrypted, 256, false);
}
