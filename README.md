# @tfpkgr/cipher

## Usage

### Cipher Class

#### Encrypt and Decrypt

```typescript
import Cipher from '@tfpkgr/cipher';

const secureKey = 'your-secure-key-32-characters-long';
const cipher = new Cipher(secureKey);

const data = 'Hello, World!';
const encrypted = cipher.encrypt(data);
console.log('Encrypted:', encrypted);

const decrypted = cipher.decrypt(encrypted);
console.log('Decrypted:', decrypted);
```

#### Hashing and Verification

```typescript
const data = 'Sensitive Data';
const hash = cipher.hash(data);
console.log('Hash:', hash);

const isValid = cipher.verify(data, hash);
console.log('Is Valid:', isValid);
```

### CipherKeyPair Class

#### Generate Key Pair

```typescript
import {CipherKeyPair} from '@tfpkgr/cipher';

const keyPair = CipherKeyPair.generate();
console.log('Public Key:', keyPair.getPublicKey());
console.log('Private Key:', keyPair.getPrivateKey());
```

#### Encrypt and Decrypt with Key Pair

```typescript
const message = 'Secret Message';
const encryptedMessage = keyPair.encrypt(message);
console.log('Encrypted Message:', encryptedMessage);

const decryptedMessage = keyPair.decrypt(encryptedMessage);
console.log('Decrypted Message:', decryptedMessage);
```

### Utility Function

#### Generate Random String

```typescript
import {CipherRandom} from '@tfpkgr/cipher';

const randomString = CipherRandom(16);
console.log('Random String:', randomString);
```
