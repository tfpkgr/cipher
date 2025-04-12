import * as crypto from 'node:crypto';

/**
 * Supported cipher hashing algorithms.
 */
export enum CipherHashAlgorithm {
	'aes-128-gcm' = 'aes-128-gcm',
	'aes-192-gcm' = 'aes-192-gcm',
	'aes-256-gcm' = 'aes-256-gcm',
}

/**
 * Options for configuring the cipher.
 */
export type CipherOptions = {
	hashAlgorithm?: CipherHashAlgorithm;
};

/**
 * Class representing a public/private key pair.
 */
export class CipherKeyPair {
	private publicKey: string;
	private privateKey: string;

	/**
	 * Creates an instance of CipherKeyPair.
	 * @param publicKey - The public key as a PEM string.
	 * @param privateKey - The private key as a PEM string.
	 */
	constructor(publicKey: string, privateKey: string) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Returns the public key.
	 * @returns The public key as a PEM string.
	 */
	getPublicKey(): string {
		return this.publicKey;
	}

	/**
	 * Returns the private key.
	 * @returns The private key as a PEM string.
	 */
	getPrivateKey(): string {
		return this.privateKey;
	}

	/**
	 * Returns both the public and private keys.
	 * @returns A read-only array containing the public and private keys as PEM strings.
	 */
	getKeyPair(): Readonly<[string, string]> {
		return [this.publicKey, this.privateKey];
	}

	/**
	 * Encrypts data using the public key.
	 * @param data - The data to encrypt.
	 * @returns The encrypted data as a base64 string.
	 */
	encrypt(data: string): string {
		if (!data) {
			throw new Error('Data is required for encryption.');
		}

		const buffer = Buffer.from(data, 'utf8');
		const encrypted = crypto.publicEncrypt(this.publicKey, buffer);
		return encrypted.toString('base64');
	}

	/**
	 * Decrypts data using the private key.
	 * @param encryptedData - The encrypted data as a base64 string.
	 * @param passphrase - Optional passphrase for the private key.
	 * @returns The decrypted plaintext string.
	 */
	decrypt(encryptedData: string, passphrase?: string): string {
		if (!encryptedData) {
			throw new Error('Encrypted data is required for decryption.');
		}

		const buffer = Buffer.from(encryptedData, 'base64');
		const decrypted = crypto.privateDecrypt(
			{
				key: this.privateKey,
				passphrase: passphrase || undefined,
			},
			buffer,
		);
		return decrypted.toString('utf8');
	}

	/**
	 * Generates a public/private key pair.
	 * @param passphrase - Optional passphrase to secure the private key.
	 * @returns An instance of CipherKeyPair containing the public and private keys.
	 */
	static generate(passphrase?: string): CipherKeyPair {
		const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: {type: 'spki', format: 'pem'},
			privateKeyEncoding: {
				type: 'pkcs8',
				format: 'pem',
				cipher: passphrase ? 'aes-256-cbc' : undefined,
				passphrase: passphrase || undefined,
			},
		});
		return new CipherKeyPair(publicKey, privateKey);
	}
}

/**
 * Class representing a Cipher for encryption and decryption.
 */
export default class Cipher {
	/**
	 * The hash algorithm used for encryption.
	 * @default 'aes-256-gcm'
	 */
	private hashAlgorithm: CipherHashAlgorithm =
		CipherHashAlgorithm['aes-256-gcm'];

	/**
	 * The length of the initialization vector.
	 * Dynamically derived from the algorithm.
	 */
	private ivLength: number;

	/**
	 * The length of the authentication tag.
	 */
	private authTagLength = 16;

	/**
	 * The secure key used for encryption and decryption.
	 */
	private secureKey: Buffer;

	/**
	 * Creates an instance of Cipher.
	 * @param secureKey - The secure key used for encryption and decryption.
	 * @param options - Optional configuration for the cipher.
	 */
	constructor(secureKey: string, options: CipherOptions = {}) {
		if (!secureKey) {
			throw new Error('Secure key is required.');
		}

		this.hashAlgorithm = options.hashAlgorithm || this.hashAlgorithm;

		// Validate the hash algorithm
		if (!Object.values(CipherHashAlgorithm).includes(this.hashAlgorithm)) {
			throw new Error(
				`Invalid hash algorithm. Supported algorithms are: ${Object.values(
					CipherHashAlgorithm,
				).join(', ')}`,
			);
		}
		// Validate the secure key length
		if (secureKey.length < 32) {
			throw new Error('Secure key must be at least 32 characters long.');
		}

		// Dynamically determine IV length based on cipher algorithm
		this.ivLength =
			crypto.getCipherInfo(this.hashAlgorithm)?.ivLength || 12;

		// Hash the provided key into a secure 32-byte buffer (for AES-256)
		this.secureKey = crypto.createHash('sha256').update(secureKey).digest();
	}

	/**
	 * Encrypts the given data.
	 * @param data - The data to encrypt.
	 * @returns The encrypted data as a single base64 string.
	 */
	encrypt(data: string): string {
		if (!data) {
			throw new Error('No data provided for encryption.');
		}

		const iv = crypto.randomBytes(this.ivLength);
		const cipher = crypto.createCipheriv(
			this.hashAlgorithm,
			this.secureKey,
			iv,
		);
		const encryptedBuffer = Buffer.concat([
			cipher.update(data, 'utf8'),
			cipher.final(),
		]);
		const authTag = cipher.getAuthTag();

		// Combine IV + encrypted data + auth tag, then encode to base64
		const combined = Buffer.concat([iv, encryptedBuffer, authTag]);
		return combined.toString('base64');
	}

	/**
	 * Decrypts the given encrypted data.
	 * @param encryptedData - The encrypted data as a base64 string.
	 * @returns The decrypted plaintext string.
	 */
	decrypt(encryptedData: string): string {
		if (!encryptedData) {
			throw new Error('No data provided for decryption.');
		}

		const combinedBuffer = Buffer.from(encryptedData, 'base64');

		// Extract IV, encrypted text, and auth tag from the buffer
		const iv = combinedBuffer.slice(0, this.ivLength);
		const encryptedText = combinedBuffer.slice(
			this.ivLength,
			-this.authTagLength,
		);
		const authTag = combinedBuffer.slice(-this.authTagLength);

		const decipher = crypto.createDecipheriv(
			this.hashAlgorithm,
			this.secureKey,
			iv,
		);
		decipher.setAuthTag(authTag);

		let decrypted = decipher.update(encryptedText, undefined, 'utf8');
		decrypted += decipher.final('utf8');

		return decrypted;
	}

	/**
	 * Hashes the given data using HMAC with the secure key.
	 * @param data - The data to hash.
	 * @returns The HMAC hash as a base64 string.
	 */
	hash(data: string): string {
		if (!data) {
			throw new Error('No data provided for hashing.');
		}

		const hmac = crypto.createHmac('sha256', this.secureKey);
		hmac.update(data);
		return hmac.digest('base64');
	}

	/**
	 * Verifies the given data against a provided HMAC hash.
	 * @param data - The data to verify.
	 * @param hash - The HMAC hash to compare against.
	 * @returns True if the hash matches, false otherwise.
	 */
	verify(data: string, hash: string): boolean {
		if (!data || !hash) {
			throw new Error('Data and hash are required for verification.');
		}

		const computedHash = this.hash(data);
		return crypto.timingSafeEqual(
			Buffer.from(computedHash, 'base64'),
			Buffer.from(hash, 'base64'),
		);
	}

	/**
	 * Generates a secure random key of given length.
	 * @param length - The desired length of the key.
	 * @returns A securely generated random key.
	 */
	static random(length = 32): string {
		if (!Number.isInteger(length) || length <= 0) {
			throw new Error(
				'Invalid length. Please provide a positive integer.',
			);
		}
		return crypto.randomBytes(length).toString('base64');
	}

	/**
	 * Creates a new Cipher instance with the provided secure key and options.
	 * @param secureKey - The secure key used for encryption and decryption.
	 * @param options - Optional configuration for the cipher.
	 * @returns A new Cipher instance.
	 */
	static from(secureKey: string, options: CipherOptions = {}): Cipher {
		return new Cipher(secureKey, options);
	}
}

// Export utility function
/**
 * Generates a random string of specified length.
 * @param length - The desired length of the random string.
 * @returns A randomly generated string of the specified length.
 */
export function CipherRandom(length: number): string {
	return Cipher.random(length);
}
