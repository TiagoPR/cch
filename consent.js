// Browser extension implementation for consent cryptographic flow with RSA
console.log("Content script loaded - Consent Cryptographic Handler");

// Helpers for browser environment
const cryptoUtils = {
	// Convert hex string to ArrayBuffer
	hexToArrayBuffer(hexString) {
		const bytes = new Uint8Array(hexString.length / 2);
		for (let i = 0; i < hexString.length; i += 2) {
			bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
		}
		return bytes.buffer;
	},

	// Convert ArrayBuffer to hex string
	arrayBufferToHex(buffer) {
		return Array.from(new Uint8Array(buffer))
			.map(b => b.toString(16).padStart(2, '0'))
			.join('');
	},

	// Convert string to ArrayBuffer
	stringToArrayBuffer(str) {
		return new TextEncoder().encode(str);
	},

	// Convert ArrayBuffer to string
	arrayBufferToString(buffer) {
		return new TextDecoder().decode(buffer);
	},

	// Generate random symmetric key (32 bytes for AES-256)
	generateRandomSymmetricKey() {
		return window.crypto.getRandomValues(new Uint8Array(32));
	},

	// Import raw bytes as AES key
	async importSymmetricKey(keyBytes) {
		return window.crypto.subtle.importKey(
			'raw',
			keyBytes,
			{ name: 'AES-GCM', length: 256 },
			false,
			['encrypt', 'decrypt']
		);
	},

	// Import RSA public key from PEM format
	async importRSAPublicKey(pemKey) {
		// Remove header, footer, and whitespace from PEM
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		const pemContents = pemKey
			.replace(pemHeader, '')
			.replace(pemFooter, '')
			.replace(/\s/g, '');

		// Convert base64 to ArrayBuffer
		const binaryString = atob(pemContents);
		const bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}

		// Import the key
		return window.crypto.subtle.importKey(
			'spki',
			bytes.buffer,
			{
				name: 'RSA-OAEP',
				hash: { name: 'SHA-256' }
			},
			false,
			['encrypt']
		);
	},

	// Encrypt symmetric key with RSA public key
	async encryptSymmetricKey(publicKey, symmetricKey) {
		const encryptedKey = await window.crypto.subtle.encrypt(
			{
				name: 'RSA-OAEP'
			},
			publicKey,
			symmetricKey
		);

		return this.arrayBufferToHex(encryptedKey);
	},

	// Encrypt consent data
	async encryptConsent(symmetricKey, consentData) {
		// Generate random IV
		const iv = window.crypto.getRandomValues(new Uint8Array(12));

		// Convert consent data to JSON string and then to bytes
		const consentBytes = new TextEncoder().encode(JSON.stringify(consentData));

		// Encrypt
		const encryptedContent = await window.crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv: iv,
				tagLength: 128 // 16 bytes tag
			},
			symmetricKey,
			consentBytes
		);

		// In AES-GCM the auth tag is appended to the ciphertext
		// We need to extract it to match our protocol
		const encryptedBytes = new Uint8Array(encryptedContent);
		const ciphertextLength = encryptedBytes.length - 16; // 16 bytes tag
		const ciphertext = new Uint8Array(encryptedBytes.buffer, 0, ciphertextLength);
		const tag = new Uint8Array(encryptedBytes.buffer, ciphertextLength, 16);

		return {
			ciphertext: this.arrayBufferToHex(ciphertext),
			iv: this.arrayBufferToHex(iv),
			tag: this.arrayBufferToHex(tag)
		};
	},

	// Sign data with RSA-PSS
	async signData(privateKey, data) {
		// Convert data to ArrayBuffer if it's not already
		const dataBuffer = typeof data === 'string'
			? this.stringToArrayBuffer(data)
			: data;

		// Sign
		const signature = await window.crypto.subtle.sign(
			{
				name: 'RSA-PSS',
				saltLength: 32 // max salt length
			},
			privateKey,
			dataBuffer
		);

		return this.arrayBufferToHex(signature);
	},

	// Generate RSA key pair for signing
	async generateRSASigningKeyPair() {
		return window.crypto.subtle.generateKey(
			{
				name: 'RSA-PSS',
				modulusLength: 2048,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
				hash: { name: 'SHA-256' }
			},
			true, // extractable
			['sign', 'verify']
		);
	},

	// Export public key to PEM format
	async exportPublicKey(publicKey) {
		const exported = await window.crypto.subtle.exportKey('spki', publicKey);
		const exportedAsBase64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		const pemBody = exportedAsBase64.match(/.{1,64}/g).join('\n');
		return `${pemHeader}\n${pemBody}\n${pemFooter}`;
	}
};

// Consent processing with RSA key exchange
async function processConsent(consentData) {
	console.log('Processing consent data with RSA:', consentData);

	try {
		// Step 1: Fetch server's RSA public key
		const publicKeyResponse = await fetch('http://127.0.0.1:3000/api/publickey');
		const publicKeyData = await publicKeyResponse.json();

		console.log('Received server public key data:', publicKeyData);

		// Step 2: Import server's RSA public key
		const serverPublicKey = await cryptoUtils.importRSAPublicKey(publicKeyData.publicKey);
		console.log('Imported server RSA public key');

		// Step 3: Generate random symmetric key
		const symmetricKeyBytes = cryptoUtils.generateRandomSymmetricKey();
		const symmetricKey = await cryptoUtils.importSymmetricKey(symmetricKeyBytes);
		console.log('Generated random symmetric key');

		// Step 4: Encrypt symmetric key with server's RSA public key
		const encryptedSymmetricKey = await cryptoUtils.encryptSymmetricKey(serverPublicKey, symmetricKeyBytes);
		console.log('Encrypted symmetric key with server public key');

		// Step 5: Generate RSA signing key pair for client
		const clientSigningKeyPair = await cryptoUtils.generateRSASigningKeyPair();
		const clientPublicSigningKeyExported = await cryptoUtils.exportPublicKey(
			clientSigningKeyPair.publicKey
		);
		console.log('Generated client RSA signing keys');

		// Step 6: Encrypt consent data with symmetric key
		const encryptedConsent = await cryptoUtils.encryptConsent(symmetricKey, consentData);
		console.log('Encrypted consent:', encryptedConsent);

		// Step 7: Sign encrypted consent
		const dataToSign = encryptedConsent.iv + encryptedConsent.ciphertext + encryptedConsent.tag;
		const clientSignature = await cryptoUtils.signData(
			clientSigningKeyPair.privateKey,
			cryptoUtils.stringToArrayBuffer(dataToSign)
		);
		console.log('Signed consent');

		// Step 8: Send package to server
		const consentPackage = {
			encryptedConsent: encryptedConsent,
			encryptedSymmetricKey: encryptedSymmetricKey,
			clientSignature: clientSignature,
			clientPublicSigningKey: clientPublicSigningKeyExported
		};

		console.log('Sending consent package to server:', consentPackage);

		const response = await fetch('http://127.0.0.1:3000/api/consent', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(consentPackage)
		});

		const result = await response.json();

		if (result.success) {
			console.log('Consent successfully processed by server');
			console.log('Server signature:', result.serverSignature);
			return true;
		} else {
			console.error('Server error:', result.error);
			return false;
		}
	} catch (error) {
		console.error('Error processing consent:', error);
		return false;
	}
}

// Listen for Klaro consent button clicks
document.addEventListener('click', function(event) {
	if (event.target.closest('.cm-btn-success')) {
		console.log("✅ User submitted positive consent");

		// Wait briefly to ensure cookie is updated
		setTimeout(() => {
			console.log("Parsing cookie...");

			// Get and parse the klaro cookie
			const cookieString = document.cookie
				.split('; ')
				.find(row => row.startsWith('klaro='));

			if (cookieString) {
				const klaroValue = decodeURIComponent(cookieString.split('=')[1]);
				const consentObject = JSON.parse(klaroValue);

				const consentData = {
					consents: consentObject,
					confirmed: true,
					timestamp: new Date().toISOString()
				};

				console.log('[DEBUG] consentData:', consentData);

				// Process consent cryptographically
				processConsent(JSON.parse(JSON.stringify(consentData)))
					.then(success => {
						console.log('Consent processing complete:', success ? 'Success' : 'Failed');
					})
					.catch(error => {
						console.error('Consent processing error:', error);
					});
			} else {
				console.error('Klaro cookie not found.');
			}
		}, 100);
	}
	else if (event.target.closest('.cm-btn-decline')) {
		console.log("✅ User submitted negative consent");

		// Similar processing for declined consent
		setTimeout(() => {
			const manager = window.klaro?.getManager();
			if (manager) {
				const consentData = {
					consents: manager.consents,
					confirmed: false,
					timestamp: new Date().toISOString()
				};

				processConsent(consentData)
					.then(success => {
						console.log('Consent processing complete:', success ? 'Success' : 'Failed');
					})
					.catch(error => {
						console.error('Consent processing error:', error);
					});
			}
		}, 100);
	}
});

// Flag to track if we're processing consent
let processingConsent = false;

// Listen for extension check events
document.addEventListener('checkConsentExtension', function(event) {
	console.log('Extension check received:', event.detail);

	// Respond to the page that extension is present
	const responseEvent = new CustomEvent('consentExtensionPresent', {
		detail: {
			id: 'cch-extension-present',
			version: '1.0'
		}
	});

	window.dispatchEvent(responseEvent);
	console.log('Extension presence confirmed to page');
});

// Listen for consent updated events from Klaro
document.addEventListener('consentUpdated', function(event) {
	console.log('Consent updated event received');

	if (processingConsent) {
		console.log('Already processing consent, skipping...');
		return;
	}

	// Get consent data from window object set by Klaro
	const consentData = window.klaroConsentData;

	if (consentData) {
		console.log('Processing consent from event:', consentData);
		processingConsent = true;

		// Mark that extension is handling the consent
		window.consentHandledByExtension = true;

		processConsent(consentData)
			.then(success => {
				console.log('Consent processing complete:', success ? 'Success' : 'Failed');
				processingConsent = false;
			})
			.catch(error => {
				console.error('Consent processing error:', error);
				processingConsent = false;
			});
	}
});

// Log that the extension is ready
console.log("Consent Cryptographic Handler ready");
