// Browser extension implementation for consent cryptographic flow with RSA
console.log("Content script loaded - Consent Cryptographic Handler");

// Helpers for browser environment
const cryptoUtils = {
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

	hexToArrayBuffer(hex) {
		const bytes = new Uint8Array(hex.length / 2);
		for (let i = 0; i < hex.length; i += 2) {
			bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
		}
		return bytes.buffer;
	},

	// Import RSA public key from PEM format
	async importRSAPublicKey(pemKey) {
		const pemHeader = "-----BEGIN PUBLIC KEY-----";
		const pemFooter = "-----END PUBLIC KEY-----";
		const pemContents = pemKey
			.replace(pemHeader, '')
			.replace(pemFooter, '')
			.replace(/\s/g, '');

		const binaryString = atob(pemContents);
		const bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) {
			bytes[i] = binaryString.charCodeAt(i);
		}

		return window.crypto.subtle.importKey(
			'spki',
			bytes.buffer,
			{
				name: 'RSA-PSS',
				hash: { name: 'SHA-256' }
			},
			false,
			['verify'] // ✅ allow verify
		);
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
	},

	async verifyServerSignature(serverPublicKey, data, signatureHex) {
		const dataBuffer = new TextEncoder().encode(JSON.stringify(data));
		const signatureBuffer = this.hexToArrayBuffer(signatureHex);

		const isValid = await window.crypto.subtle.verify(
			{
				name: "RSA-PSS",
				saltLength: 32
			},
			serverPublicKey,
			signatureBuffer,
			dataBuffer
		);

		return isValid;
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
		const serverPublicKey = await cryptoUtils.importRSAPublicKey(publicKeyData);
		console.log('Imported server RSA public key');

		// Step 3: Generate RSA signing key pair for client
		const clientSigningKeyPair = await cryptoUtils.generateRSASigningKeyPair();
		const clientPublicSigningKeyExported = await cryptoUtils.exportPublicKey(
			clientSigningKeyPair.publicKey
		);
		console.log('Generated client RSA signing keys');

		// Step 4: Sign the consent data
		const consentDataString = JSON.stringify(consentData);
		const clientSignature = await cryptoUtils.signData(
			clientSigningKeyPair.privateKey,
			consentDataString
		);
		console.log('Signed consent');

		// Step 5: Send package to server
		const consentPackage = {
			consentData: consentData,
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

		console.log("Client-side data string:", consentDataString);
		// Step 6: Verify if signature is valid
		const isValid = await cryptoUtils.verifyServerSignature(
			serverPublicKey,
			consentData,
			result.serverSignature
		);

		if (isValid) {
			console.log('✅ Server signature is valid and verified.');
		} else {
			console.warn('❌ Server signature verification failed.');
		}

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
