// Browser extension implementation for consent cryptographic flow with JWS
console.log("Content script loaded - Consent Cryptographic Handler with JWS");

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

	// Base64 URL encoding (without padding)
	base64UrlEncode(buffer) {
		const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
		return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	},

	// Base64 URL decoding
	base64UrlDecode(str) {
		// Add padding if needed
		str += '='.repeat((4 - str.length % 4) % 4);
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		return Uint8Array.from(atob(str), c => c.charCodeAt(0));
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
			['verify']
		);
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

	// Create JWS with client signature
	async createClientJWS(consentData, clientPrivateKey, clientPublicKeyPem) {
		// JWS Header
		const header = {
			alg: "PS256", // RSA-PSS with SHA-256
			typ: "JWT",
			kid: "client-key"
		};

		// JWS Payload - contains consent data and client public key
		const payload = {
			consentData: consentData,
			clientPublicKey: clientPublicKeyPem,
			iat: Math.floor(Date.now() / 1000),
			iss: "consent-client"
		};

		// Encode header and payload
		const encodedHeader = this.base64UrlEncode(this.stringToArrayBuffer(JSON.stringify(header)));
		const encodedPayload = this.base64UrlEncode(this.stringToArrayBuffer(JSON.stringify(payload)));

		// Create signing input
		const signingInput = `${encodedHeader}.${encodedPayload}`;

		// Sign with client private key
		const signature = await window.crypto.subtle.sign(
			{
				name: 'RSA-PSS',
				saltLength: 32
			},
			clientPrivateKey,
			this.stringToArrayBuffer(signingInput)
		);

		const encodedSignature = this.base64UrlEncode(signature);

		// Return complete JWS
		return `${signingInput}.${encodedSignature}`;
	},

	// Verify server-signed JWS
	async verifyServerJWS(jws, serverPublicKey) {
		const parts = jws.split('.');
		if (parts.length !== 3) {
			throw new Error('Invalid JWS format');
		}

		const [encodedHeader, encodedPayload, encodedSignature] = parts;

		// Decode header to check if it's server-signed
		const headerBuffer = this.base64UrlDecode(encodedHeader);
		const header = JSON.parse(new TextDecoder().decode(headerBuffer));

		if (header.kid !== "server-key") {
			throw new Error('JWS not signed by server');
		}

		// Verify server signature
		const signingInput = `${encodedHeader}.${encodedPayload}`;
		const signatureBuffer = this.base64UrlDecode(encodedSignature);

		const isValid = await window.crypto.subtle.verify(
			{
				name: "RSA-PSS",
				saltLength: 32
			},
			serverPublicKey,
			signatureBuffer,
			this.stringToArrayBuffer(signingInput)
		);

		if (!isValid) {
			throw new Error('Invalid server signature');
		}

		// Decode and return payload
		const payloadBuffer = this.base64UrlDecode(encodedPayload);
		return JSON.parse(new TextDecoder().decode(payloadBuffer));
	},

	// Pretty print JWS token with decoded header and payload
	logJWSToken(jws, title = 'JWS Token') {
		console.log(`\n🔍 ${title}:`);
		console.log('─'.repeat(50));

		// Print the raw JWS token
		console.log('📄 Raw JWS Token:');
		console.log(jws);
		console.log('');

		try {
			const parts = jws.split('.');
			if (parts.length !== 3) {
				console.log('❌ Invalid JWS format');
				return;
			}

			const [encodedHeader, encodedPayload, encodedSignature] = parts;

			// Decode and display header
			const headerBuffer = this.base64UrlDecode(encodedHeader);
			const header = JSON.parse(new TextDecoder().decode(headerBuffer));
			console.log('📋 Header:');
			console.log(JSON.stringify(header, null, 2));

			// Decode and display payload
			const payloadBuffer = this.base64UrlDecode(encodedPayload);
			const payload = JSON.parse(new TextDecoder().decode(payloadBuffer));
			console.log('📦 Payload:');
			console.log(JSON.stringify(payload, null, 2));

			// Display signature info
			console.log('🔐 Signature:');
			console.log(`Length: ${encodedSignature.length} characters`);
			console.log(`Preview: ${encodedSignature.substring(0, 50)}...`);

		} catch (error) {
			console.error('❌ Error decoding JWS:', error.message);
		}

		console.log('─'.repeat(50));
	}
};

// Consent processing with JWS
async function processConsent(consentData) {
	console.log('Processing consent data with JWS:', consentData);

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

		// Step 4: Create client-signed JWS
		const clientJWS = await cryptoUtils.createClientJWS(
			consentData,
			clientSigningKeyPair.privateKey,
			clientPublicSigningKeyExported
		);
		console.log('Created client JWS');

		// Log the client JWS
		cryptoUtils.logJWSToken(clientJWS, 'Client-Generated JWS');

		// Step 5: Send JWS to server
		console.log('Sending JWS to server');

		const response = await fetch('http://127.0.0.1:3000/api/consent', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ jws: clientJWS })
		});

		const result = await response.json();

		// Step 6: Verify server-signed JWS
		if (result.success && result.serverSignedJWS) {
			// Log the server-signed JWS
			cryptoUtils.logJWSToken(result.serverSignedJWS, 'Server-Signed JWS');

			try {
				const serverSignedPayload = await cryptoUtils.verifyServerJWS(
					result.serverSignedJWS,
					serverPublicKey
				);

				console.log('✅ Server-signed JWS verified successfully');
				console.log('Final payload:', serverSignedPayload);

				return true;
			} catch (verifyError) {
				console.error('❌ Server JWS verification failed:', verifyError);
				return false;
			}
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
console.log("Consent Cryptographic Handler with JWS ready");
