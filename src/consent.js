import forge from "node-forge";

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

	async importPrivateKey(pem) {
		// Remove PEM header/footer and newlines
		const pemContents = pem
			.replace(/-----BEGIN (.*)-----/, '')
			.replace(/-----END (.*)-----/, '')
			.replace(/\s+/g, '');

		// Convert base64 to ArrayBuffer
		const binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

		// Import key
		return await crypto.subtle.importKey(
			'pkcs8',
			binaryDer.buffer,
			{
				name: 'RSA-PSS',
				hash: 'SHA-256',
			},
			false,
			['sign']
		);
	},

	formatPem(pem, type) {
		const header = `-----BEGIN ${type}-----`;
		const footer = `-----END ${type}-----`;

		// Remove headers/footers and whitespace
		const base64 = pem
			.replace(/-----.*?-----/g, '')
			.replace(/\s+/g, '');

		// Rebuild properly formatted PEM
		const formatted = base64.match(/.{1,64}/g).join('\n');
		return `${header}\n${formatted}\n${footer}`;
	},

	// Generate RSA key pair for signing
	async loadSigningKeyPair() {
		let certPEM, privKey;
		try {
			certPEM = localStorage.getItem("cert");
			certPEM = this.formatPem(certPEM, "CERTIFICATE")
			console.log(certPEM);

			privKey = localStorage.getItem("privKey");
			privKey = this.formatPem(privKey, "PRIVATE KEY")
			console.log(privKey);

		} catch (e) {
			console.error("Error getting local storage PEM values:", e);
			throw e;
		}

		const cert = forge.pki.certificateFromPem(certPEM);
		const pubKey = forge.pki.publicKeyToPem(cert.publicKey);

		return { pubKey, privKey };
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

	// Sign data using RSA-PSS private key
	async signData(privateKey, data) {
		const dataBuffer = this.stringToArrayBuffer(JSON.stringify(data));

		console.log("Falha aqui?");
		const signature = await window.crypto.subtle.sign(
			{
				name: 'RSA-PSS',
				saltLength: 32 //  if you use SHA-256 as the digest algorithm, this could be 32.
			},
			privateKey,
			dataBuffer
		);
		console.log("OU aqui?");

		return this.base64UrlEncode(signature);
	},

	// Verify server-signed JWS
	async verifyServerJWS(jwsJsonString, consent, serverPublicKey) {

		const jws = JSON.parse(jwsJsonString);

		if (!jws.payload || !Array.isArray(jws.signatures)) {
			throw new Error('Invalid JWS JSON serialization format');
		}

		// Choose the server signature (e.g., the second one)
		const serverSigEntry = jws.signatures[1];
		if (!serverSigEntry || !serverSigEntry.signature || !serverSigEntry.header) {
			throw new Error('Missing server signature entry');
		}

		const isValid = await window.crypto.subtle.verify(
			{
				name: "RSA-PSS",
				saltLength: 32
			},
			serverPublicKey,
			this.base64UrlDecode(serverSigEntry.signature),
			this.stringToArrayBuffer(JSON.stringify(consent))
		);

		if (!isValid) {
			throw new Error('Invalid server signature');
		}

		// Decode and return payload
		const payloadBuffer = this.base64UrlDecode(jws.payload);
		return JSON.parse(new TextDecoder().decode(payloadBuffer));
	}
};

// Consent processing with JWS
async function processConsent(consentData) {
	console.log('Processing consent data with JWS:', consentData);

	try {
		// Step 1: Fetch server's certificate and pubKey
		const serverCert = await fetch('http://127.0.0.1:3000/api/server_certificate');
		const certPem = await serverCert.json();
		const cert = forge.pki.certificateFromPem(certPem);
		const publicKey = forge.pki.publicKeyToPem(cert.publicKey);

		console.log('Received server public key data:', publicKey);

		// Step 2: Import server's RSA public key
		const serverPublicKey = await cryptoUtils.importRSAPublicKey(publicKey);
		console.log('Imported server RSA public key');

		// Step 3: Load key pair for client
		const clientSigningKeyPair = await cryptoUtils.loadSigningKeyPair();
		const privKeyCrypto = await cryptoUtils.importPrivateKey(clientSigningKeyPair.privKey);
		console.log('Loaded client RSA signing keys');

		// Step 4: Sign consentData
		const clientSignature = await cryptoUtils.signData(privKeyCrypto, consentData);

		console.log('Client signed the consent');

		const response = await fetch('http://127.0.0.1:3000/api/consent', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({
				signature: clientSignature,
				consent: consentData,
				pubkey: clientSigningKeyPair.pubKey
			})
		});

		console.log('Client sent the info');

		const result = await response.json();

		console.log(result);

		// Step 5: Verify server-signed JWS
		if (result.success && result.serverSignedJWS) {
			try {
				const serverSignedPayload = await cryptoUtils.verifyServerJWS(
					result.serverSignedJWS,
					consentData,
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
