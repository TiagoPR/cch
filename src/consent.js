import forge from "node-forge";

// Create our own CA Store with our OpenSSL Root CA
const trustedRootPEM = `-----BEGIN CERTIFICATE-----
MIIEEzCCAvugAwIBAgIUNYrV+GWjfV9PQKreDRZjRgVg4g4wDQYJKoZIhvcNAQEL
BQAwgZgxCzAJBgNVBAYTAlBUMQ4wDAYDVQQIDAVCcmFnYTEOMAwGA1UEBwwFQnJh
Z2ExHjAcBgNVBAoMFVVuaXZlcnNpZGFkZSBkbyBNaW5obzETMBEGA1UECwwKRW5n
ZW5oYXJpYTESMBAGA1UEAwwJdW1pbmhvLnB0MSAwHgYJKoZIhvcNAQkBFhFwZzUy
NzA1QHVtaW5oby5wdDAeFw0yNTA5MDQxMDM2MTFaFw0zMDA5MDQxMDM2MTFaMIGY
MQswCQYDVQQGEwJQVDEOMAwGA1UECAwFQnJhZ2ExDjAMBgNVBAcMBUJyYWdhMR4w
HAYDVQQKDBVVbml2ZXJzaWRhZGUgZG8gTWluaG8xEzARBgNVBAsMCkVuZ2VuaGFy
aWExEjAQBgNVBAMMCXVtaW5oby5wdDEgMB4GCSqGSIb3DQEJARYRcGc1MjcwNUB1
bWluaG8ucHQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP3Rx2fZlY
2yXLXylqZElSJjqqs1n7KLPKOWZd9c6x2SCJWs0Sq3SDES3mlzkTdZqkWOmzXkrJ
64E03fF84I+PdYB/zqbvdO6GB/8C26jSnIw3RRsFh4CDsSmk8jteuvcQEawrHvfy
d3jCEFBqUt151WBYrRN4qOIFcPX4/qwCdaWmHwg/K3ah8tn+qQznbXY04Ko9ofa1
8AXB3doR2SAvj+4lzD+dt61P7RLX3Ox9D4b9dgDImXc5LsusTChmrkytrKrxUDej
7zBUpxhoH2LLgwuwCjphrPfUqvKXpzkAY3MdsMsYzfWdBAd1+hQHdxVERPmxUEYh
J7xitOkY5CVBAgMBAAGjUzBRMB0GA1UdDgQWBBSLImVuBB4QajWFbWJ6t0nH8fDY
/DAfBgNVHSMEGDAWgBSLImVuBB4QajWFbWJ6t0nH8fDY/DAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAUM5i4Cz9VzjdQSfOG/ijeSjSrdF2rVAQT
34Cl1bH3l9yZM62E91ldNN7Yi2AR3xBwsQOa7eGRSAbUypF4fbiQIbEq6SncUxUr
abNaZfHrdZyvQshva+UDmmhIE+fXm/OzHXhsNNXAXCUNShSdYdGN9Isy6sh6Y+mq
ShdQRse/ogSuJj59e7/1iF/uw/84DRUxz+XfDUjjjRgg2ysksMX7PSjBcu4HCC8L
ok3T6MmPvNcI5OoDGaZUP62e2GWBF62Qbda/3YK3jV6opb3Ak1KT84ohNXBR9DMV
CMJIu7PfLdZbP0yMZHcJUb513aWYijut7dBswxkCBqvMaqbObjRW
-----END CERTIFICATE-----`

const rootCert = forge.pki.certificateFromPem(trustedRootPEM);

const caStore = forge.pki.createCaStore([rootCert]);

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
			//certPEM = localStorage.getItem("cert");
			//certPEM = this.formatPem(certPEM, "CERTIFICATE")
			// Testing
			certPEM = `-----BEGIN CERTIFICATE-----
MIID+jCCAuKgAwIBAgIUNxdcF0bRmDEFskFJS+vrnAieXb8wDQYJKoZIhvcNAQEL
BQAwgZYxCzAJBgNVBAYTAlBUMQ4wDAYDVQQIDAVCcmFnYTEOMAwGA1UEBwwFQnJh
Z2ExHjAcBgNVBAoMFVVuaXZlcnNpZGFkZSBkbyBNaW5obzEUMBIGA1UECwwLSW5m
b3JtYXRpY2ExDzANBgNVBAMMBlVNSU5ITzEgMB4GCSqGSIb3DQEJARYRcGc1Mjcw
NUB1bWluaG8ucHQwHhcNMjUwNzI4MjEyNTExWhcNMjcxMDMxMjEyNTExWjCBkjEL
MAkGA1UEBhMCUFQxDjAMBgNVBAgMBUJyYWdhMQ4wDAYDVQQHDAVCcmFnYTEeMBwG
A1UECgwVVW5pdmVyc2lkYWRlIGRvIE1pbmhvMRAwDgYDVQQLDAdDbGllbnRlMQ8w
DQYDVQQDDAZVTUlOSE8xIDAeBgkqhkiG9w0BCQEWEXBnNTI3MDVAdW1pbmhvLnB0
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAotPkYXOKQKyypZXBolba
gmI1+aRNKq53DBA28qMCt56bJEzm7EoHQUQU69CQKGA6VjwvtSAV5csPFqF0Aqgq
ALWOYXhDw8E5N7kqAsTBaclBZ0IjlS40syjwQ3JAqWpbdB4IyqaJJ0oA+ZH4MRX+
3uXSjj25qExFty/OCDLKuVUQkd11Nr7v2TLsi/aN4AjAjJLfmwXBycZqmj9Klca0
UfQB5gbaD/nvBbRjaiNf9xeXlbQsL3dWR1eNDX7acWNXfCS2DnfSW0sXvOjMwj62
F7SiR0C0yog3N+cegyX6R61LBmdQNZ1xE21/xXHK60xGrjt3AVmqSSBk8rOiLi99
dwIDAQABo0IwQDAdBgNVHQ4EFgQUVUBLAGdqSbDMb5089bFobujXTy4wHwYDVR0j
BBgwFoAUiyJlbgQeEGo1hW1ierdJx/Hw2PwwDQYJKoZIhvcNAQELBQADggEBAGRx
0iCLuJVBMzhoggzVtVwKazuS7MOHMXKi2UhAm6Tg4jJo9N/30ytVidQuaD/S23RV
PZ0IECTOqjlljXzkxcdiYkqyQXbTvLJeCfNAkEh0Fu3HWBuQDZarqPU+u5300HPP
hdWBqD0Z+pnxRD0+nH+J+tT8vdNzYP0RDTM8ARJnEy7L5bo9Ou6KZcW6hWytup+0
Kcvtcq2GcxV0JYWMsI5gZ5NbnF1PlDqpcDQzGjKVdL1TErA7A7FoskEQPWmoSuN6
7arTriGaVsHHAsmh+k7daJDHrvD84zK1vt36fIt7NKZzdsmdqZhqxctIQ1MBmlrm
9u9FQI7orWELDzjndiE=
-----END CERTIFICATE-----`

			//privKey = localStorage.getItem("privKey");
			//privKey = this.formatPem(privKey, "PRIVATE KEY")
			// Testing
			privKey = `-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCi0+Rhc4pArLKl
lcGiVtqCYjX5pE0qrncMEDbyowK3npskTObsSgdBRBTr0JAoYDpWPC+1IBXlyw8W
oXQCqCoAtY5heEPDwTk3uSoCxMFpyUFnQiOVLjSzKPBDckCpalt0HgjKpoknSgD5
kfgxFf7e5dKOPbmoTEW3L84IMsq5VRCR3XU2vu/ZMuyL9o3gCMCMkt+bBcHJxmqa
P0qVxrRR9AHmBtoP+e8FtGNqI1/3F5eVtCwvd1ZHV40NftpxY1d8JLYOd9JbSxe8
6MzCPrYXtKJHQLTKiDc35x6DJfpHrUsGZ1A1nXETbX/FccrrTEauO3cBWapJIGTy
s6IuL313AgMBAAECgf9N5A8LhabkSVn83ApOc5M5pgPpkqELlbXFcxiwDEq2/ahf
ZH04877/+ak30AP2jvVZJVUCZ9biZt098W/eIVrZ+//sODgycUEFfrjqo5zr00xL
hhDxR2bbagqhx0OPtJg6fVMDLGTrFfIojWQxpTxLucF2B2/W8T1L5EtQ7Ilsc3xc
FKD7YchqwwZ7yZnMrUd7atBWA3VZ6E1fmXHlHZJbGzsAT1GKgc7um92BTK2fuYWs
iTs7eNdt+cbebRrgxCFsTFSbxbmpdYxdlym3WNUtwnACaGapZZymHQHzx6tquCP/
y2QQtBjc6t1soxf9N6voGGjZNcrgdbHTGz1RovkCgYEA2YXWg0rO8hVfCPyM3UNa
0WkanUGLCeydb8vrHeA8BY67La0aCc5uJOVHewhOeON1qsDwD6zD5St6+3jgMq5k
hF7do65tOz+HBZl0TdbKkHlANRDTY/HUAP8ftsyWhzgSvg9bw0zCMuLKfSdv+vG/
JZeXaQy6nsDqzV8/JX6+Y7kCgYEAv6FGzfGk6vIIioOIU/yba5Llns41HmJWaoVy
ZqwV/39WL3kaInFfAWEXlc3rIIepITnp+cRlKtv7flssUS+eYEmO0P4oKkXFBmNZ
TJyTycelCaBHN520OHLg+d4GlNT0oOjHr7vK1pMqhxwCWvTp2y/TgxklqQ/A4c+k
RyYA4q8CgYBdWxqQqKeesFtkQPe38rNkksZQXZPtw3ZiR9N1tAounG5rERLOyKDv
BtQh0pPTQFP83+dn4s8EaR/UE7GtLrmHMivPlwncVsx9M7n9ukSfstpCrCD9kQlb
ECOtUar9B6zLk03fyO7D5h/fjPB7dAuEd8YM2OCzR7q+P7WbQwU1SQKBgQC+/te7
XCWrpiCtLfwq+ZNO3NLQPWbkKc9HzEoB23LxfNFB78oEmkq+7S68uMipW41O+JIj
x4Ot/CPmBKlfIb8Q6T/XPfp6Z5/AhjTzDvyeGMZ9maph3GVL/fQOFyUoIjjQSDL/
DIVW6MdycpBGZ+TN+hUujVnj7zen2XU7FL29MQKBgFErX7A0hN9wMUXNnNzsGcnD
ogFwAJQrWZco6aO97e6SwEzeAWG2h+PWSCHbwsfrOhtRPaTCpSTFb+Vbf5UOHt3u
42X+atnAvhyZoVslYSRVxr8iWMxt7Q7w1p1gOooQ/4HvXKGVnzMEo2GW3DQzYjsR
eaPEeqOv+vuJ4LH+H39w
-----END PRIVATE KEY-----`

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
		return `${pemHeader} \n${pemBody} \n${pemFooter} `;
	},

	// Sign data using RSA-PSS private key
	async signData(privateKey, data) {
		const dataBuffer = this.stringToArrayBuffer(JSON.stringify(data));

		const signature = await window.crypto.subtle.sign(
			{
				name: 'RSA-PSS',
				saltLength: 32 //  if you use SHA-256 as the digest algorithm, this could be 32.
			},
			privateKey,
			dataBuffer
		);

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

		try {
			forge.pki.verifyCertificateChain(caStore, [cert]);
			console.log("✅ Server certificate is trusted (signed by root CA)");
			var cn = cert.subject.getField('CN').value;
			if (cn !== 'uminho.pt') {
				console.error("❌ Incorrect subject: ", cn);
			}
			console.log("✅ Correct subject ", cn);
		} catch (e) {
			console.error("❌ Certificate chain not trusted:", e.message);
		}
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
