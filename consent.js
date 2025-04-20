console.log("CMP content script loaded");

function getConsentPreferences() {
	const categories = document.querySelectorAll("fieldset[x-data]");
	const prefs = {};

	categories.forEach(fieldset => {
		const match = fieldset.getAttribute("x-data").match(/category:\s*'([^']+)'/);
		if (match) {
			const name = match[1];
			const toggle = fieldset.querySelector('input[type="checkbox"]');
			prefs[name] = toggle ? toggle.checked : true; // Default to true for essential
		}
	});

	return prefs;
}

function handleConsent(prefs) {
	console.log("User preferences:", prefs);

	if (prefs.marketing) {
		console.log("Running marketing code...");
	} else {
		console.log("Blocking marketing code...");
	}

	console.log("Essential logic always runs.");
}

document.body.addEventListener("click", (e) => {
	const btn = e.target.closest("[data-role]");

	if (!btn) return;

	const role = btn.getAttribute("data-role");

	if (role === "all") {
		console.log("Clicked Accept All");
		handleConsent({ essential: true, marketing: true });
	}

	if (role === "necessary") {
		console.log("Clicked Reject");
		handleConsent({ essential: true, marketing: false });
	}
});
