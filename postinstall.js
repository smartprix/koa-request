const GeoIP = require('./GeoIP');

async function main() {
	await GeoIP.init();
}

main();
