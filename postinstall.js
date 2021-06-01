const GeoIP = require('./GeoIP');

async function main() {
	await GeoIP.init();
}

main().then(() => {
	process.exit();
}).catch((err) => {
	console.error('KoaRequest postinstall error', err);
	process.exit(1);
});
