const maxmind = require('maxmind');
const https = require('https');
const zlib = require('zlib');
const path = require('path');
const tar = require('tar');
const fs = require('fs');

const fileName = 'GeoLite2-City';
const fileUrl = `https://raw.githubusercontent.com/GitSquared/node-geolite2-redist/master/redist/${fileName}.tar.gz`;
const fileDir = __dirname;
const filePath = `${fileDir}/${fileName}.mmdb`;
let geoInitPromise;
let geoip;

function save(url, outDir) {
	return new Promise((resolve, reject) => {
		https.get(url, (res) => {
			try {
				const untar = res.pipe(zlib.createGunzip({})).pipe(tar.t());
				untar.on('entry', (entry) => {
					if (entry.path.endsWith('.mmdb')) {
						const dstFilename = path.join(outDir, path.basename(entry.path) + '-tmp');
						try {
							entry.pipe(fs.createWriteStream(dstFilename));
						}
						catch (e) {
							reject(e);
						}
					}
				});
				untar.on('error', e => reject(e));
				untar.on('finish', () => {
					fs.rename(filePath + '-tmp', filePath, (err) => {
						if (err) {
							reject(err);
						}
						else {
							resolve();
						}
					});
				});
			}
			catch (error) {
				throw new Error(`Could not fetch ${url}\n\nError:\n${error}`);
			}
		});
	});
}

function mtime(file) {
	return new Promise((resolve) => {
		try {
			fs.stat(file, (err, stats) => {
				if (err) {
					resolve(false);
				}
				else {
					resolve(stats.mtimeMs || stats.ctimeMs);
				}
			});
		}
		catch (e) {
			resolve(false);
		}
	});
}

async function download() {
	const modifyTime = await mtime(filePath);
	if (!modifyTime) {
		console.log(`[Request::GeoIP] Downloading ${fileName} ...`);
		await save(fileUrl, fileDir);
		console.log(`[Request::GeoIP] Downloaded ${fileName} !`);
	}
}

async function updateDb() {
	const modifyTime = await mtime(filePath);
	if (modifyTime < Date.now() - 2 * 24 * 3600 * 1000) {
		console.log(`[Request::GeoIP] Downloading ${fileName} ...`);
		await save(fileUrl, fileDir);
		console.log(`[Request::GeoIP] Downloaded ${fileName} !`);
		geoip = await maxmind.open(filePath);
	}
	setTimeout(updateDb, 3 * 24 * 3600 * 1000);
}

async function geoIpInit() {
	await download();
	geoip = await maxmind.open(filePath);
	if (process.env.NODE_ENV === 'production') {
		updateDb();
	}
}

async function getGeoIp() {
	if (!geoip) {
		if (!geoInitPromise) {
			geoInitPromise = geoIpInit();
		}
		await geoInitPromise;
		geoInitPromise = null;
	}
	return geoip;
}

function getGeoIpSync() {
	if (!geoip) {
		const buffer = fs.readFileSync(filePath);
		geoip = new maxmind.Reader(buffer);
		if (process.env.NODE_ENV === 'production') {
			updateDb();
		}
	}
	return geoip;
}

class GeoIP {
	static async get(ip) {
		return (await getGeoIp()).get(ip);
	}

	static getSync(ip) {
		return getGeoIpSync().get(ip);
	}

	static async init() {
		return getGeoIp();
	}
}

module.exports = GeoIP;

async function main() {
	function random(min, max) {
		return Math.random() * (max - min) + min;
	}

	const ips = [];
	for (let i = 0; i < 100000; i++) {
		ips.push(`${random(1, 255)}.${random(1, 255)}.${random(1, 255)}.${random(1, 255)}`);
	}

	console.log((await GeoIP.get('1.2.3.4')).subdivisions);

	console.time('ipLookup');
	for (let i = 0; i < 100000; i++) {
		// eslint-disable-next-line no-await-in-loop
		await GeoIP.get(ips[i]);
	}
	console.timeEnd('ipLookup');
	// takes approx ~ 900ms for 100,000 lookups
}

if (require.main === module) {
	main();
}
