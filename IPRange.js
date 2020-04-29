const ipLib = require('ip');

const PRIVATE_IPS = [
	'0.0.0.0/8',
	'240.0.0.0/4',
	'10.0.0.0/8',
	'127.0.0.0/8',
	'169.254.0.0/16',
	'172.16.0.0/12',
	'192.168.0.0/16',
];

// Source: https://www.lifewire.com/what-is-the-ip-address-of-google-818153
const GOOGLE_IPS = [
	'64.233.160.0 - 64.233.191.255',
	'66.102.0.0 - 66.102.15.255',
	'66.249.64.0 - 66.249.95.255',
	'72.14.192.0 - 72.14.255.255',
	'74.125.0.0 - 74.125.255.255',
	'209.85.128.0 - 209.85.255.255',
	'216.239.32.0 - 216.239.63.255',
	//
	'64.68.90.1 - 64.68.90.255',
	'64.233.173.193 - 64.233.173.255',
	'66.249.64.1 - 66.249.79.255',
	'216.239.33.96 - 216.239.59.128',
];

const SEARCH_IPS = [
	'178.154.128.0/17', // YANDAX
	'87.250.224.0/19',	// YANDAX
	'157.55.0.0/16',	// Microsoft
	'207.46.0.0/19',	// Microsoft
	'17.0.0.0/8',		// Apple
];

let compiledPrivateIps;
let compiledGoogleIps;
let compiledSearchIps;
let publicIp;
let privateIp;

function ipRangeCheckRegex(cidrs) {
	const cidrJoin = cidrs.map((cidr) => {
		if (!cidr.endsWith('.')) cidr += '.';
		return cidr.replace(/\./g, '\\.');
	}).join('|');

	return new RegExp(`^(?:${cidrJoin})`);
}

function compile(cidrs) {
	if (!Array.isArray(cidrs)) {
		cidrs = [cidrs];
	}

	const ranges = [];
	const startsWith = [];
	let rangeRegex = null;

	for (const cidr of cidrs) {
		// match cidr
		if (cidr.includes('/')) {
			// Split the range by the slash
			const parts = cidr.split('/');

			// Work out how many IPs the /slash-part matches.
			// We run 2^(32-slash)
			const numIps = 2 ** (32 - Number(parts[1]));

			const ipStart = ipLib.toLong(parts[0]);
			const ipEnd = (ipStart + numIps) - 1;
			ranges.push([ipStart, ipEnd]);
		}

		// match range
		if (cidr.includes('-')) {
			const parts = cidr.split('-');
			const ipStart = ipLib.toLong(parts[0].trim());
			const ipEnd = ipLib.toLong(parts[1].trim());
			ranges.push([ipStart, ipEnd]);
		}

		// match a single ip or ips like (123.156)
		startsWith.push(cidr);
	}

	// if we only need to check for simple ranges, do it with regex
	if (startsWith.length) {
		rangeRegex = ipRangeCheckRegex(startsWith);
	}

	return [ranges, rangeRegex];
}

function contains(ip, ranges, rangeRegex) {
	if (ranges.length) {
		const ipLong = ipLib.toLong(ip);
		for (const range of ranges) {
			if (ipLong >= range[0] && ipLong <= range[1]) return true;
		}
	}

	if (rangeRegex) {
		return rangeRegex.test(ip + '.');
	}

	return false;
}

class IPRange {
	constructor(cidrs) {
		const [range, rangeRegex] = compile(cidrs || []);
		this.range = range;
		this.rangeRegex = rangeRegex;
	}

	has(ip) {
		return contains(ip, this.range, this.rangeRegex);
	}

	static has(ip, cidrs) {
		if (!cidrs || !cidrs.length) return false;
		const [ranges, rangeRegex] = compile(cidrs);
		return contains(ip, ranges, rangeRegex);
	}

	static isPrivateIp(ip) {
		if (!compiledPrivateIps) {
			compiledPrivateIps = new IPRange(PRIVATE_IPS);
		}
		return compiledPrivateIps.has(ip);
	}

	static isGoogleIp(ip) {
		if (!compiledGoogleIps) {
			compiledGoogleIps = new IPRange(GOOGLE_IPS);
		}
		return compiledGoogleIps.has(ip);
	}

	static isSearchIp(ip) {
		if (!compiledSearchIps) {
			compiledSearchIps = new IPRange(SEARCH_IPS);
		}
		return this.isGoogleIp() || compiledSearchIps.has(ip);
	}

	static isLocalhost(ip) {
		if (!publicIp) {
			publicIp = ipLib.address('public') || '0.0.0.0';
		}
		if (!privateIp) {
			privateIp = ipLib.address('private') || '127.0.0.1';
		}

		return ['127.0.0.1', publicIp, privateIp].includes(ip);
	}
}

module.exports = IPRange;
