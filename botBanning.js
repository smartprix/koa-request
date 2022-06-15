const IPRange = require('./IPRange');
const {escapeRegex} = require('./utils');

const bannedUserAgents = [
	' HTTrack ',
	'Wget/',
	'http://www.80legs.com/webcrawler.html',
	'SISTRIX Crawler',
	'http://www.diffbot.com',
	'http://www.seokicks.de/robot.html',
	'scrapy.org',
	'libwww-perl',
	'Xenu Link Sleuth',
	'http://www.msai.in',
	'TencentTraveler', // Might be real browser or a real search engine
	'EtaoSpider',
	'Python-urllib/',
	'YisouSpider',
	'Screaming Frog SEO Spider',
];

function banned(ctx, email) {
	const ip = ctx.$req.ip();
	const emailStr = email ? `If you think this is by mistake, send us an email at ${email}` : '';
	ctx.status = 403;
	ctx.body = `<pre>Our system has detected unusual traffic from your ip ${ip}. Hence your ip has been banned temporarily.\n${emailStr}</pre>`;
}

module.exports = function enableBotBanning(app, options) {
	if (!options || options.enabled === false) return;

	let userAgents = [];
	let bannedUaRegex;
	if (options.commonBots) {
		userAgents = bannedUserAgents;
	}
	if (options.userAgents) {
		userAgents = userAgents.concat(options.userAgents);
	}
	if (userAgents.length) {
		bannedUaRegex = new RegExp(bannedUserAgents.map(escapeRegex).join('|'));
	}

	let bannedIpRange;
	if (options.ips) {
		bannedIpRange = new IPRange(options.ips);
	}

	if (!bannedUaRegex && !bannedIpRange) return;

	const email = options.email;

	app.use(async (ctx, next) => {
		if (bannedUaRegex) {
			const userAgent = ctx.headers['user-agent'] || '';
			if (bannedUaRegex.test(userAgent)) return banned(ctx, email);
		}

		if (bannedIpRange) {
			const ip = ctx.$req.ip();
			if (bannedIpRange.has(ip)) return banned(ctx, email);
		}

		return next();
	});
};
