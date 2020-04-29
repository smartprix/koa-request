const {RateLimit} = require('koa2-ratelimit');

module.exports = function enableRateLimit(app, options = {}) {
	if (!options || options.enabled === false) return;

	const skip = options.skip;
	const interval = options.interval || {min: 1};
	const max = options.max || 50;

	app.use(
		RateLimit.middleware({
			interval,
			max,
			skip(ctx) {
				if (ctx.$req.isLocalhost()) return true;
				if (ctx.$req.isSearchIP()) return true;
				if (skip && skip(ctx)) return true;
				return false;
			},
			keyGenerator(ctx) {
				return ctx.$req.ip();
			},
		})
	);
};
