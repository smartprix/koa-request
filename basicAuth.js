const auth = require('koa-basic-auth');

module.exports = function enableBasicAuth(app, options = {}) {
	if (!options || options.enabled === false) return;

	app.use(async (ctx, next) => {
		try {
			await next();
		}
		catch (err) {
			if (err.status === 401) {
				ctx.status = 401;
				ctx.set('WWW-Authenticate', 'Basic');
				ctx.body = 'Not Authorized';
			}
			else {
				throw err;
			}
		}
	});

	// require auth
	app.use((ctx, next) => {
		// no need for authentication in case of localhost/proxied using nginx
		if (options.skipOnProxy && ctx.$req.isProxied()) return next();
		if (options.skipOnLocalhost && ctx.$req.isLocalhost()) return next();
		if (options.skip && options.skip(ctx)) return next();
		return auth(options)(ctx, next);
	});
};
