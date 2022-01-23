const send = require('koa-send');

/**
 * @param {object} options
 * @returns {Routes.middleware}
 */
function getMiddleware(options) {
	if (!options.path) {
		throw new Error('path is required in static');
	}
	if (!options.root) {
		throw new Error('root is required in static');
	}

	return async (ctx, next) => {
		if (options.path === '/') {
			// root requires special handling to check if extension denotes a static path
			const matches = ctx.path.match(/^\/(.*)\.(jpg|jpeg|gif|png|webp|avif|jxl|ico|css|js|mjs|json|ttf|otf|eot|woff|woff2|svg|svgz|xml|html|txt|ogg|ogv|mp4|av1|webm|rss|atom|zip|tgz|gz|rar|bz2|doc|xls|exe|ppt|tar|mid|midi|wav|bmp|rtf)$/);
			if (!matches) {
				await next();
				return;
			}

			// skip the current path
			if (options.skip && options.skip(ctx)) {
				await next();
				return;
			}
		}

		// return if request path is not static
		if (!ctx.path.startsWith(options.path)) {
			await next();
			return;
		}

		// only GET or GET like methods are allowed
		if (!['get', 'head', 'options'].includes(ctx.method.toLowerCase())) {
			ctx.body = 'Method Not Allowed';
			ctx.status = 405;
			return;
		}

		if (options.immutable) {
			// return a 304 not modified response, as immutables can't be modified
			if (ctx.headers['if-modified-since']) {
				ctx.status = 304;
				return;
			}
		}

		let path;
		if (options.getPath) {
			path = await options.getPath(ctx);
			if (!path) ctx.throw(404);

			// path is absolute, remove root directory from it
			if (path.startsWith('/')) {
				if (!path.startsWith(options.root + '/')) {
					ctx.throw(404);
					return;
				}

				path = path.substring(options.root.length + 1);
			}
		}
		else {
			path = ctx.path.substr(options.path.length);
		}

		if (options.allowOrigins) {
			ctx.set('Access-Control-Allow-Origin', options.allowOrigins);
		}

		await send(ctx, path, {
			root: options.root,
			maxAge: options.maxAge,
			immutable: options.immutable,
		});
	};
}

module.exports = function enableStaticPaths(app, items = []) {
	if (!items || !items.length) return;

	for (const item of items) {
		const options = Object.assign({
			maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year (max-age in ms)
			immutable: false,
		}, item);

		app.use(getMiddleware(options));
	}
};
