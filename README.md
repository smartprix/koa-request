# Request

Handle basic tasks for koajs.

Example config:

```js
const Koa = require('koa');
const {Request} = require('@smpx/koa-request');

const app = new Koa();

const requestOptions = {
	// install request middleware for access to ctx.$req
	middleware: true,
	// base domain of the app
	baseDomain: 'smartprix.com',
	// limit the request from a single ip (10 requests in 1 minute)
	rateLimit: {
		interval: {min: 1},
		max: 10,
		// don't apply rate limit to these requests
		skip(ctx) {
			return false;
		},
	},
	// enable basic authentication
	basicAuth: {
		enabled: true,
		// skip basic authentication if request is proxied by nginx
		skipOnProxy: true,
		// skip basic authentication if request is from localhost
		skipOnLocalhost: true,
		// custom skip function (don't apply basicAuth if this function returns true)
		skip(ctx) {
			return false;
		},
		// basicAuth username
		name: 'admin',
		// basicAuth password
		pass: 'admin',
	},
	// serve static files from these paths
	staticPaths: [
		{
			path: '/',
			root: `${__dirname}/public`,
			// don't serve these paths directly
			skip(ctx) {
				return ctx.path.startWith('/robots.txt');
			}
		},
		{
			path: '/static',
			root: `${__dirname}/static`,
			allowOrigins: '*',
			immutable: true,
		},
		{
			path: '/files',
			root: `${__dirname}/files`,
			immutable: true,
			// custom path of the file
			async getPath(ctx) {
				return DB.fetch('paths', ctx.path);
			},
		},
	],
	// ban bots
	banBots: {
		// enable banning of common bots (does not include search bots)
		commonBots: true,
		// ban these user agents
		userAgents: [
			'80legs',
		],
		// ban these ips
		ips: [
			'27.210.',
		],
		// what email to show in ban messages
		email: 'a@b.com',
	}
};

// provides, ctx.user, ctx.$req, rateLimit, static paths and more
Request.install(app, requestOptions);
```
