/* eslint-disable class-methods-use-this, max-lines */
const {UAParser} = require('ua-parser-js');
const bodyParser = require('koa-body');

const IPRange = require('./IPRange');
const GeoIP = require('./GeoIP');

const enableRateLimit = require('./rateLimit');
const enableBasicAuth = require('./basicAuth');
const enableStaticPaths = require('./staticPaths');
const enableBotBanning = require('./botBanning');

const uaParser = new UAParser();

const ONE_HOUR = 3600 * 1000;
const ONE_DAY = 24 * ONE_HOUR;
const ONE_MONTH = 30 * ONE_DAY;
const ONE_YEAR = 365 * ONE_DAY;
const TEN_YEARS = 10 * ONE_YEAR;

const PLATFORM_PARAM = 'platform';
const PLATFORM_COOKIE = 'platform';
const PLATFORM_COOKIE_DURATION = 4 * ONE_HOUR;
const APPINFO_PARAM = 'sm_app';
const APPINFO_COOKIE = 'sm_app';
const APPINFO_HEADER = 'sm-app';
const TRACKING_HEADER = 'sm-tracking';
const UTM_COOKIE = 'sm_utm';
const AFFID_PARAM = 'affid';
const SUBAFFID_PARAM = 'subaffid';
const COUNTRY_COOKIE = 'country';
const AFFID_COOKIE = 'sm_aff';
const AFFID_COOKIE_DURATION = ONE_DAY;
const REF_PARAM = 'ref';
const SESSIONID_COOKIE = 'sid';
const COOKIEID_COOKIE = 'id';
const COOKIE_PARAM_PREFIX = '_ck_';
const USER_TOKEN_COOKIE = 'utok';
const FLASH_COOKIE = 'flash';
// these cookies are httpOnly, should not be readable from js
const SENSITIVE_COOKIES = [USER_TOKEN_COOKIE, COOKIEID_COOKIE, SESSIONID_COOKIE];

const APP_PLATFORMS = new Map([
	['android', {}],
	['ios', {}],
	['wp', {}],
	['tizen', {}],
	['jio', {}],
]);

// sometimes request parameters can be an array (like &q=s&q=b)
// since we expect a string, this will convert array to a string
function handleArray(value, defaultValue = '') {
	if (Array.isArray(value)) {
		return value[value.length - 1] || value[0] || defaultValue;
	}
	return value || defaultValue;
}

function sanitizeCookiePart(value, defaultValue = '') {
	if (!value) return defaultValue;
	return handleArray(value).replace(/\|/g, '!~!').substring(0, 255);
}

function joinCookieParts(parts, defaultValue = '') {
	return parts.map(part => sanitizeCookiePart(part, defaultValue)).join('|');
}

function splitCookieParts(cookie) {
	return cookie.split('|').map(part => part.replace(/!~!/g, '|'));
}

/**
 * return [subDomain, baseDomain, canHaveSubdomain]
 */
function getDomainParts(domain) {
	const parts = domain.split('.');
	if (parts.length <= 1) {
		// domain is localhost
		return ['', domain, false];
	}
	if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(domain)) {
		// domain is an ip
		return ['', domain, false];
	}

	if (parts.length <= 2) {
		// a simple domain like example.com
		return ['', domain, true];
	}

	const secondTld = parts[parts.length - 2];
	if (/co|nic|gov/i.test(secondTld)) {
		// a domain with second level tld, like example.co.uk
		if (parts.length <= 3) {
			return ['', domain, true];
		}
	}

	return [parts[0], parts.slice(1).join('.'), true];
}

function randomId(length) {
	let id = '';
	while (id.length < length) {
		id += Math.random().toString(36).substring(2);
	}
	return id.substring(0, length);
}

function getIntegerKey(key) {
	if (typeof key === 'number') return key;
	if (typeof key === 'string') {
		let value = 0;
		for (let i = 0; i < key.length; ++i) {
			value = ((value << 5) - value) + key.charCodeAt(i); // value * 31 + c
			value |= 0; // to 32bit integer
		}
		return value;
	}
	return key;
}

function addQuery(url, query = {}) {
	const uri = new URL(url, 'http://localhost');
	if (typeof query === 'string') {
		query = new URLSearchParams(query);
		for (const [key, val] of query) {
			uri.searchParams.set(key, val);
		}
	}
	else {
		for (const [key, val] of Object.entries(query)) {
			uri.searchParams.set(key, val);
		}
	}
	return `${uri.pathname}${uri.search}`;
}

const isProduction = (process.env.NODE_ENV === 'production');

class Request {
	/**
	 * @param {import('koa').Context} ctx
	 */
	constructor(ctx, options = {}) {
		this.ctx = ctx;
		this.options = options;
	}


	/** @type {Routes.installer} */
	static install(app, options = {}) {
		enableStaticPaths(app, options.staticPaths);
		app.use(bodyParser({
			multipart: true,
		}));
		if (options.middleware) {
			app.use(this.middleware(options));
		}
		enableBasicAuth(app, options.basicAuth);
		enableBotBanning(app, options.banBots);
		enableRateLimit(app, options.rateLimit);
	}

	/** @returns {Routes.middleware} */
	static middleware(options) {
		return async (ctx, next) => {
			ctx.$req = await this.from(ctx, options);
			await next();
		};
	}

	/**
	 * @param {import('koa').Context} ctx
	 */
	static async from(ctx, options) {
		const req = new this(ctx, options);
		await req.init();
		return req;
	}

	appPlatforms() {
		return APP_PLATFORMS;
	}

	/**
	 * get or set request header value
	 * @param {string} name name of the header
	 * @param {string} value value to set, if not given header value is return
	 * @returns {string}
	 *  get: header value, or empty string if header not found
	 *  set: empty string
	 * @example
	 * // get header value
	 * ctx.$req.header('user-agent')
	 * // set header value
	 * ctx.$req.header('ETag', '1234')
	 */
	header(name, value) {
		// get header value
		if (value === undefined) {
			return this.ctx.headers[name.toLowerCase()] || '';
		}

		// set header value
		this.ctx.set(name, value);
		return '';
	}

	/**
	 * Get value from either from request body or query params
	 * @param {string} key
	 * @param {string} defaultValue
	 * @return {any}
	 */
	param(key, defaultValue = '') {
		const ctx = this.ctx;
		let paramValue;

		if (ctx.request.body &&
			ctx.request.body.fields &&
			(key in ctx.request.body.fields)
		) {
			paramValue = ctx.request.body.fields[key];
		}
		if (ctx.request.body &&
			(key in ctx.request.body)
		) {
			paramValue = ctx.request.body[key];
		}
		else {
			paramValue = ctx.query[key];
		}

		paramValue = paramValue || defaultValue;

		if (typeof paramValue === 'string') return paramValue.trim();
		if (Array.isArray(paramValue)) return paramValue.map(v => v.trim());
		return paramValue;
	}

	/**
	 * Get parameter as a string (from query or body)
	 * @param {string} key
	 * @param {number} defaultValue
	 * @returns {number}
	 */
	paramStr(key, defaultValue = '') {
		const value = this.param(key, null);
		if (value === null) return defaultValue;
		return String(value);
	}

	/**
	 * Get parameter as an integer (from query or body)
	 * @param {string} key
	 * @param {number} defaultValue
	 * @returns {number}
	 */
	paramInt(key, defaultValue = 0) {
		const value = this.param(key, null);
		if (value === null) return defaultValue;

		const intVal = Number(value);
		if (Number.isNaN(intVal)) {
			return defaultValue;
		}

		return intVal;
	}

	/**
	 * Get parameter as a boolean
	 * Only '0', 'false', 'no', 'off' are considered falsy
	 * empty string is truthy, so url?param would be truthy
	 * but url?param=0 or url?param=false would be falsy
	 * @param {string} key
	 * @param {boolean} defaultValue
	 * @returns {boolean}
	 */
	paramBool(key, defaultValue = false) {
		const value = this.param(key, null);
		if (value === null) return defaultValue;

		if (
			value === false ||
			value === 0 ||
			value === '0' ||
			value === 'false' ||
			value === 'no' ||
			value === 'off'
		) return false;

		return true;
	}

	/**
	 * Get the parameter as an id.
	 * id  any is a max 20 character long alphanumeric string
	 * @param {string} key
	 * @param {string} defaultValue
	 * @returns {string}
	 */
	paramId(key, defaultValue = '') {
		const value = this.param(key, null);
		if (value === null) return defaultValue;
		if (/^[A-Za-z0-9]{1,20}$/.test(value)) return value;
		return defaultValue;
	}

	/**
	 * get a string parameter and escape it for xss attacks
	 * @param {string} key
	 * @param {string} defaultValue
	 * @returns {string} value of the param
	 */
	paramXSS(key, defaultValue = '') {
		const param = this.param(key, null);
		if (param === null) return defaultValue;

		return param.replace(/([<>"'])/g, (match, g1) => {
			switch (g1) {
				case '<': return '&lt;';
				case '>': return '&gt;';
				case '"': return '&quot;';
				case '\'': return '&#39;';
				default: return g1;
			}
		});
	}

	/**
	 * Get the file with this param name
	 * @param {string} key
	 * @returns
	 */
	file(key) {
		return this.files(key)[0] || null;
	}

	/**
	 * Get all the files with this param name
	 * @param {string} key
	 * @returns {array}
	 */
	files(key) {
		if (this.ctx.request.files && this.ctx.request.files[key]) {
			const result = this.ctx.request.files[key];
			if (!Array.isArray(result)) return [result];
			return result.filter(Boolean);
		}

		return [];
	}

	/**
	 * Get the bearer token of the request.
	 * Authorization: Bearer abc would give abc as bearer token
	 * @returns {string}
	 */
	bearerToken() {
		const authorization = this.ctx.headers.authorization;
		if (!authorization) return '';

		const parts = authorization.split(' ');
		if (parts.length !== 2) return '';
		if (parts[0] !== 'Bearer') return '';

		return parts[1];
	}

	/**
	 * Get the api token of the request.
	 * API token can be sent as a header x-api-token
	 * @returns {string}
	 */
	apiToken() {
		return this.header('x-api-token');
	}

	/**
	 * initialize a request
	 * set important cookies and all
	 */
	async init() {
		// don't allow other domains to embed our iframe
		if (isProduction) {
			const domain = this.baseDomain();
			this.ctx.set('Content-Security-Policy', `frame-ancestors https://*.${domain}`);
		}

		if (!this.isAjax()) {
			this.handlePlatformModification();
			this.setUTMCookie();
			this.setAffidCookie();
			this.handleFlashMessage();

			// in case of visit out from app we need to set cookies from params
			if (this.ctx.query.installId) {
				await this.setCookiesFromParams();
			}
		}
	}

	/**
	 * check whether the request is http or https
	 * isHttp returns false if the request is https, true otherwise
	 * @returns {boolean}
	 */
	isHttp() {
		if (this._isHttp === undefined) {
			const ctx = this.ctx;
			this._isHttp = (ctx.headers.origin || '').startsWith('http:') || (ctx.headers.host || '').includes(':');
			if (!this._isHttp && this.ctx.protocol !== 'https') {
				this.ctx.cookies.secure = true;
			}
		}
		return this._isHttp;
	}

	/**
	 * @typedef {Object} CustomCookieOpts
	 * @property {boolean} [onlyCache]
	 * @property {boolean} [onlyCacheIfExists]
	 * @property {number} [days]
	 * @property {number} [years]
	 */

	/**
	 * Get or set a cookie
	 * @template {string | number | boolean | undefined} V
	 * @param {string} name
	 * @param {V} value
	 * @param {CustomCookieOpts & import('cookies').SetOption} [options]
	 * @returns {V extends undefined ? string : null}
	 */
	cookie(name, value, options = {}) {
		const cookies = this._cookies || (this._cookies = {});

		if (value === undefined) {
			if (name in cookies) {
				return cookies[name];
			}

			const existing = this.ctx.cookies.get(name) || '';
			return decodeURIComponent(existing);
		}

		cookies[name] = value;

		// only set the cookie in cache
		// don't set it in real
		if (options.onlyCache) {
			return null;
		}

		// set the cookie only if does not exist
		// but always set it in cache
		if (options.onlyCacheIfExists) {
			if (this.ctx.cookies.get(name)) return null;
		}

		// clone options
		options = Object.assign({}, options);

		if (options.domain === '*') {
			options.domain = this.baseDomain();
		}
		if (!('path' in options)) {
			options.path = '/';
		}
		if ('days' in options) {
			options.maxAge = options.days * ONE_DAY;
		}
		if ('years' in options) {
			options.maxAge = options.years * ONE_YEAR;
		}

		if (!('httpOnly' in options)) {
			if (!SENSITIVE_COOKIES.includes(name)) {
				options.httpOnly = false;
			}
		}

		const isHttp = this.isHttp();
		if (!('secure' in options) && !isHttp) {
			options.secure = true;
		}

		if (!('sameSite' in options)) {
			// sameSite = none means intentionally send the cookie in 3rd party contexts
			options.sameSite = isHttp ? false : 'none';
		}

		if (value) {
			value = encodeURIComponent(value);
		}

		this.ctx.cookies.set(name, value, options);
		return null;
	}

	/**
	 * Used for sending tracking info from other servers/sites
	 * @template {string | undefined} T
	 * @param {T} key
	 * @returns {T extends string ? string : Object.<string, string>}
	 */
	trackingHeader(key) {
		if (!this._trackingHeader) {
			const header = this.header(TRACKING_HEADER);
			if (!header) {
				this._trackingHeader = {};
			}
			else {
				try {
					this._trackingHeader = JSON.parse(header) || {};
				}
				catch (e) {
					this._trackingHeader = {};
				}
			}
		}

		return key ? this._trackingHeader[key] : this._trackingHeader;
	}

	/**
	 * Get the user agent of the request.
	 * @returns {string}
	 */
	userAgent() {
		return this.trackingHeader('user-agent') || this.header('user-agent');
	}

	/**
	 * Get the referer of the request.
	 * @returns {string}
	 */
	referer() {
		return this.trackingHeader('referer') || this.header('referer');
	}

	/**
	 * Get the referer name of the request.
	 * @returns {string}
	 */
	refererName() {
		return this._refererName;
	}

	/**
	 * Parse the user agent with ua-parser-js and return the result
	 * Returns {ua: '', browser: {}, cpu: {}, device: {}, engine: {}, os: {} }
	 * @returns {object}
	 */
	parseUserAgent() {
		if (!this._ua) {
			this._ua = uaParser.setUA(this.userAgent()).getResult() || {};
		}
		return this._ua;
	}

	/**
	 * Get the browser name
	 * @returns {string}
	 */
	browser() {
		const ua = this.parseUserAgent();
		const deviceType = (ua && ua.device && ua.device.type) || '';
		const browserName = (ua && ua.browser && ua.browser.name) || '';

		if (deviceType === 'mobile') {
			switch (browserName) {
				case 'Chrome': return 'Chrome Mobile';
				case 'Firefox': return 'Firefox Mobile';
				case 'Safari': return 'Safari Mobile';
				case 'Mobile Safari': return 'Safari Mobile';
				default: return browserName;
			}
		}

		return browserName;
	}

	/**
	 * Get the browser name + version (eg. Chrome 96.1.0.110)
	 * @returns {string}
	 */
	browserVersion() {
		const ua = this.parseUserAgent();
		let browerVersion = (ua.browser && ua.browser.version) || '';
		if (browerVersion) browerVersion = ' ' + browerVersion;
		return this.browser() + browerVersion;
	}

	/**
	 * Get the browser version only (eg. 96.1.0.110)
	 * @returns {string}
	 */
	browserVersionRaw() {
		const ua = this.parseUserAgent();
		const version = (ua.browser && ua.browser.version) || '';
		return String(version);
	}

	/**
	 * Get the os name (eg. Windows)
	 * @returns {string}
	 */
	os() {
		const ua = this.parseUserAgent();
		return (ua.os && ua.os.name) || '';
	}

	/**
	 * Get the os name + version (eg. Windows 11)
	 * @returns {string}
	 */
	osVersion() {
		const ua = this.parseUserAgent();
		let osVersion = (ua.os && ua.os.version) || '';
		if (osVersion) osVersion = ' ' + osVersion;
		return this.os() + osVersion;
	}

	/**
	 * Get the header sm-user-agent
	 * @returns {string}
	 */
	smUserAgent() {
		return this.header('sm-user-agent');
	}

	appUserAgent() {
		return this.smUserAgent() || this.userAgent();
	}

	getAppInfoFromUserAgent() {
		return null;
	}

	_getAppInfoFromString(infoStr, separator = '#') {
		if (!infoStr) return null;
		// eslint-disable-next-line prefer-const
		let [platform, appVersion, installId] = infoStr.split(separator);
		platform = platform.toLowerCase();

		const appInfo = {
			platform,
			appVersion,
			installId,
		};

		if (this.appPlatforms().has(platform)) {
			appInfo.isMobileApp = true;
		}

		return appInfo;
	}

	getAppInfoFromParam() {
		const appInfoParam = this.ctx.query[APPINFO_PARAM];
		if (appInfoParam) {
			this.cookie(APPINFO_COOKIE, appInfoParam, {
				path: '/',
				maxAge: TEN_YEARS,
				domain: '*',
			});

			return this._getAppInfoFromString(appInfoParam, ':');
		}

		const appInfoCookie = this.cookie(APPINFO_COOKIE);
		if (appInfoCookie) {
			return this._getAppInfoFromString(appInfoParam, ':');
		}

		return null;
	}

	getAppInfoFromHeader() {
		return this._getAppInfoFromString(this.ctx.headers[APPINFO_HEADER]);
	}

	getAppInfo() {
		const appInfoHeader = this.getAppInfoFromHeader();
		if (appInfoHeader) return appInfoHeader;

		const appInfoParam = this.getAppInfoFromParam();
		if (appInfoParam) return appInfoParam;

		const appInfoUserAgent = this.getAppInfoFromUserAgent();
		if (appInfoUserAgent) return appInfoUserAgent;

		return {};
	}

	/*
	 * get the app related info using a header / query parameter / user agent
	 * this means that you can have the url as sm_app=android
	 * and it'll automatically identify it as an android app
	 */
	appInfo(param = null) {
		if (!this._appInfo) {
			this._appInfo = this.getAppInfo() || {};
		}
		return param ? this._appInfo[param] : this._appInfo;
	}

	installId() {
		return this.appInfo('installId') || this.ctx.query.installId || '';
	}

	appVersion() {
		return this.appInfo('appVersion') || this.ctx.query.appVersion || '';
	}

	isAndroidApp() {
		return this.appInfo('platform') === 'android';
	}

	isIOSApp() {
		return this.appInfo('platform') === 'ios';
	}

	isWPApp() {
		return this.appInfo('platform') === 'wp';
	}

	isTizenApp() {
		return this.appInfo('platform') === 'tizen';
	}

	isJIOApp() {
		return this.appInfo('platform') === 'jio';
	}

	isMobileApp() {
		// for setPlatform cases
		const platform = this._platform;
		if (platform) {
			if (platform === 'mobile_app') return true;
			return false;
		}

		return !!this.appInfo('isMobileApp');
	}

	isMobileWeb() {
		// for setPlatform cases
		const platform = this._platform;
		if (platform) {
			if (platform === 'mobile_web') return true;
			return false;
		}

		if (!this._isMobileWeb) {
			const ua = this.parseUserAgent();
			this._isMobileWeb = (ua && ua.device && ua.device.type === 'mobile') || false;
		}
		return this._isMobileWeb;
	}

	isMobile() {
		return this.isMobileApp() || this.isMobileWeb();
	}

	isAPI() {
		return false;
	}

	platform() {
		if (!this._platform) {
			if (this.isMobileApp()) {
				this._platform = 'mobile_app';
			}
			else if (this.isMobileWeb()) {
				this._platform = 'mobile_web';
			}
			else if (this.isAPI()) {
				this._platform = 'api';
			}
			else {
				this._platform = 'desktop';
			}
		}

		return this._platform;
	}

	setPlatform(platform) {
		if (!platform) return false;
		platform = handleArray(platform);
		const appPlatform = platform.replace('_app', '');

		if (this.appPlatforms().has(appPlatform)) {
			this._platform = 'mobile_app';
			this._subPlatform = `${appPlatform}_app`;
			return false;
		}

		switch (platform) {
			case 'mobile':
			case 'mobile_web':
				this._platform = 'mobile_web';
				return true;
			case 'www':
			case 'desktop':
				this._platform = 'desktop';
				return true;
			case 'mobile_app':
				this._platform = 'mobile_app';
				return true;
			default:
				return false;
		}
	}

	subPlatform() {
		if (!this._subPlatform) {
			const appPlatform = this.appInfo('platform');
			if (appPlatform && this.isMobileApp()) {
				this._subPlatform = `${appPlatform}_app`;
			}
			else {
				this._subPlatform = this.platform();
			}
		}
		return this._subPlatform;
	}

	isDesktop() {
		// for setPlatform cases
		const platform = this._platform;
		if (platform) {
			if (platform === 'desktop') return true;
			return false;
		}

		return this.platform() === 'desktop';
	}

	/**
	 * @typedef {Object} UTMObject
	 * @property {string} source
	 * @property {string} medium
	 * @property {string} campaign
	 * @property {string} term
	 * @property {string} content
	 * @property {string} sourceMedium
	 */

	/**
	 * @template {string | null} P
	 * @param {P} [param]
	 * @returns {P extends null ? UTMObject : P extends string ? string : UTMObject}
	 */
	utm(param = null) {
		if (!this._utm) {
			const utmCookie = this.cookie(UTM_COOKIE);
			if (!utmCookie) {
				this._utm = {};
			}
			else {
				const [source, medium, campaign, term, content] = splitCookieParts(utmCookie);
				this._utm = {
					source,
					medium,
					campaign,
					term,
					content,
					sourceMedium: `${source}/${medium}`,
				};
			}
		}

		return param ? this._utm[param] : this._utm;
	}

	/**
	 * @returns {string}
	 */
	ref() {
		return this.param(REF_PARAM).replace(/[^a-zA-Z0-9_.:~-]+/g, '-');
	}

	_affidSubaffid() {
		const affidCookie = this.cookie(AFFID_COOKIE);
		if (!affidCookie) return ['', ''];

		const [affid, subaffid] = affidCookie.split('|');
		return [affid || '', subaffid || ''];
	}

	affid() {
		return this._affidSubaffid()[0];
	}

	subaffid() {
		return this._affidSubaffid()[1];
	}

	subAffid() {
		return this.subaffid();
	}

	cookieId() {
		let cookieId = this.cookie(COOKIEID_COOKIE);
		if (!cookieId) {
			const version = '1';
			cookieId = version + randomId(15);
			this.cookie(COOKIEID_COOKIE, cookieId, {
				maxAge: TEN_YEARS,
				domain: '*',
			});
		}

		return cookieId;
	}

	// cookie id that's existing (not set in this request)
	existingCookieId() {
		return this.ctx.cookies.get(COOKIEID_COOKIE);
	}

	sessionId() {
		let sessionId = this.cookie(SESSIONID_COOKIE);
		if (!sessionId) {
			const version = '1';
			sessionId = version + randomId(15);
			this.cookie(SESSIONID_COOKIE, sessionId, {
				domain: '*',
			});
		}

		return sessionId;
	}

	// session id that's existing (not set in this request)
	existingSessionId() {
		return this.ctx.cookies.get(SESSIONID_COOKIE);
	}

	isOriginRequest() {
		if (!isProduction) return true;

		const baseDomain = this.options.baseDomain;
		if (!baseDomain) return true;

		const origin = this.ctx.headers.origin;

		// this is needed because firefox currently does not
		// send origin with form submit requests (sends with xhr)
		// so this might cause csrf on firefox
		if (!origin) return true;

		const matches = origin.match(/^((http|https):\/\/)?([^/:]+)[/]?/i);
		if (!matches) return false;
		if (('.' + matches[3]).endsWith('.' + baseDomain)) return true;
		return false;
	}

	/**
	 * Get the ip of the request
	 * @returns {string}
	 */
	ip() {
		if (!this._ip) {
			if (this.trackingHeader('ip')) {
				this._ip = this.trackingHeader('ip');
			}
			// nginx proxy sets x-real-ip header as real ip address
			else if (this.ctx.headers['x-real-ip']) {
				this._ip = this.ctx.headers['x-real-ip'];
			}
			else {
				// ip is of format ::ffff:127.1.0.1, strip ::ffff: from it
				this._ip = this.ctx.ip.replace(/^.*:/, '');
			}
		}

		return this._ip;
	}

	/**
	 * Get the real ip of the request (after considering x-forwarded-for)
	 * @returns {string}
	 */
	realIP() {
		if (this._realIP) return this._realIP;

		const forwardedFor = this.header('x-forwarded-for');
		if (!forwardedFor) {
			this._realIP = this.ip();
			return this._realIP;
		}

		const forwardedList = forwardedFor.split(',');
		for (let ipAddress of forwardedList) {
			ipAddress = ipAddress.trim();

			// validate ipv4
			const ipv4Regex = /(::ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
			const matches = ipAddress.match(ipv4Regex);
			if (!matches) continue;
			ipAddress = matches[2];

			// validate not private
			if (IPRange.isPrivateIp(ipAddress)) continue;
			this._realIP = ipAddress;
			return this._realIP;
		}

		this._realIP = this.ip();
		return this._realIP;
	}

	/**
	 * Is the request being proxied through local proxy
	 * @returns {boolean}
	 */
	isProxied() {
		return this.header('x-real-ip') && this.ctx.ip.endsWith('127.0.0.1');
	}

	/**
	 * Is the request being proxied through an external proxy (like chrome data-saver)
	 * @returns {boolean}
	 */
	isVia() {
		return this.header('via') && this.realIP() === this.ip();
	}

	parseUrl() {
		if (!this._uri) {
			this._uri = new URL(this.ctx.href);
		}
		return this._uri;
	}

	baseDomain() {
		if (!this._domainParts) {
			this._domainParts = getDomainParts(this.domain());
		}
		return this._domainParts[1];
	}

	domain() {
		return this.ctx.hostname;
	}

	subDomain() {
		if (!this._domainParts) {
			this._domainParts = getDomainParts(this.domain());
		}
		return this._domainParts[0];
	}

	port() {
		const port = this.ctx.host.split(':')[1];
		return port ? Number(port) : 80;
	}

	isLocalhost() {
		return IPRange.isLocalhost(this.ip());
	}

	isGoogleIP() {
		return IPRange.isGoogleIp(this.ip());
	}

	isSearchIP() {
		return IPRange.isSearchIp(this.ip());
	}

	isGet() {
		return this.ctx.method.toLowerCase() === 'get';
	}

	isPost() {
		return this.ctx.method.toLowerCase() === 'post';
	}

	isGetLike() {
		return ['get', 'head', 'options'].includes(this.ctx.method.toLowerCase());
	}

	isAjax() {
		if (this._isAjax === undefined) {
			const h = this.ctx.headers['x-requested-with'];
			if (h) {
				this._isAjax = ['xmlhttprequest', 'fetch'].includes(h.toLowerCase());
			}
			else {
				this._isAjax = false;
			}
		}
		return this._isAjax;
	}

	isJSEnabled() {
		return !!this.cookie('js');
	}

	nextUrl() {
		const ctx = this.ctx;
		if (ctx.query.next) return ctx.query.next;

		const paramNext = this.param('next');
		if (paramNext) return paramNext;

		if (!['/login', '/logout', '/signup', '/user/oauth'].includes(ctx.path)) {
			return ctx.url;
		}

		return '/';
	}

	logoutUrl(redirectUrl = null) {
		const nextUrl = redirectUrl || this.nextUrl();
		return '/logout?next=' + encodeURIComponent(nextUrl);
	}

	loginUrl() {
		return '/login?next=' + encodeURIComponent(this.nextUrl());
	}

	signupUrl() {
		return '/signup?next=' + encodeURIComponent(this.nextUrl());
	}

	mobileUrl() {
		return addQuery(this.ctx.url, {[PLATFORM_PARAM]: 'mobile'});
	}

	desktopUrl() {
		return addQuery(this.ctx.url, {[PLATFORM_PARAM]: 'desktop'});
	}

	redirect(url, qs = true) {
		if (qs === true) {
			url = addQuery(url, this.ctx.querystring);
		}
		else if (typeof qs === 'object' || typeof qs === 'string') {
			url = addQuery(url, qs);
		}

		return this.ctx.redirect(url);
	}

	redirectPermanent(url, qs = true) {
		if (qs === true) {
			url = addQuery(url, this.ctx.querystring);
		}
		else if (typeof qs === 'object' || typeof qs === 'string') {
			url = addQuery(url, qs);
		}

		this.ctx.status = 301;
		return this.ctx.redirect(url);
	}

	// this is when user visits an out link from our app
	// we send all the cookies as params
	// so we need to set the cookies on browser if they don't exist
	async setCookiesFromParams() {
		const query = this.ctx.query;

		const utmCookie = query[COOKIE_PARAM_PREFIX + UTM_COOKIE];
		if (utmCookie) {
			this.cookie(UTM_COOKIE, utmCookie, {
				maxAge: ONE_MONTH,
				onlyCacheIfExists: true,
				domain: '*',
			});
		}

		const idCookie = query[COOKIE_PARAM_PREFIX + COOKIEID_COOKIE];
		if (idCookie) {
			this.cookie(COOKIEID_COOKIE, idCookie, {
				maxAge: TEN_YEARS,
				onlyCacheIfExists: true,
				domain: '*',
			});
		}

		const sessionIdCookie = query[COOKIE_PARAM_PREFIX + SESSIONID_COOKIE];
		if (sessionIdCookie) {
			this.cookie(SESSIONID_COOKIE, sessionIdCookie, {
				onlyCacheIfExists: true,
				domain: '*',
			});
		}

		const affidCookie = query[COOKIE_PARAM_PREFIX + AFFID_COOKIE];
		if (affidCookie) {
			this.cookie(AFFID_COOKIE, affidCookie, {
				maxAge: ONE_DAY,
				onlyCacheIfExists: true,
				domain: '*',
			});
		}

		const countryCookie = query[COOKIE_PARAM_PREFIX + COUNTRY_COOKIE];
		if (countryCookie) {
			this.cookie(COUNTRY_COOKIE, countryCookie, {
				maxAge: TEN_YEARS,
			});
		}
	}

	parseReferer() {
		const referer = this.referer();
		if (!referer) {
			return {
				name: '',
				source: 'direct',
				medium: 'direct',
				term: '',
			};
		}

		const refererUri = new URL(referer);
		let host = refererUri.hostname;
		const baseDomain = this.baseDomain();

		if (host.endsWith(baseDomain)) {
			return {
				name: host,
				source: host,
				medium: 'direct',
				term: '',
			};
		}

		host = host.replace(/^(?:www|m|shop|mobile|lm|l)\./, '')
			.replace('search.yahoo', 'yahoo');

		// extract search engine names
		const searchRegex = /\.(images\.google|google|yahoo|bing|ask|duckduckgo|yandex|baidu|babylon|avg|wow|reliancenetconnect|webcrawler|inspsearch|speedbit|searches|search)\./;
		const matches = `.${host}`.match(searchRegex);

		if (matches) {
			let refererSource = matches[1];
			if (['search', 'searches'].includes(refererSource)) {
				refererSource = host;
			}

			const query = refererUri.searchParams;
			const term = query.get('q') || query.get('searchfor') || query.get('pq') || 'not_available';

			return {
				name: host,
				source: refererSource,
				medium: 'organic',
				term: handleArray(term).trim(),
			};
		}

		return {
			name: host,
			source: host,
			medium: 'referral',
			term: '',
		};
	}

	setUTMCookie() {
		this.setUTMCookieFromQuery(this.ctx.query);
	}

	/**
	 * sets UTM cookies from a predefined url
	 */
	setUTMCookieFromUrl(url) {
		const uri = (url instanceof URL) ? url : new URL(url, 'http://localhost');
		const params = uri.searchParams;
		this.setUTMCookieFromQuery({
			utm_source: params.get('utm_source'),
			utm_medium: params.get('utm_medium'),
			utm_campaign: params.get('utm_campaign'),
			utm_term: params.get('utm_term'),
			utm_content: params.get('utm_content'),
			gclid: params.get('gclid'),
		});
	}

	/**
	 * sets UTM cookies from a predefined query object
	 */
	setUTMCookieFromQuery(query) {
		let source = query.utm_source || '';
		let medium = query.utm_medium || '';
		let campaign = query.utm_campaign || '';
		let term = query.utm_term || '';
		const content = query.utm_content || '';

		if (query.gclid) {
			source = source || 'google';
			medium = medium || 'cpc';
			campaign = campaign || 'google_cpc';
		}

		const utmExists = Boolean(source || medium || campaign);
		const referer = this.parseReferer();
		this._refererName = referer.name;

		if (!utmExists) {
			source = referer.source;
			medium = referer.medium;
			term = referer.term;
		}

		// if the medium is direct then only set cookie if it doesn't already exist
		const shouldSetCookie = Boolean(utmExists || medium !== 'direct' || !this.cookie(UTM_COOKIE));
		if (!shouldSetCookie) return;

		this.cookie(
			UTM_COOKIE,
			joinCookieParts([source, medium, campaign, term, content], 'none'), {
				maxAge: ONE_MONTH,
				domain: '*',
			},
		);
	}

	setAffidCookie() {
		const affid = this.ctx.query[AFFID_PARAM];
		if (!affid) return;
		const subaffid = this.ctx.query[SUBAFFID_PARAM];

		this.cookie(
			AFFID_COOKIE,
			joinCookieParts([affid, subaffid]), {
				maxAge: AFFID_COOKIE_DURATION,
				domain: '*',
			},
		);
	}

	setAffidCookieFromUrl(url) {
		const uri = (url instanceof URL) ? url : new URL(url, 'http://localhost');
		const params = uri.searchParams;
		const affid = params.get(AFFID_PARAM);
		if (!affid) return;
		const subaffid = params.get(SUBAFFID_PARAM);

		this.cookie(
			AFFID_COOKIE,
			joinCookieParts([affid, subaffid]), {
				maxAge: AFFID_COOKIE_DURATION,
				domain: '*',
			},
		);
	}

	handlePlatformModification() {
		// don't change platform in mobile apps
		if (this.isMobileApp()) return;

		const platform = this.ctx.query[PLATFORM_PARAM] || this.cookie(PLATFORM_COOKIE);
		const setPlatformCookie = this.setPlatform(platform);
		if (setPlatformCookie) {
			this.cookie(PLATFORM_COOKIE, platform, {
				maxAge: PLATFORM_COOKIE_DURATION,
				domain: '*',
			});
		}
	}

	ipLocation() {
		if (this._ipLoc === undefined) {
			const loc = GeoIP.getSync(this.ip()) || {};
			const country = loc.country;
			const city = loc.city;
			const state = loc.subdivisions && loc.subdivisions[0];
			this._ipLoc = {
				country: {
					name: (country && country.names.en) || '',
					isoCode: (country && country.iso_code) || '',
				},
				city: {
					name: (city && city.names.en) || '',
					isoCode: (city && city.iso_code) || '',
				},
				state: {
					name: (state && state.names.en) || '',
					isoCode: (state && state.iso_code) || '',
				},
			};
		}

		return this._ipLoc;
	}

	ipCountry() {
		return this.ipLocation().country.name;
	}

	ipCity() {
		return this.ipLocation().city.name;
	}

	ipState() {
		return this.ipLocation().state.name;
	}

	getABNumber(min = 0, max = false) {
		const cookieId = this.cookieId() || 'nocookie';
		const num = getIntegerKey(cookieId.substr(-4));
		if (max === false) return num;
		return (num % ((max + 1) - min)) + min;
	}

	getBot() {
		const bots = [
			['googlebot', 'googlebot'],
			['googlepreview', 'google web preview'],
			['googlemobile', 'google wireless'],
			['googleadsbot', 'Mediapartners-Google'],

			['bingbot', 'bingbot', 'msnbot'],

			['yahoobot', 'yahoo'],
			['facebookbot', 'facebook'],
			['alexabot', 'ia_archiver'],

			['baidubot', 'baidu'],
			['twitterbot', 'twitter'],

			['bot', 'bot', 'spider', 'crawl', 'dig', 'search', 'http', 'url'],
		];

		const userAgent = this.userAgent().toLowerCase();
		if (!userAgent) {
			return 'emptybot';
		}

		for (const bot of bots) {
			const botName = bot[0];
			for (let i = 1; i < bot.length; i++) {
				if (userAgent.includes(bot[i].toLowerCase())) {
					return botName;
				}
			}
		}

		return false;
	}

	isBot() {
		return Boolean(this.getBot());
	}

	supportsWebp() {
		const accept = this.ctx.headers.accept || '';
		return accept.includes('image/webp');
	}

	bestImageFormat(defaultFormat = 'jpg') {
		if (this.supportsWebp()) return 'webp';
		return defaultFormat;
	}

	handleFlashMessage() {
		if (this.isAjax()) return;

		this._flash = '';
		const cookieVal = this.cookie(FLASH_COOKIE);
		if (!cookieVal) return;

		try {
			// cookie format is `format:actualMessage`
			const formatIndex = cookieVal.indexOf(':');
			const format = cookieVal.substring(0, formatIndex);
			if (format !== 'json') {
				throw new Error(`Unknown flash message format ${format}`);
			}

			this._flash = JSON.parse(cookieVal.substring(formatIndex + 1));
		}
		catch (e) {
			this._flash = '';
			console.error('Error parsing flash message', e);
		}

		this.cookie(FLASH_COOKIE, null);
	}

	/**
	 * get or set a flash message (can be an object too)
	 * @example
	 * $req.flash('info', 'hello'); // set a flash message
	 * $req.flash('info'); // get a flash message
	 *
	 * @param {string} key key of the flash message
	 * @param {*} message message to set (skip to get the message)
	 * @returns {*} flash message
	 */
	flash(key, message) {
		if (message === undefined) {
			return (this._flash && this._flash[key]) || '';
		}

		// ignore empty flash message
		if (!message) {
			return null;
		}

		let flashes = this._responseFlash;
		if (!flashes) {
			flashes = {};
			this._responseFlash = flashes;
		}

		flashes[key] = message;

		const maxAge = 3 * 60 * 1000; // valid till 3 minutes
		const cookieValue = `json:${JSON.stringify(flashes)}`;
		this.cookie(
			FLASH_COOKIE,
			cookieValue,
			{maxAge, httpOnly: false},
		);
		return null;
	}

	static async getDummyCtx({
		params = {},
		query = {},
		state = {},
		method = 'GET',
		path = '/',
		url,
		req = false,
	} = {}) {
		const context = {
			query,
			params,
			state,
			url: url || path,
			path,
			throw: (...args) => {
				throw new Error(args.join(' '));
			},
			method,
			session: {},
			headers: {},
			cookies: new Map(),
			host: this.options.baseDomain || 'localhost',
			hostname: this.options.baseDomain || 'localhost',
			redirect: (...args) => { console.warn('Redirect to', args) },
			set(key, val) {
				if (typeof key === 'string') {
					this.headers[key] = val;
					return;
				}
				Object.assign(this.headers, key);
			},
		};
		if (req) context.$req = await this.from(context);
		return context;
	}
}

module.exports = Request;
