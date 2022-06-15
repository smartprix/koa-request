let globalLogger;

/**
 * set logger
 */
function setLogger(logger) {
	globalLogger = logger;
}

function logError(...args) {
	if (globalLogger !== undefined) {
		if (globalLogger) globalLogger.error(...args);
	}
	else {
		console.error(...args);
	}
}

module.exports = {
	setLogger,
	logError,
};
