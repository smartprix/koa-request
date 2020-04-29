/**
 * Escape a string for including in regular expressions
 * @param {string} str string to escape
 * @return {string} escaped string
 */
function escapeRegex(str) {
	if (!str) return '';
	return String(str).replace(/[-[\]{}()*+!<=:?./\\^$|#,]/g, '\\$&');
}

module.exports = {
	escapeRegex,
};
