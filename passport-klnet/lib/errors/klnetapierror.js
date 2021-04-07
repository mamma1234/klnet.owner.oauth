/**
 * `NaverAPIError` error.
 *
 * References:
 *   - http://developer.naver.com/wiki/pages/NaverLogin_Web#section-NaverLogin_Web-4.4API_ED_98_B8_EC_B6_9C_EA_B2_B0_EA_B3_BC_EC_BD_94_EB_93_9C_EC_A0_95_EC_9D_98
 *
 * @constructor
 * @param {String} [message]
 * @param {Number} [code]
 * @api public
 */
function KlnetAPIError(message, code) {
    Error.call(this);
    Error.captureStackTrace(this, arguments.callee);
    this.name = 'KlnetAPIError';
    this.message = message;
    this.type = 'KlnetAPIError';
    // @note typeof Error code (API Result Code) is `string` now.
    // @todo Discuss about handling Error code as `Number`, not `String`.
    this.code = code;
    this.status = 500;
}


KlnetAPIError.prototype.__proto__ = Error.prototype;


module.exports = KlnetAPIError;