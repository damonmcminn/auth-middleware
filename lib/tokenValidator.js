'use strict';
module.exports = TokenValidator;

const auth = require('auth-utilities');

function TokenValidator(options) {

  if (!options || !options.secret) {
    throw new ReferenceError('secret undefined');
  }

  var SECRET = options.secret;
  var jwt = auth.token(SECRET);

  return function(req, res, next) {
    // assumes header of 'Authorization: Bearer jwt'
    // req.user === JWT payload || false
    var token = parseAuthorizationHeader(req.headers.authorization);
    req.tokenPayload = jwt.authenticate(token);

    if (!token) {
      next(new Error('Missing token'));
    } else if (!req.tokenPayload) {
      next(new Error('Bad token'));
    } else if (req.tokenPayload.exp < Date.now()) {
      next(new Error('Expired token'));
    } else {
      next();
    }
  }
}

/* PRIVATE */
function parseAuthorizationHeader(header) {
  /**
   * @param {string} header - in form "Bearer json.web.token"
   */

  var bearer = 'Bearer ';
  return RegExp(bearer).test(header) ? header.replace(bearer, '') : false;
}
