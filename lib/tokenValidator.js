'use strict';
module.exports = TokenValidator;

const auth = require('auth-utilities');
const parseHeader = auth.parseHeader('token');

function TokenValidator(options) {

  if (!options || !options.secret) {
    throw new ReferenceError('secret undefined');
  }

  var SECRET = options.secret;
  var jwt = auth.token(SECRET);

  return function(req, res, next) {
    // assumes header of 'Authorization: Bearer jwt'
    // req.user === JWT payload || false
    var token = parseHeader(req.headers.authorization);
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
