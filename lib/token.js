'use strict';
module.exports = Token;

const auth = require('auth');

function Token(options) {

  if (!options || !options.secret) {
    throw new ReferenceError('secret undefined');
  }

  var SECRET = options.secret;
  var token = auth.token(SECRET);

  return function(req, res, next) {
    // assumes req.headers.token === JWT
    // req.user === JWT payload || false
    req.user = token.authenticate(req.headers.token);

    if (req.token) {
      next();
    } else {
      next(new Error('Bad token'));
    }
  }
}
