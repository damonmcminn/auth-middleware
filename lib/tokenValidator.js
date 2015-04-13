'use strict';
module.exports = TokenValidator;

const auth = require('auth-utilities');
const parseHeader = auth.parseHeader('token');
const ErrorFactory = require('simple-error-factory');
const AuthorizationError = ErrorFactory('authorization');

function TokenValidator(options) {

  if (!options || !options.secret) {
    throw new ReferenceError('secret undefined');
  }

  var jwt = auth.token(options.secret);
  var status = { code: 401 };
  var message;

  return function(req, res, next) {
    // assumes header of 'Authorization: Bearer jwt'
    // req.tokenPayload === JWT payload || false
    var token = parseHeader(req.headers.authorization);
    req.tokenPayload = jwt.authenticate(token);

    if (!token) {
      message = 'Missing token';
    } else if (!req.tokenPayload) {
      message = 'Bad token';
    } else if (req.tokenPayload.exp < Date.now()) {
      message = 'Expired token';
    } 

    message ? next(AuthorizationError(message, status)) : next();

  }
}
