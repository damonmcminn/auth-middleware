'use strict';
module.exports = TokenValidator;

const auth = require('auth-utilities');
const parseHeader = auth.parseHeader('token');
const ErrorFactory = require('simple-error-factory');
const AuthError = ErrorFactory('auth');

function TokenValidator(secret, fn) {
  /**
   * @param {String} secret - secret for validating token
   * @param {Object} fn - optional function that returns a Promise
   * that resolves with data to attach to req.use in place of payload
   *
   * @returns {Function} Express middleware
   */

  if (!secret) {
    throw new ReferenceError('secret undefined');
  }

  var jwt = auth.token(secret);
  var status = { code: 401 };
  var err;

  return function(req, res, next) {
    // assumes header of 'Authorization: Bearer jwt'
    // req.tokenPayload === JWT payload || false
    var token = parseHeader(req.headers.authorization);
    var payload = jwt.authenticate(token);

    if (!token) {
      err = 'Missing token';
    } else if (!payload) {
      err = 'Bad token';
    } else if (payload.exp < Date.now()) {
      err = 'Expired token';
    } 

    if (err) {
      return next(AuthError(err, status));
    }

    if (fn) {
      return fn(payload).then(function(data) {
        req.user = data;
        next();
      })
      .catch(next);
    } else {
      req.user = payload;
      return next();
    }
  }
}
