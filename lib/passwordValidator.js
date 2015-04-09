'use strict';

module.exports = PasswordValidator;

const auth = require('auth-utilities');

function PasswordValidator(options) {
  
  if (
    !options ||
    (typeof options.findUser !== 'function')
  ) {
    throw new ReferenceError('options.findUser undefined');
  }

  // will throw if options.secret undefined
  var token = auth.token(options.secret);
  var password = auth.password(options.rounds);

  return function(req, res, next) {
    //  ROUTE SPECIFIC MIDDLEWARE
    //
    // also assumes there is error handling middleware

    // returns {user,password} in plaintext
    var type = options.type(req);
    var authDetails = options.parse(type);

    if (!authDetails) {
      next(new TypeError(`Unable to parse ${type}`));
    }

    options.findUser(authDetails.user)
      .catch(function(err) {
        next(err);
      })
      .then(function(user) {
        // plaintext, hashed
        password.check(authDetails.password, user.password)
          .then(function(isValid) {
            if (isValid) {
              req.token = token.generate(user.payload);
              next();
            } else {
              next(new Error('Bad password'));
            }
          });
      });
  }
}
