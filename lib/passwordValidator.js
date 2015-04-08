'use strict';

module.exports = PasswordValidator;

const auth = require('auth-utilities');

function PasswordValidator(rounds) {
  var password = auth.password(rounds);

  return function(req, res, next) {
    //  ROUTE SPECIFIC MIDDLEWARE
    //
    // assumes user has been retrieved from db and attached to req
    // e.g. req.user.password === hashed password
    // also: req.body.password === unhashed password
    // also assumes there is error handling middleware

    password.check(req.body.password, req.user.password)
      .then(function(isValid) {
        if (isValid) {
          next();
        } else {
          next(new Error('Bad password'));
        }
      });
  }
}
