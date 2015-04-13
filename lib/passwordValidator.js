'use strict';
module.exports = PasswordValidator;

const auth = require('auth-utilities');

const ErrorFactory = require('simple-error-factory');
const AuthError = ErrorFactory('auth');
const status = { code: 401 };


function PasswordValidator(findUser, secret, rounds) {
  /**
   * @param {Function} findUser - Promise that resolves with:
   *    {payload, hash, plain}
   *    payload === for encoding as a JWT
   *    hash === user's hashed password
   *    plain === user's plaintext password parsed from req
   * @param {String} secret - secret for encoding JWT
   * @param {Number} rounds - bcrypt rounds
   *
   * @returns {Promise} resolve with token, reject with error
   */

  if (!findUser || !secret) {
    throw new ReferenceError('findUser or secret undefined');
  }

  if (typeof findUser !== 'function') {
    throw new TypeError('findUser not a function');
  }

  if (typeof secret !== 'string') {
    throw new TypeError('secret not a string');
  }

  var password = auth.password(rounds);
  var generateToken = auth.token(secret).generate;

  return function(req) {

    return new Promise(function(resolve, reject) {

      findUser(req).then(function(user) {
        // {payload, hash, plain}
        password.check(user.plain, user.hash)
        // nested because #check resolves with a bool...
        .then(function(isValid) {
          if (isValid) {
            resolve(generateToken(user.payload));
          } else {
            reject(AuthError('Bad password', status));
          }
        });
      })
      .catch(function(err) {
        reject(err);
      });

    });
  }

}
