'use strict';

module.exports = PasswordValidator;

const auth = require('auth-utilities');

function PasswordValidator(options) {
  /**
   * @param {Function} options.findUser
   *  returns a Promise ({payload, Hashedpassword}|false|Error)
   * @param {Function} options.toParse
   *  returns value to parse by options.parse
   *  e.g. req.headers.authorization === string
   *       req.body === object
   * @param {Function} options.parse
   *  returns {user, password} in plaintext
   * @param {string} options.secret - secret for siging JWT
   * @param {Number} [options.rounds]
   *
   * @returns {Function} Express middleware
   */
  
  if (!options) {
    throw new ReferenceError('options undefined');
  }

  // will throw if options.secret undefined
  var token = auth.token(options.secret);
  var password = auth.password(options.rounds);

  return function(req, res, next) {

    var type = options.type(req);
    var authDetails = options.parse(type);

    if (!authDetails) {
      next(new TypeError(`Unable to parse ${type}`));
    } else {
      options.findUser(authDetails.user)
        .then(function(user) {
          if (!user) {
            next(new Error('User not found'));
          } else {
            password.check(authDetails.password, user.password)
            .then(function(isValid) {
              if (isValid) {
                req.token = token.generate(user.payload);
                next();
              } else {
                next(new Error('Bad password'));
              }
            });
          }
        })
        .catch(function(err) {
          next(err);
        })
    }
  }
}
