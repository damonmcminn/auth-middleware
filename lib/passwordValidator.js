'use strict';

module.exports = PasswordValidator;

const auth = require('auth-utilities');
const ErrorFactory = require('simple-error-factory');

const AuthError = ErrorFactory('auth');
const status = { code: 401 };

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
  var generateToken = auth.token(options.secret).generate;
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
            next(AuthError('User not found', status));
          } else {
            password.check(authDetails.password, user.password)
            .then(function(isValid) {
              if (isValid) {
                var response = {
                  token: generateToken(user.payload)
                };
                res.json(response);
              } else {
                next(AuthError('Bad password', status));
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
