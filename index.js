'use strict';
module.exports = AuthMiddleware;

const authenticator = require('./lib/authenticate');
const passwordValidator = require('./lib/passwordValidator');

function AuthMiddleware() {};

AuthMiddleware.token = require('./lib/tokenValidator');
AuthMiddleware.password = function Password(findUser, SECRET, ROUNDS) {

  return authenticator(passwordValidator(findUser, SECRET, ROUNDS));

}
