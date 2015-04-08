'use strict';
module.exports = AuthMiddleware;

function AuthMiddleware() {};

AuthMiddleware.password = require('./lib/passwordValidator');
AuthMiddleware.token = require('./lib/tokenValidator');
