'use strict';
module.exports = AuthMiddleware;

function AuthMiddleware() {};

AuthMiddleware.password = require('./lib/password');
AuthMiddleware.token = require('./lib/token');
