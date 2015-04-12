var auth = require('auth-utilities');
var hash = auth.password(1).hash;
var passwordValidator = require('../lib/passwordValidator');

describe('Password', function(done) {

  var validPassword = (new Buffer('user:password')).toString('base64');
  var invalidPassword = (new Buffer('user:invalidpassword')).toString('base64');

  var errorFindingUser = passwordValidator({
    findUser: function(email) {
      return new Promise(function(resolve, reject) {
        reject(new Error('find user error'));
      });
    },
    secret: 'secret',
    parse: auth.parseHeader('basic'),
    type: function(req) {
      return req.headers.authorization;
    },
    rounds: 1
  });

  var cannotFindUser = passwordValidator({
    findUser: function(email) {
      return new Promise(function(resolve, reject) {
        resolve(false);
      });
    },
    secret: 'secret',
    parse: auth.parseHeader('basic'),
    type: function(req) {
      return req.headers.authorization;
    },
    rounds: 1
  });

  var canFindUser = passwordValidator({
    findUser: function(email) {
      return hash('password').then(function(hashed) {
        return new Promise(function(resolve, reject) {
          resolve({
            payload: {
              exp: Date.now()
            },
            password: hashed
          });
        });
      });
    },
    secret: 'secret',
    parse: auth.parseHeader('basic'),
    type: function(req) {
      return req.headers.authorization;
    },
    buildResponse: function(token) {
      return {token: token};
    },
    rounds: 1
  });

  it('should call res.json if password valid', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${validPassword}`
        }
      };
      canFindUser(req, {json: function(response) {
        expect(response.token).toEqual(jasmine.any(String));
        done();
      }});
    });
  });

  it('should call next() with PasswordError if invalid password', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${invalidPassword}`
        }
      };
      canFindUser(req, null, function(err) {
        expect(err.message).toBe('Bad password');
        expect(err.name).toBe('PasswordError');
        done();
      });
    });
  });

  it('should throw a ReferenceError if options undefined', function() {
    expect(passwordValidator).toThrowError(ReferenceError, 'options undefined');
  });

  it('should pass a TypeError to next() if cannot parse req[property]', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {}
      };
      canFindUser(req, null, function(fromNext) {
        expect(fromNext.name).toBe('TypeError');
        done();
      });
    });
  });

  it('should call next() with err from findUser', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${validPassword}`
        }
      };
      errorFindingUser(req, null, function(err) {
        expect(err.message).toBe('find user error');
        done();
      });
    });
  });

  it('should call next() with UserNotFoundError if no user found', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${validPassword}`
        }
      };
      cannotFindUser(req, null, function(err) {
        expect(err.name).toBe('UserNotFoundError');
        done();
      });
    });
  });

});
