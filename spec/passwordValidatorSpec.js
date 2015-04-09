var auth = require('auth-utilities');
var hash = auth.password(1).hash;
var passwordValidator = require('../lib/passwordValidator');

function findUser(email, callback) {
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
}

function notFoundUser(email, callback) {
  return new Promise(function(resolve, reject) {
    resolve(false);
  });
}

function findUserError(email) {
  return new Promise(function(resolve, reject) {
    reject(new Error('find user error'));
  });
}

var canFindUser = passwordValidator({
  findUser: findUser,
  secret: 'secret',
  parse: auth.parseHeader('basic'),
  type: function(req) {
    return req.headers.authorization;
  },
  rounds: 1
});
var cannotFindUser = passwordValidator({
  findUser: notFoundUser,
  secret: 'secret',
  parse: auth.parseHeader('basic'),
  rounds: 1
});
var errorFindingUser = passwordValidator({
  findUser: findUserError,
  secret: 'secret',
  parse: auth.parseHeader('basic'),
  type: function(req) {
    return req.headers.authorization;
  },
  rounds: 1
});

var validPassword = (new Buffer('user:password')).toString('base64');
var invalidPassword = (new Buffer('user:invalidpassword')).toString('base64');

describe('Password', function() {

  it('should attach req.token and call next() if valid password', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${validPassword}`
        }
      };
      canFindUser(req, null, function(fromNext) {
        expect(fromNext).toBe(undefined);
        expect(req.token).toEqual(jasmine.any(String));
        done();
      });
    });
  });

  it('should call next() with Error if invalid password', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${invalidPassword}`
        }
      };
      canFindUser(req, null, function(fromNext) {
        expect(fromNext.message).toBe('Bad password');
        done();
      });
    });
  });

  it('should throw a ReferenceError if options.findUser undefined or not a function', function() {
    expect(passwordValidator).toThrowError(ReferenceError, 'options.findUser undefined');
    expect((function() {passwordValidator({findUser: 'not a function'})}))
      .toThrowError(ReferenceError);
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

});
