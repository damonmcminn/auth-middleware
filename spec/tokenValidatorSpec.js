var jwt = require('auth-utilities').token('secret');
var TokenValidator = require('../lib/tokenValidator');
var currentJwt = jwt.generate({exp: Date.now()*2});
var expiredJwt = jwt.generate({exp: 1});

describe('TokenValidator', function() {

  var tokenValidator = TokenValidator('secret');
  var req = {headers: {}};

  it('should throw a ReferenceError if called without a secret', function() {
    expect(TokenValidator).toThrowError(ReferenceError);
  });

  it('should attach JWT payload to req.user', function(done) {
    req.headers.authorization = `Bearer ${currentJwt}`

    tokenValidator(req, null, function() {
      expect(req.user.exp).toBeGreaterThan(Date.now());
      done();
    });
  });

  it('should call next() with a missing token AuthError', function(done) {
    req.headers.authorization = undefined;

    tokenValidator(req, null, function(err) {
      expect(err.name).toBe('AuthError');
      expect(err.message).toBe('Missing token');
      expect(err.code).toBe(401);
      done();
    });
  });

  it('should call next() with an expired token AuthError', function(done) {
    req.headers.authorization = `Bearer ${expiredJwt}`;

    tokenValidator(req, null, function(err) {
      expect(err.name).toBe('AuthError');
      expect(err.message).toBe('Expired token');
      expect(err.code).toBe(401);
      done();
    });
  });

  it('should call next() with a bad token AuthError', function(done) {
    req.headers.authorization = `Bearer very.bad.token`;

    tokenValidator(req, null, function(err) {
      expect(err.name).toBe('AuthError');
      expect(err.message).toBe('Bad token');
      expect(err.code).toBe(401);
      done();
    });
  });

  it('should optionally accept a function that returns a Promise that resolves with data to attach to req.user', function(done) {

    var fn = function(payload) {
      return Promise.resolve({foo: 'bar'});
    };

    var tv = TokenValidator('secret', fn);

    req.headers.authorization = `Bearer ${currentJwt}`
    tv(req, null, function() {

      expect(req.user.foo).toBe('bar');
      done();

    });
  });

  it('optional function should return Promise that rejects with error to pass to next()', function(done) {

    var fn = function(payload) {
      return Promise.reject(new Error('rejection error'));
    };

    var tv = TokenValidator('secret', fn);

    req.headers.authorization = `Bearer ${currentJwt}`
    tv(req, null, function(err) {

      expect(err.message).toBe('rejection error');
      done();

    });

  });

});
