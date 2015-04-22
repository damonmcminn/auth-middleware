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
});
