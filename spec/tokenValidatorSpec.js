var jwt = require('auth-utilities').token('secret');
var TokenValidator = require('../lib/tokenValidator');
var currentJwt = jwt.generate({exp: Date.now()*2});
var expiredJwt = jwt.generate({exp: 1});

describe('TokenValidator', function() {

  var tokenValidator = TokenValidator({secret: 'secret'});
  var req = {headers: {}};

  it('should throw a ReferenceError if called without a secret', function() {
    expect(TokenValidator).toThrowError(ReferenceError);
  });

  it('should attach JWT payload to req.tokenPayload', function(done) {
    req.headers.authorization = `Bearer ${currentJwt}`

    tokenValidator(req, null, function() {
      expect(req.tokenPayload.exp).toBeGreaterThan(Date.now());
      done();
    });
  });

  it('should call next() with a missing token Error', function(done) {
    req.headers.authorization = undefined;

    tokenValidator(req, null, function(err) {
      expect(err.message).toBe('Missing token');
      done();
    });
  });

  it('should call next() with an expired token Error', function(done) {
    req.headers.authorization = `Bearer ${expiredJwt}`;

    tokenValidator(req, null, function(err) {
      expect(err.message).toBe('Expired token');
      done();
    });
  });

  it('should call next() with an bad token Error', function(done) {
    req.headers.authorization = `Bearer very.bad.token`;

    tokenValidator(req, null, function(err) {
      expect(err.message).toBe('Bad token');
      done();
    });
  });
});
