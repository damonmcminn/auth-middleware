describe('Password', function() {

  var auth = require('auth-utilities');
  var hash = auth.password(1).hash;
  var passwordValidator = require('../lib/passwordValidator');

  var validPassword = (new Buffer('user:password')).toString('base64');
  var invalidPassword = (new Buffer('user:invalidpassword')).toString('base64');

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
    rounds: 1
  });

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
});
