var passwordValidator = require('../lib/passwordValidator');
var auth = require('auth-utilities');
var hash = auth.password(1).hash;
var f = function() {};


describe('PasswordValidator', function() {

  it('should return a function', function() {
    var f = function() {};
    expect(passwordValidator(f, 'string')).toEqual(jasmine.any(Function));
  });

  it('should throw a ReferenceError if findUser or secret are undefined', function() {
    var p = passwordValidator;
    var f = function() {}

    var errors = [
      p,
      function() { return p(f)}
    ];

    errors.forEach(function(e) {
      expect(e).toThrowError(ReferenceError);
    });

  });

  it('should throw a TypeError if findUser or secret are incorrect type', function() {
    var p = passwordValidator;
    var f = function() {}

    var errors = [
      function() { return p({}, 'string')},
      function() { return p(f, f)}
    ];

    errors.forEach(function(e) {
      expect(e).toThrowError(TypeError);
    });

  });

  describe('returned function', function() {

    var f = function() {};

    it('should return a Promise', function() {
      var p = passwordValidator(f, 'secret');
      expect(p().constructor.name).toBe('Promise');
    });

    it('should reject with AuthError if bad password', function(done) {
      var findUser = function(req) {
        return hash('password').then(function(hashed) {
          return Promise.resolve({
            payload: {
              exp: Date.now()
            },
            plain: 'bad password',
            hash: hashed
          });
        });
      }

      var validator = passwordValidator(findUser, 'secret');
      validator()
      .catch(function(err) {
        expect(err.name).toBe('AuthError');
        expect(err.code).toBe(401);
        done();
      });

    });

    it('should resolve with token if password valid', function(done) {
      var findUser = function(req) {
        return hash('password').then(function(hashed) {
          return Promise.resolve({
            payload: {
              exp: Date.now()
            },
            plain: 'password',
            hash: hashed
          });
        });
      }

      var validator = passwordValidator(findUser, 'secret');
      validator()
      .then(function(token) {
        expect(token.split('.').length).toBe(3);
        done();
      });

    });

    it('should reject with Error from findUser', function(done) {
      var findUser = function(req) {
        return Promise.reject('findUser error');
      }

      var validator = passwordValidator(findUser, 'secret');
      validator()
      .catch(function(err) {
        expect(err).toBe('findUser error');
        done();
      });

    });

  });

});
