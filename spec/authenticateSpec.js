var authenticate = require('../lib/authenticate');

describe('Authenticate', function() {

  it('should return middleware', function() {

    var f = function() {}
    expect(authenticate(f)).toEqual(jasmine.any(Function));

  });

  it('should throw a ReferenceError if validateUser undefined or not a function', function() {

    expect(authenticate).toThrowError(ReferenceError, 'validateUser undefined or not a function');

  });

  describe('middleware', function() {

    it('should call next() with Errors', function(done) {

      var error = function() {
        return Promise.reject(new Error('rejected'));
      };

      var middleware = authenticate(error);

      middleware(null, null, function(err) {
        expect(err.message).toBe('rejected');
        done();
      });

    });

    it('should call res.json if validated', function(done) {

      var valid = function(req) {
          return Promise.resolve({validated: true});
      }

      var middleware = authenticate(valid);

      middleware(null, {json: function(response) {
        expect(response.validated).toBe(true);
        done();
      }});

    });
  });

});
