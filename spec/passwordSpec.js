var password = require('../lib/password')({});
var hash = require('auth').password.hash;

describe('Password', function() {

  it('should pass request to next() if valid', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        body: {password: 'password'},
        user: {password: hashed}
      };
      password(req, null, function(fromNext) {
        expect(fromNext).toBe(undefined);
        done();
      });
    });
  });

});
