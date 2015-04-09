describe('Password', function(done) {

  var auth = require('auth-utilities');
  var hash = auth.password(1).hash;
  var passwordValidator = require('../lib/passwordValidator');

  var validPassword = (new Buffer('user:password')).toString('base64');
  var invalidPassword = (new Buffer('user:invalidpassword')).toString('base64');

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

  it('should call next() with Error if no user found', function(done) {
    hash('password').then(function(hashed) {
      var req = {
        headers: {
          authorization: `Basic ${validPassword}`
        }
      };
      cannotFindUser(req, null, function(fromNext) {
        expect(fromNext.message).toBe('User not found');
        done();
      });
    });
  });
});
