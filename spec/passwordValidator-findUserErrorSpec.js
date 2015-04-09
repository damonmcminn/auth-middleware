describe('Password', function(done) {

  var auth = require('auth-utilities');
  var hash = auth.password(1).hash;
  var passwordValidator = require('../lib/passwordValidator');

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
