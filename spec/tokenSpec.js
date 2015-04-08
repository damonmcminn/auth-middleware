var auth = require('auth');
var Token = require('../lib/token');

describe('Token', function() {

  it('should throw a ReferenceError if called without a secret', function() {
    expect(Token).toThrowError(ReferenceError);
  });

});
