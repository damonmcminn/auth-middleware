var middleware = require('../index');

describe('auth-middleware', function() {

  it('should export #password and #token', function() {
    expect(typeof middleware.password).toBe('function');
    expect(typeof middleware.token).toBe('function');
  });

});
