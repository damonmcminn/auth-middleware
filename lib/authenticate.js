'use strict';
module.exports = Authenticate;

function Authenticate(validateUser) {

  if (!validateUser || (typeof validateUser !== 'function')) {
    throw new ReferenceError('validateUser undefined or not a function');
  }

  return function(req, res, next) {

    validateUser(req).then(function(response) {
      res.json(response);
    })
    .catch(function(err) {
      next(err);
    });
  }

}