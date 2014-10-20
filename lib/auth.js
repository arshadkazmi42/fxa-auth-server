/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const AppError = require('./error');
const logger = require('./logging').getLogger('fxa.server.auth');
const token = require('./token');
const validators = require('./validators');

const WHITELIST = require('./config').get('admin.whitelist').map(function(re) {
  logger.verbose('compiling whitelist', re);
  return new RegExp(re);
});

exports.AUTH_STRATEGY = 'dogfood';
exports.AUTH_SCHEME = 'bearer';

exports.SCOPE_CLIENT_MANAGEMENT = 'oauth';

exports.strategy = function() {
  return {
    authenticate: function dogfoodStrategy(req, reply) {
      var auth = req.headers.authorization;
      logger.debug('checking auth', auth);
      if (!auth || auth.indexOf('Bearer ') !== 0) {
        return reply(AppError.unauthorized('Bearer token not provided'));
      }
      var tok = auth.split(' ')[1];

      if (!validators.HEX_STRING.test(tok)) {
        return reply(AppError.unauthorized('Illegal Bearer token'));
      }

      token.verify(tok).done(function(details) {
        if (details.scope.indexOf(exports.SCOPE_CLIENT_MANAGEMENT) !== -1) {
          logger.debug('checking whitelist');
          var blocked = !WHITELIST.some(function(re) {
            return re.test(details._email);
          });
          if (blocked) {
            logger.warn('auth.whitelist.blocked', {
              email: details._email,
              token: tok
            });
            return reply(AppError.forbidden());
          }
        }

        logger.info('auth.success', details);
        reply(null, {
          credentials: details
        });
      }, function(err) {
        logger.debug('auth.error', err);
        reply(AppError.unauthorized('Bearer token invalid'));
      });
    }
  };
};