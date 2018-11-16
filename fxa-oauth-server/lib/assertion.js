/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use stict';

/* Utilities for verifing signed identity assertions.
 *
 * This service accepts two different kinds of identity assertions
 * for authenticating the caller:
 *
 *  - A JWT, signed by one of a fixed set of trusted server-side secret
 *    HMAC keys.
 *  - A BrowserID assertion bundle, signed via BrowserID's public key
 *    discovery mechanisms.
 *
 * The former is much simpler and easier to verify, so much so that
 * we do it inline in the server process.  The later is much more
 * complicated and we eeed to call out to an external verifier process.
 * We hope to eventually phase out support for BrowserID assertions.
 *
 */

const Joi = require('joi');
const jwt = require('jsonwebtoken');

const AppError = require('./error');
const config = require('./config');
const logger = require('./logging')('assertion');
const P = require('./promise');

const HEX_STRING = /^[0-9a-f]+$/;
const CLAIMS_SCHEMA = Joi.object({
  'uid': Joi.string().length(32).regex(HEX_STRING).required(),
  'fxa-generation': Joi.number().integer().min(0).required(),
  'fxa-verifiedEmail': Joi.string().max(255).required(),
  'fxa-lastAuthAt': Joi.number().integer().min(0).required(),
  'fxa-tokenVerified': Joi.boolean().optional(),
  'fxa-amr': Joi.array().items(Joi.string().alphanum()).optional(),
  'fxa-aal': Joi.number().integer().min(0).max(3).optional(),
  'fxa-profileChangedAt': Joi.number().integer().min(0).optional()
}).options({ stripUnknown: true });

const AUDIENCE = config.get('publicUrl');
const ALLOWED_ISSUER = config.get('browserid.issuer');

const request = require('request').defaults({
  url: config.get('browserid.verificationUrl'),
  pool: {
    maxSockets: config.get('browserid.maxSockets')
  }
});

// Verify a BrowserID assertion,
// by posting to an external verifier service.

function verifyBrowserID(assertion) {
  const d = P.defer();
  const opts = {
    json: {
      assertion: assertion,
      audience: AUDIENCE
    }
  };
  request.post(opts, (err, res, body) => {
    if (err) {
      logger.error('verify.error', err);
      return d.reject(err);
    }

    function error(msg, val) {
      logger.info('invalidAssertion', {
        msg: msg,
        val: val,
        assertion: assertion
      });
      d.reject(AppError.invalidAssertion());
    }

    if (! body || body.status !== 'okay') {
      return error('non-okay response', body);
    }
    const email = body.email;
    const parts = email.split('@');
    if (parts.length !== 2 || parts[1] !== ALLOWED_ISSUER) {
      return error('invalid email', email);
    }
    if (body.issuer !== ALLOWED_ISSUER) {
      return error('invalid issuer', body.issuer);
    }
    const uid = parts[0];

    const claims = body.idpClaims || {};
    claims.uid = uid;
    CLAIMS_SCHEMA.validate(claims, (err, claims) => {
      if (err) {
        return error(err, claims);
      }
      return d.resolve(claims);
    });
  });
  return d.promise;
}

// Verify a JWT assertion.
// Since it's just a symmetric HMAC signature,
// this should be safe and performant enough to do in-proces.
function verifyJWT(assertion) {
  // To allow for key rotation, we may have
  // several valid shared secret keys in-flight.
  let i = 0;
  const keys = config.get('authServerSecrets');
  const opts = {
    algorithms: ['HS256'],
    audience: AUDIENCE,
    issuer: ALLOWED_ISSUER,
  };
  return new P((resolve, reject) => {
    const verifyWithRemainingKeys = () => {
      if (i >= keys.length) {
        return reject(AppError.invalidAssertion());
      }
      const key = keys[i++];
      jwt.verify(assertion, key, opts, (err, claims) => {
        if (! err) {
          return resolve(claims);
        }
        // Any error other than 'invalid signature' will not
        // be resolved by trying the remianing keys.
        if (err.message !== 'invalid signature') {
          return reject(err);
        }
        verifyWithRemainingKeys();
      });
    };
    verifyWithRemainingKeys();
  });
}

module.exports = function verifyAssertion(assertion) {
  // We can differentiate between JWTs and BrowserID assertions
  // because the former cannot contain "~" while the later always do.
  if (/~/.test(assertion)) {
    return verifyBrowserID(assertion);
  } else {
    return verifyJWT(assertion);
  }
};
