/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

/* Operations on OAuth database state.
 *
 * Currently this is not actually talking to a database,
 * it's making authenticated calls to the fxa-oauth-server API
 * to interrogate and manipulate its state, essentially treating
 * fxa-oauth-server as a kind of backend micro-service.
 *
 * We want to work towards merging the fxa-oauth-server code
 * directly into the main fxa-auth-server process, at which point
 * this abstraction will convert into more direct db access.
 *
 */

const Joi = require('joi')
const JWT = require('jsonwebtoken')
const P = require('./promise')

const Pool = require('./pool')
const {
  HEX_STRING,
  DISPLAY_SAFE_UNICODE
} = require('./routes/validators')

function objMap(obj, func) {
  return Object.keys(obj).reduce((acc, k) => {
    return Object.assign(acc, { [k]: func(obj[k]) })
  }, {})
}

module.exports = (log, config) => {

  const SafeUrl = require('./safe-url')(log)

  const pool = new Pool(config.oauth.url, config.oauth.poolee)

  const SAFE_URLS = {}

  SAFE_URLS.getClientInfo = new SafeUrl('/v1/client/:clientId', 'oauthdb.getClientInfo', Joi.object({
    id: Joi.string().length(16).regex(HEX_STRING).required(),
    name: Joi.string().max(25).regex(DISPLAY_SAFE_UNICODE).required(),
    trusted: Joi.boolean().required(),
    image_uri: Joi.any(),
    redirect_uri: Joi.string().required().allow('')
  }))
  SAFE_URLS.getScopedKeyData = new SafeUrl('/v1/key-data', 'oauthdb.getScopedKeyData', Joi.object().pattern(/^/, [
    Joi.object({
      identifier: Joi.string.required(),
      keyRotationSecret: Joi.string.required(),
      keyRotationTimestamp: Joi.number().required(),
    })
  ]))

  // Make a symmetrically-signed JWT assertion that we can pass to
  // fxa-oauth-server in lieu of a full-blown BrowserID assertion.
  function makeAssertionJWT(credentials) {
    const opts = {
      algorithm: 'HS256',
      expiresIn: 60,
      audience: config.oauth.url,
      issuer: config.domain
    }
    const claims = {
      uid: credentials.uid,
      'fxa-generation': credentials.verifierSetAt,
      'fxa-verifiedEmail': credentials.email,
      'fxa-lastAuthAt': credentials.lastAuthAt(),
      'fxa-tokenVerified': credentials.tokenVerified,
      'fxa-amr': Array.from(credentials.authenticationMethods),
      'fxa-aal': credentials.authenticatorAssuranceLevel
    }
    return new P((resolve, reject) => {
      JWT.sign(claims, config.oauth.secretKey, opts, (err, token) => {
        if (err) {
          reject(err)
        } else {
          resolve(token)
        }
      })
    })
  }

  return {

    close() {
      pool.close()
    },

    RESPONSE_SCHEMA: objMap(SAFE_URLS, url => url._responseSchema),

    async getClientInfo(clientId) {
      return pool.get(SAFE_URLS.getClientInfo, { clientId })
    },

    async getScopedKeyData(sessionToken, oauthParams) {
      return makeAssertionJWT(sessionToken).then(assertion => {
        oauthParams.assertion = assertion
        return pool.post(SAFE_URLS.getScopedKeyData, {}, oauthParams)
      })
    },

    /* As we work through the process of merging oauth-server
     * into auth-server, future methods we might want to include
     * here will be things like the following:

    async getClientInstances(account) {
    },

    async createAuthorizationCode(account, params) {
    }

    async redeemAuthorizationCode(account, params) {
    }

    async checkAccessToken(token) {
    }

    async revokeAccessToken(token) {
    }

    async checkRefreshToken(token) {
    }

    async revokeRefreshToken(token) {
    }

     * But in the interests of landing small manageable changes,
     * let's only add those as we need them.
     *
     */

  }
}
