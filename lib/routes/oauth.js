/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

/* Routes for managing OAuth authorization grants.
 *
 * These routes are a more-or-less direct proxy through to
 * routes on the underlying "fxa-oauth-server", treating it
 * as a kind of back-end microservice.  We want to eventually
 * merge that codebase directly into the main auth-server
 * here, at which point these routes will become the direct
 * implementation of their respesctive features.
 *
 */

const isA = require('joi')

const error = require('../error')
const validators = require('./validators')

module.exports = (log, config, oauthdb) => {
  const routes = [
    {
      method: 'GET',
      path: '/oauth/client/:client_id',
      options: {
        validate: {
          params: {
            client_id: isA.string().regex(validators.HEX_STRING).length(16)
          }
        },
        response: {
          schema: oauthdb.RESPONSE_SCHEMA.getClientInfo
        }
      },
      handler: async function (request) {
        return oauthdb.getClientInfo(request.params.client_id)
      }
    },
    {
      method: 'GET',
      path: '/oauth/key-data',
      options: {
        auth: {
          strategy: 'sessionToken'
        },
        validate: {
          payload: {
            client_id: isA.string().regex(validators.HEX_STRING).length(16),
            scope: isA.string().max(256).regex(validators.OAUTH_SCOPE)
          }
        },
        response: {
          schema: oauthdb.RESPONSE_SCHEMA.getClientInfo
        }
      },
      handler: async function (request) {
        const sessionToken = request.auth.credentials
        if (! sessionToken.emailVerified) {
          throw error.unverifiedAccount()
        }
        return oauthdb.getScopedKeyData(sessionToken, request.payload)
      }
    },
  ]
  return routes
}
