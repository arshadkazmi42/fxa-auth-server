/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict'

var P = require('./promise')
var Pool = require('./pool')
var config = require('../config')
var localizeTimestamp = require('fxa-shared').l10n.localizeTimestamp({
  supportedLanguages: config.get('i18n').supportedLanguages,
  defaultLanguage: config.get('i18n').defaultLanguage
})

module.exports = function (log, error) {
  const SafeUrl = require('./safe-url')(log)
  const SAFE_URLS = {}

  // Perform a deep clone of payload and remove user password.
  function sanitizePayload(payload) {
    if (! payload) {
      return
    }

    const clonePayload = Object.assign({}, payload)

    if (clonePayload.authPW) {
      delete clonePayload.authPW
    }
    if (clonePayload.oldAuthPW) {
      delete clonePayload.oldAuthPW
    }

    return clonePayload
  }

  function Customs(url) {
    if (url === 'none') {
      this.pool = {
        post: function () { return P.resolve({ block: false })},
        close: function () {}
      }
    }
    else {
      this.pool = new Pool(url, { timeout: 3000 })
    }
  }

  SAFE_URLS.check = new SafeUrl('/check')
  Customs.prototype.check = function (request, email, action) {
    log.trace({ op: 'customs.check', email: email, action: action })
    return this.pool.post(
      SAFE_URLS.check,
      undefined,
      {
        ip: request.app.clientAddress,
        email: email,
        action: action,
        headers: request.headers,
        query: request.query,
        payload: sanitizePayload(request.payload)
      }
    )
    .then(
      handleCustomsResult.bind(request),
      err => {
        log.error({ op: 'customs.check.1', email: email, action: action, err: err })
        throw error.backendServiceFailure('customs', 'check')
      }
    )
  }

  function handleCustomsResult (result) {
    const request = this

    if (result.suspect) {
      request.app.isSuspiciousRequest = true
    }

    if (result.block) {
      // Log a flow event that user got blocked.
      request.emitMetricsEvent('customs.blocked')

      const unblock = !! result.unblock

      if (result.retryAfter) {
        // Create a localized retryAfterLocalized value from retryAfter.
        // For example '713' becomes '12 minutes' in English.
        const retryAfterLocalized = localizeTimestamp.format(
          Date.now() + result.retryAfter * 1000,
          request.headers['accept-language']
        )

        throw error.tooManyRequests(result.retryAfter, retryAfterLocalized, unblock)
      }

      throw error.requestBlocked(unblock)
    }
  }

  SAFE_URLS.checkAuthenticated = new SafeUrl('/checkAuthenticated')
  Customs.prototype.checkAuthenticated = function (action, ip, uid) {
    log.trace({ op: 'customs.checkAuthenticated', action: action,  uid: uid })

    return this.pool.post(
      SAFE_URLS.checkAuthenticated,
      undefined,
      {
        action: action,
        ip: ip,
        uid: uid
      }
    )
    .then(
      function (result) {
        if (result.block) {
          if (result.retryAfter) {
            throw error.tooManyRequests(result.retryAfter)
          }
          throw error.requestBlocked()
        }
      },
      function (err) {
        log.error({ op: 'customs.checkAuthenticated', uid: uid, action: action, err: err })
        throw error.backendServiceFailure('customs', 'checkAuthenticated')
      }
    )
  }

  SAFE_URLS.checkIpOnly = new SafeUrl('/checkIpOnly')
  Customs.prototype.checkIpOnly = function (request, action) {
    log.trace({ op: 'customs.checkIpOnly', action: action })
    return this.pool.post(SAFE_URLS.checkIpOnly, undefined, {
      ip: request.app.clientAddress,
      action: action
    })
    .then(
      handleCustomsResult.bind(request),
      err => {
        log.error({ op: 'customs.checkIpOnly.1', action: action, err: err })
        throw error.backendServiceFailure('customs', 'checkIpOnly')
      }
    )
  }

  SAFE_URLS.failedLoginAttempt = new SafeUrl('/failedLoginAttempt')
  Customs.prototype.flag = function (ip, info) {
    var email = info.email
    var errno = info.errno || error.ERRNO.UNEXPECTED_ERROR
    log.trace({ op: 'customs.flag', ip: ip, email: email, errno: errno })
    return this.pool.post(
      SAFE_URLS.failedLoginAttempt,
      undefined,
      {
        ip: ip,
        email: email,
        errno: errno
      }
    )
    .then(
      // There's no useful information in the HTTP response, discard it.
      function () {},
      function (err) {
        log.error({ op: 'customs.flag.1', email: email, err: err })
        throw error.backendServiceFailure('customs', 'flag')
      }
    )
  }

  SAFE_URLS.passwordReset = new SafeUrl('/passwordReset')
  Customs.prototype.reset = function (email) {
    log.trace({ op: 'customs.reset', email: email })
    return this.pool.post(
      SAFE_URLS.passwordReset,
      undefined,
      {
        email: email
      }
    )
    .then(
      // There's no useful information in the HTTP response, discard it.
      function () {},
      function (err) {
        log.error({ op: 'customs.reset.1', email: email, err: err })
        throw error.backendServiceFailure('customs', 'reset')
      }
    )
  }

  Customs.prototype.close = function () {
    return this.pool.close()
  }

  return Customs
}
