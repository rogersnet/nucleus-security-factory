var apigee = require('apigee-access'),
  request = require('request'),
  apigee_cache_promise = require('apigee-cache-promise')(apigee.getCache()),
  debug = require('debug')('securityFactory-sfdc-oauth-validator'),
  jwt = require('jsonwebtoken'),
  _ = require('lodash'),
  jwkToPem = require('jwk-to-pem'),
  utils = require('../lib/utils'),
  rp = require('request-promise');


function SalesForceOAuthValidator(options) {
  debug('options.config', options.config);
  var options = options;
  this.config = options.config;
}

SalesForceOAuthValidator.prototype.validateSalesForceJWTToken = function (options, callback) {
  var salesForceOAuthValidator = this;
  var decoded_jwt;
  try {
    decoded_jwt = jwt.decode(options.access_token, { complete: true });
    debug('access token decoded3', decoded_jwt);
    apigee_cache_promise.get('sso2SalesForceTokenKeys')
      .then(function retrieveKeysFromServer(keys) {
        // if keys found in cache, return keys immediately
        if (keys) {
          debug('ccached keys', keys);
          return keys;
        }

        // if it reached this point, keys were not found in cache, retrieve, cache, and return them from server
        return utils.promisifyRequest({ url: options.token_key_url, rejectUnauthorized: false })
          .then(function (sso2SalesForceTokenKeys) {
            debug('non-cached keys', sso2SalesForceTokenKeys);
            apigee_cache_promise.put('sso2SalesForceTokenKeys', sso2SalesForceTokenKeys, 36000); //retrieve key every 10 hrs
            return sso2SalesForceTokenKeys;
          })
      })
      .then(function verifyJWTwithJWK(sso2SalesForceTokenKeys) {
        var key = utils.getKey(decoded_jwt.header.kid, JSON.parse(sso2SalesForceTokenKeys).keys);
        utils.verifyJWT({
          access_token: options.access_token, req: options.req, res: options.res,
          public_key: jwkToPem(key), type: options.type, whitelisted_domains: salesForceOAuthValidator.config.security.email_domain
        }, callback);
      })
      .catch(function (e) {
        debug('catch', e, e.stack);
        callback(null, { valid: false, message_back: e, type: options.type });
      })
  } catch (e) {
    return callback(null, { valid: false, message_back: e, type: options.type });
  }
}

module.exports = SalesForceOAuthValidator;