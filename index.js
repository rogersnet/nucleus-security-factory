'use strict';

var apigee = require('apigee-access'),
  request = require('request'),
  cache = apigee.getCache(),
  async = require('async'),
  _ = require('lodash'),
  debug = require('debug')('securityFactory'),
  jwt = require('jsonwebtoken'),
  urljoin = require('url-join'),
  jwkToPem = require('jwk-to-pem'),
  SalesForceOAuthValidator = require('./token_validators/salesforce-oauth-validator'),
  utils = require('./lib/utils');

function securityFactory(options) {
  var config = options.config,
      messages = options.messages,
      models = options.models;
  function applySecurity(req, res, next) {
    var access_token = req.get('Authorization');
    if (access_token && access_token.length > 7) {
      access_token = access_token.substring(7);
      res.locals.jwt = jwt.decode(access_token);
      cache.get(access_token, function (error, data) {
        if (!data) {
          debug('when entry not found in cache', data);
          validateTokenAsync({
            config: config,
            access_token: access_token,
            req: req,
            res: res,
            next: next,
            messages: messages
          });
        } else {
          var _cachedEntry = JSON.parse(data);
          debug(_cachedEntry);
          if (_cachedEntry.valid) {
            utils.setRequestSecurity(req, _cachedEntry.account_list);
            next();
          } else {
            res.status('401').json({
              code: 401,
              message: messages.SEC_INVALID_ACCESS_TOKEN,
              "more": _cachedEntry.message_back
            });
          }
        }
      });
    } else {
      res.status('401').json({
        code: 401,
        message: messages.SEC_INVALID_ACCESS_TOKEN
      });
    }
  }
  function validateTokenAsync(options) {
    var config = options.config, access_token = options.access_token, messages = options.messages, req = options.req, res = options.res,
        salesForceOAuthValidator = new SalesForceOAuthValidator(options);
    debug('SalesForceOAuthValidator', SalesForceOAuthValidator);
    async.parallel([
      function (callback) {
        verifySSO2JWTToken({ access_token: access_token, token_key_url: config.security.apigee_sso2.token_key_url, req: options.req, whitelisted_domains: config.security.email_domain,
          type: 'apigee_sso22_jwt' }, callback);
      },
      function (callback) {
        validateToken({ url: config.security.google_token_info_url, access_token: access_token, req: req, callback: callback, whitelisted_domains: config.security.email_domain, type: 'google_token' });
      },
      function (callback) {
        validateToken({ url: config.security.apigee_edge.url, access_token: access_token, req: req, callback: callback, whitelisted_domains: config.security.email_domain, type: 'apigee_edge_token' });
      },
      function verifyAuth0JWT(callback) {
        validateAuth0JWTToken({ access_token: access_token, client_secret: config.security.auth0_jwt.client_secret, client_id: config.security.auth0_jwt.client_id, 
          req: options.req, whitelisted_domains: config.security.email_domain, type: 'auth0_jwt' }, callback);
      },
      function verifySalesForceToken(callback) {
        debug('validating SalesForce Token');
        salesForceOAuthValidator.validateSalesForceJWTToken({ access_token: access_token, token_key_url: config.security.salesforce_oauth.keys_url, req: options.req, type: 'salesforce_jwt' }, callback);
      },
    ],
      function (err, results) {
        debug("not in cache", results);
        var validationResult = hasAtLeastOneValidToken(results);
        debug("not in cache", validationResult);
        if (validationResult.valid) {  // token is valid
          options.next();
        } else {                          // token is invalid
          res.status('401').json({ code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN, "more": validationResult.message_back });
        }
        debug("not in cache", validationResult);
        cache.put(access_token, JSON.stringify(validationResult), 3600);
      });
  }

  function hasAtLeastOneValidToken(tokenValidations) {
    var validationResult = { valid: false };
    tokenValidations.forEach(function (_validationResult) {
      debug("getting validation result", _validationResult);
      if ((_validationResult.valid) == true) {
        validationResult = _validationResult;
      } else if (_validationResult.email) {
        validationResult = _validationResult;
      }
    });
    debug('hasAtLeastOneValidToken', validationResult);
    return validationResult;
  }

  function validateToken(options) {
    var url = options.url + options.access_token; // 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    debug('validating token with url:', url);
    request.get({ url: url, rejectUnauthorized: false }, function (error, response, body) {
      debug('response after validating token:', error, JSON.stringify(body));
      var _body = {};//body ? JSON.parse( body ) : {};
      try {
        _body = body ? JSON.parse(body) : {};
      } catch (err) {
        debug(err);
      }

      if (!error && response.statusCode === 200) {
        debug('checking options', options);
        utils.getUserAccounts({ access_token: options.access_token, email: _body.email, req: options.req, callback: options.callback, whitelisted_domains: options.whitelisted_domains, type: options.type });
      } else {
        options.callback(null, { "valid": false, type: options.type });
      }
    });
  }

  /*
  * validateAuth0JWTToken
  *
  */
  function validateAuth0JWTToken(options, callback) {
    jwt.verify(options.access_token, new Buffer(options.client_secret, 'base64'), function (err, decoded) {
      debug('jwt_decoded', decoded);
      if (err) {
        debug('not a valid Auth0 JWT');
        callback(null, { valid: false, "message_back": err });
      } else {
        var client_id = decoded.client_id !== undefined ? decoded.client_id : decoded.aud;
        debug('valid Auth0 JWTT');
        if (options.client_id != client_id) {
          return callback(null, { valid: false, "message_back": "client_id does not match OAuth App" });
        }
        utils.getUserAccounts({ access_token: options.access_token, email: decoded.email, req: options.req, callback: callback, whitelisted_domains: options.whitelisted_domains, type: options.type });
      }
    });
  }


  /*
  * verifySSO2JWTToken - first search for the token in cache, if it exists, do not bother verifying it with publicKey. Instead, check if valid flag is true
  *
  * */
  function verifySSO2JWTToken(options, callback) {
    debug('options.whitelisted_domains verifySSO2JWTToken', options.whitelisted_domains);
    cache.get('sso2TokenKey', function (error, sso2TokenKey) {
      if (!sso2TokenKey) {
        request({ url: options.token_key_url, rejectUnauthorized: false }, function (error, response, sso2TokenKeyBody) {
          debug('whitelisted_domains: options.whitelisted_domains', options.whitelisted_domains);
          if (!error) {
            cache.put('sso2TokenKey', sso2TokenKeyBody, 36000); //retrieve key every 10 hrs
            debug('publicKey_before', sso2TokenKeyBody);
            utils.verifyJWT({ access_token: options.access_token, req: options.req, res: options.res, public_key: JSON.parse(sso2TokenKeyBody).value, type: options.type,
              whitelisted_domains: options.whitelisted_domains }, callback);
          } else {
            callback(null, { valid: false, "message_back": "Error retrieving tokenKey" });
          }
        });
      } else {
        utils.verifyJWT({ access_token: options.access_token, req: options.req, res: options.res, public_key: JSON.parse(sso2TokenKey).value, type: options.type,
          whitelisted_domains: options.whitelisted_domains }, callback);
      }
    });
  }

  return applySecurity;
}

module.exports = securityFactory;

  /*  function( callback ){
        validateApigeeAccountToken( { url: urljoin(config.security.apigee_accounts.url, req.query.uuid + '.json?access_token='), access_token: access_token, req: req, callback: callback, type: 'apigee_accounts_token' } );
      },*/

/*  function verifyJWT(options, callback) {
    debug('publicKey', options.public_key);
    debug('validating access token', options.access_token);
    debug('validating access token length', options.access_token.length);
    jwt.verify(options.access_token, options.public_key, { algorithms: ['RS256'] }, function (err, decoded) {
      debug('verifyJWT response', err, decoded);
      if (!err) {
        utils.getUserAccounts({ access_token: options.access_token, email: decoded.email || decoded.cid, req: options.req, callback: callback, type: options.type });
      } else {
        debug('error triggered from verifyJWT');
        callback(null, { valid: false, "message_back": err, type: options.type });
      }
    });
  }*/

/*
  function validateSalesForceJWTToken(options, callback) {
    cache.get('sso2SalesForceTokenKeys', function (error, sso2SalesForceTokenKeys) {
      var decoded_jwt;
      try {
        decoded_jwt = jwt.decode(options.access_token, { complete: true });
        debug('access token decoded3', decoded_jwt);

        if (!sso2SalesForceTokenKeys) {
          request({ url: options.token_key_url, rejectUnauthorized: false }, function (error, response, sso2SalesForceTokenKeys) {
            if (!error) {
              cache.put('sso2SalesForceTokenKeys', sso2SalesForceTokenKeys, 36000); //retrieve key every 10 hrs
              debug('sso2SalesForceTokenKeys', sso2SalesForceTokenKeys);

              var key = getKey(decoded_jwt.header.kid, JSON.parse(sso2SalesForceTokenKeys).keys);
              debug('salesforce key', key);

              verifyJWT({ access_token: options.access_token, req: options.req, res: options.res, public_key: jwkToPem(key), type: options.type }, callback);
            } else {
              callback(null, { valid: false, "message_back": "Error retrieving tokenKey" });
            }
          });
        } else {
          var key = getKey(decoded_jwt.header.kid, JSON.parse(sso2SalesForceTokenKeys).keys);
          verifyJWT({ access_token: options.access_token, req: options.req, res: options.res, public_key: jwkToPem(key), type: options.type }, callback);
        }
      } catch (e) {
        return callback(null, { valid: false, message_back: "Error decoding JWT", type: options.type });
      }
    });
  }

  function getKey(kid, keys) {
    return keys.find(function (key) {
      return key.kid === kid;
    })
  }

*/

/*  function validateApigeeAccountToken(options) {
    var url = options.url + options.access_token; // 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    debug('validating token with url:', url);
    request.get({ url: url, rejectUnauthorized: false }, function (error, response, body) {
      debug('response after validating token:', error, JSON.stringify(body));
      var _body = body ? JSON.parse(body) : {};

      //_body.data.email = 'akshay.anand9@t-mobile.com';
      if (!error && response.statusCode === 200) {
        utils.getUserAccounts({ access_token: options.access_token, email: _body.data.email, req: options.req, callback: options.callback, type: options.type });
      } else {
        options.callback(null, { "valid": false, type: options.type });
      }
    });
  }*/

/*  function getUserAccounts(options) {
    debug('running getUserAccounts');
    var account_list = [];
    options.email = options.email.toLowerCase();
    if (endsWithAllAccess(options.email, config.security.email_domain)) {
      account_list.push('*');
      utils.callCallback({ access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type });
    } else {
      models.AccountUserMap.findAll({ where: { email: options.email }, attributes: ["email", "account_id", "roles"] })
        .then(function (accountUserMaps) {
          accountUserMaps.forEach(function (accountUserMap, idx) {
            account_list.push(accountUserMap.dataValues.account_id);
          });
          utils.callCallback({ access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type });
        });
    }
  }*/

/*  function endsWithAllAccess(email, email_domains) {
    debug('email, email_domains', email, email_domains);
    return email_domains.some(function (domain) {
      return _.endsWith(email, domain);
    });
  }*/