var request = require('request'),
    debug = require('debug')('securityFactory-utils'),
    jwt = require('jsonwebtoken'),
    _ = require('lodash'),
    Promise = require('promise');

  function verifyJWT(options, callback) {
    debug('publicKey', options.public_key);
    debug('validating access token', options.access_token);
    debug('validating access token length', options.access_token.length);
    debug('options.whitelisted_domains verifyJWT', options.whitelisted_domains)
    jwt.verify(options.access_token, options.public_key, { algorithms: ['RS256'] }, function (err, decoded) {
      debug('verifyJWT response', err, decoded);
      if (!err) {
        options.res.locals.jwt = decoded;
        getUserAccounts({ access_token: options.access_token, email: decoded.email || decoded.cid, 
          req: options.req, callback: callback, type: options.type, whitelisted_domains: options.whitelisted_domains });
      } else {
        debug('error triggered from verifyJWT');
        callback(null, { valid: false, "message_back": err, type: options.type });
      }
    });
  }

  function getUserAccounts(options) {
    debug('running getUserAccounts');
    var account_list = [];
    var models = options.req.app.get('utils').models;
    options.email = options.email.toLowerCase();
    if (isFromWhitelistedDomain(options.email, options.whitelisted_domains)) {
      account_list.push('*');
      callCallback({ access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type });
    } else {
      models.AccountUserMap.findAll({ where: { email: options.email }, attributes: ["email", "account_id", "roles"] })
        .then(function (accountUserMaps) {
          accountUserMaps.forEach(function (accountUserMap, idx) {
            account_list.push(accountUserMap.dataValues.account_id);
          });
          callCallback({ access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type });
        });
    }
  }

  function isFromWhitelistedDomain(email, email_domains) {
    debug('email, email_domains', email, email_domains);
    if(!email_domains) throw new Error('whitelisted email domains not found', email_domains);
    return email_domains.some(function (domain) {
      return _.endsWith(email, domain);
    });
  }

  function callCallback(options) {
    setRequestSecurity(options.req, options.account_list)
    var valid = false, message_back = "No accounts associated to credentials";
    if (options.account_list.length > 0) {
      valid = true;
      message_back = "ok";
    }
    var t = { "access_token": options.access_token, type: options.type, 'account_list': options.account_list, "email": options.email, "valid": valid, "message_back": message_back };
    options.callback(null, t);
  }

  function getKey(kid, keys) {
    return keys.find(function (key) {
      return key.kid === kid;
    })
  }

  function setRequestSecurity(req, account_list) {
    req.security = {};
    req.security.account_list = account_list;
  }

  function promisifyRequest(options) {
    return new Promise(function (resolve, reject) {
      request(options, function (err, response, body) {
        if (err) reject(err);
        else resolve(body);
      });
    });
  }

  module.exports = {
    verifyJWT: verifyJWT,
    getUserAccounts: getUserAccounts,
    isFromWhitelistedDomain: isFromWhitelistedDomain,
    callCallback: callCallback,
    getKey: getKey,
    setRequestSecurity: setRequestSecurity,
    promisifyRequest: promisifyRequest
  }