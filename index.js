'use strict';

var apigee = require('apigee-access'),
    request = require('request'),
    cache = apigee.getCache(),
    async = require('async'),
    _ = require('lodash'),
    debug = require('debug')('securityFactory'),
    jwt = require('jsonwebtoken'),
    urljoin = require('url-join');

function securityFactory( options ) {
  var config = options.config;
  var messages = options.messages;
  var models = options.models;
  function applySecurity(req, res, next) {
    var access_token;
    if( req.header('Authorization') ) {
      access_token = req.header('Authorization').split(/\s+/).pop();
    } else{
      access_token = req.query.access_token || '';
    }
    cache.get( access_token, function( error, data ){
      if( !data ){
        debug('when entry not found in cache', data);
        validateTokenAsync( { config: config, access_token: access_token, req: req, res: res, next: next, messages: messages } );
      } else{
        var _cachedEntry = JSON.parse( data );
        debug( _cachedEntry );
        if( _cachedEntry.valid ){
          setRequestSecurity( req, _cachedEntry.account_list );
          next();
        } else {
          res.status('401').json( { code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN, "more": _cachedEntry.message_back } );
        }
      }
    } )
  }

  function validateTokenAsync( options ) {
    var config = options.config, access_token = options.access_token, messages = options.messages, req = options.req, res = options.res;
    async.parallel([
          function( callback ){
            validateToken( { url: config.security.google_token_info_url, access_token: access_token, req: req, callback: callback, type: 'google_token' } );
          },
          function( callback ){
            validateToken( { url: config.security.apigee_edge.url, access_token: access_token, req: req, callback: callback, type: 'apigee_edge_token' } );
          },
          function( callback ){
            validateApigeeAccountToken( { url: urljoin(config.security.apigee_accounts.url, req.query.uuid + '.json?access_token='), access_token: access_token, req: req, callback: callback, type: 'apigee_accounts_token' } );
          },
          function( callback ){
            validateJWTToken( { access_token: access_token, token_key_url: config.security.apigee_sso2.token_key_url, req: options.req, type: 'apigee_sso22_jwt' }, callback );
          },
          function verifyAuth0JWT( callback ){
            validateAuth0JWTToken( { access_token: access_token, client_secret: config.security.auth0_jwt.client_secret, req: options.req, type: 'auth0_jwt' }, callback );
          },
        ],
        function( err, results ){
          debug("not in cache", results );
          var validationResult = hasAtLeastOneValidToken( results );
          debug("not in cache", validationResult );
          if( validationResult.valid ) {  // token is valid
            options.next();
          } else {                          // token is invalid
            res.status('401').json( { code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN, "more": validationResult.message_back } );
          }
          debug("not in cache", validationResult );
          cache.put( access_token, JSON.stringify( validationResult ), 3600 );
        });
  }

  function hasAtLeastOneValidToken( tokenValidations ){
    var validationResult = { valid: false };
    tokenValidations.forEach( function( _validationResult ) {
        if( (_validationResult.valid) == true ){
          validationResult = _validationResult;
        } else if ( _validationResult.email ){
          validationResult = _validationResult;
        }
      } );
    debug( 'hasAtLeastOneValidToken', validationResult );
    return validationResult;
  }

  function validateToken( options ){
    var url = options.url + options.access_token; // 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    debug('validating token with url:', url);
    request.get( {url: url, rejectUnauthorized: false} , function( error, response, body ) {
      debug('response after validating token:', error, JSON.stringify(body));
      var _body = body ? JSON.parse( body ) : {};

      //_body.email = 'akshay.anand9@t-mobile.com';
      if( !error && response.statusCode === 200 ){
        getUserAccounts( { access_token: options.access_token, email: _body.email, req: options.req, callback: options.callback, type: options.type } );
      } else{
        options.callback( null, { "valid": false, type: options.type } );
      }
    });
  }

  function validateApigeeAccountToken( options ){
    var url = options.url + options.access_token; // 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    debug('validating token with url:', url);
    request.get( {url: url, rejectUnauthorized: false} , function( error, response, body ) {
      debug('response after validating token:', error, JSON.stringify(body));
      var _body = body ? JSON.parse(body) : {};

      //_body.data.email = 'akshay.anand9@t-mobile.com';
      if( !error && response.statusCode === 200 ){
        getUserAccounts( { access_token: options.access_token, email: _body.data.email, req: options.req, callback: options.callback, type: options.type } );
      } else{
        options.callback( null, { "valid": false, type: options.type } );
      }
    });
  }

  function getUserAccounts( options ){
    var account_list = [];
    if( _.endsWith( options.email, config.security.email_domain ) ){
      account_list.push( '*' );
      callCallback( { access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type } );
    } else{
      models.AccountUserMap.findAll({ where: { email: options.email }, attributes: [ "email", "account_id", "roles"] })
        .then( function( accountUserMaps ) {
          accountUserMaps.forEach( function( accountUserMap, idx ) {
              account_list.push( accountUserMap.dataValues.account_id );
            } );
          callCallback( { access_token: options.access_token, email: options.email, req: options.req, account_list: account_list, callback: options.callback, type: options.type } );
        } );
    }
  }

  function callCallback( options ){
    setRequestSecurity( options.req, options.account_list )
    var valid = false, message_back = "No accounts associated to credentials";
    if( options.account_list.length > 0 ) {
      valid = true;
      message_back = "ok";
    }
    var t = { "access_token": options.access_token, type: "apigee_edge_token", 'account_list': options.account_list, "email": options.email, "valid": valid, "message_back": message_back };
    options.callback( null, t );
  }

  function setRequestSecurity( req, account_list ) {
    req.security = {};
    req.security.account_list = account_list;
  }


  /*
  * validateAuth0JWTToken
  *
  */
  function validateAuth0JWTToken( options, callback ) {
    jwt.verify(options.access_token, new Buffer(options.client_secret, 'base64'), function(err, decoded) {
      if( err ) {
        debug('not a valid Auth0 JWT');
        callback(null, { valid: false, "message_back": "Invalid Auth0 JWT" });
      } else {
        debug('valid Auth0 JWT')
        getUserAccounts( { access_token: options.access_token, email: decoded.email, req: options.req, callback: callback, type: options.type } );
        //callback(null, { valid: false, "message_back": "Invalid Auth0 JWT" });
      }
    });
  }

  /*
   * validate accounts.apigee.com token e.g.
   * curl https://accounts.apigee.com/api/v1/users/{uuid}.json?access_token={access_token}
   */


  /*
  * validateJWTToken - first search for the token in cache, if it exists, do not bother verifying it with publicKey. Instead, check if valid flag is true
  *
  * */
  function validateJWTToken(options, callback) {
    cache.get( 'sso2TokenKey', function( error, sso2TokenKey ){
      if( !sso2TokenKey ) {
        request( {url: options.token_key_url, rejectUnauthorized: false}, function( error, response, sso2TokenKeyBody ) {
          if( !error ) {
            cache.put( 'sso2TokenKey', sso2TokenKeyBody, 36000 ); //retrieve key every 10 hrs
            debug('publicKey_before', sso2TokenKeyBody);
            verifyJWT( { access_token: options.access_token, req: options.req, res: options.res, public_key: JSON.parse(sso2TokenKeyBody).value }, callback );
          } else{
            callback( null, { valid: false, "message_back": "Error retrieving tokenKey" } );
          }
        });
      } else {
          verifyJWT( { access_token: options.access_token, req: options.req, res: options.res, public_key: JSON.parse(sso2TokenKey).value }, callback );
      }
    });
  }

  function verifyJWT( options, callback ) {
    debug('publicKey', options.public_key);
    jwt.verify( options.access_token, options.public_key, { algorithms: ['RS256'] }, function(err, decoded) {
      debug('verifyJWT', err, decoded);
      if( !err ) {
        getUserAccounts( { access_token: options.access_token, email: decoded.email || decoded.cid, req: options.req, callback: callback, type: options.type } );
      } else {
        callback( null, { valid: false, "message_back": "Error decoding JWT" } );
      }
    });
  }

  //
  return applySecurity;
}

module.exports = securityFactory;