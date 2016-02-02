'use strict';

var apigee = require('apigee-access');
var request = require('request');
var cache = apigee.getCache();
var async = require('async');

function securityFactory( options ) {
  var config = options.config;
  var messages = options.messages;
  function applySecurity(req, res, next) {
    var access_token;
    if( req.header('Authorization') ) {
      access_token = req.header('Authorization').split(/\s+/).pop();
    } else{
      access_token = req.query.access_token || '';
    }
    cache.get( access_token, function( error, data ){
      if( !data ){
        async.parallel([
              function( callback ){
                validateGoogleToken( config.security.google_token_info_url, access_token, callback );
              },
              function( callback ){
                validateApigeeEdgeToken( config.security.google_token_info_url, access_token, callback );
              },
            ],
            function( err, results ){
              var validationResult = hasAtLeastOneValidToken( results );
              if( validationResult.valid ) {  // token is valid
                next();
              } else {                          // token is invalid
                res.status('401').json( { code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN } );
              }
              cache.put( access_token, JSON.stringify( validationResult ), 3600 );
            });
      } else{
        var _cachedEntry = JSON.parse( data );
        if( _cachedEntry.valid ){
          next();
        }
        else {
          res.status('401').json( { code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN } );
        }
      }
    } )
  };

  function hasAtLeastOneValidToken( tokenValidations ){
    var validationResult = { valid: false };
    tokenValidations.forEach( function( _validationResult ) {
      if( _validationResult.valid == true ){
        validationResult = _validationResult;
      }
    } );
    return validationResult;
  }

  function validateGoogleToken( url, access_token, callback ){
    var url = config.security.google_token_info_url + access_token; // 'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token='
    request.get( url , function( error, response, body ) {
      var _body = body ? JSON.parse( body ) : {};
      if( !error && response.statusCode === 200 && _.endsWith( _body.email, config.security.email_domain /*'@apigee.com'*/ ) ){
        callback( null, { "valid": true, type: 'google_token' } );
      } else{
        callback( null, { "valid": false, type: 'google_token' } );
      }
    });
  }

  function validateApigeeEdgeToken(url, access_token, callback){
    var url = config.security.apigee_edge.url + access_token;
    request.get( url , function( error, response, body ) {
      var _body = body ? JSON.parse( body ) : {};
      if( !error && response.statusCode === 200 ){
        callback( null, { "valid": true, type: 'apigee_edge_token' } );
      } else{
        callback( null, { "valid": false, type: 'apigee_edge_token' } );
      }
    });
  }

  return applySecurity;
}

module.exports = securityFactory;
