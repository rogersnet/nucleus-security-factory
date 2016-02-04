'use strict';

var apigee = require('apigee-access');
var request = require('request');
var cache = apigee.getCache();
var async = require('async');
var _ = require('lodash');
var debug = require('debug')('securityFactory');

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
        async.parallel([
              function( callback ){
                validateToken( { url: config.security.google_token_info_url, access_token: access_token, req: req, callback: callback, type: 'google_token' } );
              },
              function( callback ){
                validateToken( { url: config.security.apigee_edge.url, access_token: access_token, req: req, callback: callback, type: 'apigee_edge_token' } );
              },
            ],
            function( err, results ){
              debug("not in cache", results );
              var validationResult = hasAtLeastOneValidToken( results );
              debug("not in cache", validationResult );
              if( validationResult.valid ) {  // token is valid
                next();
              } else {                          // token is invalid
                res.status('401').json( { code: 401, message: messages.SEC_INVALID_ACCESS_TOKEN, "more": validationResult.message_back } );
              }
              debug("not in cache", validationResult );
              cache.put( access_token, JSON.stringify( validationResult ), 3600 );
            });
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
  };

  function hasAtLeastOneValidToken( tokenValidations ){
    var validationResult = { valid: false };
    tokenValidations.forEach( function( _validationResult ) {
        if( _validationResult.valid == true ){
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
    request.get( url , function( error, response, body ) {
      var _body = body ? JSON.parse( body ) : {};
      if( !error && response.statusCode === 200 ){  /*&& _.endsWith( _body.email, config.security.email_domain*/ /*'@apigee.com'*/
        //callback( null, { "valid": true, type: 'google_token' } );
        getUserAccounts( { access_token: options.access_token, email: _body.email, req: options.req, callback: options.callback, type: options.type } );
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

  return applySecurity;
}

module.exports = securityFactory;


/*  function validateApigeeEdgeToken( options ){
 var url = options.url + options.access_token;
 request.get( url , function( error, response, body ) {
 var _body = body ? JSON.parse( body ) : {};
 if( !error && response.statusCode === 200 ){
 getUserAccounts( { access_token: options.access_token, email: _body.email, req: options.req, callback: options.callback, type: options.type } );
 } else{
 options.callback( null, { "valid": false, type: options.type } );
 }
 });
 }*/