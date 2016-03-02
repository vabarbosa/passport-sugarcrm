
var util = require('util');
var url = require('url');
var OAuthStrategy = require('passport-oauth').OAuthStrategy;
var _  = require('lodash');


function Strategy(options, verify) {
	  options = options || {};
		
	if (!options.siteURL) {
		throw new Error('OAuthStrategy requires siteURL option');
	}
	else {
		if (options.siteURL.lastIndexOf('/') == options.siteURL.length - 1) {
			//remove trailing '/'
			options.siteURL = options.siteURL.substring(0, options.siteURL.length - 1);
		}
	}
	
	options.requestTokenURL = options.requestTokenURL || (options.siteURL + '/service/v4/rest.php');
	options.accessTokenURL = options.accessTokenURL || (options.siteURL + '/service/v4/rest.php');
	options.userAuthorizationURL = options.userAuthorizationURL || (options.siteURL + '/index.php');
	options.sessionKey = options.sessionKey || 'session-sugarcrm-oauth';

	OAuthStrategy.call(this, options, verify);
	this.name = 'sugarcrm-oauth';
};


util.inherits(Strategy, OAuthStrategy);


OAuthStrategy.prototype.requestTokenParams = function(options) {
	var params = options || {};
	params.method = "oauth_request_token";
	return params;
};

OAuthStrategy.prototype.userAuthorizationParams = function(options) {
	var params = options || {};
	params.module = "OAuthTokens";
	params.action = "authorize";
	return params;
};

OAuthStrategy.prototype.accessTokenParams = function(options) {
	var params = options || {};
	params.method = "oauth_access_token";
	return params;
};

OAuthStrategy.prototype.authenticate = function(req, options) {
	options = options || {};
	
	if (!req.session) {
		return this.error(new Error('OAuthStrategy requires session support'));
	}
	
	var self = this;
	
	if (req.query && req.query.oauth_token) {
		//user has been redirected back
		var state = req.session[self._key];
		var oauth_verifier = req.query.oauth_verifier;
		
		var params = self.accessTokenParams(options);
		var parsed = url.parse(this._oauth._accessUrl, true);

		//update access url with the oauth_verifier
		_.extend(parsed.query, parsed.query, params);
		parsed.query.oauth_verifier = req.query.oauth_verifier;
		delete parsed.search;
		
		this._oauth._accessUrl = url.format(parsed);

		//obtain an access token
		this._oauth.getOAuthAccessToken(
			state.oauth_token, 
			state.oauth_token_secret, 
			oauth_verifier, 
			function(err, oauth_access_token, oauth_access_token_secret, results) {
				if (err) {
					console.error("passport-sugarcrm.authenticate > getOAuthAccessToken - error: ", err);
					self.error(err);
				 }
				else {
					var info = {};

					_.extend(info, options, {
						oauth_access_token: oauth_access_token,
						oauth_access_token_secret: oauth_access_token_secret
				 	});
					
					self.success({}, info);
				}
			}
		);
	}
	else {
		var params = this.requestTokenParams(options);
		var callbackURL = options.callbackURL || this._callbackURL;
		    
		params.oauth_callback = callbackURL;
		    
		this._oauth.getOAuthRequestToken(
			params,
			function(err, oauth_token, oauth_token_secret, results) {
				if (err) {
					console.error("passport-sugarcrm.authenticate > getOAuthRequestToken - error: ", err);
				}
				else {
					//store token, secret in session to retrieve/use after token has been manually authorized
					req.session[self._key] = { oauth_token: oauth_token, oauth_token_secret: oauth_token_secret };

					var params = self.userAuthorizationParams(options);
					var parsed = url.parse(self._userAuthorizationURL, true);

					//update authorization url with the oauth_token
					_.extend(parsed.query, parsed.query, params);
					parsed.query.token = oauth_token;
					delete parsed.search;
					
					var userAuthorizationURL = url.format(parsed);
					
					//redirect the user to authorize the token
					self.redirect(userAuthorizationURL);
				}
			}
		);
	}
};

module.exports = Strategy;
