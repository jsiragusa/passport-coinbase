/**
 * Module dependencies.
 */
var util = require('util'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    InternalOAuthError = require('passport-oauth').InternalOAuthError,
    coinbase = require('coinbase');

/**
 * `Strategy` constructor.
 *
 * The Coinbase authentication strategy authenticates requests by delegating to
 * Coinbase using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Coinbase application's Client ID
 *   - `clientSecret`  your Coinbase application's Client Secret
 *   - `callbackURL`   URL to which Coinbase will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'balance', 'transactions', 'request', ...
 *                     (see https://coinbase.com/docs/api/permissions)
 *
 * Examples:
 *
 *     passport.use(new CoinbaseStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/coinbase/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://coinbase.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://coinbase.com/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ' ';

  // Only request the profile if we have the scopes for it
  if(options.scope && options.scope.indexOf('user') < 0) this._skipUserProfile = true;
  this._userProfileURL = options.userProfileURL || 'https://coinbase.com/api/v1/users';

  if (options.account) {
    this._account = options.account;
  }

  if (options.send_limit_amount) {
    this._send_limit_amount = options.send_limit_amount;
  }

  if (options.send_limit_currency) {
    this._send_limit_currency = options.send_limit_currency;
  }

  if (options.send_limit_period) {
    this._send_limit_period = options.send_limit_period;
  }

  OAuth2Strategy.call(this, options, verify);

  this._coinbaseClient = coinbase.Client;  // exposed to facilitate testing
  this.name = 'coinbase';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Coinbase.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `coinbase`
 *   - `id`               the user's Coinbase ID
 *   - `displayName`      the user's full name
 *   - `emails`           the user's email addresses
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var client = new this._coinbaseClient({accessToken: accessToken});
  client.getCurrentUser(function (err, user) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      var profile = {};
      profile.provider = 'coinbase';
      profile.id = user.id;
      profile.displayName = user.name;
      profile.emails = [{value: user.email }];

      profile._raw = JSON.stringify(user);
      profile._json = user;

      done(null, profile);
    }
    catch(e) {
      done(e);
    }
  });
};


/**
 * Return extra Coinbase-specific parameters to be included in the authorization
 * request.
 *
 *  See here for details: https://developers.coinbase.com/docs/wallet/coinbase-connect/permissions
 *
 * Options:
 *  - 'account' - Applications can request different access to user’s wallets, { 'select', 'new', 'all' }
 *  - 'send_limit_amount' - A limit to the amount of money your application can send from the user’s account.
 *  - 'send_limit_currency' - Currency of send_limit_amount in ISO format, {'BTC', 'USD', etc}
 *  - 'send_limit_period' - How often the send money limit expires. Default is month, {'day', 'month', 'year'}
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
  var params = {};

  if (this._account) {
    params.account = this._account;
  }

  if (this._send_limit_amount) {
    params['meta[send_limit_amount]'] = this._send_limit_amount;
  }

  if (this._send_limit_currency) {
    params['meta[send_limit_currency]'] = this._send_limit_currency;
  }

  if (this._send_limit_period) {
    params['meta[send_limit_period]'] = this._send_limit_period;
  }

  return params;
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
