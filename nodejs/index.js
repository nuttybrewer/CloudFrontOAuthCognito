'use strict';
const util = require('util');
const fetch = require('node-fetch');
const { Headers } = require('node-fetch');
const { URLSearchParams } = require('url');
const url = require('url');
const querystring = require('querystring');
const env = require('./env');
const jwtCheck = require('./jwt');
const myutil = require('./util');


const getReferer = (cfrequest, domain) => {
  if (cfrequest.headers && cfrequest.headers.referer) {
    const referer_item = cfrequest.headers.referer.find((item) => item.key === 'Referer');
    if(referer_item && referer_item.value) {
      console.log(`referer_item.value is ${referer_item.value}`);
      const parsed_referer = url.parse(referer_item.value);
      console.log(`Evaluating referer as ${parsed_referer.hostname} and ${domain.hostname}`);
      if(domain.hostname === parsed_referer.hostname) {
        console.log(`Matched domain, setting the referer as path ${parsed_referer.path}`)
        return parsed_referer.path;
      }
    }
  }
  return null;
};

exports.handler = (event, context, lambda_return_cb) => {
  console.log(util.inspect(event, {
    showHidden: false,
    depth: null
  }));

  const cfrequest = event.Records[0].cf.request;
  const uri = cfrequest.uri;
  const queryString = cfrequest.querystring;
  const domain = url.parse(env.DISTRIBUTION_DOMAIN);
  // Load the default provider from the path, default to Cognito
  var provider=env.OAUTH_PROVIDERS.cognito; // Sane default


  // OAuth or is this just a JWT check?
  if (!uri.startsWith('/oauth')) {
    console.log("Matching simple JWT check");
    if (myutil.checkAuth(cfrequest)) {
      lambda_return_cb(null, cfrequest);
      return true;
    }
    lambda_return_cb(null, myutil.oauth_redirect(uri, provider, getReferer(cfrequest, domain)));
    return false;
  }

  const provider_match = uri.match(/\/oauth\/([a-zA-Z0-9-]+)/);
  if (provider_match) {
    const potential_provider = env.OAUTH_PROVIDERS[provider_match[1]];
    if (potential_provider) {
      console.log("Setting OAuth provider to " + potential_provider.local_oauth_name);
      provider = potential_provider;
    }
  }

  // Check auth if the provider is not Cognito
  if (!provider.primary) {
    if (!myutil.checkAuth(cfrequest)) {
      console.log("Primary authentication failed trying to get to " + uri);
      // TODO Should look through and find the primary provider manually,
      // for now just use Cognito
      lambda_return_cb(null, myutil.oauth_redirect(uri, env.OAUTH_PROVIDERS.cognito, getReferer(cfrequest, domain)));
      return false;
    }
  }

  // Check if this is an authorization request
  if(uri == "/oauth/" + provider.local_oauth_name + provider.local_authorize_path) {
    lambda_return_cb(null, myutil.oauth_redirect(uri, provider, getReferer(cfrequest, domain)) );
    return true;
  }

  // Check if this is a token response from the provider

  if(uri.startsWith("/oauth/" + provider.local_oauth_name + provider.local_token_path)) {
    if (queryString) {
      console.log("QueryString detected: " + util.inspect(queryString, {
        showHidden: false,
        depth: null
      }));
      const qsItems = querystring.parse(queryString);
      var next_uri;
      console.log(`Returned from provider, qsItems is ${JSON.stringify(qsItems)}`);
      if (qsItems[provider.provider_state_key]) {
        // Check if we made the request, if we didn't return a 404
        next_uri = myutil.oauth_state_check(qsItems[provider.provider_state_key]);
        console.log(`Final redirect has a next uri of ${next_uri}`);
        if (next_uri === null) {
          // Invalid requests don't deserve an explanation!
          lambda_return_cb(null, { "status": 404} );
          return false;
        }
      }
      if (qsItems.code) {
        console.log("Code detected: " + qsItems.code);
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('client_id', provider.client_id);
        // Use uri instead of the provider.local_token_path because they should be the same
        params.append('redirect_uri', env.DISTRIBUTION_DOMAIN + uri);
        params.append('code', qsItems.code);
        var headers = {};
        headers['Accept'] = 'application/json';
        if (provider.post_auth_type === 'Authorization') {
          headers['Authorization'] =  'Basic ' +
            Buffer.from(provider.client_id + ":" + provider.client_secret).toString('base64');
        }
        else if (provider.post_auth_type === 'Parameter') {
          params.append('client_secret', provider.client_secret);
        }
        console.log("Fetching POST" + provider.provider_url + provider.provider_token_path);
        console.log("Params:" + util.inspect(params, {
          showHidden: false,
          depth: null
        }));
        console.log("Headers: " + util.inspect(headers, {
          showHidden: false,
          depth: null
        }));
        return fetch(provider.provider_url + provider.provider_token_path, {
            method: 'POST',
            body: params,
            headers: headers
          })
          .then(res => {
            console.log("Fetch result: " + util.inspect(res, {
              showHidden: false,
              depth: null
            }));
            return res.json(); })
          .then(json => {
            console.log("authorization_response received json: " +
              util.inspect(json, {
                showHidden: false,
                depth: null
              })
            );
            console.log(provider);
            lambda_return_cb(null, myutil.final_redirect(next_uri, json.access_token, provider));
            return true;
          })
          .catch(error => {
            console.log("Error fetching auth code: " + util.inspect(error, {
              showHidden: false,
              depth: null
            }));
            lambda_return_cb(null, {status: 503, statusDescription: error.message});
            return false;
          });
      }
    }
  }

  console.log("Authorization fell through");
  lambda_return_cb(null, {status: 404, statusDescription: "Authorization fell through"});
  return false;
};
