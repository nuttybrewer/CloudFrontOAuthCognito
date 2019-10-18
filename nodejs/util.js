const jsonwebtoken = require('jsonwebtoken');
const env = require('./env');
const jwtCheck = require ('./jwt');
const util = require('util');
const querystring = require('querystring');

// From Michael - sqlbot on StackOverFlow
// Taken from article: https://stackoverflow.com/questions/55128624/cloudfront-lambdaedge-set-cookie-on-viewer-request
const extract_cookie = function (headers, cname) {
    const cookies = headers['cookie'];
    if(!cookies)
    {
        console.log("extract_cookie(): no 'Cookie:' headers in request");
        return null;
    }

    // iterate through each Cookie header in the request, last to first

    for (var n = cookies.length; n--;)
    {
        // examine all values within each header value, last to first

        const cval = cookies[n].value.split(/;\ /);
        const vlen = cval.length;

        for (var m = vlen; m--;)
        {
            const cookie_kv = cval[m].split('=');
            if(cookie_kv[0] === cname)
            {
                return cookie_kv[1];
            }
        } // for m (each value)
    } // for n (each header)

    // we have no match if we reach this point
    console.log('extract_cookie(): cookies were found, but the specified cookie is absent');
    return null;
};
exports.extract_cookie = extract_cookie;


exports.checkAuth = function (request) {
  const queryString = request.querystring;
  var authToken;
  if (queryString) {
    console.log("QueryString detected: " + util.inspect(queryString, {
      showHidden: false,
      depth: null
    }));
    const qsItems = querystring.parse(queryString);
    if(qsItems.authorization) {
      console.log("Authorization querystring present: " +
        util.inspect(qsItems.authorization, {
          showHidden: false,
          depth: null
        })
      );
      authToken = qsItems.authorization;
    }
  }
  if(request.headers) {
    console.log("Headers detected");
    console.log(authToken);
    if(!authToken) {
      console.log("calling extract_cookie");
      authToken = extract_cookie(request.headers, 'sessiontoken');
    }
    if (!authToken) {
    // Check for the authorization header
      if (request.headers.Authorization) {
        const bearer = request.headers.Authorization.match(/Bearer \s+(.*)/);
        if (bearer) {
          console.log("Authorization Header present: " +
            util.inspect(request.headers.Authorization, {
              showHidden: false,
              depth: null
            })
          );
          authToken = bearer[1];
        }
      }
    }
  }
  if (authToken) {
    console.log("Authorizing token " + authToken);
    return jwtCheck.verifyToken(authToken);
  }
  return false;
}

exports.oauth_state_check = function(token) {
  try {
    console.log("OSC Decoding token " + token);
    const decodedToken = jsonwebtoken.verify(token, env.JWTKEY, {token_use: 'oauth', complete: true });
    if(decodedToken) {
      console.log("OSC Decoded token:\n" + util.inspect(decodedToken, {
        showHidden: false,
        depth: null
      }));
      if (decodedToken.payload) {
        if(decodedToken.payload.requesting_uri) {
          if (decodedToken.payload.requesting_uri.startsWith('/oauth')) {
            return "/";
          }
          return decodedToken.payload.requesting_uri;
        }
      }
    }
    console.log("Ticket doesn't contain a requesting_uri");
  }
  catch(err) {
    console.log("Unable to check State token: " + err.message + " :: " + token);
  }
  return null;
}

exports.oauth_redirect = function(uri, provider, referer) {
  // Check if the URI is in the /oauth/cognito so we're not creating a loop
  // If it is, set the requesting_uri to /
  var requesting_uri = "/" // sane default
  if (referer) {
    requesting_uri = referer;
  }
  else if (!uri.startsWith("/oauth")) {
    requesting_uri = uri
  }

  console.log(`Redirecting with requesting_uri ${requesting_uri}`)
  // Set the state with a token that will be valid for 5 minutes
  // If the user takes longer than 5 minutes on signup, they will have to start all over again
  var payload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now()/1000) + 300, token_use: "oauth", requesting_uri: requesting_uri };
  const mytoken = jsonwebtoken.sign(payload, env.JWTKEY);
  console.log(`Sending ${provider.local_oauth_name} with state key ${provider.provider_state_key}`);
  return redirect_response = {
    status: 302,
    statusDescription: 'Please authenticate',
    headers: {
      'location': [{
        "value": provider.provider_url + provider.provider_authorize_path +
          "?client_id=" + provider.client_id +
          "&redirect_uri=" + env.DISTRIBUTION_DOMAIN + "/oauth/" + provider.local_oauth_name + provider.local_token_path +
          "&response_type=code" +
          "&scope=" + provider.scopes +
          "&" + provider.provider_state_key + "=" + mytoken
      }]
    }
  };
}

exports.final_redirect = function(next_uri, token, provider) {
  // Check if the URI is in the /oauth/cognito so we're not creating a loop
  // If it is, set the requesting_uri to /
  var requesting_uri = next_uri;
  if (!requesting_uri || requesting_uri.startsWith("/oauth")) {
    requesting_uri = "/";
  }

  return redirect_response = {
    status: 302,
    statusDescription: 'Authenticated, redirecting...',
    headers: {
      'location': [{
        "value": requesting_uri + "?" + provider.querystring_parameter_key + "=" + token
      }]
    }
  };
}
