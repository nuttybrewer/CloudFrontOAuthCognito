const fetch = require('node-fetch');
const util = require('util');
var jwkToPem = require('jwk-to-pem');
var jwt = require('jsonwebtoken');

return fetch('https://cognito-idp.' +
              process.env.AWS_DEFAULT_REGION +
              '.amazonaws.com/' +
              process.env.COGNITO_USERPOOL_ID +
              '/.well-known/jwks.json'
  )
  .then(res => res.json())
  .then(json => {
    var pems = {}
    const keys = json.keys;
    for(var i = 0; i < keys.length; i++) {
        //Convert each key to PEM
        var key_id = keys[i].kid;
        var modulus = keys[i].n;
        var exponent = keys[i].e;
        var key_type = keys[i].kty;
        var jwk = { kty: key_type, n: modulus, e: exponent};
        var pem = jwkToPem(jwk);
        pems[key_id] = pem;
    }
    process.env.COGNITO_JWKS = pems;
    console.log(util.inspect(pems, {
      showHidden: false,
      depth: null
    }));
  })
  .catch(error => {
    console.log(error);
  });
