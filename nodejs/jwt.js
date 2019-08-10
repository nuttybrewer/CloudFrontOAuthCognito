const env = require('./env');
const util = require('util');
var jwt = require('jsonwebtoken');

exports.verifyToken = (jwtToken) => {
  var pems = env.COGNITO_JWKS;

  console.log(util.inspect(pems, {
    showHidden: false,
    depth: null
  }));

  const decodedJwt = jwt.decode(jwtToken, {complete: true});

  if (!decodedJwt) {
    console.log("Not a valid JWT token" + util.inspect(jwtToken, {
      showHidden: false,
      depth: null
    }));
    return false;
  }

  //Fail if token is not from your UserPool
  // if (decodedJwt.payload.iss != iss) {
  //     const err = new Error("invalid issuer");
  //     console.log(err.message);
  //     callback(err, null);
  //     return false;
  // }

  //Reject the jwt if it's not an 'Access Token'
  if (decodedJwt.payload.token_use != 'access') {
      console.log("Not an access token");
      return false;
  }

  //Get the kid from the token and retrieve corresponding PEM
  var kid = decodedJwt.header.kid;
  var pem = pems[kid];
  if (!pem) {
      console.log("Invalid access token, no related pems for " + kid);
      return false;
  }

  try {
    const payload = jwt.verify(jwtToken, pem, { token_use: 'access', complete: true });
    return true;
  }
  catch(err){
    console.log('Unable to verify token ' + err.message);
    return false;
  }
};
