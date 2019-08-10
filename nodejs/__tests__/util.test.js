const jwt = require('../jwt.js');
const jsonwebtoken = require('jsonwebtoken');
const util = require('../util.js');
const env = require ('../env.js');

beforeEach(() => {
  jest.resetModules();
});


test('extract_cookies()', () => {
  const header = {
    cookie: [{key: 'cookie1', value:'cookie1=bob'},{key: 'cookie2', value: 'cookie2=fred'}]
  };
  expect(util.extract_cookie(header, 'cookie1')).toEqual('bob');
});

test('oauth_state_check() with a valid JWT', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now() / 1000 ) + 5000, token_use: "oauth", requesting_uri: "/somepath" };
  const mytoken = jsonwebtoken.sign(payload, env.JWTKEY);
  expect(util.oauth_state_check(mytoken)).toBe('/somepath');
});

test('oauth_state_check() with an expired JWT', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ) - 5000, exp: Math.floor(Date.now() / 1000 ) - 4000 , token_use: "oauth", requesting_uri: "/somepath" };
  const mytoken = jsonwebtoken.sign(payload, env.JWTKEY);
  expect(util.oauth_state_check(mytoken)).toBeNull();
});

test('oauth_state_check() with a bogus JWT', () => {
  const mytoken = "bogusvalue";
  expect(util.oauth_state_check(mytoken)).toBeNull();
});

test('oauth_state_check() with a valid JWT but no requesting_uri', () => {
  var payload = { iat: Math.floor(Date.now() / 1000 ), token_use: "oauth" };
  const mytoken = jsonwebtoken.sign(payload, env.JWTKEY);
  expect(util.oauth_state_check(mytoken)).toBeNull();
});

test('final_redirect()', () => {
  const expected = {"headers": {"location": [{"value": "uri?provider=token"}]}, "status": 302, "statusDescription": "Authenticated, redirecting..."}
  expect(util.final_redirect("uri", "token", { querystring_parameter_key: "provider" })).toEqual(expected);
});

test('final_redirect() to an oauth endpoint', () => {
  const expected = {"headers": {"location": [{"value": "/?provider=token"}]}, "status": 302, "statusDescription": "Authenticated, redirecting..."}
  expect(util.final_redirect("/oauth/cognito/something/here", "token", { querystring_parameter_key: "provider" })).toEqual(expected);
});
