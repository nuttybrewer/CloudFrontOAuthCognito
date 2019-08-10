/* istanbul ignore file */
const jwt = require('../jwt.js');
const jsonwebtoken = require('jsonwebtoken');

beforeEach(() => {
  jest.resetModules();
});


test('Bad JWT check', () => {
  // Set up mocked up JWT access token
  const mytoken = "Invalid Token";
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(false);
});

test('JWT signed by an unknown key', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ), token_use: "access" };
  var header = { kid: 'someotherkey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(false);
});

test('JWT check with issued_time and token_use only', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ), token_use: "access" };
  var header = { kid: 'somekey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(true);
});

test('JWT check with issued_time in the future and token_use only (TODO: broken, need to fill report with project!)', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ) + 2000, token_use: "access" };
  var header = { kid: 'somekey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(true);
});

test('JWT check with bad token_use', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ) + 2000, token_use: "id_token" };
  var header = { kid: 'somekey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(false);
});

test('JWT check with expiry statement', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now() / 1000 ) + 3000, token_use: "access" };
  var header = { kid: 'somekey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(true);
});

test('JWT check expired', () => {
  // Set up mocked up JWT access token
  var payload = { iat: Math.floor(Date.now() / 1000 )-3000, exp: Math.floor(Date.now() / 1000 ) - 1000, token_use: "access" };
  var header = { kid: 'somekey' };
  const mytoken = jsonwebtoken.sign(payload, 'somekey', { header: header});
  console.log(jsonwebtoken.decode(mytoken, {complete: true }));

  expect(jwt.verifyToken(mytoken)).toBe(false);
});
