const lambda = require('../index');
const env = require ('../env');
const fetchMock = require('node-fetch');

jest.mock('jsonwebtoken');
const jsonwebtoken = require('jsonwebtoken');
const jwt = jest.requireActual('jsonwebtoken');

beforeEach(() => {
  fetchMock.reset();
})

test('Cognito Request', (done) => {
  context = {};

  const requestEvent = {
    Records: [{
      cf: {
        config: {
          distributionDomainName: 'd3w0vcdkic0509.cloudfront.net',
          distributionId: 'E22OQNGWSII4XH',
          eventType: 'viewer-request',
          requestId: 'rPxH-6zkr3ztK412y02nuJd9zNoW6lbqxTamQV3BBgE1UpYVM-PBQQ=='
        },
        request: {
          clientIp: '89.177.92.46',
          headers: {
            host: [{
              key: 'Host',
              value: 'bob2.redlabnet.com'
            }],
            'user-agent': [{
              key: 'User-Agent',
              value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36'
            }],
            'upgrade-insecure-requests': [{
              key: 'Upgrade-Insecure-Requests',
              value: '1'
            }],
            dnt: [{
              key: 'DNT',
              value: '1'
            }],
            accept: [{
              key: 'Accept',
              value: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
            }],
            referer: [{
              key: 'Referer',
              value: 'https://bob2.redlabnet.com/'
            }],
            'accept-encoding': [{
              key: 'Accept-Encoding',
              value: 'gzip, deflate, br'
            }],
            'accept-language': [{
              key: 'Accept-Language',
              value: 'en-CA,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,fr;q=0.6'
            }]
          },
          method: 'GET',
          querystring: '',
          uri: '/oauth/cognito/authorize'
        }
      }
    }]
  };
const returnEvent = {
  "headers": {
    "location": [{
      "value": "https://myidp.somewhere.internal/login?client_id=myoauth2clientid&redirect_uri=http://localhost:3000/oauth/cognito/access_token&response_type=code&scope=openid+email&state=abcdef0123456789"
    }]
  },
  "status": 302,
  "statusDescription": "Please authenticate"
};
  jsonwebtoken.sign.mockReturnValue("abcdef0123456789");
  function callback(err, data) {
    expect(data).toEqual(returnEvent);
    done();
  };
  lambda.handler(requestEvent, context, callback)
});



test('Github access_token reply', (done) => {

  // We need an actual signed token
  const accessPayload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now() / 1000 ) + 5000, token_use: "access" };
  const accessHeader = { kid: 'somekey' };
  const accessToken = jwt.sign(accessPayload, 'somekey', { header: accessHeader});

  const statePayload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now()/1000) + 5000, token_use: "oauth", requesting_uri: "/sendmehere" };
  const stateToken = jwt.sign(statePayload, env.JWTKEY);

  console.log("Access token " + accessToken);
  console.log(jwt.verify(stateToken, env.JWTKEY, { token_use: 'access', complete: true }));
  context = {};
  const requestEvent = {
    Records: [{
      cf: {
        config: {
          distributionDomainName: 'd3w0vcdkic0509.cloudfront.net',
          distributionId: 'E22OQNGWSII4XH',
          eventType: 'viewer-request',
          requestId: 'qcRHsJdt_JxZVeXuiaHmuOzs70GsjWhbR6aHUT2CM_HgrXsB_xJzaA=='
        },
        request: {
          clientIp: '213.151.83.246',
          headers: {
            host: [{
              key: 'Host',
              value: 'bob2.redlabnet.com'
            }],
            'user-agent': [{
              key: 'User-Agent',
              value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36'
            }],
            pragma: [{
              key: 'Pragma',
              value: 'no-cache'
            }],
            'cache-control': [{
              key: 'Cache-Control',
              value: 'no-cache'
            }],
            'upgrade-insecure-requests': [{
              key: 'Upgrade-Insecure-Requests',
              value: '1'
            }],
            dnt: [{
              key: 'DNT',
              value: '1'
            }],
            accept: [{
              key: 'Accept',
              value: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
            }],
            referer: [{
              key: 'Referer',
              value: 'https://github.com/'
            }],
            'accept-encoding': [{
              key: 'Accept-Encoding',
              value: 'gzip, deflate, br'
            }],
            'accept-language': [{
              key: 'Accept-Language',
              value: 'en-CA,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,fr;q=0.6'
            }],
            cookie: [{
              key: 'Cookie',
              value: 'sessiontoken=' + accessToken
            }]
          },
          method: 'GET',
          querystring: 'code=35a9f979ea6c72130594&state=' + stateToken,
          uri: '/oauth/github/access_token'
        }
      }
    }]
  };

const returnEvent = {
  "headers": {
    "location": [{
      "value": "/sendmehere?githubtoken=abcdef0123456"
    }]
  },
  "status": 302,
  "statusDescription": "Authenticated, redirecting..."
};
  jsonwebtoken.sign.mockReturnValue("abcdef0123456789");

  jsonwebtoken.decode.mockImplementation((token, params) => {
    return jwt.decode(token, params);
  });
  jsonwebtoken.verify.mockImplementation((jwtToken, pem, params ) => {
    return jwt.verify(jwtToken, pem, params);
  });
  const token_response = { body: { access_token: "abcdef0123456" }, status: 200};
  fetchMock.post("begin:" + env.OAUTH_PROVIDERS.github.provider_url, token_response);
  function callback(err, data) {
    expect(data).toEqual(returnEvent);
    done();
  };
  lambda.handler(requestEvent, context, callback)
});

test('Github access_token reply with bad authentication', (done) => {

  // We need an actual signed token
  const accessPayload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now() / 1000 ) - 5000, token_use: "access" };
  const accessHeader = { kid: 'somekey' };
  const accessToken = jwt.sign(accessPayload, 'somekey', { header: accessHeader});

  const statePayload = { iat: Math.floor(Date.now() / 1000 ), exp: Math.floor(Date.now()/1000) + 5000, token_use: "oauth", requesting_uri: "/sendmehere" };
  const stateToken = jwt.sign(statePayload, env.JWTKEY);

  console.log("Access token " + accessToken);
  console.log(jwt.verify(stateToken, env.JWTKEY, { token_use: 'access', complete: true }));
  context = {};
  const requestEvent = {
    Records: [{
      cf: {
        config: {
          distributionDomainName: 'd3w0vcdkic0509.cloudfront.net',
          distributionId: 'E22OQNGWSII4XH',
          eventType: 'viewer-request',
          requestId: 'qcRHsJdt_JxZVeXuiaHmuOzs70GsjWhbR6aHUT2CM_HgrXsB_xJzaA=='
        },
        request: {
          clientIp: '213.151.83.246',
          headers: {
            host: [{
              key: 'Host',
              value: 'bob2.redlabnet.com'
            }],
            'user-agent': [{
              key: 'User-Agent',
              value: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36'
            }],
            pragma: [{
              key: 'Pragma',
              value: 'no-cache'
            }],
            'cache-control': [{
              key: 'Cache-Control',
              value: 'no-cache'
            }],
            'upgrade-insecure-requests': [{
              key: 'Upgrade-Insecure-Requests',
              value: '1'
            }],
            dnt: [{
              key: 'DNT',
              value: '1'
            }],
            accept: [{
              key: 'Accept',
              value: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
            }],
            referer: [{
              key: 'Referer',
              value: 'https://github.com/'
            }],
            'accept-encoding': [{
              key: 'Accept-Encoding',
              value: 'gzip, deflate, br'
            }],
            'accept-language': [{
              key: 'Accept-Language',
              value: 'en-CA,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,fr;q=0.6'
            }],
            cookie: [{
              key: 'Cookie',
              value: 'sessiontoken=' + accessToken
            }]
          },
          method: 'GET',
          querystring: 'code=35a9f979ea6c72130594&state=' + stateToken,
          uri: '/oauth/github/access_token'
        }
      }
    }]
  };

const returnEvent = {
  "headers": {
    "location": [{
      "value": "https://myidp.somewhere.internal/login?client_id=myoauth2clientid&redirect_uri=http://localhost:3000/oauth/cognito/access_token&response_type=code&scope=openid+email&state=abcdef0123456789"
    }]
  },
  "status": 302,
  "statusDescription": "Please authenticate"
};
  jsonwebtoken.sign.mockReturnValue("abcdef0123456789");

  jsonwebtoken.decode.mockImplementation((token, params) => {
    return jwt.decode(token, params);
  });
  jsonwebtoken.verify.mockImplementation((jwtToken, pem, params ) => {
    return jwt.verify(jwtToken, pem, params);
  });
  const token_response = { body: { access_token: "abcdef0123456" }, status: 200};
  fetchMock.post("begin:" + env.OAUTH_PROVIDERS.github.provider_url, token_response);
  function callback(err, data) {
    expect(data).toEqual(returnEvent);
    done();
  };
  lambda.handler(requestEvent, context, callback)
});
