'use strict';

/**
 * Deliberately misconfigured target for testing parapet-scan.
 *
 * This server exists to produce findings. Every weakness below is intentional
 * and is asserted by tests/integration. It listens on loopback inside a
 * container, has no dependencies, stores nothing, and none of the credentials
 * it serves are real.
 *
 * Do not deploy this. See lab/README.md.
 */

const { createServer } = require('node:http');

const PORT = Number(process.env.PORT || 8080);

// Obviously fake. Shaped like a real dotenv file so the scanner's content
// signature matches, which is the behaviour under test.
const FAKE_ENV = [
  'DATABASE_URL=postgres://lab:not-a-real-password@localhost:5432/lab',
  'API_KEY=lab-000000000000000000000000',
  'SESSION_SECRET=lab-session-secret-placeholder',
  '',
].join('\n');

const VULNERABLE_PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="generator" content="LabCMS 4.2.1">
  <title>Lab target</title>
  <link rel="stylesheet" href="http://cdn.lab.invalid/styles.css">
</head>
<body>
  <h1>Deliberately misconfigured target</h1>

  <!-- Cross-origin script with no integrity attribute -->
  <script src="https://cdn.lab.invalid/analytics.js"></script>

  <!-- Same-origin bundle whose source map is exposed -->
  <script src="/static/app.js"></script>

  <!-- Password form posting over plaintext -->
  <form method="POST" action="http://lab.invalid/login">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>

  <!-- Cross-origin new-tab link without rel=noopener -->
  <a href="https://example.invalid/partner" target="_blank">Partner site</a>
</body>
</html>
`;

const HARDENED_PAGE = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Hardened</title></head>
<body><h1>Hardened endpoint</h1><p>Serves the headers the vulnerable page omits.</p></body>
</html>
`;

const APP_JS = 'console.log("lab bundle");\n//# sourceMappingURL=/static/app.js.map\n';

const APP_JS_MAP = JSON.stringify({
  version: 3,
  file: 'app.js',
  sources: ['src/secret-internal-module.ts'],
  sourcesContent: ['export const internalFlag = "lab";\n'],
  mappings: 'AAAA',
});

const server = createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const origin = request.headers.origin;

  // Reflects any Origin and permits credentials -- the CORS finding under test.
  if (origin) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (request.method === 'OPTIONS') {
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    response.setHeader('Access-Control-Allow-Headers', 'authorization, content-type');
    response.writeHead(204).end();
    return;
  }

  switch (url.pathname) {
    case '/':
      // Version-bearing banners, and cookies with no protective attributes.
      response.setHeader('Server', 'LabServer/1.4.2');
      response.setHeader('X-Powered-By', 'Express 4.18.2');
      response.setHeader('Set-Cookie', [
        'sessionid=lab-session-value; Path=/',
        'theme=dark; Path=/; SameSite=Lax',
        '__Host-pref=1; Path=/settings',
      ]);
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end(VULNERABLE_PAGE);
      return;

    case '/hardened':
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy':
          "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      });
      response.end(HARDENED_PAGE);
      return;

    case '/static/app.js':
      response.writeHead(200, { 'Content-Type': 'application/javascript' });
      response.end(APP_JS);
      return;

    // Source map left in the deployment artefact.
    case '/static/app.js.map':
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(APP_JS_MAP);
      return;

    // Repository metadata served from the web root.
    case '/.git/HEAD':
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('ref: refs/heads/main\n');
      return;

    case '/.git/config':
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('[core]\n\trepositoryformatversion = 0\n\tbare = false\n');
      return;

    case '/.env':
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end(FAKE_ENV);
      return;

    case '/robots.txt':
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('User-agent: *\nDisallow:\n');
      return;

    case '/healthz':
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('ok\n');
      return;

    default:
      // A styled 404 returned with a 200 status, so a scanner that keys on
      // status codes alone reports every probed path as exposed. The signature
      // matching in the exposure collector is what this is here to exercise.
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      response.end('<!doctype html><html><body><h1>Not found</h1></body></html>');
      return;
  }
});

server.listen(PORT, () => {
  process.stdout.write(`lab target listening on ${PORT}\n`);
});
