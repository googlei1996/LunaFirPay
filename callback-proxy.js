/**
 * 回调代理服务器
 * 监听端口：6666 
 * 请求格式：POST https://proxy.domain.com/https://merchant.com/notify
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const PORT = 6666;

// 所有常见“IP / 来源”相关 header
const IP_HEADERS = [
  // 通用 / RFC
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'forwarded',
  'via',
  'client-ip',
  'remote-addr',
  'true-client-ip',

  // Cloudflare
  'cf-connecting-ip',
  'cf-connecting-ipv6',
  'cf-pseudo-ipv4',
  'cf-ray',
  'cf-visitor',

  // AWS (ALB / ELB / API Gateway / CloudFront)
  'x-amzn-trace-id',
  'x-amzn-cf-id',
  'x-amz-cf-pop',
  'x-amzn-requestid',
  'x-amzn-remote-ip',

  // Azure / Edge
  'x-azure-clientip',
  'x-arr-clientip',
  'x-edge-client-ip',

  // Fastly / Akamai / CDN
  'fastly-client-ip',
  'akamai-origin-hop',
  'x-akamai-edgescape',

  // Google Cloud
  'x-goog-iap-client-ip',
  'x-cloud-trace-context',

  // 其他
  'x-real-ip',
  'x-client-ip',
  'x-originating-ip'
];

const server = http.createServer(async (req, res) => {
  const originalUrl = req.url.startsWith('/') ? req.url.slice(1) : req.url;

  if (!originalUrl.startsWith('http://') && !originalUrl.startsWith('https://')) {
    res.writeHead(400);
    res.end('Invalid URL');
    return;
  }

  try {
    const url = new URL(originalUrl);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    // 复制 headers
    const headers = { ...req.headers };

    // 移除所有 IP / 来源标头
    for (const h of IP_HEADERS) {
      delete headers[h];
    }

    // 连接相关 header 也不需要
    delete headers['connection'];

    // 设置目标 host
    headers['host'] = url.host;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: req.method,
      headers,
      rejectUnauthorized: false
    };

    const proxyReq = lib.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', () => {
      res.writeHead(502);
      res.end('Proxy Error');
    });

    req.pipe(proxyReq);

  } catch (e) {
    res.writeHead(500);
    res.end('Error');
  }
});

server.listen(PORT);
