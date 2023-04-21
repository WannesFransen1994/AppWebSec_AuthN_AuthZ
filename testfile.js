const { Buffer } = require('node:buffer');
const { createHmac } = require('node:crypto');

const header = { alg: "HS256", typ: "JWT" }
const content = { user: "wannes" }


const buf_header = Buffer.from(JSON.stringify(header), 'utf8');
const buf_content = Buffer.from(JSON.stringify(content), 'utf8');

const header_base64 = buf_header.toString('base64url');
const content_base64 = buf_content.toString('base64url');
console.log(header_base64);
console.log(content_base64);

const signature_base = header_base64 + "." + content_base64;


const hmac = createHmac('sha256', 'aa;kl;sdaflk;iouv;afd;awesfij;skdafjsecret');
hmac.update(signature_base);
const signature = hmac.digest('base64url');
console.log(signature_base + "." + signature);

