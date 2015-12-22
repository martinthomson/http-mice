'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');

var header;
var input = new Buffer([]);
var rs = 4096;
var lastHash;
var one = new Buffer([1]);

function parseParameter(a, x) {
  var v = true;
  var idx = x.indexOf('=');
  if (idx >= 0) {
    v = x.slice(idx + 1).trim();
    if (v[0] === '"') {
      v = v.slice(1, v.length - 1);
    }
  }
  a[x.slice(0, idx).trim()] = v;
  return a;
}

function parseParameters(x) {
  return x.split(';').reduce(parseParameter, {});
}

function parseHeader(a, x) {
  var idx = x.indexOf(':');
  if (idx < 0) {
    throw new Error('missing colon');
  }
  a[x.slice(0, idx).trim()] = x.slice(idx + 1).split(',').map(parseParameters);
  return a;
}

function parseHeaderBlock() {
  if (header) {
    return;
  }

  var idx = input.indexOf('\r\n\r\n');
  if (idx < 0) {
    return;
  }
  var rawheaders = input.slice(0, idx).toString('utf-8');
  input = input.slice(idx + 4);
  header = rawheaders.split('\r\n').reduce(parseHeader, {});
  if (!header.MI || !header.MI[0] || !header.MI[0].p) {
    throw new Error('MI header field with p parameter missing');
  }
  rs = parseInt(header.MI[0].rs, 10) || 4096;
  lastHash = base64.decode(header.MI[0].p);
}

function check(data) {
  var sha = crypto.createHash('sha256');
  data.forEach(function(d) {
    sha.update(d);
  });
  var h = sha.digest();
  if (Buffer.compare(h, lastHash) !== 0) {
    throw new Error('validation error');
  }
}

function validateNext() {
  if (!lastHash) {
    return;
  }
  while (input.length >= rs + 32) {
    check([input.slice(0, rs + 32), one]);
    process.stdout.write(input.slice(0, rs));
    lastHash = input.slice(rs, rs + 32);
    input = input.slice(rs + 32);
  }
}

process.stdin.on('readable', function() {
  var chunk;
  while ((chunk = process.stdin.read()) !== null) {
    input = Buffer.concat([input, chunk]);
    parseHeaderBlock();
    validateNext();
  }
});

process.stdin.on('end', function() {
  var zero = new Buffer([0]);
  check([input, zero]);
  process.stdout.write(input);
});
