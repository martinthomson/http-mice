'use strict';

var base64 = require('urlsafe-base64');
var crypto = require('crypto');

var rs = 4096;
// the optional first argument is the record size
if (process.argv.length >= 3) {
  rs = parseInt(process.argv[2], 10);
}

var chunks = [];
process.stdin.on('readable', function() {
  var chunk;
  while ((chunk = process.stdin.read()) !== null) {
    chunks.push(chunk);
  }
});

function sha256(data) {
  var h = crypto.createHash('sha256');
  data.forEach(function(d) {
    h.update(d);
  });
  return h.digest();
}

process.stdin.on('end', function() {
  var input = Buffer.concat(chunks);
  var i = Math.floor((input.length - 1) / rs) * rs;
  var output = [];
  var chunk, lastHash;
  var zero = new Buffer([0]);
  var one = new Buffer([1]);

  var tail = input.slice(i);
  output.unshift(tail);
  lastHash = sha256([tail, zero]);
  output.unshift(lastHash);
  i -= rs;

  while (i >= 0) {
    chunk = input.slice(i, i + rs);
    output.unshift(chunk);
    lastHash = sha256([chunk, lastHash, one]);
    output.unshift(lastHash);
    i -= rs;
  }

  var frmi = output.shift();
  process.stdout.write('MI: mi-sha256=' + base64.encode(frmi) + '\r\n\r\n', 'utf-8');

  var header = new Buffer(8);
  header.writeUIntBE(rs, 0, 8);
  process.stdout.write(header);

  output.forEach(function(d) {
    process.stdout.write(d);
  });
});
