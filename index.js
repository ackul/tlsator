var tls = require('tls');
    fs = require('fs');

var options = {
  key: fs.readFileSync('certs\\tlsator.com.key'),
  cert: fs.readFileSync('certs\\tlsator.com.cert')
};

// A secure (TLS) socket server.

tls.createServer(options, function (s) {
  s.write("welcome!\n");
  //s.pipe(s);
}).listen(8000);
