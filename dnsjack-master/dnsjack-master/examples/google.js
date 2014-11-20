var jack = require('../').createServer();
// route all google domains to 127.0.0.1
jack.route(['google.com', '*.google.com'], function(domain, callback) {
    callback(null, '128.105.33.127');
});

jack.listen(); // it listens on the standard DNS port of 53 per default
