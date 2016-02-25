var dns = require('native-dns');
var dnsentries = require('./dnsentries.js');

var server = dns.createServer();

server.on('request', function (request, response) {

  var question = request.question[0];
  var class_data = dnsentries[question.class];
  var rrtype_data = class_data[question.type];

  rrtype_data[question.name]['answer'].forEach(function (entry) {
	response.answer.push(entry);
  });

  response.additional.push(dns.A({
    name: 'hostA.example.org',
    address: '127.0.0.3',
    ttl: 600,
  }));
  response.send();
});

server.on('error', function (err, buff, req, res) {
  console.error(err.stack);
});

server.serve(8080);
