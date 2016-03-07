var dns = require('native-dns');
var dnsentries = require('./dnsentries.js');

var server = dns.createUDPServer();

server.on('request', function (request, response) {

    var question = request.question[0];

    var class_data = dnsentries[question.class];
    var rrtype_data = class_data[question.type];

    (function () {
        var answer = rrtype_data[question.name]['answer'];
        if (answer) {
            answer.forEach(function (entry) {
            response.answer.push(entry);
            });
        }
    })();

    (function () {
        var additional = rrtype_data[question.name]['additional'];
        if (additional) {
            additional.forEach(function (entry) {
                response.additional.push(entry);
            });
        }
    })();

    response.send();
});

server.on('error', function (err, buff, req, res) {
    console.error(err.stack);
});

server.serve(8080);
