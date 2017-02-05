var dns = require('native-dns');
var dnsentries = require('./dnsentries.js');

var server = dns.createUDPServer();

server.on('request', function(request, response) {
    var question = request.question[0];

    var classData = dnsentries[question.class];
    var rrtypeData = classData[question.type];

    (function() {
        var answer = rrtypeData[question.name].answer;
        if (answer) {
            answer.forEach(function(entry) {
                response.answer.push(entry);
            });
        }
    })();

    (function() {
        var additional = rrtypeData[question.name].additional;
        if (additional) {
            additional.forEach(function(entry) {
                response.additional.push(entry);
            });
        }
    })();

    response.send();
});

server.on('error', function(err) {
    console.error(err.stack);
});

module.exports = server;
