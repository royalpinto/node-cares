// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var cares = require('./../build/Release/cares_wrap'),
    util = require('util'),
    isFunction = util.isFunction || function (arg) {
        return typeof arg === 'function';
    },
    isString = util.isString || function (arg) {
      return typeof arg === 'string';
    };


function errnoException(errorno, syscall) {
  // TODO make this more compatible with ErrnoException from src/node.cc
  // Once all of Node is using this function the ErrnoException from
  // src/node.cc should be removed.

  // For backwards compatibility. libuv returns ENOENT on NXDOMAIN.
  if (errorno == 'ENOENT') {
    errorno = 'ENOTFOUND';
  }

  var e = new Error(syscall + ' ' + errorno);

  e.errno = e.code = errorno;
  e.syscall = syscall;
  return e;
}


// c-ares invokes a callback either synchronously or asynchronously,
// but the dns API should always invoke a callback asynchronously.
//
// This function makes sure that the callback is invoked asynchronously.
// It returns a function that invokes the callback within nextTick().
//
// To avoid invoking unnecessary nextTick(), `immediately` property of
// returned function should be set to true after c-ares returned.
//
// Usage:
//
// function someAPI(callback) {
//   callback = makeAsync(callback);
//   channel.someAPI(..., callback);
//   callback.immediately = true;
// }
function makeAsync(callback) {
  if (!isFunction(callback)) {
    return callback;
  }
  return function asyncCallback() {
    if (asyncCallback.immediately) {
      // The API already returned, we can invoke the callback immediately.
      callback.apply(null, arguments);
    } else {
      var args = arguments;
      process.nextTick(function() {
        callback.apply(null, args);
      });
    }
  };
}


function resolver(bindingName) {
  var binding = cares[bindingName];

  return function query(name, callback) {

    if (!isString(name)) {
      throw new Error('Name must be a string');
    } else if (!isFunction(callback)) {
      throw new Error('Callback must be a function');
    }

    function onanswer(status, result) {
      if (!status) {
        callback(null, result);
      } else {
        callback(errnoException(status, bindingName));
      }
    }

    callback = makeAsync(callback);
    var err = binding(name, onanswer);
    if (err) {
      throw errnoException(err, bindingName);
    }

    callback.immediately = true;
    return err;
  }
}

var resolveMap = {};
exports.resolve4 = resolveMap.A = resolver('queryA');
exports.resolve6 = resolveMap.AAAA = resolver('queryAaaa');
