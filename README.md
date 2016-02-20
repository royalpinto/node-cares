[![Build Status](https://travis-ci.org/royalpinto/node-cares.svg?branch=dev)](https://travis-ci.org/royalpinto/node-cares)

node-cares
===

node.js interface to [c-ares](http://c-ares.haxx.se/) library
------

Forked from node.js dns module, node-cares provides node.js interface to c-ares library.

#### Features:
 * Supports all stable versions of `node.js` **>= 0.10.0**.
 * Matching APIs to the upstream node.js dns module.
 * Additional **query** API to retrieve all headers and resource records.
 * Additional class **Resolver** to query by customized c-ares channel.

Installation
------

You can install with `npm`:

``` bash
$ npm install cares
```

API docs
------

In addition to mapping [APIs](http://nodejs.org/docs/latest/api/dns.html) from node.js dns module, following APIs are available:
- **Resolver([options])** - allows creating c-ares_channel instance to query by customized options. All APIs available under cares lib will be available under Resolver instance as well. Resolver creation takes an optional object with the following fields (For detailed information on these options, visit: [here](http://c-ares.haxx.se/ares_init.html))
    * `timeout`: The number of milliseconds each name server is given to respond to a query on the first try. (After the first try, the timeout algorithm becomes more complicated, but scales linearly with the value of timeout.) The default is five seconds.
    * `tries`: The number of tries the resolver will try contacting each name server before giving up. The default is four tries.
    * `ndots`: The number of dots which must be present in a domain name for it to be queried for "as is" prior to querying for it with the default domain extensions appended. The default value is 1 unless set otherwise by resolv.conf or the RES_OPTIONS environment variable.
    * `tcp_port`: The tcp port to use for queries.
    * `udp_port`: The udp port to use for queries.
    * `servers`: an array of IP addresses as strings, set them as the servers to use for resolving.
    * `flags`: the flags field should be the bitwise or of some subset of the following values:
        - `ARES_FLAG_USEVC` Always use TCP queries (the "virtual circuit") instead of UDP queries. Normally, TCP is only used if a UDP query yields a truncated result.
        - `ARES_FLAG_PRIMARY` Only query the first server in the list of servers to query.
        - `ARES_FLAG_IGNTC` If a truncated response to a UDP query is received, do not fall back to TCP; simply continue on with the truncated response.
        - `ARES_FLAG_NORECURSE` Do not set the "recursion desired" bit on outgoing queries, so that the name server being contacted will not try to fetch the answer from other servers if it doesn't know the answer locally. Be aware that ares will not do the recursion for you. Recursion must be handled by the application calling ares if `ARES_FLAG_NORECURSE` is set.
        - `ARES_FLAG_STAYOPEN` Do not close communications sockets when the number of active queries drops to zero.
        - `ARES_FLAG_NOSEARCH` Do not use the default search domains; only query hostnames as-is or as aliases.
        - `ARES_FLAG_NOALIASES` Do not honor the HOSTALIASES environment variable, which normally specifies a file of hostname translations.
        - `ARES_FLAG_NOCHECKRESP` Do not discard responses with the SERVFAIL, NOTIMP, or REFUSED response code or responses whose questions don't match the questions in the request. Primarily useful for writing clients which might be used to test or debug name servers. (NOTE: this is set by default for internal use.)

An example usage of this API is shown below:
```js
var cares = require('cares'),
    resolver1,
    resolver2,
    hostname = 'www.github.com';

resolver1 = new cares.Resolver({
    servers: ['198.41.0.4']
});

resolver2 = new cares.Resolver({
    servers: ['192.228.79.201']
});

resolver1.query(hostname, function (err, response) {
    if (err) { throw err; }
    response.answer.forEach(function (a) {
        console.log("Response from resolver1: ", a);
    });
});

resolver2.query(hostname, function (err, response) {
    if (err) { throw err; }
    response.answer.forEach(function (a) {
        console.log("Response from resolver2: ", a);
    });
});
```

- **cares.query(hostname[, options], callback)** - resolves `hostname` with options and returns all the headers and resource records.
	* `hostname`: Hostname to resolve.
	* `options`: Optional options must be an object containing following properties:
		- `class`: An integer representing qclass. Possible class constants are `cares.NS_C_*` (default `cares.NS_C_IN`).
		- `type`: An integer representing qtype. Possible type constants are `cares.NS_T_*` (default `cares.NS_T_A`).
	* `callback(err, response)`: A callback function will be called with error and response object. In case of an error, err will be an instance of `Error`. In case of success, err will be null and response will contain following fields:
		- `header`:
			* `id`: Request id
			* `qr`: Is a query response
			* `opcode`: opcode
			* `aa`: Authoritative Answer
			* `tc`: Truncation bit
			* `rd`: Recursion Desired.
			* `ra`: Recursion Available.
			* `rcode`: Response Code.
		- `question`: Array of questions containing following properties.
			* `name`
			* `class`
			* `type`
		- `authority`: Array of authorities.
		- `additional`: Array of additional records.
		- `answer`: Array of answers containing following fields(applicable for `authority` and `additional` as well).
			* `name`: The name of the resource
			* `type`: The numerical representation of the resource record type
			* `class`: The numerical representation of the class of service (usually 1 for internet)
			* `ttl`: The Time To Live for the record, in seconds

			Depending on the type following fields are available:

			* `cares.NS_T_SOA`
				- `primary`: string
				- `admin`: string
				- `serial`: number
				- `refresh`: number
				- `retry`: number
				- `expiration`: number
				- `minimum`: number
			* `cares.NS_T_A` and `cares.NS_T_AAAA`
				- `address`: string
			* `cares.NS_T_MX`
				- `priority`: number
				- `exchange`: string
			* `cares.NS_T_TXT`
				- `data`: array of strings
			* `cares.NS_T_SRV`
				- `priority`: number
				- `weight`: number
				- `port`: number
				- `target`: string
			* `cares.NS_T_NS`
				- `data`: string
			* `cares.NS_T_CNAME`
				- `data`: string
			* `cares.NS_T_PTR`
				- `data`: string
			* `cares.NS_T_NAPTR`
				- `order`: number
				- `preference`: number
				- `flags`: string
				- `service`: string
				- `regexp`: string
				- `replacement`: string


An example usage of this API is shown below.
```js
var cares = require('cares');

cares.query('www.github.com', {
    type: cares.NS_T_A,
    class: cares.NS_C_IN,
}, function (err, response) {
    if (err) { throw err; }
    response.answer.forEach(function (a) {
        console.log(a);
    });
});
```
