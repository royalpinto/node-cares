module.exports = {
	1: { // Class: IN
		1: { // RR Type: A
			'www.something.com': {
				answer: [{
					name: 'www.something.com.',
					data: 'cname1.something.com.',
					ttl: 600,
					type: 5,
					class: 1,
				}, {
					name: 'cname1.something.com.',
					data: 'cname2.something.com.',
					ttl: 600,
					type: 5,
					class: 1,
				}, {
					name: 'cname2.something.com.',
					address: '127.0.0.1',
					ttl: 600,
					type: 1,
					class: 1,
				}, {
					name: 'cname2.something.com.',
					address: '127.0.0.2',
					ttl: 600,
					type: 1,
					class: 1,
				}],
			},
		},
		88: { //RR Type: AAAA
			'ipv6.something.com': {
				answer: [{
					name: 'ipv6.something.com.',
					data: 'cname1.ipv6.something.com.',
					ttl: 600,
					type: 5,
					class: 1,
				}, {
					name: 'ipv6.something.com.',
					data: 'cname2.ipv6.something.com.',
					ttl: 600,
					type: 5,
					class: 1,
				}, {
					name: 'cname1.ipv6.something.com.',
					address: '2404:6800:4007:807::200e',
					ttl: 600,
					type: 28,
					class: 1,
				}, {
					name: 'cname2.ipv6.something.com.',
					address: '2404:6800:4007:807::200d',
					ttl: 600,
					type: 28,
					class: 1,
				}],
			},
		},
		5: { // RR Type: CNAME
			'www.something.com': {
				answer: [{
					name: 'www.something.com.',
					data: 'cname1.something.com.',
					ttl: 600,
					type: 5,
					class: 1,
				}],
			},
		},
		15: { // RR Type: MX
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					exchange: 'mx.www.something.com',
					priority: 1,
					ttl: 600,
					type: 15,
					class: 1,
				}],
			},
		},
		2: { // RR Type: NS
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					data: 'ns.www.something.com',
					ttl: 600,
					type: 2,
					class: 1,
				}],
			},
		},
		16: { // RR Type: TXT
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					data: ["v=spf1 include:_spf.something.com ~all"],
					ttl: 600,
					type: 16,
					class: 1,
				}],
			},
		},
		33: { // RR Type: SRV
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					priority: 1,
					weight: 1,
					port: 8000,
					target: 'srv.www.something.com',
					ttl: 600,
					type: 33,
					class: 1,
				}]
			},
		},
		35: { //RR Type: NAPTR
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					order: 100,
					preference: 100,
					flags: 's',
					service: 'http+I2R',
					regexp: '',
					replacement: "_http._tcp.example.com",
					ttl: 600,
					type: 35,
					class: 1,
				}],
			},
		},
		6: { //RR Type SOA
			'www.something.com': {
				answer: [{
					name: 'www.something.com',
					primary: 'ns1.something.com',
					admin: 'admin.something.com',
					serial: 2009012202,
					refresh: 10800,
					retry: 3600,
					expiration: 604800,
					minimum: 3600,
					ttl: 600,
					type: 6,
					class: 1,
				}],
			},
		},
	},
};
