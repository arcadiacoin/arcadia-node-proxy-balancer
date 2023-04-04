var express = require('express');
var fs = require('fs');
var path = require('path');
var http = require('http');
var https = require('https');
var bodyParser = require('body-parser')
var app = express();
var router = express.Router();
var cors = require('cors');
var redis = require('redis');
var rateLimit = require('express-rate-limit');
var WebSocket = require('ws');

// DEFAULT SETTINGS
var runHTTPS = false;
var runHTTP = true;
var runWS = true;

var HTTPS_PORT = 7205;
var HTTP_PORT = 7206;
var HTTP_PATH = '/';
var WS_PORT = 7208;
var PREFIX_OVERRIDE = false;

var ENDPOINTS_PUBLIC = [{hostname:'127.0.0.1', port:'7046', path: '/'}];
var ENDPOINTS_PRIVATE = [{hostname:'127.0.0.1', port:'7046', path: '/'}];
var ENDPOINTS_HEAVY = [{hostname:'127.0.0.1', port:'7046', path: '/'}];
var ENDPOINT_WS = 'ws://127.0.0.1:7048';

// CERTIFICATE //
var privateKey = '/etc/letsencrypt/live/domain/privkey.pem';
var certificate = '/etc/letsencrypt/live/domain/cert.pem';
var ca = '/etc/letsencrypt/live/domain/chain.pem';

var limit_exclusion_ips = [];

var public_actions = [
	"accounts_balances",
	"accounts_frontiers",
	"accounts_pending",
	"account_info",
	"account_history",
	"active_difficulty",
	"block_count",
	"block_info",
	"blocks_info",
	"confirmation_history",
	"confirmation_quorum",
	"peers",
	"pending",
	"representatives",
	"representatives_online",
	"uptime",
	"version",
	"delegators"
];
var protected_actions = [
	"process",
];
var protected_heavy_actions = [
	"work_generate"
];

// Command Line Arguments
var argv = require('minimist')(process.argv.slice(2));

// Overwrite default settings
if(argv.configfile)
{
	console.log(argv.configfile);
	config = require(argv.configfile);
	
	if(config.runHTTPS)
		runHTTPS = config.runHTTPS;
	if(config.runHTTP)
		runHTTP = config.runHTTP;
	if(config.runWS)
		runWS = config.runWS;

	if(config.HTTPS_PORT)
		HTTPS_PORT = config.HTTPS_PORT;
	if(config.HTTP_PORT)
		HTTP_PORT = config.HTTP_PORT;
	if(config.HTTP_PATH)
		HTTP_PATH = config.HTTP_PATH;
	if(config.WS_PORT)
		WS_PORT = config.WS_PORT;
	if(config.PREFIX_OVERRIDE)
		PREFIX_OVERRIDE = config.PREFIX_OVERRIDE;

	if(config.ENDPOINTS_PUBLIC)
		ENDPOINTS_PUBLIC = config.ENDPOINTS_PUBLIC;
	if(config.ENDPOINTS_HEAVY)
		ENDPOINTS_HEAVY = config.ENDPOINTS_HEAVY;
	if(config.ENDPOINTS_PRIVATE)
		ENDPOINTS_PRIVATE = config.ENDPOINTS_PRIVATE;
	
	if(config.privateKey)
		limit_exclusion_ips = config.privateKey;
	if(config.certificate)
		certificate = config.certificate;
	if(config.ca)
		ca = config.ca;
	
	if(config.limit_exclusion_ips)
		limit_exclusion_ips = config.limit_exclusion_ips;
	
	if(config.public_actions)
		public_actions = config.public_actions;
	if(config.protected_actions)
		protected_actions = config.protected_actions;
	if(config.protected_heavy_actions)
		protected_heavy_actions = config.protected_heavy_actions;
}

/// Connect to redis

const redisClient = redis.createClient();
redisClient.on('error', err => {
    console.log('Error ' + err);
});
redisClient.connect();


///////////////
// Create an HTTP server
if(runHTTP)
{
	let server = http.createServer(app).listen(HTTP_PORT,function() {
	  console.log('Listening HTTP on port ' + HTTP_PORT);
	});
	server.on('connection', function(socket) {
	   console.log("A new connection was made by a client.");
	   socket.setTimeout(60 * 1000);
	});
}

// Create HTTPS server
if(runHTTPS)
{
	let privateKeyData = fs.readFileSync(privateKey, 'utf8');
	let certificateData = fs.readFileSync(certificate, 'utf8');
	let caData = fs.readFileSync(caData, 'utf8');
	let credentials = {key: privateKeyData, cert: certificateData, ca: caData};
	
	let server_https = https.createServer(credentials, app).listen(HTTPS_PORT,function() {
	  console.log('Listening HTTP on port ' + HTTPS_PORT);
	});
	server_https.on('connection', function(socket) {
	  console.log("A new connection was made by a client with IP address: " + socket.remoteAddress);
	  socket.setTimeout(60 * 1000);
	});
}


const apiLimiter = rateLimit({
	windowMs: 120, // 2 minutes
	max: 50, // 50 requests
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})
app.use(apiLimiter)

app.use(cors({
  'allowedHeaders': ['Content-Type', 'DNT', 'X-CustomHeader', 'Access-Control-Allow-Headers', 'User-Agent', 'X-Requested-With', 'If-Modified-Since', 'Cache-Control', 'Content-Type', 'Keep-Alive'], //
  'exposedHeaders': ['sessionId'],
  'origin': '*',
  'methods': 'GET, HEAD, OPTIONS',
  'preflightContinue': false,
  'credentials': true
}));
app.options('*', cors());

// Endpoint for forwarding
router.post(HTTP_PATH, bodyParser.text({
  type: ['json', 'text', 'application/*+json', 'application/x-www-form-urlencoded']
}), async function(req, res) {
	
	if (req.method == "OPTIONS") {
		console.log('OPTIONS');
		res.setHeader('Access-Control-Allow-Origin', '*');
		res.setHeader('Access-Control-Allow-Credentials', 'true');
		res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
		res.setHeader('Access-Control-Allow-Headers', 'DNT,X-CustomHeader,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Keep-Alive');//
		res.send('');
		return
	}

	let ip = typeof(req.headers['x-forwarded-for']) != 'undefined' ? req.headers['x-forwarded-for'] : req.connection.remoteAddress;
	console.log(ip + ' - REQUEST: ' + JSON.stringify(req.body));
	
	try
	{
		body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
	}
	catch (e) {
		console.log(e);
		res.send('{"result": "error"}');
		return;
	}
	
	// THROTTLING

	const unixTime = Math.floor(Date.now() / 1000);
	
	if(limit_exclusion_ips.indexOf(ip) == -1)
	{
		let throttle30 = {'requests' : 0, 'started' : unixTime};
		let throttle24hrs = {'requests' : 0, 'started' : unixTime};
		
		let cache = await redisClient.get('throttle:30min:['+ip+']');
		if(cache != null && JSON.parse(cache).started > (unixTime - 60*5))
			throttle30 = JSON.parse(cache);
			
		cache = await redisClient.get('throttle:24hrs:['+ip+']');
		if(cache != null && JSON.parse(cache).started > (unixTime - 60*60))
			throttle24hrs = JSON.parse(cache);
		
		if(protected_heavy_actions.indexOf(body.action) != -1)
		{			
			if(throttle30.requests > 90)
			{
				console.log(`${ip} - WORK LIMIT REACHED`)
				res.send('{"result": "error", "error":"too many requests, consider using your own node"}');
				return;
			}
			if(throttle24hrs.requests > 600)
			{
				console.log(`${ip} - WORK LIMIT REACHED`)
				res.send('{"result": "error", "error":"too many requests, consider using your own node"}');
				return;
			}
		
			throttle30.requests += 1;
			throttle24hrs.requests += 1;
		}
			
		redisClient.set('throttle:30min:['+ip+']', JSON.stringify(throttle30), 'EX', 60 * 60 * 24);
		redisClient.set('throttle:24hrs:['+ip+']', JSON.stringify(throttle24hrs), 'EX', 60 * 60 * 24);
	}

	// MAKE REQUEST
	try {
		res.setHeader('Access-Control-Allow-Origin', '*');
		res.setHeader('Access-Control-Allow-Credentials', 'true');
		res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
		res.setHeader('Access-Control-Allow-Headers', 'DNT,X-CustomHeader,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Keep-Alive'); //,Keep-Alive
		res.setHeader('Content-Type', 'application/json');
	}
	catch (e) {
		console.log(e);
	}
		
	try {
		sendRequestToOtherEndPoints(res, body, ip);
	}
	catch (e) {
		console.log(e);
		res.send('{"result": "error"}');
		return;
	}
	
});
app.use(router);

function sendRequestToOtherEndPoints(userEp, data, ip){
	
	// Get the EP
	var ep = false; 
	if(public_actions.indexOf(data.action) != -1)
	{
		ep = ENDPOINTS_PUBLIC[Math.floor(Math.random()*ENDPOINTS_PUBLIC.length)];
	}
	else if(protected_actions.indexOf(data.action) != -1)
	{
		ep = ENDPOINTS_PRIVATE[Math.floor(Math.random()*ENDPOINTS_PRIVATE.length)];
	}
	else if(protected_heavy_actions.indexOf(data.action) != -1)
	{
		ep = ENDPOINTS_HEAVY[Math.floor(Math.random()*ENDPOINTS_HEAVY.length)];
	}
	else
	{
		userEp.send('{"result": "error", "error": "unsupported action"}');
		return;
	}
		
	// Forward request
	var options = {
		hostname: ep.hostname,
		port: ep.port,
		path: ep.path,
		method: 'POST',
		timeout: 60000
	}
	var request = http.request(options, result => {
		console.log(`${ip} - statusCode: ${result.statusCode}`)

		var data = '';
		result.on('data', chunk => {
			data += chunk;
		})
		result.on('end', () => {
			try
			{
				userEp.send(data);
			}
			catch(e)
			{
				console.log(e);
			}
		});
	});
	request.on('timeout', function() {
		console.log(ip + ' - timeout (EP: ' + ep + ')' + JSON.stringify(data))
		sendRequestToOtherEndPoints(userEp, data, ip);
	});
	request.on('error', function(e) {
		console.log('problem with request: ' + e.message);
	});
	request.write(JSON.stringify(data));
	request.end();
}



// Set to hold all subscribed WebSocket clients
if(runWS)
{
	const wss = new WebSocket.Server({ port: WS_PORT });
	const subscriptions = new Set();
	let node_ws = null;

	function connectToNodeWs() {
		node_ws = new WebSocket(ENDPOINT_WS);

		node_ws.on('open', function() {
			console.log('Connected to node WebSocket server');
			node_ws.send('{"action": "subscribe", "topic": "confirmation"}');
		});

		node_ws.on('message', function incoming(data) {
			console.log('Received data from node WebSocket:', JSON.parse(data));
			
			let json = JSON.parse(data);
			
			// Replace account prefix
			if(PREFIX_OVERRIDE != false)
				json = JSON.parse(JSON.stringify(json).replace(new RegExp('adia_', 'g'), PREFIX_OVERRIDE));
			
			console.log(json);
			let msg_account = json.message.account
			let msg_link = json.message.block.link_as_account
			
			if (json.topic === "confirmation") {
				// Forward the data to all subscribed clients
				subscriptions.forEach(function each(client) {
					if (client.readyState === WebSocket.OPEN) {
						if(client.accounts === false) {
							// Client subscribed to all confirmations. Send the confirmation.
							client.send(JSON.stringify(json));
							console.log(json);
						}
						else {
							// Send the confirmation if client specifically subscribed to the account.
							client.accounts.forEach(function each(account) {
								if(msg_account == account)
								{
									client.send(JSON.stringify(json));
								}
							});
						}
					}
				});
			}
		});

		node_ws.on('close', function() {
			console.log('Node WebSocket disconnected');

			// Close all subscribed clients
			subscriptions.forEach(function each(client) {
				if (client.readyState === WebSocket.OPEN) {
					client.close();
				}
			});

			// Remove all subscriptions
			subscriptions.clear();

			// Reconnect to the node WebSocket after a delay
			setTimeout(connectToNodeWs, 5000);
		});
	}

	// Connect to the node WebSocket server
	connectToNodeWs();
	
	
	// Wait for a client to connect to the proxy server
	wss.on('connection', function connection(ws) {
		console.log('Client connected');

		// Add the new client to the subscriptions set
		ws.accounts = false;
		subscriptions.add(ws);

		// Wait for the client to send a message
		ws.on('message', function incoming(data) {
			console.log('Received data from client:', JSON.parse(data));

			// Parse the message data
			let msg;
			try {
				msg = JSON.parse(data);
			} catch (err) {
				console.error('Invalid message from client:', data);
				return;
			}

			// Check for subscription message
			if (msg.action === 'subscribe') {
				// Subscriber wants specific accounts
				if(msg.options && msg.options.accounts && msg.options.accounts.length > 0)
					ws.accounts = msg.options.accounts;
				else
					ws.accounts = false;
				
				console.log('Client subscribed');
				return;
			}

			// Check for ping message
			if (msg.action === 'ping') {
				// Send a pong message back to the client
				ws.send(JSON.stringify({ ack: 'pong' }));
				console.log('Sent pong message to client');
				return;
			}

			console.error('Invalid message action from client:', msg.action);
		});

		// Wait for the client to disconnect
		ws.on('close', function() {
			console.log('Client disconnected');

			// Remove the client from the subscriptions set
			subscriptions.delete(ws);
		});

		ws.on('error', function(error) {
			console.error('WebSocket error:', error);
		});
	});
	
	function makeid(length) {
		let result = '';
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const charactersLength = characters.length;
		let counter = 0;
		while (counter < length) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
			counter += 1;
		}
		return result;
	}
}
