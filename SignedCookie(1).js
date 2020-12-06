const util = require('util');
const url = require('url');
const fs = require('fs');

const AWS = require('aws-sdk/global');
const CF = require('aws-sdk/clients/cloudfront');

const TIMEDELTA = (24 * 3600); // 24hrs
const KEYPAIR_ID = 'AAAAAAAAAAAAAAAAAAAA';
const PRIV_KEY_FILE = 'aaaaaaaaaaaa.pem';

var policy = null;
var priv_key = null;

exports.handler = async function(event, context) {
if (policy == null) {
console.debug("policy data is null - calling loadPolicy()");
loadPolicy();
}

if (priv_key == null) {
console.debug("private key is not loaded - calling loadKey()");
loadKey();
}

var signer = new CF.Signer(KEYPAIR_ID, priv_key);

var record = event.Records[0];
var response = record.cf.response;

var domain = record.cf.config.distributionDomainName;
var incoming_uri = record.cf.request.uri;

var changed_path = translateUriPath(incoming_uri);
console.debug(changed_path);

var uri = url.format({
protocol: 'https',
hostname: domain,
pathname: changed_path,
});

var policy_str = getPolicy(uri);

var cookie = signer.getSignedCookie({
url: uri,
policy: policy_str,
});

console.debug(util.inspect(cookie));

var cookie_entries = new Array();

for (var key in cookie) {
var o = {
key: 'Set-Cookie',
// value: util.format('%s=%s; Domain=%s; Path=%s; Secure; HttpOnly', key, cookie[key], domain, changed_path),
value: util.format('%s=%s; Domain=%s; Path=%s; Secure', key, cookie[key], domain, '/'),
};

cookie_entries.push(o);
}

response.headers['set-cookie'] = cookie_entries;

return response;
};

function loadPolicy() {
var policy_data = fs.readFileSync('signing_policy.json', {encoding: 'utf-8'});
// console.debug(util.inspect(policy_data));
policy = policy_data;
}

function loadKey() {
var key_data = fs.readFileSync(PRIV_KEY_FILE, {encoding: 'utf-8'});
// console.debug(util.inspect(key_data));
priv_key = key_data;
}

function getUnixTimestamp() {
return Math.floor((new Date()).getTime() / 1000);
}

function getPolicy(resource_uri, epoch_time = getUnixTimestamp()) {
var policy_str = policy.replace('$RESOURCE$', resource_uri);
policy_str = policy_str.replace('$EPOCHTIME$', epoch_time + TIMEDELTA);

return policy_str;
}

function translateUriPath(incoming_uri) {
var uri_parts = url.parse(incoming_uri);

console.debug(util.inspect(uri_parts));

var parts = uri_parts.path.split("/");
var basename = parts.pop();

console.debug('basename from uri: ' + basename);

parts.push('*');

console.debug(util.inspect(parts));

var changed_path = parts.join("/");

return changed_path;
}