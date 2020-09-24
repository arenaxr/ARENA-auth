/* jshint esversion: 8 */
/* jshint node: true */

'use strict';

const express = require('express');
const logger = require('morgan');
const args = require('minimist')(process.argv.slice(2));
const config = require(args.c); // use arg '-c path/config.json' for config file
const https = require('https');
const fs = require('fs');
const { JWT, JWK } = require('jose');
const bodyParser = require('body-parser');
const { OAuth2Client } = require('google-auth-library');

const gOauthClient = new OAuth2Client(config.gauth_clientid);
const app = express();

const key = fs.readFileSync(config.keypath);
const cert = fs.readFileSync(config.certpath);
const jwk = JWK.asKey({ kty: 'oct', k: config.secret });
const server = https.createServer({ key: key, cert: cert }, app);

// engine setup
app.use(logger('dev')); // TODO(mwfarb): switch to 'common'
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

function signMqttToken(user = null, exp = '1 hour', sub = null, pub = null) {
    var claims = { "sub": user };
    if (sub && sub.length > 0) {
        claims.subs = sub;
    }
    if (pub && pub.length > 0) {
        claims.publ = pub;
    }
    var iat = new Date(new Date() - 20000); // allow for clock skew between issuer and broker
    return JWT.sign(claims, jwk, { "alg": "HS256", "expiresIn": exp, "now": iat });
}

async function verifyGToken(token) {
    // validate Google id token before issuing mqtt-token
    const ticket = await gOauthClient.verifyIdToken({
        idToken: token,
        audience: config.gauth_clientid
    });
    return ticket.getPayload();
}

function verifyAnon(username) {
    // check user announced themselves an anonymous
    if (!username.startsWith("anonymous-")) {
        throw 'Anonymous users must prefix usernames with "anonymous-"';
    }
}

function generateMqttToken(req, jwt, type) {
    var realm = config.realm;
    var scene = req.body.scene;
    var auth_name = req.body.username;
    var scene_obj = realm + "/s/" + scene + "/#";
    var scene_admin = realm + "/admin/s/" + scene + "/#";
    switch (type) {
        // service-level scenarios
        case 'persistdb':
            // persistance service subs all scene, pubs status
            jwt = signMqttToken(auth_name, '1 year',
                [realm + "/s/#", realm + "/admin/s/#"], ["service_status"]);
            break;
        case 'sensorthing':
            // realm/g/<session>/uwb or realm/g/<session>/vio (global data)
            jwt = signMqttToken(auth_name, '1 year',
                [realm + "/g/#"], [realm + "/g/#"]);
            break;
        case 'sensorcamera':
            // realm/g/a/<cameras> (g=global, a=anchors)
            jwt = signMqttToken(auth_name, '1 year',
                [realm + "/g/a/#"], [realm + "/g/a/#"]);
            break;

        // user-level scenarios
        case 'graphview':
            // graph viewer
            jwt = signMqttToken(auth_name, '1 day',
                ["$GRAPH"], null);
            break;
        case 'admin':
            // admin is normal scene pub/sub, plus admin tasks
            jwt = signMqttToken(auth_name, '1 day',
                [scene_admin, scene_obj], [scene_admin, scene_obj]);
            break;
        case 'editor':
            // editor is normal scene pub/sub
            jwt = signMqttToken(auth_name, '1 day',
                [scene_obj], [scene_obj]);
            break;
        case 'viewer':
            var user_objects = [];
            if (req.body.camid != undefined) {
                user_objects.push(realm + "/s/" + scene + "/" + req.body.camid);
                user_objects.push(realm + "/s/" + scene + "/arena-face-tracker");
            }
            if (req.body.ctrlid1 != undefined) {
                user_objects.push(realm + "/s/" + scene + "/" + req.body.ctrlid1);
            }
            if (req.body.ctrlid2 != undefined) {
                user_objects.push(realm + "/s/" + scene + "/" + req.body.ctrlid2);
            }
            // viewer is sub scene, pub cam/controllers
            jwt = signMqttToken(auth_name, '1 day',
                [scene_obj], user_objects);
            break;
        case 'all':
            jwt = signMqttToken(auth_name, '1 day',
                ["#"], ["#"]);
            break;
        default:
            jwt = null;
            break;
    }
    return { auth_name, jwt };
}

// main auth endpoint
app.post('/', async (req, res) => {
    console.log("Request:", req.body.id_auth, req.body.username);
    var auth_type = 'none';
    // first, verify the id-token
    switch (req.body.id_auth) {
        case "google":
            let identity = await verifyGToken(req.body.id_token).catch((error) => {
                console.error(error);
                res.status(403);
                res.json({ error: error });
                return;
            });
            auth_type = 'all';
            console.log('Verified Google user:', auth_type, req.body.username, identity.email);
            break;
        case "anonymous":
            try {
                verifyAnon(req.body.username);
            } catch(error) {
                console.error(error);
                res.status(403);
                res.json({ error: error });
                return;
            }
            auth_type = 'viewer';
            console.warn('Allowing anonymous user:', auth_type, req.body.username);
            break;
        default:
            var error = ("Invalid authorization provider name:", req.body.id_auth);
            console.error(error);
            res.json({ error: error });
            return;
    }

    // TODO(mwfarb): second, pull/create user record and associate id from token with it

    // third, generate mqtt-token with ACL-level permissions
    var auth_name, jwt;
    ({ auth_name, jwt } = generateMqttToken(req, jwt, auth_type));
    res.json({ username: auth_name, token: jwt });
});

server.listen(config.port, () => {
    console.log(`ARENA MQTT-Auth app listening at port ${config.port}`);
    console.log('Press Ctrl+C to quit.');
});

