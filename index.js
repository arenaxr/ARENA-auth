'use strict';

// TODO(mwfarb): migrate user-configurable settings to config
const CLIENT_ID = '173603117246-7lehsb3tpq4i17e7sla5bue1an4ps9t6.apps.googleusercontent.com';
const PORT = 8888;

const express = require('express');
const logger = require('morgan');
const args = require('minimist')(process.argv.slice(2));
const config = require(args.c); // use arg '-c path/config.json' for config file
const https = require('https')
const fs = require('fs')
const { JWT, JWK } = require('jose')
const bodyParser = require('body-parser');
const { OAuth2Client } = require('google-auth-library');

const gOauthClient = new OAuth2Client(CLIENT_ID);
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
    var iat = new Date(new Date - 20000); // allow for clock skew between issuer and broker
    return JWT.sign(claims, jwk, { "alg": "HS256", "expiresIn": exp, "now": iat });
}

async function verifyGToken(username, token) {
    const ticket = await gOauthClient.verifyIdToken({
        idToken: token,
        audience: CLIENT_ID,
    });
    return ticket.getPayload();
}

function generateMqttToken(req, jwt) {
    var realm = config.realm;
    var scene = req.body.scene;
    var auth_name = req.body.username;
    var scene_obj = realm + "/s/" + scene + "/#";
    var scene_admin = realm + "/admin/s/" + scene + "/#";
    switch (auth_name) {
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
        default:
            // TODO(mwfarb): hook into authorization ACL, for now allow all pub/sub for 1 day
            //jwt = null;
            jwt = signMqttToken(auth_name, '1 day',
                ["#"], ["#"]);
            break;
    }
    return { auth_name, jwt };
}

// main auth endpoint
app.post('/', (req, res) => {
    console.log("Request:", req.body.username)

    // first, verify the id-token
    switch (req.body.id_auth) {
        case "google":
            let identity = verifyGToken(req.body.username, req.body.id_token).catch((error) => {
                console.error(error);
                res.json({ error: error });
                return;
            });
            console.log('Verified Google user', identity);
            break;
        default:
            error = ("Invalid authorization provider name:", req.body.id_auth);
            console.error(error);
            res.json({ error: error });
            return;
    }

    // TODO(mwfarb): second, pull/create user record and associate id from token with it

    // third, generate mqtt-token with ACL-level permissions
    var auth_name, jwt;
    ({ auth_name, jwt } = generateMqttToken(req, jwt));
    res.json({ username: auth_name, token: jwt });
});

server.listen(PORT, () => {
    console.log(`MQTT-Auth app listening at port ${PORT}.`);
    console.log('Press Ctrl+C to quit.');
});
