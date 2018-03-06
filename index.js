const userVerify = require("./user.js");
const request = require("request");
const loginUrl = "/mgclogin";

const fs = require("fs");
const session = require('express-session')
const FileStore = require('session-file-store')(session);
const express = require('express');
const app = express();
const path = require("path");
const bodyParser = require('body-parser')
var identityKey = 'publicYourSite_Session';
var siteConf;

const max_login_erron_count = 5;
const block_seconds = 60 * 10; //10 minutes
var login_fail_list = {};

function getSiteConf() {
    if (siteConf) {
        return siteConf;
    } else {
        siteConf = JSON.parse(fs.readFileSync("./site.conf"));
        return siteConf;
    }
}

function cannotLoginWithThisIp(req) {
    var clientIp = getClientIp(req);
    var failInfo = login_fail_list[clientIp];

    if (failInfo) {
        var loginSpan = (new Date() - failInfo.firstLoginAt) / 1000;

        if (loginSpan > block_seconds) {
            login_fail_list[clientIp] = null;
            return false
        } else {
            var blocked = failInfo && failInfo.cnt > max_login_erron_count;

            if(blocked){
                failInfo.firstLoginAt = new Date();
            }

            return blocked;
        }
    } else {
        return false;
    }

}

function handleLoginFailed(req) {
    var clientIp = getClientIp(req);
    var failInfo = login_fail_list[clientIp]
    if (failInfo) {
        var loginSpan = (new Date() - failInfo.firstLoginAt) / 1000;

        if (loginSpan > block_seconds) {
            login_fail_list[clientIp] = {
                cnt: 1,
                firstLoginAt: new Date()
            };
        } else {
            failInfo.cnt += 1;

            if (failInfo.cnt > max_login_erron_count) {
                return false;
            }
        }
    } else {
        login_fail_list[clientIp] = {
            cnt: 1,
            firstLoginAt: new Date()
        };
    }

    return true;
}

function getClientIp(req) {
    return req.headers['x-real-ip'] || req.connection.remoteAddress;
}

function inWhitelist(req) {
    var remoteIp = getClientIp(req);
    return getSiteConf()["whitelistIp"].indexOf(remoteIp) > -1;
}

var listenPort = getSiteConf()["port"];

function getTargetSite(req) {
    var host = req.hostname;
    return getSiteConf()["sites"][host];
}

function pipReq(req, res) {
    var tgt = getTargetSite(req);
    var requrl = tgt + req.originalUrl;
    req.pipe(request[req.method.toLowerCase()]({
        "followRedirect":false,
        "url": requrl,
        "headers": {
            "host": req.hostname
        }
    })).pipe(res);
}

app.use(session({
    secret: identityKey,
    cookie: {},
    store: new FileStore(),
     resave: true,
    saveUninitialized: true
}));

app.use("/static", express.static('static'));

app.use(function (req, res, next) {
    if (cannotLoginWithThisIp(req)) {
        res.send("Your ip has been blcoked since you login failed many times, please try again later!");
        return;
    }

    var tgt = getTargetSite(req);

    if (!tgt) {
        res.send("Invalid request, please contact the site administrator to get a valid url!");
        return;
    }

    if (!inWhitelist(req)) {
        var url = req.originalUrl;
        if (url != loginUrl) {
            if (!req.session.user) {
                return res.redirect(loginUrl);
            } else {
                next();
            }
        } else {
            next();
        }
    } else {
        next();
    }
}, function (req, res, next) {
    if (!inWhitelist(req)) {
        var url = req.originalUrl;
        if (url != loginUrl) {
            pipReq(req, res);
        } else {
            next();
        }
    } else {
        pipReq(req, res);
    }
}, bodyParser.urlencoded());

// Access the session as req.session
app.get(loginUrl, function (req, res, next) {
    if (req.session.user) {
        res.redirect("/");
    } else {
        res.sendFile(path.join(__dirname + '/login.html'));
    }
});

app.post(loginUrl, function (req, res, next) {
    userVerify.verify(req.body.usercode, req.body.inputPassword).catch(function (error) {
        handleLoginFailed(req);
    }).then(function (user) {
        if (user) {
            req.session.regenerate(function (err) {
                if (err) {
                    return res.json({
                        ret_code: 2,
                        ret_msg: 'Login faild!'
                    });
                }

                req.session.user = user;
                // res.json({
                //     ret_code: 0,
                //     ret_msg: '登录成功'
                // });
                res.redirect("/");
            });

        } else {
            res.send('Wrong user name or password!');
        }
    });
});

app.listen(listenPort, function () {
    console.log(`Started, work on port ${listenPort}    ${new Date()}`);
});