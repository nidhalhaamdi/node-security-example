const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

require('dotenv').config();

const PORT = 3000;

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google Profile', profile);
    done(null, profile);
}

// Setting up passport STRATEGY which determines how passport authenticate users !
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save the session to the cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Read the session from the cookie
passport.deserializeUser((id, done) => {
    // user.findByid(id).then(user => {
    //     done(null, user);
    // });
    done(null, id);
});

const app = express();

app.use(helmet());

app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000, // 1 day until session expires
    keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ], // The server SIGN cookies, send it to the browser with this secret key 
        //& will in turn verify incoming cookies to make sure that they were created with that secret key
}));

// Middleware that set up passport SESSION
app.use(passport.initialize()); 
/* a function that returns this passport middleware that helps us to set up passport 
specifically the passport SESSION */

app.use(passport.session());
// Passport understands cookie Session and the req.user object set by cookie session middleware

function checkLoggedIn(req, res, next) {
    console.log('Current user is:', req.user);
    const isLoggedIn = req.isAuthenticated() && req.user;
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must log in!',
        });
    }
    next();
}

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email'],
}));

app.get('/auth/google/callback', 
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true, // true by default = we can remove it
    }), 
    (req, res) => {
        console.log('Google called us back!');
    }
);

app.get('/auth/logout', (req, res) => {
    req.logout(); // removes req.user property from the request(req) & terminates any logged in session
    return res.redirect('/');
});

// In express, you can pass in middleware for each endpoint individually when definind the route
app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('Your personal secret value is 17!');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/failure', (req, res) => {
    return res.send('Failed to log in!');
});

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});