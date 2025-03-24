const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
require("dotenv").config();
const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public')); // For serving static files like styles.css
const PORT = process.env.PORT || 8000;
let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover('https://cognito-idp.us-west-2.amazonaws.com/us-west-2_GVly2zl16');
    client = new issuer.Client({
        client_id: '2ii6hvd4ssgpc8eg9tjt6k2mga',
        client_secret: '13vp5vjj1hfa9rmtk15nf89soa4o4rpv1kh53vgd2eo4lsl9djpr',
        // redirect_uris: ['https://d84l1y8p4kdic.cloudfront.net'],
        redirect_uris: ["http://localhost:8000/callback"],
        response_types: ['code']
    });
};
initializeClient().catch(console.error);

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

const checkAuth = (req, res, next) => {
    if (!req.session.userInfo) {
        req.isAuthenticated = false;
    } else {
        req.isAuthenticated = true;
    }
    next();
};

app.get('/', checkAuth, (req, res) => {
    console.log('Session Info:', req.session.userInfo);  // Debugging line
    res.render('home', {
        isAuthenticated: req.isAuthenticated,
        userInfo: req.session.userInfo
    });
});

app.get('/login', (req, res) => {
    const nonce = generators.nonce();
    const state = generators.state();

    req.session.nonce = nonce;
    req.session.state = state;

    const authUrl = client.authorizationUrl({
        scope: 'phone openid email',
        state: state,
        nonce: nonce,
    });

    res.redirect(authUrl);
});

app.get('/main', checkAuth, (req, res) => {
    console.log('Session Info:', req.session.userInfo);  // Debugging line
    if (req.isAuthenticated) {
        res.render('main', {
            userInfo: req.session.userInfo
        });
    } else {
        res.redirect('/');
    }
});
app.get('/help', (req, res) => {
    res.render('help');
});
// Helper function to get the path from the URL. Example: "http://localhost/hello" returns "/hello"
function getPathFromURL(urlString) {
    try {
        const url = new URL(urlString);
        return url.pathname;
    } catch (error) {
        console.error('Invalid URL:', error);
        return null;
    }
}

app.get('/callback', async (req, res) => {
    try {
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            'http://localhost:8000/callback',
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state
            }
        );

        const userInfo = await client.userinfo(tokenSet.access_token);
        req.session.userInfo = userInfo;

        // Redirect to the main page after successful login
        res.redirect('/main');
    } catch (err) {
        console.error('Callback error:', err);
        res.redirect('/');
    }
});

// Logout route
// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    const logoutUrl = `https://us-west-2gvly2zl16.auth.us-west-2.amazoncognito.com/logout?client_id=2ii6hvd4ssgpc8eg9tjt6k2mga&logout_uri=http://localhost:8000`;
    res.redirect(logoutUrl);
});

app.listen(PORT, () => {
    console.log(`Server running at port ${PORT}`);
});