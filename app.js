const express = require("express");
const session = require("express-session");
const https = require("https");
const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv/config");
const { Issuer, generators } = require("openid-client");

const app = express();
const SECRET = process.env.SECRET;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const LOGOUT_URI = process.env.LOGOUT_URI;
const PORT = process.env.PORT || 3000;

if (!SECRET || !CLIENT_SECRET || !REDIRECT_URI || !LOGOUT_URI) {
    console.error(
        "Missing required environment variables SECRET or CLIENT_SECRET or REDIRECT_URI or LOGOUT_URI"
    );
    process.exit(1);
}

const options = {
    key: fs.readFileSync(path.join(__dirname, "key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "cert.pem")),
};

let client;
// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover(
        "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_GVly2zl16"
    );
    client = new issuer.Client({
        client_id: "2ii6hvd4ssgpc8eg9tjt6k2mga",
        client_secret: CLIENT_SECRET,
        redirect_uris: [REDIRECT_URI],
        response_types: ["code"],
    });
}
initializeClient().catch(console.error);

app.use(
    session({
        secret: SECRET,
        resave: false,
        saveUninitialized: false,
    })
);
app.use(express.static("public"));

const checkAuth = (req, res, next) => {
    if (!req.session.userInfo) {
        req.isAuthenticated = false;
    } else {
        req.isAuthenticated = true;
    }
    next();
};

app.set("view engine", "ejs");

app.get("/", checkAuth, (req, res) => {
    if (req.isAuthenticated) {
        res.redirect("/main");
        return;
    }
    res.render("home");
});

app.get("/login", (req, res) => {
    const nonce = generators.nonce();
    const state = generators.state();

    req.session.nonce = nonce;
    req.session.state = state;

    const authUrl = client.authorizationUrl({
        scope: "phone openid email",
        state: state,
        nonce: nonce,
    });

    res.redirect(authUrl);
});

app.get("/main", checkAuth, (req, res) => {
    if (!req.isAuthenticated) {
        res.redirect("/");
        return;
    }

    res.render("main", {
        userInfo: req.session.userInfo,
    });
});

app.get("/help", (req, res) => {
    res.render("help");
});

app.get("/callback", async (req, res) => {
    try {
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            REDIRECT_URI,
            params,
            {
                nonce: req.session.nonce,
                state: req.session.state,
            }
        );

        const userInfo = await client.userinfo(tokenSet.access_token);
        req.session.userInfo = userInfo;

        console.log("User info retrieved and stored in session:", userInfo);
        res.redirect("/");
    } catch (err) {
        console.error("Callback error:", err);
        res.redirect("/");
    }
});

// Logout route
app.get("/logout", (req, res) => {
    req.session.destroy();
    const logoutUrl = `https://us-west-2gvly2zl16.auth.us-west-2.amazoncognito.com/logout?client_id=2ii6hvd4ssgpc8eg9tjt6k2mga&logout_uri=${LOGOUT_URI}`;
    res.redirect(logoutUrl);
});

https.createServer(options, app).listen(PORT, () => {
    console.log(`Server running at https://localhost:${PORT}`);
});