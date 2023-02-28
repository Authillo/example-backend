const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("node:crypto");
const fetch = require("node-fetch");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const app = express();
const port = 5001;

// Set the client ID and client secret for your app here
const clientId = process.env.CLIENT_ID_PROD;
const clientSecret = process.env.CLIENT_SECRET_PROD;
const jwtKey = process.env.JWT_KEY_PROD;
const redirect_uri = "com.authillo.ios-integration-demo://";
let codeVerifier = "UNSAFECODEVERIFIER";
// let codeChallenge = "c2a2edfcc102b7604c01c9427d73a755f5c34df7e0039f78425d26e86c04bf44";
let codeChallenge = "wqLt_MECt2BMAclCfXOnVfXDTffgA594Ql0m6GwEv0Q";
let accessToken;

app.use(function (req, res, next) {
	res.setHeader("Access-Control-Allow-Origin", "http://localhost:3001");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
	res.setHeader("Access-Control-Allow-Headers", "X-Requested-With,content-type");
	res.setHeader("Access-Control-Allow-Credentials", true);
	next();
});
app.use(bodyParser.json());

app.get("/hello", (req, res) => {
	console.log("hello enpoint hit");
});
/**
 * 1) Randomly generate a codeVerifier string
 * 2) Generate the codeChallenge by setting it equal to the hash of the codeVerifier using SHA256
 * 3) Store both using a persistent backend database
 * 4) Send the user the hashed version of the codeVerifier ( aka the codeChallenge)
 */
app.get("/codechallenge", (req, res) => {
	codeVerifier = crypto.randomBytes(32).toString("base64url");
	codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
	console.log("codechallengecalled");
	/**
	 * WARNING - This is an example backend so we don't store these codes using a database & we instead save the values in the codeVerifier & codeChallenge variables respectively.
	 * In production, your backend would have to store the codeVerifier & codeChallenge in a presistent database
	 */
	res.json(`${codeChallenge}`);
});

/**
 * Typically called once user gets redirected back to your frontend with their authorizationCode
 * 1) Parse the authorizationCode from query (the authorizationCode was returned alongside the user as they're redirected back to your platform's frontend & the user then passes the authorizationCode to your backend to recieve an IDToken to prove they've authenticated)
 * 2) Fetch the codeVerifier from storage
 * 3) Perform token request to authillo's api & sign request by including the authorizationCode & the codeVerifier
 * 4) Recieve user's IDToken & the accessToken which enables access to get userinfo
 * 5) Perform userinfo request & sign request by including the accessToken as the bearer in the authorization header
 * 6) Return IDToken & userInfo to client side
 */
app.get("/codeResponse", async (req, res) => {
	console.log(req.query);
	const code = req.query.code;
	const url = `https://auth.authillo.com/token?grant_type=authorization_code&code=${code}&redirect_uri=${redirect_uri}&code_verifier=${codeVerifier}&client_id=${clientId}&client_secret=${clientSecret}&request_type=OIDC`;
	console.log(`url for tokenRequest = ${url}`);

	const tokenRes = await fetch(url, {
		method: "POST",
	});
	const parsed = await tokenRes.json();
	console.log(parsed);
	accessToken = parsed?.result?.feedback?.access_token;
	const idToken = parsed?.result?.feedback?.id_token;
	console.log(idToken);
	let verifiedToken;

	try {
		verifiedToken = jwt.verify(idToken, jwtKey);
		console.log("token is valid: ", verifiedToken);
	} catch (err) {
		console.log("invalid token");
		console.log(err);
	}
	let userInfo;
	if (req.query.makeUserInfoReq === "true") {
		userInfo = await userInfoReq(accessToken);
		console.log(new Date().toISOString());
		console.log("userInfo in codeResponse: ", userInfo);
	}

	res.json(
		JSON.stringify({
			idTokenParsed: verifiedToken,
			idToken,
			userInfo: userInfo ?? null,
		})
	);
});

/**
 * Calls Authillo api endpoint that responds with the user's information
 */
const userInfoReq = async (token) => {
	const url = `https://auth.authillo.com/userinfo`;
	const userInfoRes = await fetch(url, {
		headers: {
			Authorization: `Bearer ${token}`,
		},
	});
	const parsedRes = await userInfoRes.json();
	console.log(parsedRes);
	console.log(parsedRes?.result?.feedback);
	return parsedRes?.result?.feedback;
};

app.listen(port, () => {
	console.log(`express server started listening on ${port}`);
});
