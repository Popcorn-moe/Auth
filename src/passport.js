import session from "express-session";
import passport from "passport";
import jwt from "jsonwebtoken";
import uuid from "uuid/v4";
import { hash } from "bcrypt";
import {
	SSOExchangeAuth,
	LocalAuth,
	KitsuAuth,
	TwitterAuth,
	DiscordAuth
} from "./auth";

const SPECIAL_PROVIDERS = ["local", "ssoExchange", "signup"];
const ssoExchange = new SSOExchangeAuth();

const {
	DISCORD_CLIENT_ID,
	DISCORD_CLIENT_SECRET,
	TWITTER_CLIENT_ID,
	TWITTER_CLIENT_SECRET,
	COOKIE_DOMAIN,
	AUTH_URL
} = process.env;

function validProvider(providers) {
	return (req, res, next) => {
		const { provider } = req.params;
		if (providers.includes(provider)) {
			next();
		} else {
			res.status(400).send("Provider not found");
		}
	};
}

function withReq(fn) {
	return (req, res, next) => fn(req, res, next)(req, res, next);
}

export default function(app, db) {
	app.use(
		session({
			secret: "keyboard cat",
			resave: false,
			saveUninitialized: true
			//cookie: { secure: true }
		})
	);
	app.use(passport.initialize());
	app.use(passport.session());

	passport.use(ssoExchange);
	passport.use(new LocalAuth(db));
	if (DISCORD_CLIENT_ID)
		passport.use(
			new DiscordAuth(
				db,
				DISCORD_CLIENT_ID,
				DISCORD_CLIENT_SECRET,
				getCallback("discord")
			)
		);
	if (TWITTER_CLIENT_ID)
		passport.use(
			new TwitterAuth(
				db,
				TWITTER_CLIENT_ID,
				TWITTER_CLIENT_SECRET,
				getCallback("twitter")
			)
		);
	passport.use(
		new KitsuAuth(
			db,
			"dd031b32d2f56c990b1425efe6c42ad847e7fe3ab46bf1299f05ecd856bdb7dd",
			"54d7307928f63414defd96399fc31ba847961ceaecef3a5fd93144e960c0e151"
		)
	);

	const PROVIDERS = Object.keys(passport._strategies).filter(
		p => !SPECIAL_PROVIDERS.includes(p) && p !== "session" // session is a default provider for passport
	);

	console.log("Registered sso providers:", PROVIDERS.join(", "));

	passport.serializeUser((user, cb) => cb(null, user));

	app.post(
		"/login",
		withReq((req, res, next) =>
			passport.authenticate("local", { session: false }, (err, user, info) => {
				if (err) return next(err);
				if (!user) {
					res.status(401);
					res.send(info);
					return;
				}
				req.user = user;
				next();
			})
		),
		redirect
	);

	app.post("/signup", (req, res) => {
		hash(req.body.password, 10)
			.then(password =>
				db.insertOne({
					email: req.body.email,
					login: req.body.login,
					group: "VIEWER",
					newsletter: req.body.newsletter || false,
					password
				})
			)
			.then(({ ops: [user] }) => {
				req.user = user;
				req.user.provider = "signup";
				redirect(req, res);
			})
			.catch(e => {
				console.error(e);
				res.status(500).end();
			});
	});

	app.post("/ssoExchange", passport.authenticate("ssoExchange"), redirect);

	app.get(
		"/login/:provider",
		validProvider(PROVIDERS),
		withReq(({ params: { provider }, query: { callback } }, res) => {
			console.log("Callback", callback);
			res.cookie("callback", callback, { httpOnly: true });
			return passport.authenticate(provider);
		})
	);

	app.get(
		"/login/:provider/callback",
		validProvider(PROVIDERS),
		withReq(({ params: { provider } }) =>
			passport.authenticate(provider, { session: false })
		),
		redirect
	);
}

function redirect(req, res) {
	if (SPECIAL_PROVIDERS.includes(req.user.provider)) {
		const id = uuid();
		res.cookie(
			"session",
			jwt.sign(
				{
					_id: req.user._id
				},
				"secret",
				{
					expiresIn: "31 days",
					audience: "session",
					jwtid: id
				}
			),
			{
				domain: COOKIE_DOMAIN,
				maxAge: 24 * 60 * 60 * 1000,
				httpOnly: true
			}
		);

		if (req.cookies.ssoExchange) res.clearCookie("ssoExchange");
		req.session.destroy();

		res.json({
			csrf: jwt.sign(
				{
					id
				},
				"secret",
				{
					expiresIn: "31 days",
					audience: "csrf"
				}
			)
		});
	} else {
		res.clearCookie("callback");
		ssoExchange.createToken(req.user).then(token => {
			res.cookie("ssoExchange", token, { maxAge: 60 * 1000 });
			res.redirect(req.cookies.callback);
		});
	}
}

function getCallback(name) {
	return `${AUTH_URL || "http://localhost:3031"}/login/${name}/callback`;
}
