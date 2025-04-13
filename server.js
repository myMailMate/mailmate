import { ExpressAuth, getSession } from "@auth/express";
import Credentials from "@auth/express/providers/credentials";
import Google from "@auth/express/providers/google";
import Database from "better-sqlite3";
import crypto, { sign } from "crypto";
import "dotenv/config";
import express, { json, urlencoded } from "express";
import expressLayouts from "express-ejs-layouts";
import expressUploads from "express-fileupload";
import expressMethodOverride from "method-override";
import { join } from "path";

import fs from 'node:fs/promises';
import path from 'node:path';
import { authenticate } from '@google-cloud/local-auth';
import { google } from 'googleapis';


const __dirname = import.meta.dirname;

const app = express();
const port = 3000;

const secret = process.env.AUTH_SECRET;

if (!secret) {
	console.error("AUTH_SECRET is not set! Authentication may not work correctly.");
	process.exit(1); // Exit if AUTH_SECRET is missing in production
}

// Database setup
const db = new Database("./data.db");

const schema = `
    CREATE TABLE IF NOT EXISTS "templates" (
        "id" TEXT PRIMARY KEY,
		"user_id" TEXT NOT NULL,
        "name" TEXT NOT NULL,
        "to" TEXT NOT NULL,
        "cc" TEXT,
        "bcc" TEXT,
        "subject" TEXT NOT NULL,
        "body" TEXT NOT NULL,
        "fields" TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS "users" (
        "id" TEXT PRIMARY KEY,
        "email" TEXT NOT NULL UNIQUE,
        "password" TEXT NOT NULL
    );

	CREATE TABLE IF NOT EXISTS "logs" (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "user_id" TEXT NOT NULL,
        "to" TEXT NOT NULL,
		"cc" TEXT,
		"bcc" TEXT,
		"subject" TEXT,
		"body" TEXT,
		"date" DATE NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
    );

	CREATE TABLE IF NOT EXISTS "scheduled_emails" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "user_id" TEXT NOT NULL,
    "to" TEXT NOT NULL,
    "cc" TEXT,
    "bcc" TEXT,
    "subject" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "scheduled_time" DATETIME NOT NULL,
    "status" TEXT DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES users(id)
	);
`;

db.exec(schema);

// Middleware
app.use(expressLayouts);
app.use(expressUploads());
app.use(expressMethodOverride("_method"));
app.use(urlencoded({ extended: true }));
app.use(json()); // Add json middleware
app.use(express.static("public"));

/**
 * @type {import("@auth/express").ExpressAuthConfig}
 */
const authConfig = {
	secret,
	trustHost: true,
	// pages: {
	// 	signIn: "/login", // Custom sign-in page
	// },
	providers: [
		Google(),
		Credentials({
			credentials: {
				email: { label: "Email", type: "text" },
				password: { label: "Password", type: "password" },
			},
			async authorize(credentials, req) {
				if (!credentials?.email || !credentials?.password) {
					return null;
				}
				const user = getUser(credentials.email);

				if (!user) {
					return null;
				}

				const [storedHash, salt] = user.password.split(":");

				if (!storedHash || !salt) {
					console.error("Invalid password format in database.");
					return null;
				}

				const isValid = verifyPassword(credentials.password, salt, storedHash);

				if (isValid) {
					// **IMPORTANT**: Return a user object that MUST contain `id` and `email`
					return { id: user.id, email: user.email };
				} else {
					return null;
				}
			},
		}),
	],
	//allows user id to be accessed
	callbacks: {
		async session({ session, token }) {
			if (token) {
				const user = getUser(token.email);

				if (!user) {
					return null;
				}

				session.user.id = user.id
			}
			return session;
		},
		async jwt({ token, user }) {
			if (user) {
				token.id = user.id;
			}
			return token;
		},
		signIn: async ({ account, profile }) => {
			if (account.provider === "google") {
				const user = getUser(profile.email);

				if (!user) {
					addUser(profile.email, nanoId());
				}

				return true;
			}

			return true;
		},
	},
	// debug: true,
};

const authSession = async (req, res, next) => {
	res.locals.session = await getSession(req, authConfig);
	next();
};

//session debugging
app.get("/debug-session", async (req, res) => {
	const session = await getSession(req, authConfig);
	console.log("Session:", session);
	res.json(session);
});

app.use("/auth/*", ExpressAuth(authConfig));

app.use(authSession);

// Express Settings
app.set("view engine", "ejs");
app.set("views", join(__dirname, "views"));
app.set("layout", "layouts/layout");
app.set("trust proxy", true);

// Helper functions
const saltAndHashPassword = (password) => {
	const salt = crypto.randomBytes(16).toString("hex");
	const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
	return { salt, hash };
};

const verifyPassword = (password, salt, storedHash) => {
	const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
	return storedHash === hash;
};

const nanoId = (length = 5) => {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	let str = "";
	for (let i = 0; i < length; i++) {
		const randomIndex = Math.floor(Math.random() * chars.length);
		str += chars[randomIndex];
	}
	return str;
};

// Database helper methods
const getUser = (email) => {
	return db.prepare('SELECT * FROM "users" WHERE "email" = ?').get(email);
};

const addUser = (email, password) => {
	const { salt, hash } = saltAndHashPassword(password);
	const userId = nanoId(10);
	db.prepare('INSERT INTO "users" ("id", "email", "password") VALUES (?, ?, ?)').run(userId, email, `${hash}:${salt}`);
};

//get all templates matching id
const getTemplates = (userId) => {
	const templates = db.prepare('SELECT * FROM "templates" WHERE "user_id" = ?').all(userId);
	return templates.map((template) => ({
		...template,
		fields: JSON.parse(template.fields),
		stringified: sanitizeJSON(JSON.stringify({ ...template, fields: JSON.parse(template.fields) })),
	}));
};

//get all logs matching id
const getLogs = (userId) => {
	const logs = db.prepare('SELECT * FROM "logs" WHERE "user_id" = ?').all(userId);
	return logs
};

//save log in db
const logEmail = (user_id, to, cc, bcc, subject, body) => {
	const date = new Date().toISOString().split("T")[0];
	db.prepare('INSERT INTO "logs" ("user_id", "to", "cc", "bcc", "subject", "body", "date") VALUES (?, ?, ?, ?, ?, ?, ?)').run(user_id, to, cc, bcc, subject, body, date);
}

const getTemplate = (id) => {
	const template = db.prepare('SELECT * FROM "templates" WHERE "id" = ?').get(id);
	if (template) {
		template.fields = JSON.parse(template.fields);
		template.stringified = sanitizeJSON(JSON.stringify(template));
	}
	return template;
};

const createTemplate = (template, userId) => {
	const { id, name, to, cc, bcc, subject, body, fields } = template;
	db.prepare(
		'INSERT INTO "templates" ("id", "user_id", "name", "to", "cc", "bcc", "subject", "body", "fields") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
	).run(id, userId, name, to, cc, bcc, subject, body, JSON.stringify(fields));
};

const updateTemplate = (id, template) => {
	const { name, to, cc, bcc, subject, body, fields } = template;
	db.prepare(
		'UPDATE "templates" SET "name" = ?, "to" = ?, "cc" = ?, "bcc" = ?, "subject" = ?, "body" = ?, "fields" = ? WHERE "id" = ?'
	).run(name, to, cc, bcc, subject, body, JSON.stringify(fields), id);
};

const deleteTemplate = (id) => {
	db.prepare('DELETE FROM "templates" WHERE "id" = ?').run(id);
};

const getNextScheduledEmail = () => {
	return db.prepare(
		"SELECT * FROM scheduled_emails WHERE status = 'pending' ORDER BY scheduled_time ASC LIMIT 1"
	).get();
};

const getDueEmails = () => {
	const now = new Date().toISOString();
	return db.prepare(
		"SELECT * FROM scheduled_emails WHERE status = 'pending' AND scheduled_time <= ? ORDER BY scheduled_time ASC"
	).all(now);
};

const markEmailAsSent = (id) => {
	db.prepare(
		"UPDATE scheduled_emails SET status = 'sent' WHERE id = ?"
	).run(id);
};

const markEmailAsFailed = (id, error) => {
	db.prepare(
		"UPDATE scheduled_emails SET status = 'failed' WHERE id = ?"
	).run(id);
};

const scheduleEmail = (userId, to, cc, bcc, subject, body, scheduledTime) => {
	const result = db.prepare(
		'INSERT INTO scheduled_emails (user_id, "to", cc, bcc, subject, body, scheduled_time) VALUES (?, ?, ?, ?, ?, ?, ?)'
	).run(userId, to, cc, bcc, subject, body, scheduledTime);

	// Check if we need to update the scheduler
	const scheduledDate = new Date(scheduledTime);
	if (!emailScheduler.nextCheckTime || scheduledDate < emailScheduler.nextCheckTime) {
		emailScheduler.scheduleNextCheck();
	}

	return result.lastInsertRowid;
};

// If modifying these scopes, delete token.json.
const SCOPES = [
	'https://www.googleapis.com/auth/gmail.readonly',
	'https://www.googleapis.com/auth/gmail.send',
	'https://www.googleapis.com/auth/gmail.compose',
	'https://www.googleapis.com/auth/gmail.modify'
];
// The file token.json stores the user's access and refresh tokens, and is
// created automatically when the authorization flow completes for the first
// time.
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

/**
 * Reads previously authorized credentials from the save file.
 *
 * @return {Promise<OAuth2Client|null>}
 */
async function loadSavedCredentialsIfExist() {
	try {
		const content = await fs.readFile(TOKEN_PATH);
		const credentials = JSON.parse(content);
		return google.auth.fromJSON(credentials);
	} catch (err) {
		return null;
	}
}

/**
 * Serializes credentials to a file compatible with GoogleAuth.fromJSON.
 *
 * @param {OAuth2Client} client
 * @return {Promise<void>}
 */
async function saveCredentials(client) {
	const content = await fs.readFile(CREDENTIALS_PATH);
	const keys = JSON.parse(content);
	const key = keys.installed || keys.web;
	const payload = JSON.stringify({
		type: 'authorized_user',
		client_id: key.client_id,
		client_secret: key.client_secret,
		refresh_token: client.credentials.refresh_token,
	});
	await fs.writeFile(TOKEN_PATH, payload);
}

/**
 * Load or request or authorization to call APIs.
 *
 */
async function authorize() {
	let client = await loadSavedCredentialsIfExist();
	if (client) {
		return client;
	}
	client = await authenticate({
		scopes: SCOPES,
		keyfilePath: CREDENTIALS_PATH,
	});
	if (client.credentials) {
		await saveCredentials(client);
	}
	return client;
}

/**
 * Send an email using Gmail API.
 *
 * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
 */
async function sendEmail(auth, options) {
	const gmail = google.gmail({ version: 'v1', auth });

	// Extract email options
	const { to, cc, bcc, subject, body } = options;

	// Construct email content
	const emailContent = [
		`To: ${to}`,
		cc ? `Cc: ${cc}` : '',
		bcc ? `Bcc: ${bcc}` : '',
		'Content-Type: text/plain; charset=utf-8',
		'MIME-Version: 1.0',
		`Subject: ${subject}`,
		'',
		body
	]
		.filter(Boolean) // Remove empty lines (for optional cc/bcc)
		.join('\r\n');

	// Encode the email in base64url format as required by Gmail API
	const encodedEmail = Buffer.from(emailContent)
		.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');

	try {
		const res = await gmail.users.messages.send({
			userId: 'me',
			requestBody: {
				raw: encodedEmail
			}
		});

		console.log('Email sent successfully:', res.data);
		return res.data;
	} catch (error) {
		console.error('Error sending email:', error);
		throw error;
	}
}

const emailScheduler = {
	nextCheckTime: null,
	timerId: null,

	init() {
		this.scheduleNextCheck();
	},

	scheduleNextCheck() {
		if (this.timerId) {
			clearTimeout(this.timerId);
		}

		const nextMail = getNextScheduledEmail();

		if (!nextMail) {
			this.nextCheckTime = null;
			console.log("No scheduled emails found.");
			return;
		}

		const now = new Date();
		const nextSendTime = new Date(nextMail.scheduled_time);

		let delay = nextSendTime - now;

		if (delay <= 0) {
			delay = 100;
		}

		this.nextCheckTime = new Date(now.getTime() + delay);
		console.log(`Next scheduled email will be sent at: ${this.nextCheckTime}`);

		this.timerId = setTimeout(() => this.processQueue(), delay);
	},

	async processQueue() {
		console.log("Processing scheduled email...");

		try {
			const dueEmails = getDueEmails();

			for (const email of dueEmails) {
				try {
					const auth = await authorize();
					await sendEmail(auth, {
						to: email.to,
						cc: email.cc,
						bcc: email.bcc,
						subject: email.subject,
						body: email.body
					});

					markEmailAsSent(email.id);
				}
				catch (error) {
					console.error(`Failed to send scheduled email ${email.id}:`, error);
					markEmailAsFailed(email.id, error.message);
				}
			}
		}
		catch (error) {
			console.error("Error processing scheduled emails:", error);
		}

		this.scheduleNextCheck();
	}
};

emailScheduler.init();

// Authentication middleware
const authenticatedUser = async (req, res, next) => {
	const session = res.locals.session ?? (await getSession(req, authConfig));
	if (!session?.user) {
		res.redirect("/login");
	} else {
		next();
	}
};

// Routes
app.get("/login", (req, res) => {
	if (res.locals.session?.user) {
		return res.redirect("/");
	}
	res.render("login");
});

app.get("/signup", (req, res) => {
	if (res.locals.session?.user) {
		return res.redirect("/");
	}
	res.render("signup");
});

app.post("/signup", (req, res) => {
	const { email, password } = req.body;

	try {
		addUser(email, password);
		res.redirect("/login");
	} catch (error) {
		console.log({ error });
		res.status(400).render("signup", { error: "Error registering user. Email may already exist." });
	}
});

app.get("/logout", (req, res) => {
	res.redirect("/auth/signout");
});

// Protected routes
app.use(authenticatedUser);

app.get("/", async (_, res) => {
	const userId = res.locals.session?.user?.id;
	const templates = getTemplates(userId);
	res.render("home", { templates, query: "" });
});

app.get("/guide", (_, res) => {
	res.render("guide");
});

//render logs
app.get("/sent", async (_, res) => {
	const userId = res.locals.session?.user?.id;
	const logs = getLogs(userId);
	res.render("sent", { logs });
});

app.get("/template/:id", async (req, res) => {
	const { id } = req.params;
	const template = getTemplate(id);

	if (!template) {
		return res.status(404).send("Template not found");
	}

	res.render("template", {
		template,
		stringified: template.stringified,
		subject: template.subject,
		emailBody: template.body,
	});
});

app.put("/template/:id", async (req, res) => {
	const { id } = req.params;
	const { name, to, cc, bcc, subject, body } = req.body;

	const template = getTemplate(id);

	if (!template) {
		return res.status(404).send("Template not found");
	}

	const fields = extractDynamicFields(`${subject}${body}`);

	updateTemplate(id, { name, to, cc, bcc, subject, body, fields });

	res.redirect("/");
});

app.post("/template", async (req, res) => {
	const { name, to, cc, bcc, subject, body } = req.body;
	const id = nanoId();
	const fields = extractDynamicFields(`${subject}${body}`);
	const userId = res.locals.session?.user?.id;

	console.log({ userId });
	createTemplate({ id, name, to, cc, bcc, subject, body, fields }, userId);

	res.redirect("/");
});

app.delete("/template/:id", async (req, res) => {
	const { id } = req.params;
	deleteTemplate(id);
	res.redirect("/");
});

app.get("/search", async (req, res) => {
	const query = req.query.q.toLowerCase();
	const templates = getTemplates();

	const searchResults = templates.filter((template) => {
		return (
			template.name.toLowerCase().includes(query) ||
			template.body.toLowerCase().includes(query) ||
			template.subject.toLowerCase().includes(query)
		);
	});

	return res.render("home", { query, templates: searchResults });
});

app.post("/generate", async (req, res) => {
	const { templateId } = req.query;
	const { sendMethod, to, cc, bcc, ...fields } = req.body;

	const template = getTemplate(templateId);
	if (!template) {
		return res.status(404).send("Template not found");
	}

	for (const field of template.fields) {
		if (!fields[field.id]) {
			return res.status(400).send(`Field ${field.label} is required`);
		}
	}

	const subject = replaceDynamicFields(template.subject, fields);
	const body = replaceDynamicFields(template.body, fields);
	const userId = res.locals.session?.user?.id;

	// Log email regardless of send method
	logEmail(userId, to, cc || '', bcc || '', subject, body);

	if (sendMethod === 'gmail') {
		try {
			const auth = await authorize();
			await sendEmail(auth, { to, cc, bcc, subject, body });
			return res.redirect('/sent?status=success');
		} catch (error) {
			console.error('Error sending email via Gmail:', error);
			return res.redirect(`/template/${templateId}?error=${encodeURIComponent('Failed to send email via Gmail')}`);
		}
	} else {
		// Default to mailto link
		const e = encodeURIComponent;
		const mailtoLink = `mailto:${e(to)}?cc=${e(cc)}&bcc=${e(bcc)}&subject=${e(subject)}&body=${e(body)}`;
		return res.redirect(mailtoLink);
	}
});

app.post("/schedule-email", async (req, res) => {
	const { templateId } = req.query;
	const { scheduledTime, to, cc, bcc, ...fields } = req.body;

	const template = getTemplate(templateId);
	if (!template) {
		return res.status(404).send("Template not found");
	}

	const subject = replaceDynamicFields(template.subject, fields);
	const body = replaceDynamicFields(template.body, fields);
	const userId = res.locals.session?.user?.id;

	try {
		const emailId = scheduleEmail(userId, to, cc || '', bcc || '', subject, body, scheduledTime);
		return res.redirect(`/scheduled?status=scheduled&id=${emailId}`);
	} catch (error) {
		console.error('Error scheduling email:', error);
		return res.redirect(`/template/${templateId}?error=${encodeURIComponent('Failed to schedule email')}`);
	}
});

app.get("/scheduled", async (req, res) => {
	const userId = res.locals.session?.user?.id;
	const { status, id } = req.query;

	let scheduledEmail = null;
	if (id) {
		scheduledEmail = db.prepare(
			'SELECT * FROM scheduled_emails WHERE id = ? AND user_id = ?'
		).get(id, userId);
	}

	const scheduledEmails = db.prepare(
		'SELECT * FROM scheduled_emails WHERE user_id = ? ORDER BY scheduled_time ASC'
	).all(userId);

	const showCelebration = status === 'scheduled';

	res.render("scheduled", {
		scheduledEmails,
		scheduledEmail,
		showCelebration,
		status,
		id
	});
});

// Additional helper functions
const extractDynamicFields = (content) => {
	content = content.trim();
	const regex = /\{@(.*?):(.*?)\}/gm;
	const fields = [];
	const matches = content.match(regex);

	for (let match of new Set(matches)) {
		const dup = match.slice(1, -1);
		const [type, body] = dup.split(":");
		const [label, value = ""] = body.split("|");
		fields.push({ id: match, type: type.replace("@", ""), label: label.trim(), value: value.trim() });
	}
	return fields;
};

const replaceDynamicFields = (content, fields) => {
	let newContent = content;
	for (const [id, value] of Object.entries(fields)) {
		newContent = newContent.replaceAll(id, value);
	}
	return newContent;
};

const sanitizeJSON = (unsanitized) => {
	return unsanitized
		.replace(/\\/g, "\\\\")
		.replace(/\n/g, "\\n")
		.replace(/\r/g, "\\r")
		.replace(/\t/g, "\\t")
		.replace(/\f/g, "\\f")
		.replace(/"/g, '\\"')
		.replace(/'/g, "\\'")
		.replace(/\&/g, "\\&");
};

app.listen(port, () => {
	console.log(`App listening at http://localhost:${port}`);
});
