import { ExpressAuth, getSession } from "@auth/express";
import Credentials from "@auth/express/providers/credentials";
import Database from "better-sqlite3";
import crypto from "crypto";
import "dotenv/config";
import express, { json, urlencoded } from "express"; // Import json middleware
import expressLayouts from "express-ejs-layouts";
import expressUploads from "express-fileupload";
import expressMethodOverride from "method-override";
import { join } from "path";

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
        "name" TEXT NOT NULL,
        "to" TEXT NOT NULL,
        "cc" TEXT,
        "bcc" TEXT,
        "subject" TEXT NOT NULL,
        "body" TEXT NOT NULL,
        "fields" TEXT
    );

    CREATE TABLE IF NOT EXISTS "users" (
        "id" TEXT PRIMARY KEY,
        "email" TEXT NOT NULL UNIQUE,
        "password" TEXT NOT NULL
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
	pages: {
		signIn: "/login", // Custom sign-in page
	},
	providers: [
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
	debug: true, // Enable debug logs for troubleshooting
};

const authSession = async (req, res, next) => {
	res.locals.session = await getSession(req, authConfig);
	next();
};

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
	const id = nanoId();
	db.prepare('INSERT INTO "users" ("id", "email", "password") VALUES (?, ?, ?)').run(id, email, `${hash}:${salt}`);
};

const getTemplates = () => {
	const templates = db.prepare('SELECT * FROM "templates"').all();
	return templates.map((template) => ({
		...template,
		fields: JSON.parse(template.fields),
		stringified: sanitizeJSON(JSON.stringify({ ...template, fields: JSON.parse(template.fields) })),
	}));
};

const getTemplate = (id) => {
	const template = db.prepare('SELECT * FROM "templates" WHERE "id" = ?').get(id);
	if (template) {
		template.fields = JSON.parse(template.fields);
		template.stringified = sanitizeJSON(JSON.stringify(template));
	}
	return template;
};

const createTemplate = (template) => {
	const { id, name, to, cc, bcc, subject, body, fields } = template;
	db.prepare(
		'INSERT INTO "templates" ("id", "name", "to", "cc", "bcc", "subject", "body", "fields") VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
	).run(id, name, to, cc, bcc, subject, body, JSON.stringify(fields));
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
	const templates = getTemplates();
	res.render("home", { templates, query: "" });
});

app.get("/guide", (_, res) => {
	res.render("guide");
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

	createTemplate({ id, name, to, cc, bcc, subject, body, fields });

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
	const { to, cc, bcc, ...fields } = req.body;

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

	const e = encodeURIComponent;
	const mailtoLink = `mailto:${e(to)}?cc=${e(cc)}&bcc=${e(bcc)}&subject=${e(subject)}&body=${e(body)}`;

	res.redirect(mailtoLink);
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
