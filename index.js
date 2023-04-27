// agent-secret
const apm = require('elastic-apm-node').start({
    // Override service name from package.json
    // Allowed characters: a-z, A-Z, 0-9, -, _, and space
    serviceName: 'my-nodejs-application',

    // Use if APM Server requires a token
    // secretToken: 'agent-secret',

    // Set custom APM Server URL (default: http://127.0.0.1:8200)
    // serverUrl: 'http://172.20.50.198:8200',
    serverUrl: 'http://172.20.50.193:8200',
})

// === SETUP ===
const express = require('express');
const argon2 = require('argon2');
const mysql = require("mysql2")
const dotenv = require('dotenv')
const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');
const cookieParser = require('cookie-parser')
const app = express();


dotenv.config({ path: './.env' })
const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
})

db.connect((error) => {
    if (error) {
        console.log(error)
    } else {
        console.log("MySQL connected!")
    }
})

app.set('view engine', 'hbs')
app.use(express.urlencoded({ extended: 'false' }))
app.use(express.json())
app.use(cookieParser());

// === APPLICATION LOGIC ===

const cookie_identifier = 'session_id';
const api_header_name = 'x-api-key';

let api_data = {
    "aperson": { posts: ["some post", "another post"], can_view: ["otherperson"] },
    "xx": { posts: ["some post", "another post"], can_view: ["aperson"] }
}

function generate_jwt(email) {
    let jwt_header = { "alg": "HS256", "typ": "JWT" }
    let jwt_payload = { "email": email }

    let header_encoded = Buffer.from(JSON.stringify(jwt_header)).toString("base64url")
    let payload_encoded = Buffer.from(JSON.stringify(jwt_payload)).toString("base64url")
    let signature = crypto.createHmac('sha256', process.env.JWT_SECRET).update(header_encoded + "." + payload_encoded).digest("base64url");

    let jwt = header_encoded + "." + payload_encoded + "." + signature;

    return jwt
}

function verify_jwt(jwt) {
    let splitted_jwt = jwt.split(".");

    let tbv_header = splitted_jwt[0]
    let tbv_payload = splitted_jwt[1]
    let tbv_signature = splitted_jwt[2]

    let valid_or_not = crypto.createHmac('sha256', process.env.JWT_SECRET).update(tbv_header + "." + tbv_payload).digest("base64url") == tbv_signature;

    return valid_or_not
}

function get_jwt_payload(jwt) {
    let splitted_jwt = jwt.split(".");

    let tbv_payload = Buffer.from(splitted_jwt[1], 'base64url').toString("utf8")
    return JSON.parse(tbv_payload)
}

function unix_ts() {
    return Math.floor(Date.now() / 1000)
}

function can_user_view_posts(resource_email, performer_email) {
    // api_data[req.params.email] && api_data[req.params.email]["can_view"].includes(get_jwt_payload(header_value).email)
    if (resource_email == performer_email) { return true }
    if (api_data[resource_email]["can_view"].includes(performer_email)) { return true }
    return false
}

app.get("/", (req, res) => {
    res.render("index")
})

app.get("/api/users/:email/posts", (req, res) => {
    res.set('Access-Control-Allow-Origin', 'http://localhost:4000')
    let header_value = req.header(api_header_name)
    if (!header_value || !verify_jwt(header_value)) {
        return res.status(400).json("invalid or missing jwt")
    } else if (can_user_view_posts(req.params.email, get_jwt_payload(header_value).email)) {
        return res.status(200).json(api_data[req.params.email]["posts"])
    }

    return res.status(400).json("not allowed to view this person his/her posts")


})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req, res) => {
    res.clearCookie(cookie_identifier)
    res.redirect('login');
})

app.get("/welcome", (req, res) => {
    if (!req.cookies.session_id || !verify_jwt(req.cookies.session_id)) {
        return res.render('login', { message: "log in first" })
    }
    return res.render("welcome", { email: get_jwt_payload(req.cookies.session_id).email })
})

app.post("/auth/login", (req, res) => {
    if (!req.body.email || !req.body.password) {
        res.render('login', { message: "Enter both email and pasword" })
    } else {
        var x = process.hrtime();
        const { email, password } = req.body
        db.query('SELECT email, hashed_password FROM users WHERE email = ?', [email], async (error, result) => {
            if (error) {
                console.log(error)
            } else if (result.length == 0) {
                t = process.hrtime(x);
                console.log('LOGIN;EMAIL_NOT_FOUND;%d sec;%d millisec', t[0], t[1] / 1000000);
                return res.render('login', { message: 'Invalid email/password combination' })
            } else if (await argon2.verify(result[0].hashed_password, password)) {
                // Set session here
                // let session_id = generate_session_key();
                // memory_sessions[session_id] = { email: result[0].email, last_usage: unix_ts() }
                let session_id = generate_jwt(result[0].email)
                res.cookie(cookie_identifier, session_id, { sameSite: 'Strict', httpOnly: true, secure: false, maxAge: 36000000 })


                t = process.hrtime(x);
                console.log("Logging in!");
                console.log('LOGIN;LOGIN_SUCCESS;%d sec;%d millisec', t[0], t[1] / 1000000);
                res.redirect('/welcome');
            } else {
                t = process.hrtime(x);
                console.log("Invalid password");
                console.log('LOGIN;INVALID_PASSWORD;%d sec;%d millisec', t[0], t[1] / 1000000);
                return res.render('login', { message: 'Invalid email/password combination' })
            }
        })
    }
})

app.post("/auth/register", (req, res) => {
    const { email, password, password_confirm } = req.body

    db.query('SELECT email FROM users WHERE email = ?', [email], async (error, result) => {
        if (error) {
            console.log(error)
        } else if (result.length > 0) {
            return res.render('register', {
                message: 'This email is already in use'
            })
        } else if (password !== password_confirm) {
            return res.render('register', {
                message: 'Passwords do not match!'
            })
        } else {
            let hashedPassword = await argon2.hash(password)

            db.query('INSERT INTO users SET?', { email: email, hashed_password: hashedPassword }, (error, result) => {
                if (error) {
                    console.log(error)
                } else {
                    return res.render('register', {
                        message: 'User registered!'
                    })
                }
            })
        }
    })

})

app.listen(process.env.DEVPORT, () => {
    console.log("server started on port " + process.env.DEVPORT)
})