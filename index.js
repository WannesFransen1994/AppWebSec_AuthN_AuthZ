// === SETUP ===
const express = require('express');
const argon2 = require('argon2');
const mysql = require("mysql2")
const dotenv = require('dotenv')
const crypto = require('crypto');
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

// TODO: clean up periodically with https://stackoverflow.com/questions/1224463/is-there-any-way-to-call-a-function-periodically-in-javascript
let memory_sessions = {};
const session_char_length = 32;
const cookie_identifier = 'session_id';

function generate_session_key() {
    return crypto.randomBytes(session_char_length).toString('hex')
}
function unix_ts() {
    return Math.floor(Date.now() / 1000)
}

app.get("/", (req, res) => {
    res.render("index")
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
    console.log(memory_sessions)
    if (!req.cookies.session_id || !memory_sessions[req.cookies.session_id]) {
        return res.render('login', { message: "log in first" })
    }
    return res.render("welcome", { email: memory_sessions[req.cookies.session_id].email })
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
                let session_id = generate_session_key();
                memory_sessions[session_id] = { email: result[0].email, last_usage: unix_ts() }
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

app.listen(4000, () => {
    console.log("server started on port 4000")
})