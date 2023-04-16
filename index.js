const express = require('express');
const argon2 = require('argon2');
const mysql = require("mysql2")
const dotenv = require('dotenv')


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

app.get("/", (req, res) => {
    res.render("index")
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
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
                t = process.hrtime(x);
                console.log("Logging in!");
                console.log('LOGIN;LOGIN_SUCCESS;%d sec;%d millisec', t[0], t[1] / 1000000);
                res.render('index');
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