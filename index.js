const express = require('express');

const app = express();

app.set('view engine', 'hbs')

app.get("/", (req, res) => {
    res.render("index")
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.listen(4000, ()=> {
    console.log("server started on port 4000")
})