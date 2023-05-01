require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

//Expires after 1 hour (hour * minutes * seconds * milliseconds)
const expireTime = 1 * 60 * 60 * 1000;

//Users and Passwords (in memory 'database')
var users = [];

/* Secret Information Section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, 
    saveUninitialized: false,
    resave: true,
  })
);

//Home page that checks for authentication status and offers login or sign-up
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    const buttons = `
        <button onclick="window.location.href='/signup'">Sign up</button>
        <button onclick="window.location.href='/login'">Log in</button>
      `;
    res.send(`<h1>Welcome to Munyoung's Website</h1>${buttons}`);
  } else {
    const buttons = `
        <button onclick="window.location.href='/members'">Go to Members Area</button>
        <button onclick="window.location.href='/logout'">Log out</button>
      `;
    res.send(`<h1>Hello, ${req.session.name}!</h1>${buttons}`);
  }
});

app.get("/nosql-injection", async (req, res) => {
  var name = req.query.user;

  if (!name) {
    res.send(
      `<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + name);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello, ${name}!</h1>`);
});

//Sign up function
app.get("/signup", (req, res) => {
  var html = `
      <h1>Create User Account</h1>
      <form action='/submitUser' method='post'>
      <input name='name' type='text' placeholder='Name'>
      <br>
      <input name='email' type='email' placeholder='Email'>
      <br>
      <input name='password' type='password' placeholder='Password'>
      <br>
      <button>Submit</button>
      </form>
      `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  if (!name || !email || !password) {
    res.send(`All fields are required. <br><br>Please <a href='/signup'>try again</a>`);
    return;
  }

  const schema = Joi.object({
    name: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
  });

  const validationResult = schema.validate({ name, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    var errorMessage = validationResult.error.details[0].message;
    res.send(`Error: ${errorMessage}. <br><br> Please <a href="/signup">try again</a>.`);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    password: hashedPassword,
    email: email,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/loggedin");
});

app.get("/login", (req, res) => {
  var html = `
      <h1>Login Page</h1>
      <form action='/loggingin' method='post'>
      <input name='Email' type='text' placeholder='Email'>
      <br>
      <input name='Password' type='password' placeholder='Password'>
      <br>
      <button>Log in</button>
      </form>
      `;
  res.send(html);
});

app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(`Fill out both email and password. <br><br> Please <a href='/login'>try again!</a>.`);
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length === 0) {
    res.send('Invalid email/password. <br><br> Please <a href="/login">try again</a>.');
    return;
  } else if (result.length != 1) {
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/loggedin");
    return;
  } else {
    res.send('Invalid email/password. <br><br> Please <a href="/login">try again</a>.');
    return;
  }
});

  app.get('/loggedin', (req, res) => {
    if (req.session.authenticated) {
      res.redirect('/members');
    } else {
      res.redirect('/');
    }
  });
  
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });
  
  app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
      res.redirect('/');
    } else {
      const images = ['/Cookie.gif', '/Cute.gif', '/fluffy.gif', '/Yay.gif'];
  
      const randomindex = Math.floor(Math.random() * images.length);
  
      res.send(`<h1>Hello, ${req.session.name}.</h1>
      <img src='${images[randomindex]}' width= "250px">
      <form action='/logout' method='get'> 
        <br>
        <button type ='submit'>Log out</button>
      </form>`);
      
    }
  });

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  const img = `<img src="/404.gif" alt="404"><br>`;
  res.send(img + "<h1>Page not found - 404<h1>");
});

app.listen(port, () => {
  console.log("Assignment 1 listening on port " + port);
});