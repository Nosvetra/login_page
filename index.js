import express from "express";
import env from "dotenv";
import pg from "pg";
import bodyParser from "body-parser";
import passport from "passport";
import session from "express-session";
import bcrypt from "bcrypt";
import { Strategy } from "passport-local";

const app = express();
env.config();
const port = process.env.EXPRESS_PORT;
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
const saltRounds = 11;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());

db.connect();
app.get("/", (req, res) => {
  res.render("index.ejs");
});
app.get("/login", (req, res) => {
  res.render("login.ejs");
});
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/random", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("random.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  const userName = req.body.username;
  const password = req.body.password;

  try {
    const initialCheck = await db.query(
      "SELECT * FROM login_pj WHERE username = $1",
      [userName]
    );
    console.log(initialCheck.rowCount);
    if (initialCheck.rowCount > 0) {
      console.log("User already Exists");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("error Hashing Passowrd", err);
        } else {
          const result = await db.query(
            "INSERT INTO login_pj (username, password) VALUES ($1,$2) RETURNING *",
            [userName, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/random");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/random",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query(
        "SELECT * FROM login_pj WHERE username = $1",
        [username]
      );
      if (result.rowCount > 0) {
        const user = result.rows[0];
        const storedHashedPassword = result.rows[0].password;
        bcrypt.compare(password, storedHashedPassword, (err, outcome) => {
          if (err) {
            console.log("hashing Error", err);
          } else {
            if (outcome) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("Username Does not exits");
      }
    } catch (err) {
      console.log("its not happening");
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  return cb(null, user);
});
passport.deserializeUser((user, cb) => {
  return cb(null, user);
});
app.listen(port, () => {
  console.log(`Server is running on ${port}`);
});
