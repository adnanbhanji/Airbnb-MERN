const express = require("express");
const app = express();
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const userModel = require("./models/User");
const bcryptjs = require("bcryptjs");
require("dotenv").config();
const jsonwebtoken = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const bcryptSalt = bcryptjs.genSaltSync(10);
const jsonwebtokenSecret = process.env.JSON_WEB_TOKEN_SECRET;

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: "http://localhost:5173",
  })
);

mongoose.connect(process.env.MONGO_URL);

app.get("/test", (req, res) => {
  res.json("Hello World!");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const userDoc = await userModel.create({
      name,
      email,
      password: bcryptjs.hashSync(password, bcryptSalt),
    });
    res.json(userDoc);
  } catch (error) {
    res.status(422).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const userDoc = await userModel.findOne({ email });
  if (userDoc) {
    const passOk = bcryptjs.compareSync(password, userDoc.password);
    if (passOk) {
      jsonwebtoken.sign(
        { email: userDoc.email, id: userDoc._id },
        jsonwebtokenSecret,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token).json(userDoc);
        }
      );
    } else {
      res.status(422).json("pass not ok");
    }
  } else {
    res.json("User not found");
  }
});

app.get("/profile", async (req, res) => {
  const token = req.cookies.token;
  if (token) {
    jsonwebtoken.verify(token, jsonwebtokenSecret, {}, async (err, user) => {
      if (err) throw err;
      const userDoc = await userModel.findById(user.id);
      res.json({ name: userDoc.name, email: userDoc.email, id: userDoc._id });
    });
  } else {
    res.json(null);
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token").json("Logged out");
});

app.listen(4000);
