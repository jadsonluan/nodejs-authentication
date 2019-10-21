const auth = require("../middleware/auth");
const bcrypt = require("bcrypt");
const { User, validate, validateCredentials } = require("../models/user.model");
const express = require("express");
const router = express.Router();

router.get("/current", auth, async (req, res) => {
  const user = await User.findById(req.user._id).select("-password");
  res.send(user);
});

router.post("/", async (req, res) => {
  // validate the request body first
  const { error } = validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  //find an existing user
  let user = await User.findOne({ email: req.body.email });
  if (user) return res.status(400).send("User already registered.");

  user = new User({
    name: req.body.name,
    password: req.body.password,
    email: req.body.email
  });
  user.password = await bcrypt.hash(user.password, 10);
  await user.save();

  const token = user.generateAuthToken();
  res.header("x-auth-token", token).send({
    _id: user._id,
    name: user.name,
    email: user.email
  });
});

router.post("/auth", async (req, res) => {
  const { error } = validateCredentials(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const user = await User.findOne({ email: req.body.email });
  const match = await bcrypt.compare(req.body.password, user.password);

  if (!match) return res.status(401).send("Access denied. Wrong password.");

  const token = user.generateAuthToken();
  
  res.header("x-auth-token", token).send({
    _id: user._id,
    name: user.name,
    email: user.email
  });
})

module.exports = router;