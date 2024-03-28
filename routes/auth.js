const express = require("express");
const User = require("../models/user");
const ExpressError = require("../expressError");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const router = express.Router();

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const isAuth = await User.authenticate(username, password);

    if (isAuth) {
      const token = jwt.sign({ username: req.body.username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    }

    return next(new ExpressError("invalid username/password", 400));
  } catch (error) {
    return next(error);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    const result = await User.register(req.body);
    const token = jwt.sign({ username: result.username }, SECRET_KEY);

    return res.json({ token });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
