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
      const _token = jwt.sign({ username: req.body.username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ _token });
    }

    return next(new ExpressError("invalid username/password"));
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
    const { username } = req.body;
    const result = await User.register(username);
    return res.json({ result });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
