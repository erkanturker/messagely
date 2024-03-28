const express = require("express");
const Message = require("../models/message");
const { ensureLoggedIn } = require("../middleware/auth");
const ExpressError = require("../expressError");

const router = express.Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);

    if (
      req.user.username === message.from_user.username ||
      req.user.username === message.to_user.username
    ) {
      return res.json({ message });
    }
    throw new ExpressError("You are unauthorized the see the message", 401);
  } catch (error) {
    return next(error);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async (req, res, next) => {
  try {
    const sendMsg = { from_username: req.user.username, ...req.body };
    console.log(sendMsg);
    const newMsg = await Message.create(sendMsg);
    return res.json({ message: newMsg });
  } catch (error) {
    return next(error);
  }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (req.user.username === message.to_user.username) {
      const updatedMessage = await Message.markRead(req.params.id);
      return res.json({
        message: {
          id: updatedMessage.id,
          read_at: updatedMessage.read_at,
        },
      });
    }
    throw new ExpressError("Unauhotized Action", 403);
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
