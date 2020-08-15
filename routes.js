const express = require("express");
const passport = require("passport");
// password resets and password validation
const nodemailer = require("nodemailer"); // sending email
const crypto     = require("crypto");     // generate random tokens for reset, part of nodejs
const {check, validationResult} = require("express-validator"); // to recheck password and other checks
const async = require("async");      // async.waterfall to avoid the use of nested callbacks
require("dotenv").config();

const User = require("./models/user");

const router = express.Router();

router.use((req, res, next) => { // these are for ejs templates
  res.locals.currentUser = req.user;
  res.locals.errors = req.flash("error");
  res.locals.infos = req.flash("info");
  next();
});

router.get("/", (req, res, next) => { // Using queries to list users from the newest
  User.find()
  .sort({createdAt: "descending"})
  .exec((err, users) => {
    if (err) {return  next(err);}
    res.render("index", {users});
  });
});

router.get("/signup", (req, res) => {
  res.render("signup");
});

router.post("/signup", [
  check('username')
        .not()
        .isEmpty()
        .withMessage('Name is required!'),
  check('password', 'Password is required')
        .isLength({min: 5})
        .custom((val, {req, loc, path}) => {
          if (val !== req.body.confirm) {
            throw new Error("Passwords don't match");
          } else {
            return value;
          }
        }),
  check('email', 'Email is required!').isEmail()
], (req, res, next) => {
  let username = req.body.username;
  let password = req.body.password;
  let email    = req.body.email;

  let errors = validationResult(req).array();

  User.findOne({$and: [{username}, {email}]}, (err, user) => {
    if (err) {return next(err);}
    if (user) {
      req.flash("error", "User or email already exists!");
      return res.redirect("/signup");
    }
    if (errors) {
      for (let error of errors) {
        req.flash("error", String(error.msg));
      }
      return res.redirect("/signup");
    }
    let newUser = new User({
      username,
      password,
      email
    });
    newUser.save(next); // Create a new user instance, save it to the database and move to the next request handler
  });
}, passport.authenticate("login", { // Authenticate the user with passport
  successRedirect: "/",
  failureRedirect: "/signup",
  failureFlash:    true
}));

router.get("/users/:username", (req, res, next) => {
  User.findOne({username: req.params.username}, (err, user) => {
    if (err) {return next(err);}
    if (!user) {return next(404);}
    res.render("profile", {user});
  });
});

router.get("/login", (req, res) => {
  res.render("login");
});

router.post("/login", passport.authenticate("login", {
  successRedirect: "/",
  failureRedirect: "/login",
  failureFlash: true
}));

router.get("/logout", (req, res) => {
  req.logout(); // thanks to passport, it also populates req.user, req.flash("error"), req.flash("info")
  res.redirect("/");
});

// ensure that users are authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { // thanks to passport
    next();
  } else {
    req.flash("info", "You need to log in to view this page!");
    res.redirect("/login");
  }
}

router.get("/edit", ensureAuthenticated, (req, res) => {
  res.render("edit");
});

router.post("/edit", ensureAuthenticated, (req, res, next) => {
  req.user.displayName = req.body.displayname;
  req.user.bio = req.body.bio;
  req.user.save(err => {
    if (err) {
      next(err);
      return;
    }
    req.flash("info", "Profile updated!");
    res.redirect("/edit");
  });
});

router.get("/forgot", (req, res) => {
  res.render("forgot");
});

router.post("/forgot", (req, res, next) => {
  async.waterfall([
    (done) => {
      crypto.randomBytes(20, (err, buf) => {
        let token = buf.toString("hex");
        done(err, token);
      });
    },
    (token, done) => {
      User.findOne({email: req.body.email}, (err, user) => {
        if (!user) {
          req.flash("error", "No account with that email exists!");
          return res.redirect("/forgot");
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(err => {
          done(err, token, user);
        });
      });
    },
    (token, user, done) => {
      const smtpTransport = nodemailer.createTransport({
        service: "SendGrid",
        auth: {
          user: process.env.REACT_APP_SENDGRID_USERNAME,
          pass: process.env.REACT_APP_SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to: user.email,
        from: process.env.REACT_APP_SENDGRID_USERNAME,
        subject: 'LearnFromMe Password Reset',
        text: 'You are receiving this because you (or someone else) have requested ' +
        'the reset of the password for your account on Learn From Me webpage. \n\n' +
        'Please click on the following link, or paste this into your browser to complete ' +
        'the process: \n\n' +
        'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        'If you did not request this, please ignore this email and your password ' +
        'will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, err => {
        req.flash("info", `An email has been sent to ${user.email} with further instructions.\n
Check your spam folder since this is a test!`);
        done(err);
      });
    }
  ], (err) => {
    if (err) {return next(err);}
    res.redirect("/forgot");
  });
});

router.get("/reset/:token", (req, res, next) => {
  User.findOne( {resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
    if(err) {return next(err);}
    if(!user) {
      req.flash("error", "Password token is invalid/expired!");
      return res.redirect("/forgot");
    }
    res.render("reset");
  });
});

router.post("/reset/:token", (req, res, next) => {
  async.waterfall([
    done => {
      User.findOne( {resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
        if (err) {return next(err);}
        if (!user) {
          req.flash("error", "Password token has expired or is invalid!");
          return res.redirect("forgot");
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(err => {
          if (err) {return next(err);}
          passport.authenticate("login", {
            successRedirect: "/",
            failureRedirect: "/login",
            failureFlash: true
          });
          done(err, user);
        });
      });
    },
    (user, done) => {
      const smtpTransport = nodemailer.createTransport({
        service: "SendGrid",
        auth: {
          user: process.env.REACT_APP_SENDGRID_USERNAME,
          pass: process.env.REACT_APP_SENDGRID_PASSWORD
        }
      });
      const mailOptions = {
        to:       user.email,
        from:     process.env.REACT_APP_SENDGRID_USERNAME,
        subject:  'LearnFromMe password has been changed,',
        text:  'Hi, \n\n' +
        'This is a confirmation that your password for the account' + user.email +
        'has been changed. \n\n' +
        'Best, \n' + 'LearnFromMe team.'
      };
      smtpTransport.sendMail(mailOptions, err => {
        req.flash('info', 'Success! Your password has been changed!');
        done(err);
      });
    }
  ], err => {
    if (err) throw new Error("OOPS! Something is wrong!");
    res.redirect("/");
  });
});

module.exports = router;
