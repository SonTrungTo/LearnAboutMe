const User = require("./models/user");

const passport = require("passport");

module.exports = () => {
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      done(err, user);
    });
  });
};

const LocalStrategy = require("passport-local").Strategy;

passport.use("login", new LocalStrategy(
  (username, password, done) => {
    User.findOne({username}, (err, user) => {
      if (err) {return done(err);}
      if (!user) {
        return done(null, false,
         {message: "User does not exist!"});
      }
      user.checkPassword(password, (err, isMatch) => {
        if (err) {return done(err);}
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false,
           {message: "Wrong password!"});
        }
      });
    });
  }
));
