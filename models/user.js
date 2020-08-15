let {genSalt, hash, compare} = require("bcrypt-nodejs");
let {Schema, model} = require("mongoose");
let userSchema = Schema({
  username: {type: String, required: true, unique: true},
  email:    {type: String, unique: true},
  password: {type: String, required: true},
  createdAt: {type: Date, default: Date.now},
  displayName: String,
  bio: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

const SALT_FACTOR = 10;

let noop = () => {}; // for use with the bcrypt module.

userSchema.pre("save", function(done) { // hashing password before it is saved!, 'this' is new User
  let user = this;
  if (!user.isModified("password")) {
    done();
  }
  genSalt(SALT_FACTOR, (err, salt) => {
    if (err) {return done(err);}
    hash(user.password, salt, noop, (err, hashedPassword) => {
      if (err) {return done(err);}
      user.password = hashedPassword;
      done();
    });
  });
});

userSchema.methods.checkPassword = function (guess, done) {
  compare(guess, this.password, (err, isMatch) => {
    done(err, isMatch);
  });
};

userSchema.methods.name = function () {
  return this.displayName || this.username;
};

// We now connect the schema to the database model.
let User = model("User", userSchema);
module.exports = User;
