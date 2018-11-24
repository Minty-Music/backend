const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const Users = mongoose.model('Users');
const jwtSecret = process.env.JWT_SECRET;

const getToken = function(req) {
  return req.header('token');
};

const verifyToken = function(req, res, next) {
  var token = getToken(req);
  if (token) {
    jwt.verify(token, jwtSecret, function(err, decoded) {
      if(err) {
        return res.status(401).send({
          success: false,
          message: "Failed to authenticate token."
        });
      }
      else {
        req.decoded = decoded;
        next();
      }
    });
  }
  else {
    return res.status(403).send({
      success: false,
      message: "No token provided"
    });
  }
};

const signup = function(req, res) {
    var params = req.body;

    //Create new user from request params
    const newUser = new Users(params);
    newUser.setPassword(params.password);

    //Save new user
    newUser.save(function(err) {
      if (err) {
        res.json({
          success: false,
          errorMap: { message: "failed to save user." },
          token: null
        });
      } else {
        res.json({
          success: true,
          message: "user successfully created",
          token: newUser.createJWT(),
          user: newUser.toJSON()
        });
      }
    });
};

const login = function(req, res, next) {
  var params = req.body;

  if (!params.email || !params.password) {
    res.json({
        success: false,
        message: 'Insufficient login information'
    });
  }

  return passport.authenticate('local', { session: false }, function(err, user) {
    if (err) {
      return next(err);
    }
    if (user) {
      user.token = user.createJWT();
      res.json({
        success: true,
        message: "user successfully signed in",
        token: user.token,
      });
    }
    else {
      res.json({
        success: false,
        message: "Invalid email/password",
      });
    }
  })(req, res, next);
};

var functions = {
    login,
    signup,
    verifyToken,
};

module.exports = functions;
