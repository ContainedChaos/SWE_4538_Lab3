const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const initializePassport = require("../config/passport");
var fs = require('fs')
const user = require("../users.json")
var passwordValidator = require('password-validator');

var schema = new passwordValidator();

schema
.is().min(8)                                    // Minimum length 8
.is().max(100)                                  // Maximum length 100
.has().uppercase()                              // Must have uppercase letters
.has().lowercase()                              // Must have lowercase letters
.has().digits(1)       


const usersData = JSON.parse(fs.readFileSync(path.join(__dirname, '../users.json'), 'utf8'));

function getUserByEmail(email) {
  return usersData.find(user => user.email === email);
}

function getUserById(id) {
  return usersData.find(user => user.id === id);
}

initializePassport(passport, getUserByEmail, getUserById);

const postLogin = (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      return next(err); // Pass any errors to the next middleware
    }

    if (!user) {
      return res.status(401).send(info.message); // Send an unauthorized status and the error message
    }

    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect('/welcome');
    });
  })(req, res, next);
};


const getLogin = async (req, res) => {
  const filePath = path.join(__dirname, "..", "views", "login.html");
  res.sendFile(filePath);
};

// const postLogin = (req, res, next) => {

//   passport.authenticate("local", {
//     successRedirect: "/welcome",
//     failureRedirect: "/login",
//     failureFlash: true,
//   })(req, res, next);
// };



const getRegister = async (req, res) => {
  const filePath = path.join(__dirname, "..", "views", "register.html");
  res.sendFile(filePath);
};

const postRegister = async (req, res, next) => {
  let existingData = [];
  
  try {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;

    if (passwordRegex.test(req.body.password)) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);

      const jsonData = fs.readFileSync('users.json', 'utf8');
      existingData = JSON.parse(jsonData);

      const id = Date.now().toString();
      const name = req.body.username;
      const email = req.body.email;

      const newData = { "id": id, "name": name, "email": email, "password": hashedPassword };

      existingData.push(newData);

      fs.writeFileSync('users.json', JSON.stringify(existingData, null, 2));

      res.redirect("/login");
    } else {
      res.send("Password error. Must have at least 8 characters, 1 capital letter, 1 small letter, and 1 number.");
    }    
  } catch(error) {
    console.log(error)
    res.redirect("/register");
  }
};



module.exports = {
  getLogin,
  getRegister,
  postLogin,
  postRegister,
};
