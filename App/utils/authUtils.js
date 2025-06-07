const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

//--------------------------------------------------------------------------------------
//                            Function to Hash a Password
//--------------------------------------------------------------------------------------
const HashedPassword = (password) => {
  try {
    const salt = 10;
    const hashedPassword = bcrypt.hashSync(password, salt);
    return hashedPassword;
  } catch (e) {
    console.log(e);
  }
};

//--------------------------------------------------------------------------------------
//                            Function to Compare Passwords
//--------------------------------------------------------------------------------------
const comparePassword = (password, hashedPassword) => {
  return bcrypt.compareSync(password, hashedPassword);
};

//--------------------------------------------------------------------------------------
//                            Middleware to Authenticate Token
//--------------------------------------------------------------------------------------
const AuthCheck = (req, res, next) => {
  console.log("he==>", req.headers.token);

  const token = req.headers.token || req?.headers["x-access-token"];

  console.log("Token ===>", token);
  if (!token) {
    return res
      .status(403)
      .json({ message: "A token is required for authentication" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
  } catch (error) {
    return res.status(401).json({
      message: "Invalid Token",
    });
  }

  return next();
};

module.exports = {
  HashedPassword,
  comparePassword,
  AuthCheck,
};
