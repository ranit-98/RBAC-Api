const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        statusCode: 401,
        message: 'No token, authorization denied',
        data: null
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      statusCode: 401,
      message: 'Token is not valid',
      data: null
    });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        statusCode: 403,
        message: 'Access denied. Admin role required.',
        data: null
      });
    }
    next();
  } catch (err) {
    return res.status(500).json({
      statusCode: 500,
      message: 'Server error',
      data: null
    });
  }
};

module.exports = { auth, adminAuth };
