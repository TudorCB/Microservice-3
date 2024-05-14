
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load environment variables

const authenticate = async (req, res, next) => {
  const token = req.headers['x-access-token'] || req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.user = decoded.user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

const authorize = (requiredPermissions) => {
  return async (req, res, next) => {
    const user = req.user;
    if (!user || !user.roles) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const hasPermission = user.roles.some(role => {
      return requiredPermissions.includes(role.name);
    });

    if (!hasPermission) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    next();
  };
};

module.exports = { authenticate, authorize };

