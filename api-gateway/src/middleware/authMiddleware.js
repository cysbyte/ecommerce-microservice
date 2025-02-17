const logger = require("../utils/logger");
const jwt = require("jsonwebtoken");

const validateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  const refreshToken = req.cookies.refreshToken;

  if (!token) {
    logger.warn("Access attempt without valid token!");
    return res.status(401).json({
      message: "Authentication required",
      success: false,
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // Check if error is due to token expiration and refresh token exists
      if (err.name === "TokenExpiredError" && refreshToken) {
        // Verify refresh token
        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (refreshErr, refreshUser) => {
          if (refreshErr) {
            logger.warn("Invalid refresh token!");
            return res.status(401).json({
              message: "Invalid refresh token!",
              success: false,
            });
          }

          // Generate new access token
          const newAccessToken = jwt.sign(
            { userId: refreshUser.userId },
            process.env.JWT_SECRET,
            { expiresIn: "15m" }
          );

          // Set new access token in response header
          res.setHeader("Authorization", `Bearer ${newAccessToken}`);
          
          // Continue with the request using refresh token's user data
          req.user = refreshUser;
          next();
        });
      } else {
        logger.warn("Invalid token!");
        return res.status(401).json({
          message: "Invalid token!",
          success: false,
        });
      }
    } else {
      req.user = user;
      next();
    }
  });
};

module.exports = { validateToken };
