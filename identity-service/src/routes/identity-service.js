const express = require("express");
const {
  registerUser,
  loginUser,
  refreshTokenUser,
  logoutUser,
  loginWithGoogleAuth,
} = require("../controllers/identity-controller");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/refresh-token", refreshTokenUser);
router.post("/logout", logoutUser);
router.post("/google-auth", loginWithGoogleAuth);
module.exports = router;
