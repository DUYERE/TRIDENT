const express = require("express");
const router = express.Router();
router.get("/home", requireAuth, (req, res) => res.send("ok"));
