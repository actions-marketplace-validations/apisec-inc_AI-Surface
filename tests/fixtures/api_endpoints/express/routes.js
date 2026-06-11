// A small Express app fixture for the api_endpoints detector.
const express = require("express");
const app = express();
const router = express.Router();

app.get("/api/products", (req, res) => res.json([]));
app.post("/api/products", (req, res) => res.json({}));

router.get("/api/products/:id", (req, res) => res.json({}));
router.delete("/api/products/:id", (req, res) => res.json({}));

module.exports = router;
