const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const fetch = require("node-fetch");

require("dotenv").config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// ===== MODELS =====
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  ageConfirmed: { type: Boolean, default: false },
  favorites: [{ id: String, title: String, snippet: String, url: String }]
});
const User = mongoose.model("User", UserSchema);

// ===== MIDDLEWARE =====
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "no_token" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: "bad_token" });
  }
}

// ===== ROUTES =====
// Register
app.post("/register", async (req, res) => {
  const { email, password, age } = req.body;
  if (!email || !password || !age) return res.status(400).json({ error: "missing_fields" });
  if (age < 18) return res.status(403).json({ error: "must_be_18" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ email, password: hash, ageConfirmed: true });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "email_taken" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "no_user" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "wrong_pass" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// Search
app.post("/search", auth, async (req, res) => {
  const { query, page = 1 } = req.body;
  if (!query) return res.status(400).json({ error: "no_query" });

  // placeholder external API call
  const results = Array.from({ length: 10 }).map((_, i) => ({
    id: `${query}_${page}_${i}`,
    title: `Result ${i + 1} for "${query}"`,
    snippet: `This is a placeholder snippet for ${query}.`,
    url: `https://example.com/${query}/${i}`
  }));

  // fake moderation filter (flag even items)
  const moderated = results.map((r, idx) => ({
    ...r,
    flagged: idx % 2 === 0 // simulate
  }));

  res.json({ results: moderated, nextPage: page + 1 });
});

// Favorites
app.post("/favorites", auth, async (req, res) => {
  const { id, title, snippet, url } = req.body;
  const user = await User.findById(req.userId);
  user.favorites.push({ id, title, snippet, url });
  await user.save();
  res.json({ ok: true });
});

app.get("/favorites", auth, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json({ favorites: user.favorites });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Server running on", PORT));