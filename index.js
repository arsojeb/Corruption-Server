// server.js
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();

// ---------------- MIDDLEWARE ----------------
app.use(cors());
app.use(express.json());

// ---------------- DATABASE CONNECTION ----------------
const uri = process.env.MONGO_URI;
const DB_NAME = "Nasir";

if (!uri) {
  console.error("❌ MONGO_URI not defined in .env");
  process.exit(1);
}

let cachedClient = null;
let cachedDb = null;

async function connectDB() {
  if (cachedClient && cachedDb) return { client: cachedClient, db: cachedDb };

  const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  });

  try {
    await client.connect();
    const db = client.db(DB_NAME);

    cachedClient = client;
    cachedDb = db;

    console.log("✅ MongoDB Connected & Cached");
    return { client, db };
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.stack || err);
    throw err;
  }
}

// Attach DB to request
const attachDB = async (req, res, next) => {
  try {
    const { db } = await connectDB();
    req.db = db;
    req.usersCollection = db.collection("users");
    req.casesCollection = db.collection("cases");
    next();
  } catch (err) {
    console.error("AttachDB Error:", err.stack || err);
    res.status(500).json({ message: "Database connection failed" });
  }
};

// ---------------- AUTH MIDDLEWARE ----------------
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token provided" });

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    console.error("Auth Error:", err.stack || err);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ---------------- MULTER (memory storage for Vercel) ----------------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// ---------------- BASIC ROUTE ----------------
app.get("/", (req, res) => res.send("🚀 API is running..."));

// ---------------- AUTH ROUTES ----------------
// Register
app.post("/api/register", attachDB, async (req, res) => {
  try {
    const { name = "", email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const existing = await req.usersCollection.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);

    await req.usersCollection.insertOne({
      name,
      email,
      password: hashed,
      role: "user",
      blocked: false,
      createdAt: new Date(),
    });

    res.json({ message: "Registered successfully" });
  } catch (err) {
    console.error("Register Error:", err.stack || err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/login", attachDB, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const user = await req.usersCollection.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Wrong password" });

    if (user.blocked) return res.status(403).json({ message: "User is blocked" });

    const token = jwt.sign(
      { id: user._id.toString(), role: user.role }, // convert ObjectId to string
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error("Login Error:", err.stack || err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- CASE ROUTES ----------------
// Get all cases
app.get("/api/cases", attachDB, async (req, res) => {
  try {
    const cases = await req.casesCollection.find().toArray();
    res.json(cases);
  } catch (err) {
    console.error("Get Cases Error:", err.stack || err);
    res.status(500).json({ message: "Failed to fetch cases" });
  }
});

// Add case
app.post("/api/cases", attachDB, upload.single("image"), auth, async (req, res) => {
  try {
    const { title, category, description } = req.body;
    if (!title || !category || !description)
      return res.status(400).json({ message: "All fields required" });

    // Store image as base64 string in MongoDB
    let imageUrl = "";
    if (req.file) {
      const base64 = req.file.buffer.toString("base64");
      imageUrl = `data:${req.file.mimetype};base64,${base64}`;
    }

    await req.casesCollection.insertOne({
      title,
      category,
      description,
      image: imageUrl,
      userId: new ObjectId(req.user.id),
      createdAt: new Date(),
    });

    res.json({ message: "Case added successfully" });
  } catch (err) {
    console.error("Add Case Error:", err.stack || err);
    res.status(500).json({ message: "Failed to add case" });
  }
});

// Delete case (Admin only)
app.delete("/api/cases/:id", attachDB, auth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Case ID" });
    if (req.user.role !== "admin") return res.status(403).json({ message: "Admin only" });

    const result = await req.casesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ message: "Case not found" });

    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("Delete Case Error:", err.stack || err);
    res.status(500).json({ message: "Delete failed" });
  }
});

// ---------------- RUN LOCALLY ----------------
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}

// ---------------- EXPORT FOR VERCEL ----------------
module.exports = app;