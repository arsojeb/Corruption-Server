// ---------------- ENV ----------------
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

// ---------------- MODULES ----------------
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");

// ---------------- APP ----------------
const app = express();
app.use(cors());
app.use(express.json());

// ---------------- DATABASE ----------------
const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = "Hadi";

let cachedClient = null;
let cachedDb = null;

async function connectDB() {
  if (cachedClient && cachedDb) return { client: cachedClient, db: cachedDb };

  try {
    const client = new MongoClient(MONGO_URI, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    });

    await client.connect();

    const db = client.db(DB_NAME);

    // Test connection
    await db.command({ ping: 1 });

    cachedClient = client;
    cachedDb = db;

    console.log("✅ MongoDB Connected");
    return { client, db };
  } catch (err) {
    console.error("❌ MongoDB connection failed:", err);
    throw err;
  }
}

// Middleware to attach DB to requests
const attachDB = async (req, res, next) => {
  try {
    const { db } = await connectDB();
    req.db = db;
    req.usersCollection = db.collection("users");
    req.casesCollection = db.collection("cases");
    next();
  } catch (err) {
    res.status(500).json({ message: "Database connection failed", error: err.message });
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
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// ---------------- FILE UPLOAD ----------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

// ---------------- ROUTES ----------------
app.get("/", (req, res) => {
  res.send("🚀 API running...");
});

// -------- AUTH ROUTES --------

// Register
app.post("/api/register", attachDB, async (req, res) => {
  try {
    const { name = "", email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "All fields required" });

    const existing = await req.usersCollection.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

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
    console.error(err);
    res.status(500).json({ message: "Register failed", error: err.message });
  }
});

// Login
app.post("/api/login", attachDB, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await req.usersCollection.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Wrong password" });
    if (user.blocked) return res.status(403).json({ message: "Blocked" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({ token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// -------- CASE ROUTES --------

// Get all cases
app.get("/api/cases", attachDB, async (req, res) => {
  try {
    const cases = await req.casesCollection.find().toArray();
    res.json(cases);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch cases", error: err.message });
  }
});

// Get case by ID
app.get("/api/cases/:id", attachDB, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid ID" });

    const caseData = await req.casesCollection.findOne({ _id: new ObjectId(id) });
    if (!caseData) return res.status(404).json({ message: "Case not found" });

    res.json(caseData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch case", error: err.message });
  }
});

// Add case
app.post("/api/cases", auth, attachDB, upload.single("image"), async (req, res) => {
  try {
    const { title, category, description } = req.body;
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

    res.json({ message: "Case added" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Add case failed", error: err.message });
  }
});

// Delete case (Admin only)
app.delete("/api/cases/:id", auth, attachDB, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid ID" });
    if (req.user.role !== "admin") return res.status(403).json({ message: "Admin only" });

    const result = await req.casesCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ message: "Case not found" });

    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed", error: err.message });
  }
});

// ---------------- SERVER ----------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// ---------------- EXPORT ----------------
module.exports = app;