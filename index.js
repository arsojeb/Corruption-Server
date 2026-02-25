require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");

const app = express();

// ---------------- MIDDLEWARE ----------------
app.use(cors());
app.use(express.json());

// ---------------- DATABASE ----------------
const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;
let casesCollection;

async function connectDB() {
  if (!client.topology?.isConnected()) {
    await client.connect();
    const db = client.db("Nasir");
    usersCollection = db.collection("users");
    casesCollection = db.collection("cases");
    console.log("✅ MongoDB Connected");
  }
}

connectDB().catch(console.error);

// ---------------- AUTH MIDDLEWARE ----------------
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token provided" });

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ---------------- MULTER (Temporary Memory Storage for Vercel) ----------------
const upload = multer({
  storage: multer.memoryStorage(), // IMPORTANT for serverless
});

// ---------------- AUTH ROUTES ----------------

// Register
app.post("/api/register", async (req, res) => {
  try {
    await connectDB();

    const { name = "", email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const existing = await usersCollection.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);

    await usersCollection.insertOne({
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
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    await connectDB();

    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const user = await usersCollection.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ message: "Wrong password" });

    if (user.blocked)
      return res.status(403).json({ message: "User is blocked" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- CASE ROUTES ----------------

// Get all cases
app.get("/api/cases", async (req, res) => {
  try {
    await connectDB();
    const cases = await casesCollection.find().toArray();
    res.json(cases);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch cases" });
  }
});

// Add case
app.post("/api/cases", auth, upload.single("image"), async (req, res) => {
  try {
    await connectDB();

    const { title, category, description } = req.body;

    await casesCollection.insertOne({
      title,
      category,
      description,
      image: "", // file storage removed for Vercel safety
      userId: new ObjectId(req.user.id),
      createdAt: new Date(),
    });

    res.json({ message: "Case added successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to add case" });
  }
});

// Delete case (Admin only)
app.delete("/api/cases/:id", auth, async (req, res) => {
  try {
    await connectDB();

    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await casesCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });

    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Delete failed" });
  }
});

// ---------------- EXPORT FOR VERCEL ----------------
module.exports = app;