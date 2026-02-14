require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// ===== MongoDB Connection =====
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
  await client.connect();
  const db = client.db("Nasir");

  usersCollection = db.collection("users");
  casesCollection = db.collection("cases");

  console.log("✅ MongoDB Connected");
}

// ===== Multer Setup =====
const storage = multer.diskStorage({
  destination: "./uploads",
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ===== Auth Middleware =====
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token provided" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ================= AUTH =================

// Register (Email Based)
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const exist = await usersCollection.findOne({ email });
    if (exist)
      return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);

    await usersCollection.insertOne({
      name: name || "",
      email,
      password: hashed,
      role: "user",
      blocked: false,
      createdAt: new Date(),
    });

    res.json({ message: "Registered successfully" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login (Email Based)
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const user = await usersCollection.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
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
    res.status(500).json({ message: "Server error" });
  }
});

// ================= CASES =================

// Get all cases
app.get("/api/cases", async (req, res) => {
  try {
    const cases = await casesCollection.find().toArray();
    res.json(cases);
  } catch {
    res.status(500).json({ message: "Failed to fetch cases" });
  }
});

// Add case
app.post("/api/cases", auth, upload.single("image"), async (req, res) => {
  try {
    const { title, category, description } = req.body;

    await casesCollection.insertOne({
      title,
      category,
      description,
      image: req.file ? "/uploads/" + req.file.filename : "",
      userId: new ObjectId(req.user.id),
      createdAt: new Date(),
    });

    res.json({ message: "Case added successfully" });

  } catch {
    res.status(500).json({ message: "Failed to add case" });
  }
});

// Delete case (Admin Only)
app.delete("/api/cases/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    await casesCollection.deleteOne({
      _id: new ObjectId(req.params.id),
    });

    res.json({ message: "Deleted successfully" });

  } catch {
    res.status(500).json({ message: "Delete failed" });
  }
});

// Block user (Admin Only)
app.put("/api/block/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ message: "Admin only" });

    const user = await usersCollection.findOne({
      _id: new ObjectId(req.params.id),
    });

    if (!user)
      return res.status(404).json({ message: "User not found" });

    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { blocked: !user.blocked } }
    );

    res.json({ message: "User status updated" });

  } catch {
    res.status(500).json({ message: "Update failed" });
  }
});

// ===== Create Admin (Use Once Then Delete) =====
app.get("/create-admin", async (req, res) => {
  const exist = await usersCollection.findOne({
    email: "admin@corruption.com",
  });

  if (exist) return res.send("Admin already exists");

  const hashed = await bcrypt.hash("admin123", 10);

  await usersCollection.insertOne({
    name: "Admin User",
    email: "admin@corruption.com",
    password: hashed,
    role: "admin",
    blocked: false,
    createdAt: new Date(),
  });

  res.send("Admin created → email: admin@corruption.com password: admin123");
});

// ===== START SERVER =====
connectDB()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`🚀 Server running at http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("❌ DB Connection Failed:", err);
  });
