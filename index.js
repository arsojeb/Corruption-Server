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

// -----------------------------------------------------------------------------
// helpers & middleware
// -----------------------------------------------------------------------------

app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));

if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: "./uploads",
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

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

// -----------------------------------------------------------------------------
// database
// -----------------------------------------------------------------------------

const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;
let casesCollection;

const connectDB = async () => {
  await client.connect();
  const db = client.db("Nasir");
  usersCollection = db.collection("users");
  casesCollection = db.collection("cases");
  console.log("✅ MongoDB Connected");
};

// -----------------------------------------------------------------------------
// auth routes
// -----------------------------------------------------------------------------

// register
app.post("/api/register", async (req, res) => {
  try {
    const { name = "", email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    if (await usersCollection.findOne({ email })) {
      return res.status(400).json({ message: "Email already registered" });
    }

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
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Wrong password" });
    }

    if (user.blocked) return res.status(403).json({ message: "User is blocked" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// -----------------------------------------------------------------------------
// case routes
// -----------------------------------------------------------------------------

app.get("/api/cases", async (req, res) => {
  try {
    const cases = await casesCollection.find().toArray();
    res.json(cases);
  } catch (err) {
    console.error("Fetch cases error:", err);
    res.status(500).json({ message: "Failed to fetch cases" });
  }
});

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
  } catch (err) {
    console.error("Add case error:", err);
    res.status(500).json({ message: "Failed to add case" });
  }
});

app.delete("/api/cases/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }
    await casesCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("Delete case error:", err);
    res.status(500).json({ message: "Delete failed" });
  }
});

// -----------------------------------------------------------------------------
// admin utilities
// -----------------------------------------------------------------------------

app.put("/api/block/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }
    const user = await usersCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.status(404).json({ message: "User not found" });

    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { blocked: !user.blocked } }
    );
    res.json({ message: "User status updated" });
  } catch (err) {
    console.error("Block user error:", err);
    res.status(500).json({ message: "Update failed" });
  }
});

// one‑time admin creation
app.get("/create-admin", async (req, res) => {
  try {
    const exist = await usersCollection.findOne({ email: "admin@corruption.com" });
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
  } catch (err) {
    console.error("Create admin error:", err);
    res.status(500).send("Error creating admin");
  }
});

// -----------------------------------------------------------------------------
// start server
// -----------------------------------------------------------------------------

connectDB()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`🚀 Server running at http://localhost:${PORT}`)
    );
  })
  .catch((err) => {
    console.error("❌ DB Connection Failed:", err);
  });