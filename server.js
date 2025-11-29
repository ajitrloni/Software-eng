/**********************************************
 *  ONE FILE BACKEND - MINI LINKEDIN
 *********************************************/

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

/**********************************************
 *  CONNECT TO MONGO
 *********************************************/
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

/**********************************************
 *  MODELS
 *********************************************/
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    bio: String,
    skills: [String],
    connections: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
  })
);

const ConnectionRequest = mongoose.model(
  "ConnectionRequest",
  new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    status: { type: String, default: "pending" }
  })
);

const Job = mongoose.model(
  "Job",
  new mongoose.Schema({
    company: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    title: String,
    description: String,
    location: String,
    skillsRequired: [String],
    applicants: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
  })
);

/**********************************************
 *  MIDDLEWARE
 *********************************************/
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    User.findById(decoded.id)
      .select("-password")
      .then((user) => {
        req.user = user;
        next();
      });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

/**********************************************
 *  AUTH ROUTES
 *********************************************/
app.post("/api/auth/user/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (await User.findOne({ email }))
      return res.status(400).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/user/login", async (req, res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email });
  if (!u) return res.status(400).json({ message: "Invalid email" });

  if (!bcrypt.compareSync(password, u.password))
    return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: u._id }, process.env.JWT_SECRET);
  res.json({ token, user: u });
});

/**********************************************
 *  USERS ROUTES
 *********************************************/
app.get("/api/users/all", auth, async (req, res) => {
  const q = req.query.q || "";
  const users = await User.find({ name: { $regex: q, $options: "i" } });
  res.json(users);
});

/**********************************************
 *  CONNECTION ROUTES
 *********************************************/
app.post("/api/connections/request/:id", auth, async (req, res) => {
  const sender = req.user._id;
  const receiver = req.params.id;

  const exists = await ConnectionRequest.findOne({ sender, receiver });
  if (exists) return res.status(400).json({ message: "Already sent" });

  const reqObj = await ConnectionRequest.create({ sender, receiver });
  res.json(reqObj);
});

/**********************************************
 *  JOB ROUTES
 *********************************************/
app.get("/api/jobs/all", auth, async (req, res) => {
  const jobs = await Job.find().populate("company", "name");
  res.json(jobs);
});

app.get("/api/jobs/:id", auth, async (req, res) => {
  const job = await Job.findById(req.params.id).populate("company", "name");
  res.json(job);
});

app.post("/api/jobs/apply/:id", auth, async (req, res) => {
  await Job.findByIdAndUpdate(req.params.id, {
    $addToSet: { applicants: req.user._id }
  });
  res.json({ message: "Applied" });
});

/**********************************************
 *  START SERVER
 *********************************************/
app.listen(process.env.PORT, () =>
  console.log(`Server running on ${process.env.PORT}`)
);
