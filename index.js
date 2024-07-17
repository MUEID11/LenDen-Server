require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");
const crypto = require("crypto");
const app = express();
const port = process.env.port || 5000;

app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
  })
);

app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.i7qzqrj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
const verifyToken = (req, res, next) => {
  // console.log("verify token from middleware", req.headers.authorization);
  const token = req.headers.authorization?.split(" ")[1];
  console.log("verify token", token);
  if (!token) {
    return res.status(401).send({ message: "Forbidden access" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
    if (error) {
      return res.status(403).send({ message: "Unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });

    const lenden = client.db("lenden");
    const users = lenden.collection("users");
    app.post("/register", async (req, res) => {
      const { name, email, phone, pin, role } = req.body;
      const user = {
        name,
        email,
        phone,
        pin,
        role,
        status: "pending",
        balance: 0,
      };
      try {
        const existingUser = await users.findOne({
          role,
          $or: [{ email }, { phone }],
        });
        if (existingUser) {
          return res.send({ error: "User already exists" });
        }

        const hmac = crypto
          .createHmac("sha256", process.env.SECRET_PIN)
          .update(pin);
        const pin_hash = hmac.digest("hex");
        user.pin = pin_hash;
        const result = await users.insertOne(user);

        res.send(result);
      } catch (error) {
        res.send({ error: error.message });
      }
    });

    app.get("/authentication", verifyToken, async (req, res) => {
      const { email, phone, role } = req.decoded;
      const result = await users.findOne({ email, phone, role });
      if (!result) {
        return res.status(403).send({ message: "Unauthorized access" });
      }
      res.send({
        email: result.email,
        phone: result.phone,
        role: result.role,
        name: result.name,
        status: result.status,
        balance: result.balance,
      });
    });
    app.post("/signin", async (req, res) => {
      const { phonemail, pin } = req.body;

      try {
        const signInUser = await users.findOne({
          $or: [{ email: phonemail }, { phone: phonemail }],
        });

        if (!signInUser) {
          return res.status(404).json({ message: "User not found" });
        }

        if (signInUser.status !== "active") {
          return res
            .status(400)
            .send({ message: "User is not active, please try again later" });
        }

        const hmac = crypto
          .createHmac("sha256", process.env.SECRET_PIN)
          .update(pin);
        const pin_hash = hmac.digest("hex");

        if (signInUser.pin !== pin_hash) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
          {
            email: signInUser.email,
            phone: signInUser.phone,
            role: signInUser.role,
            status: signInUser.status,
          },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.send({ signInUser, token });
      } catch (error) {
        res.status(500).send({ message: "Internal server error" });
      }
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server is sleeping");
});
app.listen(port, () => {
  console.log(`server is running on ${port}`);
});
