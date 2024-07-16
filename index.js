const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const port = process.env.PORT || 5000;

// middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:5174",
    // "https://survey-vista.web.app",
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

// cookie parser
app.use(cookieParser());

const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nbrjeuw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const usersCollection = client.db("GuardianWalletDB").collection("users");

    // User Related api
    // save user in database
    app.put("/user", async (req, res) => {
      const hashedPassword = await bcrypt.hash(req.body.pin, 10);
      const user = req.body;

      const query = { email: user?.email };
      const isExist = await usersCollection.findOne(query);
      if (isExist) {
        return res.send(isExist);
      }

      // save user in database for first time
      const options = { upsert: true };
      const updateDoc = {
        $set: {
          email: user?.email,
          name: user?.name,
          phone: user?.phone,
          role: user?.role,
          password: hashedPassword,
        },
      };
      const result = await usersCollection.updateOne(query, updateDoc, options);
      res.send(result);
    });

    // Login user
    app.post("/login", async (req, res) => {
      try {
        const { email, pin } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).send("Invalid email or password");
        }
        const isMatch = await bcrypt.compare(pin, user?.password);
        if (!isMatch) {
          return res.status(401).send("Invalid email or password");
        }
        const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
          expiresIn: "1h",
        });
        res.cookie("token", token, { httpOnly: true }).send("Logged in!");
      } catch (err) {
        console.error(err);
        res.status(401).send("Authentication failed");
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Wallet server starting...");
});

app.listen(port, () => {
  console.log(`Wallet in running on port ${port}`);
});
