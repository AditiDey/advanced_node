const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost:27017/marketplace_db', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  quantity: {
    type: Number,
    required: true,
  },
});

const Product = mongoose.model('Product', productSchema);

// Authentication Middleware

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (token == null) {
      return res.sendStatus(401);
    }
  
    jwt.verify(token, "12345", (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  }

// User Registration and Authentication
app.post('/api/user/register', [
  body('username').notEmpty().isAlphanumeric(),
  body('password').notEmpty().isLength({ min: 6 }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  const user = new User({ username, password: hashedPassword });

  user.save()
    .then(() => {
      res.status(201).json({ message: 'User registered successfully' });
    })
    .catch((error) => {
      res.status(400).json({ error: 'Failed to register user' });
    });
});

app.post('/api/user/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username:username })
    .then((user) => {
      if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      const id=user._id;

      const accessToken = jwt.sign({id}, '12345',{
        expiresIn: 6*60*60
      });
      console.log(accessToken);
      res.cookie('jwt',accessToken,{httpOnly:true,maxAge:6*60*60});
      //return res.status(200).json({msg:"customer registered"});
      res.json({ accessToken });
    })
    .catch((error) => {
      res.status(500).json({ error: error });
    });
});

// Product Listing and Search
app.post('/api/products', [
  body('title').notEmpty(),
  body('price').notEmpty().isNumeric(),
  body('quantity').notEmpty().isInt(),
], authenticateToken, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, price, quantity } = req.body;
  const product = new Product({ title, price, quantity });

  product.save()
    .then(() => {
      res.status(201).json({ message: 'Product listed successfully' });
    })
    .catch((error) => {
      res.status(400).json({ error: 'Failed to list product' });
    });
});


app.get('/api/products', (req, res) => {
  const { query } = req.query;
  const regex = new RegExp(query, 'i');

  Product.find({ title: regex })
    .then((products) => {
      res.json(products);
    })
    .catch((error) => {
      res.status(400).json({ error: 'Failed to fetch products' });
    });
});

// Admin Section
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.isAdmin) {
    User.find()
      .then((users) => {
        res.json(users);
      })
      .catch((error) => {
        res.status(400).json({ error: 'Failed to fetch users' });
      });
  } else {
    res.sendStatus(403);
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal Server Error' });
});
app.post('/api/user/logout', authenticateToken, (req, res) => {
  // Clear the JWT cookie by setting its maxAge to 1 millisecond
  res.cookie('jwt', '', { maxAge: 1 });

  res.status(200).json({ message: 'User logged out successfully' });
});

// Start the server
app.listen(8080, () => {
  console.log('Server is running on http://localhost:8080');
});
