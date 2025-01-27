import express, { Router } from "express";
import mysql from "mysql2";
import dotenv from "dotenv";
import cors from "cors";
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
import multer from "multer";
import { Server } from "socket.io";
import http from "http";

dotenv.config();


const app = express();

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", // or restrict to your front-end domain
    methods: ["GET", "POST"],
  },
  path: "/socket.io", // Explicitly setting the path
});


io.on("connection", (socket) => {
  console.log("A user connected");

  // Join vendor-specific room
  socket.on("joinRoom", ({ vendorId }) => {
    socket.join(`vendor_${vendorId}`);
    console.log(`Vendor with ID ${vendorId} joined room`);
  });

  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });
});

// CORS Options

app.use(cors());

app.use(bodyParser.json());

// MySQL Connection Pool
const db = mysql.createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    port: process.env.MYSQL_PORT,
}).promise();

db.query('SELECT 1')
  .then(() => console.log('Connected to the database!'))
  .catch(err => console.error('Database connection failed:', err));

const storage = multer.memoryStorage(); // Stores the file buffer in memory
const upload = multer({ storage });
// Middleware to Test Backend
app.get("/", (req, res) => {
    res.json("Hello, this is middleware practice!");
});

// Route to Retrieve All Data from Table
app.get("/getUsers", async (req, res) => {
    try {
        // Query the MySQL table
        const [result] = await db.query("SELECT cart FROM new_table;");
        //console.log("Fetched Data:", result);

        // Send data as JSON
        res.json(result);
    } catch (err) {
        console.error("Error fetching users:", err.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



app.post('/vendors/register', async (req, res) => {
  const { 
    email, 
    kitchenBusinessName, 
    name, 
    contact, 
    dob, 
    address, 
    pinCode, 
    city, 
    serviceableArea, 
    bankDetails, 
    fsaiLicense, 
    adharDoc, 
    password  // Add password field
  } = req.body;

  // Check for missing required fields
  if (!email || !kitchenBusinessName || !name || !contact || !dob || !address || !pinCode || !city || !serviceableArea || !bankDetails || !fsaiLicense || !adharDoc || !password) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  try {
    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL query including the Password field
    const query = `
      INSERT INTO Vendor 
      (Email, Kitchen_Business_name, Name, Contact, Dob, Address, PIN_code, City, Serviceable_area, Bank_Details, Fsai_License_detail, DOC_ADHAR, Password) 
      VALUES 
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    // Execute the query with all the form data and the hashed password
    const [result] = await db.execute(query, [
      email, 
      kitchenBusinessName, 
      name, 
      contact, 
      dob, 
      address, 
      pinCode, 
      city, 
      serviceableArea, 
      bankDetails, 
      fsaiLicense, 
      adharDoc, 
      hashedPassword // Use the hashed password here
    ]);

    res.status(201).json({ message: 'Vendor registered successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

const secretKey = 'your-secret-key'; // Replace with your secret key for JWT if using tokens

app.post('/vendors/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and Password are required' });
  }

  try {
    // SQL Query to fetch the user by email
    const query = `SELECT * FROM Vendor WHERE Email = ?`;
    const [rows] = await db.execute(query, [email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No vendor found with this email' });
    }

    const vendor = rows[0];

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, vendor.Password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // If valid, optionally generate a JWT or session (based on requirements)
    const token = jwt.sign(
      { vendorId: vendor.ID, email: vendor.Email }, // Payload
      secretKey,                                    // Secret key
      { expiresIn: '2h' }                           // Expiration time
    );

    res.status(200).json({
      message: 'Login successful!',
      token, // Return the token to the client for authentication in future requests
      vendor: {
        id: vendor.Vendor_id ,
        name: vendor.Name,
        email: vendor.Email,
        kitchenBusinessName: vendor.Kitchen_Business_name,
        city: vendor.City
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.put('/vendors/profile-photo', upload.single('photo'), async (req, res) => {
  const email = req.body.email; // Pass the email in the form-data
  const photo = req.file ? req.file.buffer : null; // Get the image file buffer

  if (!email || !photo) {
    return res.status(400).json({ error: 'Email and photo are required' });
  }

  try {
    const query = `
      UPDATE Vendor
      SET profile_photo = ?
      WHERE Email = ?
    `;

    const [result] = await db.execute(query, [photo, email]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    res.json({ message: 'Profile photo updated successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Fetch Vendor Profile with Photo
app.get('/vendors/profile', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const query = `
      SELECT Name, Email, Contact, Address, profile_photo FROM Vendor
      WHERE Email = ?
    `;
    const [rows] = await db.execute(query, [email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    const profile = rows[0];

    // Convert the photo binary to Base64
    if (profile.profile_photo) {
      profile.profile_photo = profile.profile_photo.toString('base64');
    }

    res.json(profile);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

// Update Vendor Profile
app.put("/vendors/profile", async (req, res) => {
  const { email, name, phone, address } = req.body;

  // Validate required fields
  if (!email || !name || !phone || !address) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const query = `
      UPDATE Vendor
      SET Name = ?, Contact = ?, Address = ?
      WHERE Email = ?
    `;
    const [result] = await db.execute(query, [name, phone, address, email]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Vendor not found" });
    }

    res.json({ message: "Profile updated successfully!" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Something went wrong" });
  }
});



app.post('/add-product', upload.single('image'), async (req, res) => {
  const { name, description, price, vendor_id } = req.body;
  const image = req.file ? req.file.buffer : null;

  const query = `
    INSERT INTO food_product (Name, Description, Vendor_id, price, product_image)
    VALUES (?, ?, ?, ?, ?)
  `;

  try {
    await db.execute(query, [name, description, vendor_id, price, image]);
    res.status(201).json({ message: 'Product added successfully!' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'A product with this name already exists for this vendor.' });
    } else {
      res.status(500).json({ error: 'Something went wrong.' });
    }
  }
});

app.get('/products', async (req, res) => {
  const vendorId = req.query.vendor_id; // Retrieve vendor ID from query parameters

  const query = `
    SELECT Product_id, Name, Description, price, product_image FROM food_product WHERE Vendor_id = ?
  `;

  try {
    const [products] = await db.execute(query, [vendorId]);

    // Convert the image data to Base64
    const productsWithBase64Images = products.map(product => {
      if (product.product_image) {
        // Convert image buffer to base64 string
        const base64Image = product.product_image.toString('base64');
        product.product_image = base64Image;
      }
      return product;
    });

    // Send products data with images encoded as Base64
    res.json({ products: productsWithBase64Images });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.delete('/delete-product/:id', async (req, res) => {
  const productId = req.params.id; // Get the product ID from the URL parameter

  const query = `
    DELETE FROM food_product WHERE Product_id = ?
  `;

  try {
    const [result] = await db.execute(query, [productId]);

    if (result.affectedRows > 0) {
      res.json({ message: 'Product deleted successfully' });
    } else {
      res.status(404).json({ error: 'Product not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});



app.post('/user/register', async (req, res) => {
  const { 
    email, 
    name, 
    password,  // Add password field
    phone  
  } = req.body;

  // Check for missing required fields
  if (!email ||  !name || !phone ||  !password) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  try {
    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // SQL query including the Password field
    const query = `
      INSERT INTO new_table 
      (email, phone, name, password) 
      VALUES 
      (?, ?, ?, ?)
    `;

    // Execute the query with all the form data and the hashed password
    const [result] = await db.execute(query, [
      email, 
      phone, 
      name, 
      hashedPassword // Use the hashed password here
    ]);

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/user/login', async (req, res) => {
  const { phone, password } = req.body;

  // Check if email and password are provided
  if (!phone || !password) {
    return res.status(400).json({ error: 'Email and Password are required' });
  }

  try {
    // SQL Query to fetch the user by email
    const query = `SELECT * FROM new_table WHERE phone = ?`;
    const [rows] = await db.execute(query, [phone]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No vendor found with this email' });
    }

    const user = rows[0];

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid phone or password' });
    }

    // If valid, optionally generate a JWT or session (based on requirements)
    const token = jwt.sign(
      { userId: user.cust_id, email: user.email }, // Payload
      secretKey,                                    // Secret key
      { expiresIn: '2h' }                           // Expiration time
    );

    res.status(200).json({
      message: 'Login successful!',
      token, // Return the token to the client for authentication in future requests
      user: {
        id: user.cust_id ,
        name: user.name,
        email: user.email,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/user/profile', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const query = `
      SELECT Profile_Photo FROM new_table
      WHERE email = ?
    `;
    const [rows] = await db.execute(query, [email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    const profile = rows[0];

    // Convert the photo binary to Base64
    if (profile.Profile_Photo) {
      profile.Profile_Photo = profile.Profile_Photo.toString('base64');
    }
    res.json(profile);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get("/getProducts", async (req, res) => {
  const Vendor_id = req.query.Vendor_id;

  if (!Vendor_id) {
    return res.status(400).json({ error: 'Vendor ID is required' });
  }

  try {
      // Query the MySQL table
      const [result] = await db.query(`SELECT * FROM food_product WHERE Vendor_id = ${Vendor_id};`);
      //console.log("Fetched Data:", result);
      const productsWithBase64Images = result.map(product => {
        if (product.product_image) {
          // Convert image buffer to base64 string
          const base64Image = product.product_image.toString('base64');
          product.product_image = base64Image;
        }
        return product;
      });
      cleanCart();
      // Send data as JSON
      res.json(result);
  } catch (err) {
      console.error("Error fetching products:", err.message);
      res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get('/vendor/name', async (req, res) => {
  const Vendor_id = req.query.Vendor_id;

  if (!Vendor_id) {
    return res.status(400).json({ error: 'Vendor ID is required' });
  }

  try {
    const query = `
      SELECT Name FROM Vendor
      WHERE Vendor_id = ?
    `;
    const [rows] = await db.execute(query, [Vendor_id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Vendor not found' });
    }

    const name = rows[0];

    res.json(name);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.put('/user/cart', async (req, res) => {
  const { 
    email, 
    cart  
  } = req.body;

  // Check for missing required fields
  if (!email ||  !cart) {
    return res.status(400).json({ error: 'Required fields are missing' });
  }

  try {
    const query = `
      UPDATE new_table
      SET cart = ?
      WHERE email = ?
    `;

    // Execute the query with all the form data and the hashed password
    const [result] = await db.execute(query, [
      JSON.stringify(cart), 
      email
    ]);
    cleanCart();
    res.status(201).json({ message: 'Cart updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.get('/user/cart', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const query = `
      SELECT cart FROM new_table
      WHERE email = ?
    `;
    const [rows] = await db.execute(query, [email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'user not found' });
    }

    const cart = rows[0];
    cleanCart();
    res.json(cart);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/getProductsByIds', async (req, res) => {
  const { productIds } = req.body;

  if (!productIds || productIds.length === 0) {
    return res.status(400).json({ error: 'Product IDs are required' });
  }

  try {
    const placeholders = productIds.map(() => '?').join(',');
    const query = `SELECT * FROM food_product WHERE Product_id IN (${placeholders})`;
    const [rows] = await db.execute(query, productIds);
    const productsWithBase64Images = rows.map(product => {
      if (product.product_image) {
        // Convert image buffer to base64 string
        const base64Image = product.product_image.toString('base64');
        product.product_image = base64Image;
      }
      return product;
    });
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.get('/api/user', async (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const query = `
      SELECT * FROM new_table
      WHERE email = ?
    `;
    const [rows] = await db.execute(query, [email]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'user not found' });
    }

    const cart = rows[0];

    if (cart.Profile_Photo) {
      cart.Profile_Photo = cart.Profile_Photo.toString('base64');
    }



    res.json(cart);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.put('/api/user/:email', async (req, res) => {
  const userEmail = req.params.email;
  const updates = req.body; // e.g., { phone: '1234567890', name: 'John Doe' }

  // Dynamically construct the SQL query based on provided fields
  const fields = Object.keys(updates)
    .map((key) => `${key} = ?`)
    .join(', ');

  const values = [...Object.values(updates), userEmail];

  const sqlQuery = `UPDATE new_table SET ${fields} WHERE email = ?`;

  try {
    const [result] = await db.execute(sqlQuery, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ message: 'User data updated successfully' });
  } catch (err) {
    console.error('Error updating user data:', err);
    res.status(500).json({ message: 'Failed to update user data' });
  }
});

app.put('/api/user/photo/:email', upload.single('Profile_Photo'), async (req, res) => {
  const { email } = req.params;
  const Profile_Photo_Path = req.file ? req.file.buffer : null;

  const sqlQuery = 'UPDATE new_table SET Profile_Photo = ? WHERE email = ?';

  try {
    const [result] = await db.execute(sqlQuery, [Profile_Photo_Path, email]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ Profile_Photo: Profile_Photo_Path });
  } catch (err) {
    console.error('Error updating Profile_Photo:', err);
    res.status(500).json({ message: 'Failed to update Profile_Photo' });
  }
});

app.get('/user/addresses', async (req, res) => {
  try {
    const { email } = req.query;

    // Check if email is provided
    if (!email) {
      return res.status(400).json({ message: 'Email parameter is required' });
    }

    // Query database to fetch delivery address using prepared statements
    const [rows] = await db.execute(
      'SELECT delivery_address FROM new_table WHERE email = ?',
      [email]
    );

    // Handle response based on query results
    if (rows.length > 0) {
      res.status(200).json({
        success: true,
        delivery_address: rows[0].delivery_address || [],
      });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Error fetching address:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update an existing address for the user
app.put('/user/addresses', async (req, res) => {
  try {
    const { email, new_address} = req.body;

    // Validate input
    if (!email || !new_address ) {
      return res.status(400).json({ message: 'Email, old address, and new address are required' });
    }

    // Update the address in the database
    const [result] = await db.execute(
      'UPDATE new_table SET delivery_address = ? WHERE email = ? ',
      [new_address, email]
    );

    if (result.affectedRows > 0) {
      res.status(200).json({ success: true, message: 'Address updated successfully' });
    } else {
      res.status(404).json({ message: 'Address not found or no changes made' });
    }
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

const cleanCart = async () => {
  try {
    // Fetch all valid product IDs from food_product table
    const [products] = await db.query("SELECT Product_id FROM food_product");
    const validProductIds = new Set(products.map((product) => product.Product_id));
    
    // Fetch all carts from new_table
    const [customers] = await db.query("SELECT cust_id, cart FROM new_table");
    
    for (let customer of customers) {
      const cart = (customer.cart || "{}");
      let updatedCart = {};

      // Retain only valid products in the cart
      for (const productId in cart) {
        if (validProductIds.has(parseInt(productId))) {
          updatedCart[productId] = cart[productId];
        }
      }
      // Update the customer's cart in the database
      await db.query("UPDATE new_table SET cart = ? WHERE cust_id = ?", [
        JSON.stringify(updatedCart),
        customer.cust_id,
      ]);
    }

    
  } catch (error) {
    console.error("Error cleaning up cart:", error);
    throw error;
  }
};


app.get('/getVendors', async (req, res) => {
  try {
    const [vendors] = await db.query(
      "SELECT Vendor_id, Name, profile_photo FROM Vendor"
    ); // Assuming vendor_table exists.
   

    vendors.forEach(vendor => {
      if (vendor.profile_photo) {
        vendor.profile_photo = vendor.profile_photo.toString('base64');
      }
    });

    res.json(vendors);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch vendors." });
  }
});


app.post('/createOrder', async (req, res) => {
  const { customerId, vendorId, cart, deliveryAddress } = req.body;

  if (!cart || Object.keys(cart).length === 0) {
    return res.status(400).json({ message: 'Cart is empty.' });
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    
    let totalOrderPrice = 0;
    const orderItems = [];

    for (const [productId, quantity] of Object.entries(cart)) {
      const [rows] = await connection.execute("SELECT price FROM food_product WHERE Product_id = ?", [productId]);

      if (rows.length > 0) {
        const price = rows[0].price;
        totalOrderPrice += price * quantity;
        orderItems.push([customerId, vendorId, productId, quantity, price]);
      } else {
        throw new Error('Product not found');
      }
    }

    const [orderResult] = await connection.execute(
      "INSERT INTO orders (customer_id, vendor_id, delivery_address, total_price) VALUES (?, ?, ?, ?)",
      [customerId, vendorId, deliveryAddress, totalOrderPrice]
    );

    const orderId = orderResult.insertId;

    for (const item of orderItems) {
      await connection.execute(
        "INSERT INTO order_items (order_id, product_id, quantity, Item_price) VALUES (?, ?, ?, ?)",
        [orderId, ...item.slice(2)]
      );
    }

    await connection.commit();

    // Emit a message to the vendor's room after the order is created
    io.to(`vendor_${vendorId}`).emit('newOrder', {
      orderId,
      customerId,
      vendorId,
      cart,
      totalPrice: totalOrderPrice,
      deliveryAddress
    });

    res.status(201).json({ message: 'Order created successfully', orderId });
  } catch (error) {
    console.error(error);
    await connection.rollback();
    res.status(500).json({ message: 'Failed to create order', error: error.message });
  } finally {
    connection.release();
  }
});

// Endpoint to fetch vendor orders
app.get('/getVendorOrders/:vendorId', async (req, res) => {
  const { vendorId } = req.params;

  try {
    const [orders] = await db.query(
      `SELECT o.Order_id, o.Customer_id, c.name AS CustomerName, c.phone, o.Total_price, o.Order_date, o.Status
       FROM orders o
       JOIN new_table c ON o.Customer_id = c.cust_id
       WHERE o.Vendor_id = ?`,
      [vendorId]
    );

    const orderDetails = [];

    for (const order of orders) {
      const [items] = await db.query(
        `SELECT oi.Product_id, f.Name AS ProductName, oi.Quantity, oi.Item_price
         FROM order_items oi
         JOIN food_product f ON oi.Product_id = f.Product_id
         WHERE oi.Order_id = ?`,
        [order.Order_id]
      );

      orderDetails.push({
        ...order,
        items,
      });
    }

    res.status(200).json(orderDetails);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.put('/updateOrderStatus', async (req, res) => {
  const { orderId, newStatus } = req.body;

  try {
    const [result] = await db.execute(
      'UPDATE orders SET Status = ? WHERE Order_id = ?',
      [newStatus, orderId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }

    res.status(200).json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to update order status', error: error.message });
  }
});

// Start Server
const PORT = process.env.PORT ;
app.listen(PORT, () => {
    console.log(`Connected to backend! Listening on port ${PORT}`);
});