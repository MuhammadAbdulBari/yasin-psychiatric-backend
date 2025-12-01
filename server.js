const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
// CORS configuration
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware
app.use(express.json());

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});


db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected...');
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    
    db.execute(query, [name, email, hashedPassword, role], (err, result) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'User registered successfully' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  const query = 'SELECT * FROM users WHERE email = ?';
  db.execute(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(400).json({ error: 'User not found' });
    
    const user = results[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) return res.status(400).json({ error: 'Invalid password' });
    
    const token = jwt.sign(
      { id: user.id, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role }
    });
  });
});

// Patient routes - Only for reception and doctors, not pharmacy
app.post('/api/patients', authenticateToken, (req, res) => {
  if (req.user.role === 'pharmacy') {
    return res.status(403).json({ error: 'Access denied. Pharmacy cannot register patients.' });
  }
  
  const { name, contact, gender, dob } = req.body;
  
  const patientQuery = 'INSERT INTO patients (name, contact, gender, dob) VALUES (?, ?, ?, ?)';
  db.execute(patientQuery, [name, contact, gender, dob], (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    
    const patientId = result.insertId;
    const slipNumber = 'SL' + Date.now();
    
    const slipQuery = 'INSERT INTO slips (patient_id, slip_number, status) VALUES (?, ?, ?)';
    db.execute(slipQuery, [patientId, slipNumber, 'pending'], (err, slipResult) => {
      if (err) return res.status(400).json({ error: err.message });
      
      res.json({
        slipId: slipResult.insertId,
        slipNumber,
        patientId,
        message: 'Patient registered successfully'
      });
    });
  });
});

app.get('/api/patients/slip/:slipNumber', authenticateToken, (req, res) => {
  const { slipNumber } = req.params;
  
  const query = `
    SELECT p.*, s.id as slip_id, s.status as slip_status 
    FROM patients p 
    JOIN slips s ON p.id = s.patient_id 
    WHERE s.slip_number = ?
  `;
  
  db.execute(query, [slipNumber], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Slip not found' });
    
    res.json(results[0]);
  });
});

// Get prescription by slip number - Available for all roles
app.get('/api/prescriptions/slip/:slipNumber', authenticateToken, (req, res) => {
  const { slipNumber } = req.params;
  
  const query = `
    SELECT 
      pr.*, 
      p.name as patient_name, 
      p.contact, 
      p.gender,
      p.dob,
      u.name as doctor_name,
      s.slip_number,
      s.status as slip_status
    FROM prescriptions pr
    JOIN slips s ON pr.slip_id = s.id
    JOIN patients p ON s.patient_id = p.id
    JOIN users u ON pr.doctor_id = u.id
    WHERE s.slip_number = ?
  `;
  
  db.execute(query, [slipNumber], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Prescription not found' });
    
    const prescription = results[0];
    try {
      prescription.medicine_list = JSON.parse(prescription.medicine_list);
    } catch (e) {
      prescription.medicine_list = [];
    }
    
    res.json(prescription);
  });
});

// Get all prescriptions for a patient - Only for doctors
app.get('/api/prescriptions/patient/:patientId', authenticateToken, (req, res) => {
  if (req.user.role !== 'doctor') {
    return res.status(403).json({ error: 'Access denied. Doctor role required.' });
  }

  const { patientId } = req.params;
  
  const query = `
    SELECT 
      pr.*,
      u.name as doctor_name,
      s.slip_number,
      pr.created_at as prescription_date
    FROM prescriptions pr
    JOIN slips s ON pr.slip_id = s.id
    JOIN users u ON pr.doctor_id = u.id
    WHERE s.patient_id = ?
    ORDER BY pr.created_at DESC
  `;
  
  db.execute(query, [patientId], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const prescriptions = results.map(prescription => {
      try {
        prescription.medicine_list = JSON.parse(prescription.medicine_list);
      } catch (e) {
        prescription.medicine_list = [];
      }
      return prescription;
    });
    
    res.json(prescriptions);
  });
});

// Prescription routes - Only for doctors
app.post('/api/prescriptions', authenticateToken, (req, res) => {
  if (req.user.role !== 'doctor') {
    return res.status(403).json({ error: 'Access denied. Doctor role required.' });
  }

  const { slip_id, medicine_list, notes } = req.body;
  const doctor_id = req.user.id;
  
  const query = `
    INSERT INTO prescriptions (slip_id, doctor_id, medicine_list, notes) 
    VALUES (?, ?, ?, ?)
  `;
  
  db.execute(query, [slip_id, doctor_id, JSON.stringify(medicine_list), notes], (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    
    // Update slip status
    const updateSlipQuery = 'UPDATE slips SET status = ? WHERE id = ?';
    db.execute(updateSlipQuery, ['processed', slip_id], (err) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'Prescription saved successfully' });
    });
  });
});

// Get patient by ID - Only for doctors and reception
app.get('/api/patients/:id', authenticateToken, (req, res) => {
  if (req.user.role === 'pharmacy') {
    return res.status(403).json({ error: 'Access denied. Pharmacy cannot view individual patients.' });
  }

  const { id } = req.params;
  
  const query = 'SELECT * FROM patients WHERE id = ?';
  
  db.execute(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Patient not found' });
    
    res.json(results[0]);
  });
});

// Get all patients - Only for doctors and reception, not pharmacy
app.get('/api/patients', authenticateToken, (req, res) => {
  if (req.user.role === 'pharmacy') {
    return res.status(403).json({ error: 'Access denied. Pharmacy cannot view all patients.' });
  }

  const query = `
    SELECT p.*, 
           COUNT(DISTINCT s.id) as total_visits,
           MAX(s.created_at) as last_visit
    FROM patients p
    LEFT JOIN slips s ON p.id = s.patient_id
    GROUP BY p.id
    ORDER BY p.created_at DESC
  `;
  
  db.execute(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});


// Delete prescription - Only for doctors
app.delete('/api/prescriptions/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'doctor') {
    return res.status(403).json({ error: 'Access denied. Doctor role required.' });
  }

  const { id } = req.params;
  
  const query = 'DELETE FROM prescriptions WHERE id = ?';
  
  db.execute(query, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    res.json({ message: 'Prescription deleted successfully' });
  });
});

// Delete patient - Only for doctors
app.delete('/api/patients/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'doctor') {
    return res.status(403).json({ error: 'Access denied. Doctor role required.' });
  }

  const { id } = req.params;
  
  // First delete prescriptions linked to this patient's slips
  const deletePrescriptionsQuery = `
    DELETE pr FROM prescriptions pr
    JOIN slips s ON pr.slip_id = s.id
    WHERE s.patient_id = ?
  `;
  
  db.execute(deletePrescriptionsQuery, [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Then delete slips
    const deleteSlipsQuery = 'DELETE FROM slips WHERE patient_id = ?';
    db.execute(deleteSlipsQuery, [id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      
      // Finally delete patient
      const deletePatientQuery = 'DELETE FROM patients WHERE id = ?';
      db.execute(deletePatientQuery, [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Patient not found' });
        }
        
        res.json({ message: 'Patient and all associated records deleted successfully' });
      });
    });
  });
});

// Get patient with prescriptions history - Only for doctors
app.get('/api/patients/:id/prescriptions', authenticateToken, (req, res) => {
  if (req.user.role !== 'doctor') {
    return res.status(403).json({ error: 'Access denied. Doctor role required.' });
  }

  const { id } = req.params;
  
  const query = `
    SELECT 
      pr.*,
      u.name as doctor_name,
      s.slip_number,
      s.created_at as visit_date
    FROM prescriptions pr
    JOIN slips s ON pr.slip_id = s.id
    JOIN users u ON pr.doctor_id = u.id
    WHERE s.patient_id = ?
    ORDER BY pr.created_at DESC
  `;
  
  db.execute(query, [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const prescriptions = results.map(prescription => {
      try {
        prescription.medicine_list = JSON.parse(prescription.medicine_list);
      } catch (e) {
        prescription.medicine_list = [];
      }
      return prescription;
    });
    
    res.json(prescriptions);
  });
});

// Pharmacy routes - Only for pharmacy role

// Get all prescriptions - For doctors, pharmacy, and reception
app.get('/api/prescriptions', authenticateToken, (req, res) => {
  // Check if user has permission (doctor, pharmacy, or reception)
  if (req.user.role !== 'doctor' && req.user.role !== 'pharmacy' && req.user.role !== 'reception') {
    return res.status(403).json({ error: 'Access denied. Doctor, Pharmacy, or Reception role required.' });
  }

  const query = `
    SELECT 
      pr.*,
      p.name as patient_name,
      p.contact as patient_contact,
      p.gender as patient_gender,
      p.dob as patient_dob,
      u.name as doctor_name,
      s.slip_number,
      s.created_at as visit_date
    FROM prescriptions pr
    JOIN slips s ON pr.slip_id = s.id
    JOIN patients p ON s.patient_id = p.id
    JOIN users u ON pr.doctor_id = u.id
    ORDER BY pr.created_at DESC
  `;
  
  db.execute(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const prescriptions = results.map(prescription => {
      try {
        if (typeof prescription.medicine_list === 'string') {
          prescription.medicine_list = JSON.parse(prescription.medicine_list);
        }
      } catch (e) {
        prescription.medicine_list = [];
      }
      return prescription;
    });
    
    res.json(prescriptions);
  });
});

// Update pharmacy status - Only for pharmacy
app.put('/api/pharmacy/prescriptions/:id/status', authenticateToken, (req, res) => {
  if (req.user.role !== 'pharmacy') {
    return res.status(403).json({ error: 'Access denied. Pharmacy role required.' });
  }

  const { id } = req.params;
  const { status } = req.body;
  const pharmacist_id = req.user.id;

  const validStatuses = ['pending', 'preparing', 'ready', 'dispensed'];
  
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  let query;
  let params;

  if (status === 'preparing' || status === 'ready') {
    query = 'UPDATE prescriptions SET pharmacy_status = ?, prepared_by = ? WHERE id = ?';
    params = [status, pharmacist_id, id];
  } else {
    query = 'UPDATE prescriptions SET pharmacy_status = ? WHERE id = ?';
    params = [status, id];
  }

  db.execute(query, params, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    res.json({ 
      message: `Prescription status updated to ${status}`,
      pharmacist_id: pharmacist_id
    });
  });
});

// Get pharmacy dashboard stats - Only for pharmacy
app.get('/api/pharmacy/dashboard', authenticateToken, (req, res) => {
  if (req.user.role !== 'pharmacy') {
    return res.status(403).json({ error: 'Access denied. Pharmacy role required.' });
  }

  const query = `
    SELECT 
      COUNT(*) as total_prescriptions,
      SUM(CASE WHEN pharmacy_status = 'pending' THEN 1 ELSE 0 END) as pending_count,
      SUM(CASE WHEN pharmacy_status = 'preparing' THEN 1 ELSE 0 END) as preparing_count,
      SUM(CASE WHEN pharmacy_status = 'ready' THEN 1 ELSE 0 END) as ready_count,
      SUM(CASE WHEN pharmacy_status = 'dispensed' THEN 1 ELSE 0 END) as dispensed_count
    FROM prescriptions
    WHERE DATE(created_at) = CURDATE()
  `;
  
  db.execute(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    
    res.json(results[0]);
  });
});

// Payment routes - Only for reception
app.post('/api/payments', authenticateToken, (req, res) => {
  if (req.user.role !== 'reception') {
    return res.status(403).json({ error: 'Access denied. Reception role required.' });
  }

  const { slip_id, total_amount } = req.body;
  
  const query = 'INSERT INTO payments (slip_id, total_amount, payment_status) VALUES (?, ?, ?)';
  db.execute(query, [slip_id, total_amount, 'paid'], (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ message: 'Payment recorded successfully' });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));

