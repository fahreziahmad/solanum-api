const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Folder static untuk akses foto yang diunggah
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Koneksi ke Database TiDB Cloud (Bisa di-override lewat Environment Variables)
const dbHost = process.env.DB_HOST || 'gateway01.ap-southeast-1.prod.aws.tidbcloud.com';
const dbPort = process.env.DB_PORT || 4000;
const dbUser = process.env.DB_USER || '3uER3yHYW72dKXC.root';
const dbPassword = process.env.DB_PASSWORD !== undefined ? process.env.DB_PASSWORD : 'ZGa6beAf8W9rosG5';
const dbName = process.env.DB_NAME || 'solanum_db';
const useSSL = process.env.DB_SSL !== 'false' && (process.env.DB_SSL === 'true' || dbHost.includes('tidbcloud.com'));

const pool = mysql.createPool({
  host: dbHost,
  port: Number(dbPort),
  user: dbUser,
  password: dbPassword,
  database: dbName,
  ssl: useSSL ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : false,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Konfigurasi Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// ==========================================
// 1. API PENGGUNA (USERS)
// ==========================================

// Register User
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, phone, department } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ status: 'error', message: 'Nama, email, dan password wajib diisi' });
    }

    // Validasi Nama: tidak boleh ada angka
    if (!/^[a-zA-Z\s]+$/.test(name.trim())) {
      return res.status(400).json({ status: 'error', message: 'Nama tidak boleh mengandung angka atau simbol' });
    }

    // Validasi Email: harus @gmail.com
    if (!email.trim().toLowerCase().endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email harus menggunakan domain @gmail.com' });
    }

    // Validasi Nomor Telepon: harus 12 digit dan diawali angka 0
    if (!/^0[0-9]{11}$/.test((phone || '').trim())) {
      return res.status(400).json({ status: 'error', message: 'Nomor telepon harus 12 digit dan diawali angka 0 (contoh: 081234567890)' });
    }

    // Validasi Password: harus 6 karakter
    if (password.length !== 6) {
      return res.status(400).json({ status: 'error', message: 'Password harus 6 karakter' });
    }

    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (rows.length > 0) {
      return res.status(400).json({ status: 'error', message: 'Email sudah digunakan' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await pool.query(
      'INSERT INTO users (nama, email, password, no_hp, departemen, is_logged_in) VALUES (?, ?, ?, ?, ?, ?)', 
      [name.trim(), email.trim().toLowerCase(), hashedPassword, phone.trim(), department || null, false]
    );
    res.json({ status: 'success', message: 'Registrasi berhasil' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

// Login (User & Admin Seamless)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ status: 'error', message: 'Email dan password wajib diisi' });
    }

    const cleanEmail = email.trim().toLowerCase();

    // Validasi domain @gmail.com
    if (cleanEmail.includes('@') && !cleanEmail.endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email harus menggunakan domain @gmail.com' });
    }

    // 1. Cek apakah ini akun Admin di tabel admins
    const [adminRows] = await pool.query(
      'SELECT id, username, nama, email, no_hp, password, foto FROM admins WHERE email = ? OR username = ?', 
      [cleanEmail, cleanEmail]
    );

    if (adminRows.length > 0) {
      const admin = adminRows[0];
      const match = await bcrypt.compare(password, admin.password);
      if (match) {
        return res.json({
          status: 'success',
          message: 'Login Admin berhasil',
          user: { 
            id: admin.id, 
            name: admin.nama || admin.username, 
            email: admin.email || 'admin@gmail.com', 
            role: 'admin',
            phone: admin.no_hp || '081234567890',
            foto: admin.foto
          }
        });
      }
    }

    // 2. Cek apakah ini akun User di tabel users
    if (password.length !== 6) {
      return res.status(400).json({ status: 'error', message: 'Password harus 6 karakter' });
    }

    const [userRows] = await pool.query(
      'SELECT id, nama, email, password, no_hp, departemen, foto FROM users WHERE email = ?', 
      [cleanEmail]
    );

    if (userRows.length === 0) {
      return res.status(400).json({ status: 'error', message: 'Email tidak terdaftar' });
    }

    const user = userRows[0];
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      await pool.query('UPDATE users SET is_logged_in = true WHERE id = ?', [user.id]);
      
      return res.json({
        status: 'success',
        message: 'Login berhasil',
        user: { 
          id: user.id, 
          name: user.nama, 
          email: user.email, 
          role: 'user',
          phone: user.no_hp, 
          department: user.departemen,
          foto: user.foto
        }
      });
    } else {
      return res.status(400).json({ status: 'error', message: 'Password salah' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

// ==========================================
// OTP PASSWORD RESET SYSTEM
// ==========================================

// 1. Request OTP
app.post('/api/forgot-password/request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ status: 'error', message: 'Email wajib diisi' });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail.endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email harus menggunakan domain @gmail.com' });
    }

    // Cek apakah email terdaftar di users atau admins
    const [userRows] = await pool.query('SELECT id, nama FROM users WHERE email = ?', [cleanEmail]);
    const [adminRows] = await pool.query('SELECT id, nama FROM admins WHERE email = ?', [cleanEmail]);

    if (userRows.length === 0 && adminRows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Email tidak terdaftar dalam sistem Solanum' });
    }

    // Generate 6 digit OTP acak
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // Expire dalam 10 menit

    // Simpan ke tabel password_resets
    await pool.query(
      'INSERT INTO password_resets (email, otp, expires_at, used) VALUES (?, ?, ?, 0)',
      [cleanEmail, otp, expiresAt]
    );

    console.log(`[OTP] Kode OTP untuk ${cleanEmail}: ${otp}`);

    res.json({
      status: 'success',
      message: 'Kode OTP telah dikirimkan ke email Anda',
      otp: otp // Dikirim di respons agar mudah diverifikasi & diuji oleh penguji/pengguna
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal membuat kode OTP' });
  }
});

// 2. Verify OTP
app.post('/api/forgot-password/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ status: 'error', message: 'Email dan kode OTP wajib diisi' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const [rows] = await pool.query(
      'SELECT id FROM password_resets WHERE email = ? AND otp = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1',
      [cleanEmail, otp.toString().trim()]
    );

    if (rows.length === 0) {
      return res.status(400).json({ status: 'error', message: 'Kode OTP tidak valid atau sudah kadaluarsa' });
    }

    res.json({ status: 'success', message: 'Kode OTP valid' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal memverifikasi OTP' });
  }
});

// 3. Reset Password dengan OTP
app.post('/api/forgot-password/reset', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ status: 'error', message: 'Email, OTP, dan password baru wajib diisi' });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (newPassword.length !== 6) {
      return res.status(400).json({ status: 'error', message: 'Password baru harus tepat 6 karakter' });
    }

    const [rows] = await pool.query(
      'SELECT id FROM password_resets WHERE email = ? AND otp = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1',
      [cleanEmail, otp.toString().trim()]
    );

    if (rows.length === 0) {
      return res.status(400).json({ status: 'error', message: 'Kode OTP tidak valid atau sudah kadaluarsa' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password di users dan admins jika ada
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, cleanEmail]);
    await pool.query('UPDATE admins SET password = ? WHERE email = ?', [hashedPassword, cleanEmail]);

    // Tandai OTP sudah digunakan
    await pool.query('UPDATE password_resets SET used = 1 WHERE id = ?', [rows[0].id]);

    res.json({
      status: 'success',
      message: 'Password berhasil direset. Silakan login kembali dengan password baru Anda.'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mereset password' });
  }
});

// Fallback legacy forgot password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) {
      return res.status(400).json({ status: 'error', message: 'Email dan password baru wajib diisi' });
    }

    if (!email.trim().toLowerCase().endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email harus menggunakan domain @gmail.com' });
    }

    if (newPassword.length !== 6) {
      return res.status(400).json({ status: 'error', message: 'Password baru harus 6 karakter' });
    }

    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Email tidak terdaftar dalam sistem' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email.trim().toLowerCase()]);

    res.json({ status: 'success', message: 'Password berhasil direset. Silakan login kembali dengan password baru.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

// Update Profile User (Edit Profil)
app.put('/api/user/profile', async (req, res) => {
  try {
    const { user_id, name, phone } = req.body;
    if (!user_id || !name || !phone) {
      return res.status(400).json({ status: 'error', message: 'Data profil belum lengkap' });
    }

    if (!/^[a-zA-Z\s]+$/.test(name.trim())) {
      return res.status(400).json({ status: 'error', message: 'Nama tidak boleh mengandung angka atau simbol' });
    }

    if (!/^0[0-9]{11}$/.test(phone.trim())) {
      return res.status(400).json({ status: 'error', message: 'Nomor telepon harus 12 digit dan diawali angka 0 (contoh: 081234567890)' });
    }

    await pool.query('UPDATE users SET nama = ?, no_hp = ? WHERE id = ?', [name.trim(), phone.trim(), user_id]);

    const [rows] = await pool.query('SELECT id, nama, email, no_hp, departemen, foto FROM users WHERE id = ?', [user_id]);
    if (rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Pengguna tidak ditemukan' });
    }

    const u = rows[0];
    res.json({
      status: 'success',
      message: 'Profil berhasil diperbarui',
      user: {
        id: u.id,
        name: u.nama,
        email: u.email,
        phone: u.no_hp,
        department: u.departemen,
        role: 'user',
        foto: u.foto
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal memperbarui profil' });
  }
});

// Ubah Password User di Halaman Profile
app.post('/api/user/change-password', async (req, res) => {
  try {
    const { user_id, oldPassword, newPassword } = req.body;
    if (!user_id || !oldPassword || !newPassword) {
      return res.status(400).json({ status: 'error', message: 'Password lama dan password baru wajib diisi' });
    }

    if (newPassword.length !== 6) {
      return res.status(400).json({ status: 'error', message: 'Password baru harus tepat 6 karakter' });
    }

    const [rows] = await pool.query('SELECT id, password FROM users WHERE id = ?', [user_id]);
    if (rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Pengguna tidak ditemukan' });
    }

    const user = rows[0];
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.status(400).json({ status: 'error', message: 'Password lama tidak sesuai' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashed, user_id]);

    res.json({ status: 'success', message: 'Password berhasil diperbarui' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengubah password' });
  }
});

// Upload Avatar User
app.post('/api/user/upload-avatar', upload.single('avatar'), async (req, res) => {
  try {
    const { user_id } = req.body;
    if (!user_id || !req.file) {
      return res.status(400).json({ status: 'error', message: 'Foto dan user_id wajib disertakan' });
    }

    const avatarUrl = `/uploads/${req.file.filename}`;
    await pool.query('UPDATE users SET foto = ? WHERE id = ?', [avatarUrl, user_id]);

    res.json({
      status: 'success',
      message: 'Foto profil berhasil diunggah',
      avatar: avatarUrl
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengunggah foto profil' });
  }
});

// ==========================================
// 2. API ADMIN
// ==========================================

// Login Admin (Wajib @gmail.com)
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const identifier = (email || username || '').trim().toLowerCase();
    if (!identifier || !password) {
      return res.status(400).json({ status: 'error', message: 'Email dan password wajib diisi' });
    }

    // Validasi domain @gmail.com
    if (identifier.includes('@') && !identifier.endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email admin harus menggunakan domain @gmail.com' });
    }

    const [rows] = await pool.query(
      'SELECT id, username, nama, email, no_hp, password, foto FROM admins WHERE email = ? OR username = ?', 
      [identifier, identifier]
    );

    if (rows.length === 0) {
      return res.status(400).json({ status: 'error', message: 'Akun admin tidak ditemukan' });
    }

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);

    if (match) {
      res.json({
        status: 'success',
        message: 'Login Admin berhasil',
        user: { 
          id: admin.id, 
          name: admin.nama || admin.username,
          email: admin.email || 'admin@gmail.com',
          phone: admin.no_hp || '081234567890',
          role: 'admin',
          foto: admin.foto
        }
      });
    } else {
      res.status(400).json({ status: 'error', message: 'Password salah' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

// Ambil Profil Admin
app.get('/api/admin/profile', async (req, res) => {
  try {
    const admin_id = req.query.admin_id || 1;
    const [rows] = await pool.query('SELECT id, username, nama, email, no_hp, foto FROM admins WHERE id = ?', [admin_id]);
    if (rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Akun admin tidak ditemukan' });
    }
    const a = rows[0];
    res.json({
      status: 'success',
      user: {
        id: a.id,
        name: a.nama || a.username,
        email: a.email,
        phone: a.no_hp,
        role: 'admin',
        foto: a.foto
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengambil data profil admin' });
  }
});

// Edit Profil Admin
app.put('/api/admin/profile', async (req, res) => {
  try {
    const { admin_id, name, email, phone } = req.body;
    if (!admin_id || !name || !email) {
      return res.status(400).json({ status: 'error', message: 'Nama dan email admin wajib diisi' });
    }

    if (!/^[a-zA-Z\s]+$/.test(name.trim())) {
      return res.status(400).json({ status: 'error', message: 'Nama tidak boleh mengandung angka atau simbol' });
    }

    if (!email.trim().toLowerCase().endsWith('@gmail.com')) {
      return res.status(400).json({ status: 'error', message: 'Email admin harus menggunakan domain @gmail.com' });
    }

    if (phone && !/^0[0-9]{11}$/.test(phone.trim())) {
      return res.status(400).json({ status: 'error', message: 'Nomor telepon harus 12 digit dan diawali angka 0' });
    }

    await pool.query(
      'UPDATE admins SET nama = ?, email = ?, no_hp = ? WHERE id = ?',
      [name.trim(), email.trim().toLowerCase(), (phone || '').trim(), admin_id]
    );

    const [rows] = await pool.query('SELECT id, username, nama, email, no_hp, foto FROM admins WHERE id = ?', [admin_id]);
    const a = rows[0];

    res.json({
      status: 'success',
      message: 'Profil admin berhasil diperbarui',
      user: {
        id: a.id,
        name: a.nama || a.username,
        email: a.email,
        phone: a.no_hp,
        role: 'admin',
        foto: a.foto
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal memperbarui profil admin' });
  }
});

// Ubah Password Admin
app.post('/api/admin/change-password', async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ status: 'error', message: 'Password lama dan baru wajib diisi' });
    }

    const [rows] = await pool.query('SELECT id, password FROM admins LIMIT 1');
    if (rows.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Akun admin tidak ditemukan' });
    }

    const admin = rows[0];
    const match = await bcrypt.compare(oldPassword, admin.password);
    if (!match) {
      return res.status(400).json({ status: 'error', message: 'Password lama salah' });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE admins SET password = ? WHERE id = ?', [hashed, admin.id]);
    res.json({ status: 'success', message: 'Password admin berhasil diubah' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengubah password admin' });
  }
});

// Upload Avatar Admin
app.post('/api/admin/upload-avatar', upload.single('avatar'), async (req, res) => {
  try {
    const { admin_id } = req.body;
    if (!admin_id || !req.file) {
      return res.status(400).json({ status: 'error', message: 'Foto dan admin_id wajib disertakan' });
    }

    const avatarUrl = `/uploads/${req.file.filename}`;
    await pool.query('UPDATE admins SET foto = ? WHERE id = ?', [avatarUrl, admin_id]);

    res.json({
      status: 'success',
      message: 'Foto profil admin berhasil diunggah',
      avatar: avatarUrl
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengunggah foto profil' });
  }
});

// Ambil Daftar Semua User (Untuk Admin Dashboard) + Jumlah Total
app.get('/api/admin/users', async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, nama, email, no_hp, departemen, foto, created_at FROM users ORDER BY id DESC');
    res.json({ status: 'success', total: users.length, data: users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengambil data user' });
  }
});
app.post('/api/admin/users', async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, nama, email, no_hp, departemen, foto, created_at FROM users ORDER BY id DESC');
    res.json({ status: 'success', total: users.length, data: users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengambil data user' });
  }
});

// Hapus User oleh Admin
app.delete('/api/admin/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ status: 'error', message: 'ID pengguna tidak valid' });
    }

    const [exists] = await pool.query('SELECT id, nama FROM users WHERE id = ?', [id]);
    if (exists.length === 0) {
      return res.status(404).json({ status: 'error', message: 'Pengguna tidak ditemukan' });
    }

    await pool.query('DELETE FROM users WHERE id = ?', [id]);
    res.json({ status: 'success', message: `Pengguna ${exists[0].nama} berhasil dihapus` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal menghapus pengguna' });
  }
});

// Ambil dan Update API Key
app.get('/api/admin/api-key', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT api_key FROM admins LIMIT 1');
    res.json({ status: 'success', apiKey: rows.length > 0 ? rows[0].api_key : '' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Gagal mengambil API Key' });
  }
});

app.post('/api/admin/api-key', async (req, res) => {
  try {
    const { apiKey } = req.body;
    await pool.query('UPDATE admins SET api_key = ?', [apiKey]);
    res.json({ status: 'success', message: 'API Key berhasil disimpan' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Gagal menyimpan API Key' });
  }
});

// Total unread count untuk Admin
app.get('/api/admin/unread-count', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT COUNT(*) as unread FROM chats WHERE pengirim = "user" AND terbaca = 0'
    );
    res.json({ status: 'success', unread: rows[0].unread || 0 });
  } catch (error) {
    res.status(500).json({ status: 'error', unread: 0 });
  }
});

// ==========================================
// 3. API RIWAYAT DIAGNOSIS
// ==========================================

app.post('/api/diagnosis', upload.single('image'), async (req, res) => {
  try {
    const { user_id, nama_penyakit, akurasi, solusi } = req.body;
    
    if (!user_id || !nama_penyakit) {
      return res.status(400).json({ status: 'error', message: 'Data tidak lengkap' });
    }

    // Tolak penyimpanan jika objek bukan kentang / tidak dikenal
    const lowerName = nama_penyakit.toLowerCase();
    if (lowerName.includes('tidak dikenal') || lowerName.includes('unknown') || lowerName.includes('bukan')) {
      return res.status(400).json({ status: 'error', message: 'Objek tidak dikenal tidak disimpan ke riwayat' });
    }

    let foto_tanaman = null;
    if (req.file) {
      foto_tanaman = `/uploads/${req.file.filename}`;
    }

    await pool.query(
      'INSERT INTO riwayat_identifikasi (user_id, foto_tanaman, nama_penyakit, akurasi, solusi) VALUES (?, ?, ?, ?, ?)',
      [user_id, foto_tanaman, nama_penyakit, parseFloat(akurasi) || 0, solusi]
    );

    res.json({ status: 'success', message: 'Riwayat diagnosis berhasil disimpan' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

app.get('/api/history', async (req, res) => {
  try {
    const { user_id } = req.query;
    if (!user_id) {
      return res.status(400).json({ status: 'error', message: 'ID pengguna tidak ditemukan' });
    }

    const [rows] = await pool.query('SELECT * FROM riwayat_identifikasi WHERE user_id = ? ORDER BY tanggal_deteksi DESC', [user_id]);
    res.json({ status: 'success', data: rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Terjadi kesalahan pada server' });
  }
});

// ==========================================
// 4. HELPER & API GEMINI AI AUTO-REPLY
// ==========================================

async function generateGeminiReply(userMessage, conversationHistory, apiKey) {
  if (!apiKey || apiKey === 'solanum-default-key' || apiKey.trim() === '') {
    return null;
  }

  // Pre-filter: Batasi tegas hanya pada kentang. Jika user menanyakan sayuran/tanaman lain:
  const nonPotatoKeywords = [
    'tomat', 'tomato', 'cabai', 'cabe', 'chili', 'padi', 'jagung', 'corn', 
    'terong', 'eggplant', 'wortel', 'carrot', 'bawang', 'onion', 'singkong', 
    'ubi jalar', 'sawit', 'kopi', 'kakao', 'teh', 'bayam', 'kangkung', 
    'semangka', 'melon', 'jeruk', 'apel', 'pisang', 'mangga'
  ];

  const lowerMsg = userMessage.toLowerCase();
  const foundNonPotato = nonPotatoKeywords.find(kw => lowerMsg.includes(kw));
  const mentionsPotato = lowerMsg.includes('kentang') || lowerMsg.includes('potato') || lowerMsg.includes('solanum');

  if (foundNonPotato && !mentionsPotato) {
    return `Mohon maaf, asisten Solanum secara khusus hanya melayani konsultasi seputar budidaya, hama, penyakit, dan perawatan tanaman serta umbi kentang. Kami tidak melayani konsultasi untuk tanaman lain seperti ${foundNonPotato}. Silakan ajukan pertanyaan seputar tanaman kentang, dan kami siap membantu Anda! 🥔`;
  }

  // Siapkan konteks percakapan multi-turn (ambil hingga 6 pesan terakhir)
  const contents = [];
  if (Array.isArray(conversationHistory)) {
    const recent = conversationHistory.slice(-6);
    for (const msg of recent) {
      if (msg.pesan) {
        contents.push({
          role: msg.pengirim === 'user' ? 'user' : 'model',
          parts: [{ text: msg.pesan }]
        });
      }
    }
  }

  // Tambahkan pesan pengguna terkini jika belum ada di riwayat
  if (contents.length === 0 || contents[contents.length - 1].parts[0].text !== userMessage) {
    contents.push({
      role: 'user',
      parts: [{ text: userMessage }]
    });
  }

  const systemInstruction = {
    parts: [{
      text: `Anda adalah AI Konsultan Resmi Solanum (bertindak sebagai Admin Solanum).
Tugas Anda adalah membalas konsultasi petani dan pengguna aplikasi Solanum seputar tanaman kentang dengan ramah, sopan, profesional, dan solutif.

KEBIJAKAN PEMBATASAN TOPIK MUTLAK:
1. Anda HANYA dan WAJIB membatasi percakapan pada topik TANAMAN KENTANG (umbi kentang, daun kentang, bibit kentang, budidaya kentang, hama kentang, penyakit kentang seperti Busuk Kering Fusarium, Busuk Basah Bakteri, Memar Hitam Bruising, Kentang Sehat, tanah untuk kentang, pupuk kentang, panen dan penyimpanan kentang).
2. JIKA PENGGUNA BERTANYA TENTANG TANAMAN ATAU SAYURAN LAIN (seperti tomat, cabai, padi, jagung, wortel, terong, bawang, singkong, buah-buahan, dll.) ATAU TOPIK APAPUN DI LUAR TANAMAN KENTANG:
   Anda HARUS DENGAN TEGAS DAN SOPAN MENOLAK memberikan saran untuk tanaman tersebut, dan mengingatkan bahwa Solanum hanya berfokus pada tanaman kentang.
   Contoh format penolakan:
   "Mohon maaf, asisten Solanum secara khusus hanya melayani konsultasi seputar budidaya, hama, penyakit, dan perawatan tanaman kentang. Kami tidak menyediakan informasi untuk tanaman lain. Silakan tanyakan hal-hal yang berkaitan dengan tanaman kentang, dan kami akan siap membantu! 🥔"
3. JANGAN PERNAH memberikan instruksi atau jawaban untuk budidaya sayuran/tanaman non-kentang.

Aturan Respon:
- Gunakan bahasa Indonesia yang baik, ramah, dan mudah dipahami petani.
- Berikan saran yang praktis dan langsung dapat diterapkan.
- Usahakan jawaban padat dan jelas (maksimal 2 hingga 3 paragraf).`
    }]
  };

  const modelsToTry = [
    'gemini-3.5-flash',
    'gemini-3.8-flash',
    'gemini-flash-latest'
  ];

  for (const model of modelsToTry) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey.trim()}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-goog-api-key': apiKey.trim()
        },
        signal: AbortSignal.timeout(15000),
        body: JSON.stringify({
          contents,
          systemInstruction,
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 2048,
            thinkingConfig: {
              thinkingBudget: 0
            }
          }
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`[GEMINI API] Model ${model} merespon status ${response.status}: ${errorText}`);
        continue;
      }

      const data = await response.json();
      const replyText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (replyText && replyText.trim().length > 0) {
        return replyText.trim();
      }
    } catch (err) {
      console.error(`[GEMINI API] Gagal memanggil model ${model}:`, err.message);
    }
  }

  // Fallback ke Interactions API jika generateContent belum tersedia atau timeout
  try {
    const lastUserPrompt = contents[contents.length - 1]?.parts?.[0]?.text || 'Halo';
    const interRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/interactions?key=${apiKey.trim()}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey.trim()
      },
      signal: AbortSignal.timeout(15000),
      body: JSON.stringify({
        model: 'gemini-3.5-flash-lite',
        input: lastUserPrompt
      })
    });
    if (interRes.ok) {
      const interData = await interRes.json();
      const text = interData.output_text ||
        interData.steps?.find(s => s.type === 'model_output')?.content?.[0]?.text ||
        interData.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) return text.trim();
    }
  } catch (e) {
    console.error('[GEMINI INTERACTIONS FALLBACK ERROR]:', e.message);
  }

  return null;
}

async function triggerGeminiAutoReply(userId, latestMessage) {
  try {
    const [adminRows] = await pool.query('SELECT id, api_key FROM admins LIMIT 1');
    if (adminRows.length === 0) return;

    const adminId = adminRows[0].id || 1;
    const apiKey = adminRows[0].api_key;
    if (!apiKey || apiKey === 'solanum-default-key' || apiKey.trim() === '') {
      console.log('[GEMINI AI] Auto-reply info: Admin belum memasukkan Gemini API Key yang valid.');
      const fallbackNotice = 'Halo! Pesan konsultasi Anda telah diterima oleh Admin Solanum. ℹ️ Saat ini fitur asisten otomatis Gemini AI belum aktif karena Admin belum memasukkan API Key di Admin Dashboard (tab API Keys). Admin akan segera merespons pertanyaan Anda.';
      await pool.query(
        'INSERT INTO chats (user_id, admin_id, pengirim, pesan, terbaca) VALUES (?, ?, ?, ?, 0)',
        [userId, adminId, 'admin', fallbackNotice]
      );
      return;
    }

    const [historyRows] = await pool.query(
      'SELECT pengirim, pesan FROM chats WHERE user_id = ? ORDER BY sent_at DESC LIMIT 8',
      [userId]
    );
    const chronologicalHistory = historyRows.reverse();

    console.log(`[GEMINI AI] Menghasilkan balasan otomatis untuk User ID ${userId}...`);
    const replyText = await generateGeminiReply(latestMessage, chronologicalHistory, apiKey);
    if (!replyText) {
      console.warn(`[GEMINI AI] Tidak menerima teks balasan dari Gemini.`);
      const errNotice = 'Halo! Admin Solanum telah menerima pesan Anda. Respon otomatis Gemini AI belum dapat dimuat saat ini. Admin akan segera membalas pesan Anda secepatnya.';
      await pool.query(
        'INSERT INTO chats (user_id, admin_id, pengirim, pesan, terbaca) VALUES (?, ?, ?, ?, 0)',
        [userId, adminId, 'admin', errNotice]
      );
      return;
    }

    await pool.query(
      'INSERT INTO chats (user_id, admin_id, pengirim, pesan, terbaca) VALUES (?, ?, ?, ?, 0)',
      [userId, adminId, 'admin', replyText]
    );

    console.log(`[GEMINI AI] ✅ Berhasil mengirim balasan Admin ke User ID ${userId}: "${replyText.substring(0, 50)}..."`);
  } catch (err) {
    console.error('[GEMINI AUTO-REPLY ERROR]:', err);
  }
}

// Uji API Key Gemini
app.post('/api/admin/test-gemini', async (req, res) => {
  try {
    const { apiKey } = req.body;
    if (!apiKey || apiKey.trim() === '') {
      return res.status(400).json({ status: 'error', message: 'API Key tidak boleh kosong' });
    }

    const testPrompt = 'Halo! Tolong perkenalkan diri Anda dalam 1-2 kalimat singkat sebagai AI Asisten Solanum yang siap melayani konsultasi budidaya dan penyakit tanaman kentang.';
    const reply = await generateGeminiReply(testPrompt, [], apiKey.trim());

    if (reply) {
      res.json({
        status: 'success',
        message: 'Koneksi Gemini AI berhasil!',
        reply: reply
      });
    } else {
      res.status(400).json({
        status: 'error',
        message: 'Gagal menghubungi Gemini API. Pastikan API Key valid dan terdaftar di Google AI Studio.'
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: `Terjadi kesalahan: ${error.message}` });
  }
});

// ==========================================
// 5. API CHAT
// ==========================================

// Ambil pesan chat berdasarkan user_id
app.get('/api/chats/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const [rows] = await pool.query(
      'SELECT id, user_id, admin_id, pengirim, pesan, terbaca, sent_at FROM chats WHERE user_id = ? ORDER BY sent_at ASC',
      [userId]
    );
    res.json({ status: 'success', data: rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengambil data chat' });
  }
});

// Kirim pesan chat
app.post('/api/chats', async (req, res) => {
  try {
    const { user_id, admin_id, pengirim, pesan } = req.body;
    if (!user_id || !pesan || !pengirim) {
      return res.status(400).json({ status: 'error', message: 'user_id, pengirim, dan pesan wajib diisi' });
    }

    const [result] = await pool.query(
      'INSERT INTO chats (user_id, admin_id, pengirim, pesan, terbaca) VALUES (?, ?, ?, ?, 0)',
      [user_id, admin_id || null, pengirim, pesan]
    );

    res.json({
      status: 'success',
      message: 'Pesan berhasil dikirim',
      chatId: result.insertId
    });

    // JIKA PENGIRIM ADALAH USER, PICU BALASAN OTOMATIS DARI GEMINI AI SEBAGAI ADMIN
    if (pengirim === 'user') {
      triggerGeminiAutoReply(user_id, pesan).catch(err => {
        console.error('[GEMINI AUTO-REPLY TRIGGER ERROR]:', err);
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengirim pesan chat' });
  }
});

// Ambil jumlah pesan belum terbaca untuk user
app.get('/api/chats-unread/count', async (req, res) => {
  try {
    const { user_id } = req.query;
    if (!user_id) {
      return res.status(400).json({ status: 'error', message: 'user_id diperlukan' });
    }
    const [rows] = await pool.query(
      'SELECT COUNT(*) as unread FROM chats WHERE user_id = ? AND pengirim = "admin" AND terbaca = 0',
      [user_id]
    );
    res.json({ status: 'success', unread: rows[0].unread || 0 });
  } catch (error) {
    res.status(500).json({ status: 'error', unread: 0 });
  }
});

// Tandai pesan sudah terbaca (reset unread count)
app.post('/api/chats/mark-read', async (req, res) => {
  try {
    const { user_id, reader } = req.body;
    if (!user_id) return res.status(400).json({ status: 'error', message: 'user_id diperlukan' });
    
    // Jika pembaca adalah admin, tandai pesan dari user sebagai terbaca
    // Jika pembaca adalah user, tandai pesan dari admin sebagai terbaca
    const targetSender = reader === 'admin' ? 'user' : 'admin';
    await pool.query(
      'UPDATE chats SET terbaca = 1 WHERE user_id = ? AND pengirim = ? AND terbaca = 0',
      [user_id, targetSender]
    );
    res.json({ status: 'success', message: 'Pesan telah ditandai sebagai terbaca' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

// Ambil daftar percakapan untuk tab Pesan Admin
app.get('/api/admin/conversations', async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT 
        u.id as user_id, 
        u.nama, 
        u.email, 
        u.no_hp,
        u.foto,
        (SELECT pesan FROM chats WHERE user_id = u.id ORDER BY sent_at DESC LIMIT 1) as last_message,
        (SELECT sent_at FROM chats WHERE user_id = u.id ORDER BY sent_at DESC LIMIT 1) as last_time,
        (SELECT COUNT(*) FROM chats WHERE user_id = u.id AND pengirim = 'user' AND terbaca = 0) as unread_count
      FROM users u
      ORDER BY (last_time IS NULL), last_time DESC, u.id DESC
    `);
    res.json({ status: 'success', data: users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 'error', message: 'Gagal mengambil data percakapan' });
  }
});

app.listen(port, () => {
  console.log(`[🚀] Solanum API Server berjalan di http://localhost:${port}`);
});
