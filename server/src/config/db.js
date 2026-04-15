/**
 * MySQL connection pool.
 *
 * Uses mysql2/promise for async/await support throughout the codebase.
 * The pool manages up to 10 concurrent connections and queues extras.
 */

import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

const pool = mysql.createPool({
  host:              process.env.DB_HOST || 'localhost',
  port:              parseInt(process.env.DB_PORT, 10) || 3306,
  user:              process.env.DB_USER || 'root',
  password:          process.env.DB_PASSWORD || '',
  database:          process.env.DB_NAME || 'passvault',
  waitForConnections: true,
  connectionLimit:   10,
  queueLimit:        0,
});

export default pool;
