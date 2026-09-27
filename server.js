const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const app = express();

// Configurações de Middleware com aumento de limite para aceitar imagens em Base64 com segurança
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());

// Servir a pasta public estaticamente
app.use(express.static(path.join(__dirname, 'public')));

// Conexão com o Banco de Dados PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inicializar tabelas e dados padrão automaticamente ao ligar o servidor
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'Nível 1',
        blocked BOOLEAN DEFAULT false
      );

      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        num VARCHAR(20) NOT NULL,
        class VARCHAR(30) NOT NULL,
        threat VARCHAR(30) DEFAULT 'Não Especificada',
        sci VARCHAR(100) NOT NULL,
        comp VARCHAR(100),
        dclass VARCHAR(100) NOT NULL,
        cont TEXT NOT NULL,
        desc_text TEXT NOT NULL,
        obs TEXT NOT NULL,
        image TEXT,
        creator VARCHAR(50) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        reject_reason TEXT DEFAULT ''
      );
    `);
    
    // Criar usuário admin padrão se não existir
    const adminCheck = await pool.query("SELECT * FROM users WHERE username = 'admin'");
    if (adminCheck.rows.length === 0) {
      const hashedPass = await bcrypt.hash('OFICINA DO CAOS', 10);
      await pool.query(
        "INSERT INTO users (username, password, role, blocked) VALUES ($1, $2, $3, $4)",
        ['admin', hashedPass, 'O5', false]
      );
      console.log('>> Usuário ADMIN padrão criado com segurança.');
    }
    console.log('>> Banco de dados conectado e tabelas verificadas com sucesso!');
  } catch (err) {
    console.error('Erro fatal ao inicializar o banco de dados:', err);
  }
}
initDB();

// ==========================================
// ROTAS DA API - DOCUMENTOS
// ==========================================

// Listar todos os documentos
app.get('/api/docs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM documents ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar documentos:', err);
    res.status(500).json({ error: err.message });
  }
});

// Criar novo documento SCP
app.post('/api/docs', async (req, res) => {
  try {
    const { num, class: objClass, threat, sci, comp, dclass, cont, desc, obs, image, creator } = req.body;
    
    // Validação básica de campos obrigatórios no servidor
    if (!num || !objClass || !sci || !dclass || !cont || !desc || !obs || !creator) {
      return res.status(400).json({ error: 'Campos obrigatórios em falta no envio do documento.' });
    }

    const query = `
      INSERT INTO documents (num, class, threat, sci, comp, dclass, cont, desc_text, obs, image, creator, status, reject_reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending', '') RETURNING *;
    `;
    const values = [
      num, 
      objClass, 
      threat || 'Não Especificada', 
      sci, 
      comp || '', 
      dclass, 
      cont, 
      desc, 
      obs, 
      image || null, 
      creator
    ];

    const newDoc = await pool.query(query, values);
    res.status(201).json(newDoc.rows[0]);
  } catch (err) {
    console.error('Erro ao inserir documento no PostgreSQL:', err);
    res.status(500).json({ error: err.message });
  }
});

// Atualizar avaliação (Aprovar / Rejeitar)
app.put('/api/docs/:id/eval', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, rejectReason } = req.body;
    const query = 'UPDATE documents SET status = $1, reject_reason = $2 WHERE id = $3 RETURNING *;';
    const updated = await pool.query(query, [status, rejectReason || '', id]);
    
    if (updated.rows.length === 0) {
      return res.status(404).json({ error: 'Documento não encontrado para avaliação.' });
    }

    res.json(updated.rows[0]);
  } catch (err) {
    console.error('Erro ao avaliar documento:', err);
    res.status(500).json({ error: err.message });
  }
});

// Deletar documento permanentemente (Nível 5 e O5)
app.delete('/api/docs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = 'DELETE FROM documents WHERE id = $1 RETURNING *;';
    const deleted = await pool.query(query, [id]);
    
    if (deleted.rows.length === 0) {
      return res.status(404).json({ error: 'Documento não encontrado.' });
    }
    
    res.json({ message: 'Documento deletado com sucesso.', doc: deleted.rows[0] });
  } catch (err) {
    console.error('Erro ao deletar documento:', err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ROTAS DA API - USUÁRIOS E AUTENTICAÇÃO
// ==========================================

// Listar todos os usuários
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role, blocked FROM users');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    res.status(500).json({ error: err.message });
  }
});

// Criar novo usuário (Painel O5)
app.post('/api/users', async (req, res) => {
  try {
    const { username, password, role, blocked } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
    }

    const cleanUser = username.trim().toLowerCase();

    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUser]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Este nome de usuário já está em uso.' });
    }

    const hashedPass = await bcrypt.hash(password, 10);
    const userRole = role || 'Nível 1';
    const isBlocked = blocked || false;

    const query = `
      INSERT INTO users (username, password, role, blocked)
      VALUES ($1, $2, $3, $4) RETURNING id, username, role, blocked;
    `;
    const newUser = await pool.query(query, [cleanUser, hashedPass, userRole, isBlocked]);
    
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    console.error('Erro ao criar usuário:', err);
    res.status(500).json({ error: err.message });
  }
});

// Atualizar cargo ou status de bloqueio do usuário
app.put('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { role, blocked }++req.body; // mantendo segurança abaixo

    const targetUser = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
    if (targetUser.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const current = targetUser.rows[0];
    const newRole = req.body.role !== undefined ? req.body.role : current.role;
    const newBlocked = req.body.blocked !== undefined ? req.body.blocked : current.blocked;

    const query = 'UPDATE users SET role = $1, blocked = $2 WHERE username = $3 RETURNING id, username, role, blocked;';
    const updated = await pool.query(query, [newRole, newBlocked, username.toLowerCase()]);

    res.json(updated.rows[0]);
  } catch (err) {
    console.error('Erro ao atualizar usuário:', err);
    res.status(500).json({ error: err.message });
  }
});

// Realizar Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Preencha usuário e senha.' });
    }

    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username.trim().toLowerCase()]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Credencial inválida.' });
    }

    const user = userResult.rows[0];
    if (user.blocked) {
      return res.status(403).json({ error: 'Usuário bloqueado pelo Comando O5.' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Credencial inválida.' });
    }

    res.json({ username: user.username, role: user.role, blocked: user.blocked });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// REDIRECIONAMENTO SPA E INICIALIZAÇÃO
// ==========================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
