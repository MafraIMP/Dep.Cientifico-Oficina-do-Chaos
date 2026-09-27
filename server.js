// ... (mantenha todo o início do seu código, imports, pool e initDB)

// Rotas da API - Documentos
app.get('/api/docs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM documents ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/docs', async (req, res) => {
  try {
    const { num, class: objClass, sci, comp, dclass, cont, desc, obs, image, creator } = req.body;
    const query = `
      INSERT INTO documents (num, class, sci, comp, dclass, cont, desc_text, obs, image, creator, status, reject_reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', '') RETURNING *;
    `;
    const values = [num, objClass, sci, comp, dclass, cont, desc, obs, image, creator];
    const newDoc = await pool.query(query, values);
    res.json(newDoc.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/docs/:id/eval', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, rejectReason } = req.body;
    const query = 'UPDATE documents SET status = $1, reject_reason = $2 WHERE id = $3 RETURNING *;';
    const updated = await pool.query(query, [status, rejectReason || '', id]);
    res.json(updated.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// ROTAS DE USUÁRIOS (ADICIONADAS / CORRIGIDAS)
// ==========================================

// Listar usuários
app.get('/api/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role, blocked FROM users');
    res.json(result.rows);
  } catch (err) {
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

    // Verificar se o usuário já existe
    const existing = await pool.query('SELECT * FROM users WHERE username = $1', [cleanUser]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Este nome de usuário já está em uso.' });
    }

    // Criptografar a senha com bcrypt
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
    res.status(500).json({ error: err.message });
  }
});

// Atualizar cargo ou status de bloqueio do usuário
app.put('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { role, blocked } = req.body;

    const targetUser = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
    if (targetUser.rows.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const current = targetUser.rows[0];
    const newRole = role !== undefined ? role : current.role;
    const newBlocked = blocked !== undefined ? blocked : current.blocked;

    const query = 'UPDATE users SET role = $1, blocked = $2 WHERE username = $3 RETURNING id, username, role, blocked;';
    const updated = await pool.query(query, [newRole, newBlocked, username.toLowerCase()]);

    res.json(updated.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
    
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
    res.status(500).json({ error: err.message });
  }
});

// Redirecionar qualquer outra rota para o index.html (essencial para SPAs)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
