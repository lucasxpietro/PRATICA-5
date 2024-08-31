const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const app = express();

app.use(bodyParser.json());

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

// Chave secreta para assinar os tokens JWT
const secretKey = 'your-secret-key';

// Mock de dados
const users = [
    {"username": "user", "password": "123456", "id": 123, "email": "user@dominio.com", "perfil": "user"},
    {"username": "admin", "password": "123456789", "id": 124, "email": "admin@dominio.com", "perfil": "admin"},
    {"username": "colab", "password": "123", "id": 125, "email": "colab@dominio.com", "perfil": "user"},
];

// Função de login
app.post('/api/auth/login', (req, res) => {
    const credentials = req.body;
    const userData = doLogin(credentials);

    if (userData) {
        const token = jwt.sign({ id: userData.id, perfil: userData.perfil }, secretKey, { expiresIn: '1h' });
        res.json({ token: token });
    } else {
        res.status(401).json({ message: 'Credenciais inválidas' });
    }
});

// Função de autenticação de token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extrai apenas o token, ignorando o 'Bearer'

    if (!token) return res.status(401).json({ message: 'Token não fornecido' });

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });

        req.user = user;
        next();
    });
}

// Endpoint para recuperação dos dados de todos os usuários cadastrados
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.perfil !== 'admin') {
        return res.status(403).json({ message: 'Acesso proibido' });
    }
    res.status(200).json({ data: users });
});

// Endpoint para recuperação dos contratos existentes
app.get('/api/contracts/:empresa/:inicio', authenticateToken, (req, res) => {
    if (req.user.perfil !== 'admin') {
        return res.status(403).json({ message: 'Acesso proibido' });
    }

    const empresa = req.params.empresa;
    const dtInicio = req.params.inicio;
    const result = getContracts(empresa, dtInicio);

    if (result && result.length > 0)
        res.status(200).json({ data: result });
    else
        res.status(404).json({ data: 'Dados Não encontrados' });
});

// Função de login
function doLogin(credentials) {
    return users.find(item => credentials.username === item.username && credentials.password === item.password);
}

// Função para simular a recuperação de contratos
function getContracts(empresa, inicio) {
    // Refatorado para evitar SQL Injection
    const sanitizedEmpresa = empresa.replace(/[^a-zA-Z0-9 ]/g, '');
    const sanitizedInicio = inicio.replace(/[^0-9-]/g, '');

    const repository = new Repository();
    const query = `SELECT * FROM contracts WHERE empresa = '${sanitizedEmpresa}' AND data_inicio = '${sanitizedInicio}'`;
    return repository.execute(query);
}

// Classe fake emulando um script externo
class Repository {
    execute(query) {
        // Retornar resultados simulados
        return [];
    }
}
