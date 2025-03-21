// Se importa Express para crear y configurar el servidor web
const express = require('express');
// Se importa bcrypt para cifrar contraseñas antes de almacenarlas en la base de datos, mejorando la seguridad
const bcrypt = require('bcrypt');
// Se importa jsonwebtoken (JWT) para generar y verificar tokens de autenticación, permitiendo la gestión de sesiones seguras
const jwt = require('jsonwebtoken');
// Se importa mongoose para gestionar la base de datos MongoDB
const mongoose = require('mongoose');
const { Schema } = mongoose;

const app = express();
const PUERTO = 3000;
const clave = 'claveultrasecreta';

app.use(express.json());

// Conexión a la base de datos MongoDB
mongoose.connect('mongodb://localhost:27017/auth_demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Definición del esquema de Usuario
const UsuarioSchema = new Schema({
  nombreUsuario: { type: String, unique: true, required: true },
  contrasena: { type: String, required: true },
  rol: { type: String, enum: ['admin', 'estandar'], default: 'estandar' },
});

// Definición del esquema de Artículo
const ArticuloSchema = new Schema({
  titulo: { type: String, required: true },
  descripcion: { type: String, required: true },
  precio: { type: Number, required: true },
});

const Usuario = mongoose.model('Usuario', UsuarioSchema);
const Articulo = mongoose.model('Articulo', ArticuloSchema);

// Middleware de autenticación con JWT
const autenticar = async (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Acceso denegado' });

  try {
    const verificado = jwt.verify(token, clave);
    req.usuario = verificado;
    next();
  } catch (err) {
    res.status(400).json({ error: 'Token inválido' });
  }
};

// Ruta para registrar un nuevo usuario
app.post('/registro', async (req, res) => {
  try {
    const { nombreUsuario, contrasena, rol } = req.body;
    const contrasenaHasheada = await bcrypt.hash(contrasena, 10);
    const usuario = new Usuario({ nombreUsuario, contrasena: contrasenaHasheada, rol });
    await usuario.save();
    res.json({ mensaje: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(400).json({ error: 'El nombre de usuario ya existe o los datos son inválidos' });
  }
});

// Ruta para autenticar a un usuario y generar un token JWT
app.post('/login', async (req, res) => {
  const { nombreUsuario, contrasena } = req.body;
  const usuario = await Usuario.findOne({ nombreUsuario });
  if (!usuario || !(await bcrypt.compare(contrasena, usuario.contrasena))) {
    return res.status(400).json({ error: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ id: usuario._id, rol: usuario.rol }, clave, { expiresIn: '1h' });
  res.json({ token });
});

// Ruta para crear un artículo (solo para administradores)
app.post('/articulos', autenticar, async (req, res) => {
  if (req.usuario.rol !== 'admin') {
    return res.status(403).json({ error: 'No autorizado para crear artículos' });
  }
  const { titulo, descripcion, precio } = req.body;
  try {
    const articulo = new Articulo({ titulo, descripcion, precio });
    await articulo.save();
    res.json({ mensaje: 'Artículo creado exitosamente' });
  } catch (error) {
    res.status(400).json({ error: 'Datos de artículo inválidos' });
  }
});

// Ruta protegida que permite a los usuarios autenticados obtener la lista de artículos
app.get('/articulos', autenticar, async (req, res) => {
  try {
    const articulos = await Articulo.find();
    res.json(articulos);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener los artículos' });
  }
});

// Iniciar el servidor en el puerto especificado
app.listen(PUERTO, () => {
  console.log(`Servidor corriendo en http://localhost:${PUERTO}`);
});
