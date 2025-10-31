require('dotenv').config();
// 1. Importar las librerías
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 2. Inicializar la aplicación
const app = express();
const port = 3000;

// 3. Constantes de Negocio
const COMMISSION_PERCENT = 5; // 5% global
const SUBSCRIPTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 días

// 4. Configurar Middlewares
app.use(cors()); // Permite que tu index.html hable con este servidor
app.use(express.json()); // Permite al servidor entender JSON (req.body)

// 5. Conectar a la Base de Datos
const MONGO_URL = process.env.MONGO_URL;

mongoose.connect(MONGO_URL)
  .then(() => {
    console.log('¡Conectado a MongoDB Atlas! ✅');
  })
  .catch((err) => {
    console.error('Error al conectar a MongoDB:', err);
  });

// 6. Modelos de la Base de Datos (Mongoose)

// Modelo de la Tienda (Store)
const storeSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  whatsapp: { type: String },
  password: { type: String, required: true },
  isPublic: { type: Boolean, default: true },
  subscriptionPaidUntil: { type: Date },
  blocked: { type: Boolean, default: false },
  // --- CAMPOS NUEVOS PARA GANANCIAS ---
  totalRevenue: { type: Number, default: 0 }, // Ingresos de la tienda
  platformFeeOwed: { type: Number, default: 0 } // Comisión para JTL
});
const Store = mongoose.model('Store', storeSchema);

// Modelo del Producto (Product)
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, default: 'General' },
  price: { type: Number, required: true, min: 0 },
  stock: { type: Number, default: 0, min: 0 },
  img: { type: String },
  store: { type: mongoose.Schema.Types.ObjectId, ref: 'Store', required: true }
});
const Product = mongoose.model('Product', productSchema);


// 7. Seguridad: Middleware de Autenticación (JWT)

const JWT_SECRET = process.env.JWT_SECRET;

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.status(401).json({ message: 'No estás autorizado' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user; // { storeId: '...', name: '...' }
    next();
  });
};

// Middleware para verificar si es admin (JTL)
const authenticateAdmin = (req, res, next) => {
  if (req.user.name !== 'jtl') {
    return res.status(403).json({ message: 'No tienes permisos de administrador' });
  }
  next();
};


// 8. Rutas de la API (Endpoints)

// --- RUTAS PÚBLICAS (Login, Registro, Ver) ---

// RUTA GET: OBTENER TODAS LAS TIENDAS (PÚBLICA)
app.get('/api/stores', async (req, res) => {
  try {
    // Solo enviamos los campos necesarios para la UI
    const stores = await Store.find({}, 'name isPublic'); // _id se incluye por defecto
    res.json(stores);
  } catch (error) {
    console.error('Error al obtener tiendas:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA GET: OBTENER PRODUCTOS DE UNA TIENDA (PÚBLICA)
app.get('/api/products/:storeId', async (req, res) => {
  try {
    // Ahora buscamos por el _id de MongoDB, no por el nombre
    const store = await Store.findById(req.params.storeId);
    if (!store) {
      console.log('Tienda no encontrada con ID:', req.params.storeId);
      return res.json([]);
    }
    const products = await Product.find({ store: store._id });
    res.json(products);
  } catch (error) {
    console.error('Error buscando productos:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA POST: REGISTRAR TIENDA (PÚBLICA) - Usada por tu 'curl'
app.post('/api/stores/register', async (req, res) => {
  try {
    const { name, password, whatsapp } = req.body;
    const existingStore = await Store.findOne({ name: name });
    if (existingStore) {
      return res.status(400).json({ message: 'Ya existe una tienda con ese nombre' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newStore = new Store({
      name: name,
      password: hashedPassword,
      whatsapp: whatsapp || '',
      subscriptionPaidUntil: new Date(Date.now() + SUBSCRIPTION_MS) // +30 días gratis
    });
    await newStore.save();
    console.log('¡Tienda registrada con éxito:', newStore.name);
    res.status(201).json({ message: 'Tienda registrada con éxito', store: newStore });
  } catch (error) {
    console.error('Error al registrar tienda:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA POST: LOGIN DE TIENDA (PÚBLICA)
app.post('/api/stores/login', async (req, res) => {
  try {
    // Ahora el frontend envía el _id de MongoDB como 'storeId'
    const { storeId, password } = req.body;
    const store = await Store.findById(storeId);
    if (!store) {
      return res.status(404).json({ message: 'Tienda no encontrada' });
    }
    const isMatch = await bcrypt.compare(password, store.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta' });
    }
    const token = jwt.sign(
      { storeId: store._id, name: store.name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.status(200).json({ message: 'Login exitoso', token: token, store: store });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// --- RUTAS DE PRODUCTOS (PRIVADAS) ---

// RUTA POST: CREAR PRODUCTO (PRIVADA - REQUIERE TOKEN)
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, category, price, stock, img } = req.body;
    if (!name || !price) {
      return res.status(400).json({ message: 'Nombre y precio son requeridos' });
    }
    const storeId = req.user.storeId;
    const newProduct = new Product({
      name: name,
      category: category || 'General',
      price: Number(price),
      stock: Number(stock) || 0,
      img: img || '',
      store: storeId
    });
    await newProduct.save();
    console.log(`Producto "${name}" guardado para la tienda "${req.user.name}"`);
    res.status(201).json({ message: 'Producto guardado con éxito', product: newProduct });
  } catch (error) {
    console.error('Error al guardar producto:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA DELETE: BORRAR UN PRODUCTO (PRIVADA - REQUIERE TOKEN)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const productId = req.params.id;
    const storeId = req.user.storeId;
    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ message: 'Producto no encontrado' });
    }
    if (product.store.toString() !== storeId) {
      return res.status(403).json({ message: 'No tienes permiso para borrar este producto' });
    }
    await Product.findByIdAndDelete(productId);
    console.log(`Producto ID "${productId}" eliminado por la tienda "${req.user.name}"`);
    res.status(200).json({ message: 'Producto eliminado con éxito' });
  } catch (error) {
    console.error('Error al eliminar producto:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// --- RUTAS DE VENTAS (PRIVADAS) ---

// RUTA POST: VENTA EN EFECTIVO (PRIVADA - REQUIERE TOKEN)
app.post('/api/sales/cash', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity, paidAmount } = req.body;
    const storeId = req.user.storeId;

    if (!productId || !quantity || !paidAmount) {
      return res.status(400).json({ message: 'Faltan datos' });
    }
    const qty = Number(quantity);
    if (qty <= 0) return res.status(400).json({ message: 'Cantidad inválida' });

    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    if (product.store.toString() !== storeId) return res.status(403).json({ message: 'Producto no pertenece a tu tienda' });
    if (product.stock < qty) return res.status(400).json({ message: `Stock insuficiente. Solo quedan ${product.stock}` });
    
    const total = product.price * qty;
    const paid = Number(paidAmount);
    if (paid < total) return res.status(400).json({ message: 'El monto recibido no cubre el total' });
    
    const change = paid - total;
    const commission = total * (COMMISSION_PERCENT / 100);

    // Actualizar BD
    product.stock -= qty;
    await product.save();
    
    const updatedStore = await Store.findByIdAndUpdate(storeId, {
      $inc: {
        totalRevenue: total,
        platformFeeOwed: commission
      }
    }, { new: true }); // {new: true} devuelve el documento actualizado

    console.log(`Venta en efectivo registrada por "${req.user.name}": ${qty}x ${product.name}`);
    
    res.status(200).json({
      message: `Venta registrada — Cambio: RD$${change.toFixed(2)} — Comisión: RD$${commission.toFixed(2)}`,
      newStats: {
        totalRevenue: updatedStore.totalRevenue,
        platformFeeOwed: updatedStore.platformFeeOwed
      }
    });
  } catch (error) {
    console.error('Error en Venta en Efectivo:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA POST: VENTA POR WHATSAPP (PÚBLICA, PERO ACTUALIZA STOCK)
// Esta es más compleja, la haremos más simple: solo actualiza stock
app.post('/api/sales/whatsapp', async (req, res) => {
    try {
        const { cart, storeId } = req.body; // cart es [{productId, qty}]
        if (!cart || !storeId) return res.status(400).json({ message: 'Faltan datos' });

        let totalSale = 0;
        let totalCommission = 0;
        let stockErrors = [];

        const operations = cart.map(async (item) => {
            const product = await Product.findById(item.productId);
            if (!product) {
                stockErrors.push(`Producto ID ${item.productId} no encontrado.`);
                return;
            }
            if (product.store.toString() !== storeId) {
                stockErrors.push(`Producto ${product.name} no pertenece a esta tienda.`);
                return;
            }
            if (product.stock < item.qty) {
                stockErrors.push(`Stock insuficiente para ${product.name}. Solo quedan ${product.stock}.`);
                return;
            }

            const total = product.price * item.qty;
            totalSale += total;
            totalCommission += total * (COMMISSION_PERCENT / 100);

            // Preparamos la operación de actualización de stock
            return Product.findByIdAndUpdate(item.productId, {
                $inc: { stock: -item.qty }
            });
        });

        await Promise.all(operations);

        if (stockErrors.length > 0) {
            return res.status(400).json({ message: 'Error de stock: ' + stockErrors.join(', ') });
        }

        // Actualizamos las ganancias de la tienda
        await Store.findByIdAndUpdate(storeId, {
            $inc: {
                totalRevenue: totalSale,
                platformFeeOwed: totalCommission
            }
        });

        console.log(`Venta WhatsApp registrada para Tienda ID ${storeId}, Total: ${totalSale}`);
        res.status(200).json({ message: 'Venta registrada con éxito' });

    } catch (error) {
        console.error('Error en Venta WhatsApp:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


// --- RUTAS DE ADMIN (PRIVADAS) ---

// RUTA GET: OBTENER ESTADÍSTICAS (PRIVADA - REQUIERE TOKEN)
app.get('/api/stats/:storeId', authenticateToken, async (req, res) => {
  try {
    const storeId = req.params.storeId;
    // Seguridad: O eres el dueño de la tienda O eres JTL
    if (req.user.storeId !== storeId && req.user.name !== 'jtl') {
      return res.status(403).json({ message: 'No tienes permiso para ver estas estadísticas' });
    }
    const store = await Store.findById(storeId, 'totalRevenue platformFeeOwed name subscriptionPaidUntil');
    if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
    
    res.status(200).json(store);
  } catch (error) {
    console.error('Error al obtener stats:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// RUTA POST: RESETEAR GANANCIAS (PRIVADA - REQUIERE TOKEN)
app.post('/api/stores/resetprofit', authenticateToken, async (req, res) => {
    try {
        const storeId = req.user.storeId;
        const updatedStore = await Store.findByIdAndUpdate(storeId, {
            totalRevenue: 0,
            platformFeeOwed: 0
        }, { new: true });
        console.log(`Ganancias reseteadas por "${req.user.name}"`);
        res.status(200).json({
            message: 'Ganancias y comisiones reseteadas',
            newStats: {
                totalRevenue: updatedStore.totalRevenue,
                platformFeeOwed: updatedStore.platformFeeOwed
            }
        });
    } catch (error) {
        console.error('Error al resetear ganancias:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// RUTA PUT: CAMBIAR CONTRASEÑA (PRIVADA - REQUIERE TOKEN)
app.put('/api/stores/password', authenticateToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const storeId = req.user.storeId;
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        await Store.findByIdAndUpdate(storeId, { password: hashedPassword });
        console.log(`Contraseña actualizada por "${req.user.name}"`);
        res.status(200).json({ message: 'Contraseña actualizada con éxito' });
    } catch (error) {
        console.error('Error al cambiar contraseña:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


// --- RUTAS DE SÚPER-ADMIN (JTL ONLY) ---

// RUTA POST: CREAR TIENDA (PRIVADA - JTL ONLY)
app.post('/api/stores', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const { name, password, whatsapp, isPublic } = req.body;
        if (!name || !password) {
            return res.status(400).json({ message: 'Nombre y contraseña requeridos' });
        }
        // Re-usamos la lógica de /register
        const existingStore = await Store.findOne({ name: name });
        if (existingStore) {
          return res.status(400).json({ message: 'Ya existe una tienda con ese nombre' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newStore = new Store({
          name: name,
          password: hashedPassword,
          whatsapp: whatsapp || '',
          isPublic: isPublic || false,
          subscriptionPaidUntil: new Date(Date.now() + SUBSCRIPTION_MS) // +30 días gratis
        });
        await newStore.save();
        console.log(`Tienda "${name}" CREADA por JTL`);
        res.status(201).json({ message: 'Tienda creada con éxito', store: newStore });
    } catch (error) {
        console.error('Error al crear tienda (JTL):', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// RUTA PUT: ALTERNAR PÚBLICA/PRIVADA (PRIVADA - JTL ONLY)
app.put('/api/stores/:id/public', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const { isPublic } = req.body;
        const updatedStore = await Store.findByIdAndUpdate(storeId, { isPublic: isPublic }, { new: true });
        console.log(`Tienda "${updatedStore.name}" actualizada a pública=${isPublic} por JTL`);
        res.status(200).json({ message: 'Estado de tienda actualizado', store: updatedStore });
    } catch (error) {
        console.error('Error al alternar pública:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// RUTA PUT: REGISTRAR PAGO DE SUSCRIPCIÓN (PRIVADA - JTL ONLY)
app.put('/api/stores/:id/pay', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        const store = await Store.findById(storeId);
        if (!store) return res.status(404).json({ message: 'Tienda no encontrada' });
        
        // Si la sub está vencida, empieza desde hoy. Si no, añade 30 días al final.
        const now = Date.now();
        const start = store.subscriptionPaidUntil.getTime() > now ? store.subscriptionPaidUntil.getTime() : now;
        
        const newPaidUntil = new Date(start + SUBSCRIPTION_MS);
        
        store.subscriptionPaidUntil = newPaidUntil;
        store.blocked = false; // Desbloquear si estaba bloqueada
        await store.save();
        
        console.log(`Pago registrado para "${store.name}" por JTL. Nueva fecha: ${newPaidUntil}`);
        res.status(200).json({ message: 'Pago registrado con éxito', store: store });
    } catch (error) {
        console.error('Error al registrar pago:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// RUTA DELETE: BORRAR TIENDA (PRIVADA - JTL ONLY)
app.delete('/api/stores/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    try {
        const storeId = req.params.id;
        if (storeId === req.user.storeId) {
            return res.status(400).json({ message: 'No puedes borrar tu propia tienda (JTL)' });
        }
        
        // 1. Borrar la tienda
        const deletedStore = await Store.findByIdAndDelete(storeId);
        if (!deletedStore) return res.status(404).json({ message: 'Tienda no encontrada' });

        // 2. Borrar todos los productos asociados a esa tienda
        await Product.deleteMany({ store: storeId });
        
        console.log(`Tienda "${deletedStore.name}" y sus productos fueron ELIMINADOS por JTL`);
        res.status(200).json({ message: 'Tienda y todos sus productos eliminados' });
    } catch (error) {
        console.error('Error al borrar tienda (JTL):', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});


// 9. Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor de Tienda JTL escuchando en http://localhost:${port}`);
});