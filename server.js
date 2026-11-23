const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { randomUUID } = require("crypto");
const { Pool } = require("pg");
const { MongoClient, ObjectId } = require("mongodb");
const { createClient } = require("redis");
const neo4j = require("neo4j-driver");

const env = process.env;
const PORT = env.PORT || 3000;
const SESSION_TTL = 3600;
const CACHE_TTL = 300;

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const pgPool = new Pool({
  host: env.PG_HOST || "localhost",
  port: Number(env.PG_PORT) || 5432,
  user: env.PG_USER || "dapurkita",
  password: env.PG_PASSWORD || "dapurkita_password",
  database: env.PG_DB || "dapurkita_auth",
});

const mongoClient = new MongoClient(
  env.MONGO_URI || "mongodb://admin:password@localhost:27017",
);
let recipesCol;

const redisClient = createClient({
  url: env.REDIS_URL || "redis://localhost:6379",
});
redisClient.on("error", (err) => console.error("Redis error:", err.message));

const neo4jDriver = neo4j.driver(
  env.NEO4J_URI || "bolt://localhost:7687",
  neo4j.auth.basic(
    env.NEO4J_USER || "neo4j",
    env.NEO4J_PASSWORD || "dapurkita_password",
  ),
);

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
const todayKey = () =>
  `leaderboard:daily:${new Date().toISOString().slice(0, 10)}`;
const toObjectId = (id) => (ObjectId.isValid(id) ? new ObjectId(id) : null);

async function runCypher(query, params) {
  const session = neo4jDriver.session();
  try {
    return await session.run(query, params);
  } finally {
    await session.close();
  }
}

async function retry(name, fn, attempts = 30, delayMs = 2000) {
  for (let i = 1; i <= attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === attempts) throw err;
      console.log(`Menunggu ${name} siap (${i}/${attempts})...`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

async function initDatabases() {
  await retry("PostgreSQL", () => pgPool.query("SELECT 1"));

  await retry("MongoDB", () => mongoClient.connect());
  recipesCol = mongoClient.db("dapurkita_catalog").collection("recipes");
  await recipesCol.createIndex({ category: 1, "ingredients.name": 1 });
  await recipesCol.createIndex({ title: "text" });

  await retry("Redis", () => redisClient.connect());

  await retry("Neo4j", () => neo4jDriver.verifyConnectivity());
  for (const q of [
    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT recipe_id IF NOT EXISTS FOR (r:Recipe) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT ingredient_name IF NOT EXISTS FOR (i:Ingredient) REQUIRE i.name IS UNIQUE",
    "CREATE CONSTRAINT category_name IF NOT EXISTS FOR (c:Category) REQUIRE c.name IS UNIQUE",
  ])
    await runCypher(q);

  console.log(
    "Semua 4 database (PostgreSQL, MongoDB, Redis, Neo4j) terhubung!",
  );
}

async function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Token tidak ditemukan" });

  const sessionData = await redisClient.get(`session:${token}`);
  if (!sessionData)
    return res.status(401).json({ error: "Sesi kedaluwarsa atau tidak valid" });

  await redisClient.expire(`session:${token}`, SESSION_TTL);
  req.user = JSON.parse(sessionData);
  req.token = token;
  next();
}
const auth = wrap(authMiddleware);

// ================= AUTH (PostgreSQL + Redis + Neo4j) =================
app.post(
  "/api/auth/register",
  wrap(async (req, res) => {
    const { email, password, display_name, role = "contributor" } = req.body;
    if (!email || !password || !display_name) {
      return res
        .status(400)
        .json({ error: "Email, password, dan nama tampilan wajib diisi" });
    }

    const client = await pgPool.connect();
    let user;
    try {
      await client.query("BEGIN");
      const hash = await bcrypt.hash(password, 10);
      const userRes = await client.query(
        "INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id, email, display_name",
        [email, hash, display_name],
      );
      user = userRes.rows[0];
      const roleRes = await client.query(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2",
        [user.id, role],
      );
      if (roleRes.rowCount === 0)
        throw new Error(`Role '${role}' tidak dikenal`);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      const msg = err.code === "23505" ? "Email sudah terdaftar" : err.message;
      return res.status(400).json({ error: msg });
    } finally {
      client.release();
    }

    await runCypher("MERGE (u:User {id: $id}) SET u.display_name = $name", {
      id: user.id.toString(),
      name: user.display_name,
    });

    res.status(201).json({ message: "Registrasi berhasil (ACID)", user });
  }),
);

app.post(
  "/api/auth/login",
  wrap(async (req, res) => {
    const { email, password } = req.body;
    const userRes = await pgPool.query(
      `SELECT u.id, u.email, u.password_hash, u.display_name, u.is_active,
            array_remove(array_agg(r.name), NULL) AS roles
     FROM users u
     LEFT JOIN user_roles ur ON u.id = ur.user_id
     LEFT JOIN roles r ON ur.role_id = r.id
     WHERE u.email = $1 GROUP BY u.id`,
      [email],
    );

    const user = userRes.rows[0];
    const ok =
      user &&
      user.is_active &&
      password &&
      (await bcrypt.compare(password, user.password_hash));
    await pgPool.query(
      "INSERT INTO login_audit (user_id, status, ip_address) VALUES ($1, $2, $3)",
      [user ? user.id : null, ok ? "success" : "fail", req.ip],
    );
    if (!ok)
      return res.status(401).json({ error: "Email atau password salah" });

    const token = randomUUID();
    const payload = {
      id: user.id.toString(),
      email: user.email,
      display_name: user.display_name,
      roles: user.roles,
    };
    await redisClient.set(`session:${token}`, JSON.stringify(payload), {
      EX: SESSION_TTL,
    });

    res.json({ token, user: payload, session_ttl_seconds: SESSION_TTL });
  }),
);

app.post(
  "/api/auth/logout",
  auth,
  wrap(async (req, res) => {
    await redisClient.del(`session:${req.token}`);
    res.json({ message: "Logout instan berhasil" });
  }),
);

app.get("/api/auth/me", auth, (req, res) => res.json({ user: req.user }));

// ================= RECIPE & SEARCH (MongoDB + Neo4j) =================
app.post(
  "/api/recipes",
  auth,
  wrap(async (req, res) => {
    const {
      title,
      category,
      prep_time_minutes,
      attributes,
      ingredients,
      steps,
    } = req.body;
    if (!title || !category)
      return res.status(400).json({ error: "Judul dan kategori wajib diisi" });

    const doc = {
      author_id: req.user.id,
      author_name: req.user.display_name,
      title,
      category,
      prep_time_minutes: Number(prep_time_minutes) || 30,
      attributes: attributes || {},
      ingredients: (ingredients || []).filter(
        (i) => i && i.name && i.name.trim(),
      ),
      steps: (steps || []).filter(
        (s) => s && s.instruction && s.instruction.trim(),
      ),
      stats: { views: 0, likes_count: 0 },
      created_at: new Date(),
    };

    const result = await recipesCol.insertOne(doc);
    const recipeId = result.insertedId.toString();

    await runCypher(
      `MERGE (r:Recipe {id: $id}) SET r.title = $title
     MERGE (c:Category {name: $category})
     MERGE (r)-[:IN_CATEGORY]->(c)
     WITH r
     UNWIND $ingredients AS ing
     MERGE (i:Ingredient {name: toLower(trim(ing.name))})
     MERGE (r)-[u:USES]->(i)
     SET u.amount = ing.amount`,
      { id: recipeId, title, category, ingredients: doc.ingredients },
    );

    res.status(201).json(doc);
  }),
);

app.get(
  "/api/recipes",
  wrap(async (req, res) => {
    const { q, category, ingredient } = req.query;
    const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const filter = {};
    if (q) filter.title = { $regex: escape(q), $options: "i" };
    if (category) filter.category = category;
    if (ingredient)
      filter["ingredients.name"] = {
        $regex: escape(ingredient),
        $options: "i",
      };

    const list = await recipesCol
      .find(filter)
      .sort({ created_at: -1 })
      .limit(20)
      .toArray();
    res.json(list);
  }),
);

// ================= DETAIL (Cache-Aside Redis + Leaderboard) =================
app.get(
  "/api/recipes/:id",
  wrap(async (req, res) => {
    const start = Date.now();
    const { id } = req.params;
    const oid = toObjectId(id);
    if (!oid) return res.status(400).json({ error: "ID resep tidak valid" });

    const cacheKey = `recipe:detail:${id}`;
    let source = "REDIS_CACHE_HIT";
    let recipe;

    const cached = await redisClient.get(cacheKey);
    if (cached) {
      recipe = JSON.parse(cached);
    } else {
      source = "MONGODB_CACHE_MISS";
      recipe = await recipesCol.findOne({ _id: oid });
      if (!recipe)
        return res.status(404).json({ error: "Resep tidak ditemukan" });
      await redisClient.set(cacheKey, JSON.stringify(recipe), {
        EX: CACHE_TTL,
      });
    }
    const latency = Date.now() - start;

    const key = todayKey();
    const [views] = await Promise.all([
      redisClient.incr(`recipe:views:${id}`),
      redisClient.zIncrBy(key, 1, id),
      redisClient.expire(key, 172800),
    ]);

    res.json({ source, latency_ms: latency, views, data: recipe });
  }),
);

// ================= INTERACTION (MongoDB + Redis + Neo4j) =================
app.post(
  "/api/recipes/:id/like",
  auth,
  wrap(async (req, res) => {
    const { id } = req.params;
    const oid = toObjectId(id);
    if (!oid) return res.status(400).json({ error: "ID resep tidak valid" });
    if (!(await recipesCol.findOne({ _id: oid }, { projection: { _id: 1 } }))) {
      return res.status(404).json({ error: "Resep tidak ditemukan" });
    }

    const rating = Math.min(5, Math.max(1, Number(req.body.rating) || 5));
    const result = await runCypher(
      `MERGE (u:User {id: $userId}) SET u.display_name = $userName
     MERGE (r:Recipe {id: $recipeId})
     WITH u, r, EXISTS { (u)-[:LIKED]->(r) } AS already
     MERGE (u)-[l:LIKED]->(r)
     ON CREATE SET l.created_at = datetime()
     SET l.rating = $rating
     RETURN already`,
      {
        userId: req.user.id,
        userName: req.user.display_name,
        recipeId: id,
        rating,
      },
    );

    if (result.records[0].get("already")) {
      return res.json({
        message: "Resep sudah pernah disukai, rating diperbarui di Neo4j",
      });
    }

    const key = todayKey();
    await recipesCol.updateOne(
      { _id: oid },
      { $inc: { "stats.likes_count": 1 } },
    );
    await Promise.all([
      redisClient.del(`recipe:detail:${id}`),
      redisClient.zIncrBy(key, 5, id),
      redisClient.expire(key, 172800),
    ]);

    res.json({ message: "Resep disukai & relasi graf tercatat di Neo4j" });
  }),
);

app.get(
  "/api/popular/daily",
  wrap(async (req, res) => {
    const top = await redisClient.zRangeWithScores(todayKey(), 0, 4, {
      REV: true,
    });
    const ids = top.map((t) => toObjectId(t.value)).filter(Boolean);
    const docs = await recipesCol
      .find({ _id: { $in: ids } }, { projection: { title: 1, category: 1 } })
      .toArray();
    const byId = new Map(docs.map((d) => [d._id.toString(), d]));
    res.json(
      top
        .filter((t) => byId.has(t.value))
        .map((t) => ({ ...byId.get(t.value), popularity_score: t.score })),
    );
  }),
);

// ================= RECOMMENDATION (Neo4j) =================
app.get(
  "/api/recipes/:id/similar",
  wrap(async (req, res) => {
    const start = Date.now();
    const result = await runCypher(
      `MATCH (r:Recipe {id: $id})-[:USES|IN_CATEGORY]->(shared)<-[:USES|IN_CATEGORY]-(rec:Recipe)
     WHERE rec.id <> $id
     RETURN rec.id AS id, rec.title AS title, count(shared) AS similarity_score,
            [s IN collect(shared) WHERE s:Ingredient | s.name] AS shared_ingredients
     ORDER BY similarity_score DESC LIMIT 5`,
      { id: req.params.id },
    );
    const items = result.records.map((r) => ({
      id: r.get("id"),
      title: r.get("title"),
      score: r.get("similarity_score").toNumber(),
      shared_ingredients: r.get("shared_ingredients"),
    }));
    res.json({ latency_ms: Date.now() - start, recommendations: items });
  }),
);

app.get(
  "/api/recommendations/personal",
  auth,
  wrap(async (req, res) => {
    const start = Date.now();
    const result = await runCypher(
      `MATCH (u:User {id: $userId})-[:LIKED]->(:Recipe)<-[:LIKED]-(other:User)-[:LIKED]->(rec:Recipe)
     WHERE NOT (u)-[:LIKED]->(rec) AND other.id <> $userId
     RETURN rec.id AS id, rec.title AS title, count(DISTINCT other) AS match_score
     ORDER BY match_score DESC LIMIT 5`,
      { userId: req.user.id },
    );
    const items = result.records.map((r) => ({
      id: r.get("id"),
      title: r.get("title"),
      score: r.get("match_score").toNumber(),
    }));
    res.json({ latency_ms: Date.now() - start, recommendations: items });
  }),
);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Terjadi kesalahan server" });
});

initDatabases()
  .then(() =>
    app.listen(PORT, () =>
      console.log(`Server DapurKita berjalan di http://localhost:${PORT}`),
    ),
  )
  .catch((err) => {
    console.error("Gagal terhubung ke database:", err.message);
    process.exit(1);
  });

const shutdown = async () => {
  await Promise.allSettled([
    pgPool.end(),
    mongoClient.close(),
    redisClient.quit(),
    neo4jDriver.close(),
  ]);
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
