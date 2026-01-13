use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use log::info;

pub type DbPool = Pool<Sqlite>;

pub async fn init_db() -> Result<DbPool, sqlx::Error> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:./dojo.db?mode=rwc".to_string());

    info!("Connecting to database: {}", database_url);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Create tables
    create_tables(&pool).await?;

    // Seed data
    seed_data(&pool).await?;

    Ok(pool)
}

async fn create_tables(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ssn TEXT,
            credit_card TEXT,
            secret_note TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            api_key TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            category TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            total REAL DEFAULT 0,
            shipping_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id TEXT UNIQUE NOT NULL,
            flag_value TEXT NOT NULL,
            hint TEXT,
            points INTEGER DEFAULT 100
        )
        "#,
    )
    .execute(pool)
    .await?;

    info!("Database tables created");
    Ok(())
}

async fn seed_data(pool: &DbPool) -> Result<(), sqlx::Error> {
    // Check if data already exists
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if count.0 > 0 {
        info!("Database already seeded");
        return Ok(());
    }

    info!("Seeding database...");

    // Users (password hashes for: admin123, password123, password456)
    let users = vec![
        ("admin", "admin@dojo.local", "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G1vO2F1F1F1F1e", "123-45-6789", "4111-1111-1111-1111", "Admin secret note", "admin", "ak_admin_secret_key_12345"),
        ("john", "john@example.com", "$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", "987-65-4321", "4222-2222-2222-2222", "John's private data", "user", "ak_john_key_67890"),
        ("jane", "jane@example.com", "$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", "555-55-5555", "4333-3333-3333-3333", "Jane's secret", "user", "ak_jane_key_11111"),
    ];

    for (username, email, password_hash, ssn, cc, note, role, api_key) in users {
        sqlx::query(
            "INSERT OR IGNORE INTO users (username, email, password_hash, ssn, credit_card, secret_note, role, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(ssn)
        .bind(cc)
        .bind(note)
        .bind(role)
        .bind(api_key)
        .execute(pool)
        .await?;
    }

    // Products
    let products = vec![
        ("Laptop Pro", "High-performance laptop", 1299.99, 50, "electronics"),
        ("Wireless Mouse", "Ergonomic wireless mouse", 29.99, 200, "electronics"),
        ("USB-C Hub", "7-in-1 USB-C hub", 49.99, 150, "electronics"),
        ("Mechanical Keyboard", "RGB mechanical keyboard", 89.99, 100, "electronics"),
        ("Monitor 27\"", "4K IPS monitor", 399.99, 30, "electronics"),
        ("Coffee Mug", "Developer coffee mug", 12.99, 500, "accessories"),
        ("T-Shirt", "API Security Dojo t-shirt", 24.99, 200, "clothing"),
    ];

    for (name, desc, price, stock, category) in products {
        sqlx::query(
            "INSERT OR IGNORE INTO products (name, description, price, stock, category) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(name)
        .bind(desc)
        .bind(price)
        .bind(stock)
        .bind(category)
        .execute(pool)
        .await?;
    }

    // Sample orders
    sqlx::query(
        "INSERT OR IGNORE INTO orders (id, user_id, status, total, shipping_address) VALUES (1, 2, 'completed', 1329.98, '123 Main St')"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT OR IGNORE INTO orders (id, user_id, status, total, shipping_address) VALUES (2, 3, 'pending', 89.99, '456 Oak Ave')"
    )
    .execute(pool)
    .await?;

    // Flags for CTF
    let flags = vec![
        ("V01", "FLAG{BOLA_rust_1d0r_4cc3ss}", "Access another user's data"),
        ("V02", "FLAG{AUTH_rust_3num3r4t10n}", "Enumerate valid usernames"),
        ("V03", "FLAG{DATA_rust_3xp0s3d}", "Find sensitive data in response"),
        ("V05", "FLAG{MASS_rust_4ss1gn}", "Escalate privileges via mass assignment"),
        ("V06", "FLAG{SQLI_rust_1nj3ct10n}", "Extract data via SQL injection"),
        ("V07", "FLAG{CMDI_rust_sh3ll}", "Execute commands via injection"),
        ("G01", "FLAG{GQL_rust_1ntr0sp3ct}", "Discover schema via introspection"),
        ("G05", "FLAG{GQL_rust_4uth_byp4ss}", "Bypass GraphQL authorization"),
    ];

    for (vuln_id, flag, hint) in flags {
        sqlx::query(
            "INSERT OR IGNORE INTO flags (vulnerability_id, flag_value, hint) VALUES (?, ?, ?)"
        )
        .bind(vuln_id)
        .bind(flag)
        .bind(hint)
        .execute(pool)
        .await?;
    }

    info!("Database seeded successfully");
    Ok(())
}
