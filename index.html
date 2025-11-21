const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { Dropbox } = require('dropbox');
const NodeCache = require('node-cache');

// ==================== CONFIGURATION ====================
const IS_RENDER = process.env.RENDER === 'true';
const PORT = process.env.PORT || 3000;
const RENDER_DOMAIN = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'moadop-super-secret-key-2024';

// Domain setup
function getShortDomainName() {
    if (!RENDER_DOMAIN) return 'local';
    let domain = RENDER_DOMAIN.replace(/^https?:\/\//, '');
    domain = domain.replace(/\.(render|onrender)\.com$/, '');
    domain = domain.split('.')[0];
    return domain || 'local';
}

const SHORT_DOMAIN = getShortDomainName();

// ==================== DATABASE PATHS ====================
const DB_DIR = path.join(__dirname, 'database');
const PATHS = {
    main: path.join(DB_DIR, 'main_database.json'),
    admin: path.join(DB_DIR, 'admin_database.json'),
    users: path.join(DB_DIR, 'users'),
    workers: path.join(DB_DIR, 'workers'),
    chats: path.join(DB_DIR, 'chats'),
    backups: path.join(DB_DIR, 'backups')
};

// ==================== INITIALIZE DATABASE SYSTEM ====================
function initDatabaseSystem() {
    try {
        // Create directories
        Object.values(PATHS).forEach(dirPath => {
            if (dirPath.includes('.json')) {
                const dir = path.dirname(dirPath);
                if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            } else {
                if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
            }
        });

        // Initialize main database
        if (!fs.existsSync(PATHS.main)) {
            const mainDb = {
                system: {
                    name: "Moadop Worker Management System",
                    version: "2.0",
                    domain: SHORT_DOMAIN,
                    startupCount: 0,
                    lastStartup: new Date().toISOString()
                },
                statistics: {
                    totalUsers: 0,
                    totalWorkers: 0,
                    totalOrders: 0,
                    websiteVisits: 0,
                    monthlyStats: {},
                    currentMonth: new Date().toISOString().slice(0, 7) // YYYY-MM
                },
                settings: {
                    welcomeMessage: "🏢 Welcome to Moadop Professional System",
                    autoArchiveDays: 7,
                    backupEnabled: true
                },
                notifications: [],
                activityLog: []
            };
            writeMainDatabase(mainDb);
        }

        // Initialize admin database
        if (!fs.existsSync(PATHS.admin)) {
            const adminDb = {
                adminId: "superadmin",
                orders: {},
                workers: {},
                monthlyReports: {},
                systemLogs: [],
                createdAt: new Date().toISOString()
            };
            writeAdminDatabase(adminDb);
        }

        // Initialize default admin user
        initDefaultAdmin();

        console.log('✅ Database system initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ Database system initialization failed:', error);
        return false;
    }
}

// ==================== DATABASE OPERATIONS ====================

function writeMainDatabase(data) {
    try {
        data.system.lastUpdate = new Date().toISOString();
        fs.writeFileSync(PATHS.main, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Main database write error:', error);
        return false;
    }
}

function readMainDatabase() {
    try {
        if (!fs.existsSync(PATHS.main)) {
            initDatabaseSystem();
        }
        const data = fs.readFileSync(PATHS.main, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('❌ Main database read error:', error);
        return { system: {}, statistics: {}, settings: {}, notifications: [], activityLog: [] };
    }
}

function writeAdminDatabase(data) {
    try {
        fs.writeFileSync(PATHS.admin, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Admin database write error:', error);
        return false;
    }
}

function readAdminDatabase() {
    try {
        if (!fs.existsSync(PATHS.admin)) {
            initDatabaseSystem();
        }
        const data = fs.readFileSync(PATHS.admin, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('❌ Admin database read error:', error);
        return { adminId: "superadmin", orders: {}, workers: {}, monthlyReports: {}, systemLogs: [] };
    }
}

// ==================== USER MANAGEMENT ====================

function initDefaultAdmin() {
    const adminUser = {
        id: "superadmin",
        email: "admin@moadop.com",
        password: bcrypt.hashSync("admin123", 10),
        firstName: "Super",
        lastName: "Admin",
        role: "superadmin",
        phone: "+1234567890",
        status: "active",
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString()
    };
    
    const userFile = path.join(PATHS.users, 'superadmin.json');
    if (!fs.existsSync(userFile)) {
        fs.writeFileSync(userFile, JSON.stringify(adminUser, null, 2));
        console.log('✅ Default admin user created');
    }
}

function createUser(userData) {
    try {
        const userId = userData.email.split('@')[0] + '_' + Date.now();
        const user = {
            id: userId,
            email: userData.email,
            password: bcrypt.hashSync(userData.password, 10),
            firstName: userData.firstName,
            lastName: userData.lastName,
            role: userData.role,
            phone: userData.phone,
            status: "pending",
            createdAt: new Date().toISOString(),
            lastLogin: null
        };

        const userFile = path.join(PATHS.users, `${userId}.json`);
        fs.writeFileSync(userFile, JSON.stringify(user, null, 2));

        // Update main database statistics
        const mainDb = readMainDatabase();
        mainDb.statistics.totalUsers = (mainDb.statistics.totalUsers || 0) + 1;
        writeMainDatabase(mainDb);

        return { success: true, user: user };
    } catch (error) {
        console.error('❌ User creation error:', error);
        return { success: false, error: error.message };
    }
}

function authenticateUser(email, password) {
    try {
        const userFiles = fs.readdirSync(PATHS.users);
        
        for (const file of userFiles) {
            if (!file.endsWith('.json')) continue;
            
            const userData = JSON.parse(fs.readFileSync(path.join(PATHS.users, file), 'utf8'));
            
            if (userData.email === email && bcrypt.compareSync(password, userData.password)) {
                // Update last login
                userData.lastLogin = new Date().toISOString();
                fs.writeFileSync(path.join(PATHS.users, file), JSON.stringify(userData, null, 2));
                
                return { success: true, user: userData };
            }
        }
        
        return { success: false, error: "Invalid email or password" };
    } catch (error) {
        console.error('❌ Authentication error:', error);
        return { success: false, error: "Authentication failed" };
    }
}

function getUserById(userId) {
    try {
        const userFile = path.join(PATHS.users, `${userId}.json`);
        if (fs.existsSync(userFile)) {
            return JSON.parse(fs.readFileSync(userFile, 'utf8'));
        }
        return null;
    } catch (error) {
        console.error('❌ Get user error:', error);
        return null;
    }
}

function approveUser(userId, approvedBy) {
    try {
        const userFile = path.join(PATHS.users, `${userId}.json`);
        if (fs.existsSync(userFile)) {
            const user = JSON.parse(fs.readFileSync(userFile, 'utf8'));
            user.status = "active";
            user.approvedBy = approvedBy;
            user.approvedAt = new Date().toISOString();
            
            fs.writeFileSync(userFile, JSON.stringify(user, null, 2));
            
            // Create worker database if applicable
            if (user.role !== 'superadmin') {
                createWorkerDatabase(user);
            }
            
            return { success: true, user: user };
        }
        return { success: false, error: "User not found" };
    } catch (error) {
        console.error('❌ User approval error:', error);
        return { success: false, error: error.message };
    }
}

// ==================== WORKER DATABASE MANAGEMENT ====================

function createWorkerDatabase(user) {
    try {
        const workerDb = {
            workerId: user.id,
            personalInfo: {
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone,
                role: user.role
            },
            orders: {
                assigned: [],
                processing: [],
                delivered: [],
                archived: []
            },
            statistics: {
                totalOrders: 0,
                deliveredThisMonth: 0,
                processingThisMonth: 0,
                monthlyHistory: {}
            },
            messages: [],
            notifications: [],
            performance: {
                rating: 0,
                completedOrders: 0,
                responseTime: 0
            },
            createdAt: new Date().toISOString(),
            lastActive: new Date().toISOString()
        };

        const workerFile = path.join(PATHS.workers, `${user.id}.json`);
        fs.writeFileSync(workerFile, JSON.stringify(workerDb, null, 2));

        // Update main database
        const mainDb = readMainDatabase();
        mainDb.statistics.totalWorkers = (mainDb.statistics.totalWorkers || 0) + 1;
        writeMainDatabase(mainDb);

        console.log(`✅ Worker database created for: ${user.firstName} ${user.lastName}`);
        return true;
    } catch (error) {
        console.error('❌ Worker database creation error:', error);
        return false;
    }
}

function getWorkerDatabase(workerId) {
    try {
        const workerFile = path.join(PATHS.workers, `${workerId}.json`);
        if (fs.existsSync(workerFile)) {
            return JSON.parse(fs.readFileSync(workerFile, 'utf8'));
        }
        return null;
    } catch (error) {
        console.error('❌ Get worker database error:', error);
        return null;
    }
}

function updateWorkerDatabase(workerId, updates) {
    try {
        const workerFile = path.join(PATHS.workers, `${workerId}.json`);
        if (fs.existsSync(workerFile)) {
            const workerDb = JSON.parse(fs.readFileSync(workerFile, 'utf8'));
            const updatedDb = { ...workerDb, ...updates, lastUpdate: new Date().toISOString() };
            fs.writeFileSync(workerFile, JSON.stringify(updatedDb, null, 2));
            return { success: true, data: updatedDb };
        }
        return { success: false, error: "Worker database not found" };
    } catch (error) {
        console.error('❌ Update worker database error:', error);
        return { success: false, error: error.message };
    }
}

// ==================== ORDER MANAGEMENT ====================

function createOrder(orderData, createdBy = "system") {
    try {
        const orderId = `order_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const order = {
            id: orderId,
            customerName: orderData.customerName,
            customerPhone: orderData.customerPhone,
            alternatePhone: orderData.alternatePhone,
            product: orderData.product,
            quantity: orderData.quantity || 1,
            status: "pending",
            priority: orderData.priority || "normal",
            createdAt: new Date().toISOString(),
            createdBy: createdBy,
            assignedTo: null,
            assignedAt: null,
            processedBy: null,
            processedAt: null,
            deliveredBy: null,
            deliveredAt: null,
            messages: [],
            notes: []
        };

        // Add to admin database
        const adminDb = readAdminDatabase();
        adminDb.orders[orderId] = order;
        writeAdminDatabase(adminDb);

        // Update main database statistics
        const mainDb = readMainDatabase();
        mainDb.statistics.totalOrders = (mainDb.statistics.totalOrders || 0) + 1;
        
        const currentMonth = new Date().toISOString().slice(0, 7);
        if (!mainDb.statistics.monthlyStats[currentMonth]) {
            mainDb.statistics.monthlyStats[currentMonth] = {
                orders: 0,
                delivered: 0,
                processing: 0,
                pending: 0
            };
        }
        mainDb.statistics.monthlyStats[currentMonth].orders++;
        mainDb.statistics.monthlyStats[currentMonth].pending++;
        
        writeMainDatabase(mainDb);

        // Add to activity log
        addActivityLog({
            type: "order_created",
            user: createdBy,
            orderId: orderId,
            details: `New order created: ${orderData.product}`,
            timestamp: new Date().toISOString()
        });

        return { success: true, order: order };
    } catch (error) {
        console.error('❌ Order creation error:', error);
        return { success: false, error: error.message };
    }
}

function assignOrder(orderId, workerId, assignedBy) {
    try {
        const adminDb = readAdminDatabase();
        if (adminDb.orders[orderId]) {
            adminDb.orders[orderId].assignedTo = workerId;
            adminDb.orders[orderId].assignedAt = new Date().toISOString();
            adminDb.orders[orderId].status = "assigned";
            writeAdminDatabase(adminDb);

            // Add to worker's database
            const workerDb = getWorkerDatabase(workerId);
            if (workerDb) {
                workerDb.orders.assigned.push(orderId);
                updateWorkerDatabase(workerId, workerDb);
            }

            // Send notification to worker
            sendNotification(workerId, {
                type: "order_assigned",
                title: "New Order Assigned",
                message: `You have been assigned order #${orderId}`,
                orderId: orderId,
                timestamp: new Date().toISOString(),
                read: false
            });

            addActivityLog({
                type: "order_assigned",
                user: assignedBy,
                orderId: orderId,
                workerId: workerId,
                details: `Order assigned to worker ${workerId}`,
                timestamp: new Date().toISOString()
            });

            return { success: true, order: adminDb.orders[orderId] };
        }
        return { success: false, error: "Order not found" };
    } catch (error) {
        console.error('❌ Order assignment error:', error);
        return { success: false, error: error.message };
    }
}

// ==================== MESSAGING SYSTEM ====================

function sendMessage(senderId, receiverId, message, orderId = null) {
    try {
        const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const conversationId = [senderId, receiverId].sort().join('_');
        const chatFile = path.join(PATHS.chats, `${conversationId}.json`);

        let conversation = [];
        if (fs.existsSync(chatFile)) {
            conversation = JSON.parse(fs.readFileSync(chatFile, 'utf8'));
        }

        const messageData = {
            id: messageId,
            senderId: senderId,
            receiverId: receiverId,
            message: message,
            orderId: orderId,
            timestamp: new Date().toISOString(),
            read: false
        };

        conversation.push(messageData);
        fs.writeFileSync(chatFile, JSON.stringify(conversation, null, 2));

        // Send notification to receiver
        sendNotification(receiverId, {
            type: "new_message",
            title: "New Message",
            message: `You have a new message from ${getUserById(senderId)?.firstName}`,
            senderId: senderId,
            timestamp: new Date().toISOString(),
            read: false
        });

        return { success: true, message: messageData };
    } catch (error) {
        console.error('❌ Send message error:', error);
        return { success: false, error: error.message };
    }
}

function getConversation(userId1, userId2) {
    try {
        const conversationId = [userId1, userId2].sort().join('_');
        const chatFile = path.join(PATHS.chats, `${conversationId}.json`);
        
        if (fs.existsSync(chatFile)) {
            return JSON.parse(fs.readFileSync(chatFile, 'utf8'));
        }
        return [];
    } catch (error) {
        console.error('❌ Get conversation error:', error);
        return [];
    }
}

// ==================== NOTIFICATION SYSTEM ====================

function sendNotification(userId, notification) {
    try {
        const user = getUserById(userId);
        if (!user) return false;

        // Add to user's notifications in their database
        if (user.role !== 'superadmin') {
            const workerDb = getWorkerDatabase(userId);
            if (workerDb) {
                workerDb.notifications.unshift(notification);
                if (workerDb.notifications.length > 100) {
                    workerDb.notifications = workerDb.notifications.slice(0, 100);
                }
                updateWorkerDatabase(userId, workerDb);
            }
        }

        // Also add to admin notifications if needed
        if (notification.type === 'order_created' || notification.type === 'system_alert') {
            const adminDb = readAdminDatabase();
            adminDb.systemLogs.unshift({
                type: "notification",
                userId: userId,
                notification: notification,
                timestamp: new Date().toISOString()
            });
            if (adminDb.systemLogs.length > 200) {
                adminDb.systemLogs = adminDb.systemLogs.slice(0, 200);
            }
            writeAdminDatabase(adminDb);
        }

        return true;
    } catch (error) {
        console.error('❌ Send notification error:', error);
        return false;
    }
}

function getNotifications(userId) {
    try {
        if (userId === 'superadmin') {
            const adminDb = readAdminDatabase();
            return adminDb.systemLogs.filter(log => log.type === 'notification').slice(0, 50);
        } else {
            const workerDb = getWorkerDatabase(userId);
            return workerDb?.notifications || [];
        }
    } catch (error) {
        console.error('❌ Get notifications error:', error);
        return [];
    }
}

// ==================== ACTIVITY LOGGING ====================

function addActivityLog(activity) {
    try {
        const mainDb = readMainDatabase();
        mainDb.activityLog.unshift(activity);
        if (mainDb.activityLog.length > 1000) {
            mainDb.activityLog = mainDb.activityLog.slice(0, 1000);
        }
        writeMainDatabase(mainDb);
        return true;
    } catch (error) {
        console.error('❌ Activity log error:', error);
        return false;
    }
}

// ==================== MONTHLY ARCHIVING SYSTEM ====================

function checkMonthlyArchiving() {
    try {
        const mainDb = readMainDatabase();
        const currentMonth = new Date().toISOString().slice(0, 7);
        
        if (mainDb.statistics.currentMonth !== currentMonth) {
            console.log(`🔄 New month detected: ${currentMonth}, checking for archiving...`);
            
            const previousMonth = mainDb.statistics.currentMonth;
            const now = new Date();
            const daysInNewMonth = now.getDate();
            
            if (daysInNewMonth >= 7) {
                // Archive previous month's data
                archiveMonthlyData(previousMonth);
                mainDb.statistics.currentMonth = currentMonth;
                writeMainDatabase(mainDb);
                console.log(`✅ Archived data for month: ${previousMonth}`);
            }
        }
    } catch (error) {
        console.error('❌ Monthly archiving check error:', error);
    }
}

function archiveMonthlyData(month) {
    try {
        const archiveData = {
            month: month,
            archivedAt: new Date().toISOString(),
            statistics: {},
            orders: [],
            workersPerformance: {}
        };

        // Get main database statistics for the month
        const mainDb = readMainDatabase();
        archiveData.statistics = mainDb.statistics.monthlyStats[month] || {};

        // Archive orders from admin database
        const adminDb = readAdminDatabase();
        const monthOrders = Object.values(adminDb.orders).filter(order => 
            order.createdAt.startsWith(month)
        );
        archiveData.orders = monthOrders;

        // Archive worker performance
        const workerFiles = fs.readdirSync(PATHS.workers);
        workerFiles.forEach(file => {
            if (file.endsWith('.json')) {
                const workerId = file.replace('.json', '');
                const workerDb = getWorkerDatabase(workerId);
                if (workerDb && workerDb.statistics.monthlyHistory[month]) {
                    archiveData.workersPerformance[workerId] = {
                        personalInfo: workerDb.personalInfo,
                        monthlyStats: workerDb.statistics.monthlyHistory[month]
                    };
                }
            }
        });

        // Save archive
        const archiveFile = path.join(PATHS.backups, `archive_${month}.json`);
        fs.writeFileSync(archiveFile, JSON.stringify(archiveData, null, 2));

        // Clean up current data (keep only statistics)
        Object.values(adminDb.orders).forEach(order => {
            if (order.createdAt.startsWith(month)) {
                delete adminDb.orders[order.id];
            }
        });
        writeAdminDatabase(adminDb);

        console.log(`✅ Successfully archived data for ${month}`);
        return true;
    } catch (error) {
        console.error('❌ Monthly archiving error:', error);
        return false;
    }
}

// ==================== EXPRESS SERVER SETUP ====================

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('views'));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ success: false, error: "Authentication required" });
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.session.user && req.session.user.role === role) {
            next();
        } else {
            res.status(403).json({ success: false, error: "Insufficient permissions" });
        }
    };
}

// ==================== WEBSITE ROUTES ====================

// Serve main pages
app.get('/', (req, res) => {
    const mainDb = readMainDatabase();
    mainDb.statistics.websiteVisits = (mainDb.statistics.websiteVisits || 0) + 1;
    writeMainDatabase(mainDb);
    
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
    const user = req.session.user;
    
    if (user.role === 'superadmin') {
        res.sendFile(path.join(__dirname, 'views', 'admin-dashboard.html'));
    } else if (user.role === 'customer_service') {
        res.sendFile(path.join(__dirname, 'views', 'customer-service-dashboard.html'));
    } else if (user.role === 'rider') {
        res.sendFile(path.join(__dirname, 'views', 'rider-dashboard.html'));
    } else {
        res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
    }
});

// ==================== API ROUTES ====================

// Authentication APIs
app.post('/api/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, phone, role } = req.body;
        
        // Validation
        if (!firstName || !lastName || !email || !password || !role) {
            return res.json({ success: false, error: "All fields are required" });
        }
        
        if (password.length < 6) {
            return res.json({ success: false, error: "Password must be at least 6 characters" });
        }
        
        const result = createUser({ firstName, lastName, email, password, phone, role });
        res.json(result);
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = authenticateUser(email, password);
        if (result.success) {
            req.session.user = result.user;
            res.json({ success: true, user: result.user });
        } else {
            res.json({ success: false, error: result.error });
        }
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: "Logged out successfully" });
});

// Order APIs
app.post('/api/orders', requireAuth, (req, res) => {
    try {
        const orderData = req.body;
        const result = createOrder(orderData, req.session.user.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/orders', requireAuth, (req, res) => {
    try {
        const adminDb = readAdminDatabase();
        const orders = Object.values(adminDb.orders);
        res.json({ success: true, orders: orders });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Message APIs
app.post('/api/messages', requireAuth, (req, res) => {
    try {
        const { receiverId, message, orderId } = req.body;
        const result = sendMessage(req.session.user.id, receiverId, message, orderId);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/messages/:userId', requireAuth, (req, res) => {
    try {
        const conversation = getConversation(req.session.user.id, req.params.userId);
        res.json({ success: true, messages: conversation });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Notification APIs
app.get('/api/notifications', requireAuth, (req, res) => {
    try {
        const notifications = getNotifications(req.session.user.id);
        res.json({ success: true, notifications: notifications });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Statistics APIs
app.get('/api/statistics', requireAuth, (req, res) => {
    try {
        const mainDb = readMainDatabase();
        const adminDb = readAdminDatabase();
        
        const stats = {
            system: mainDb.system,
            statistics: mainDb.statistics,
            totalOrders: Object.keys(adminDb.orders).length,
            pendingOrders: Object.values(adminDb.orders).filter(o => o.status === 'pending').length,
            activeWorkers: mainDb.statistics.totalWorkers || 0
        };
        
        res.json({ success: true, statistics: stats });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Worker Management APIs
app.get('/api/workers', requireAuth, (req, res) => {
    try {
        const workerFiles = fs.readdirSync(PATHS.workers);
        const workers = [];
        
        workerFiles.forEach(file => {
            if (file.endsWith('.json')) {
                const workerDb = getWorkerDatabase(file.replace('.json', ''));
                if (workerDb) {
                    workers.push({
                        id: workerDb.workerId,
                        personalInfo: workerDb.personalInfo,
                        statistics: workerDb.statistics,
                        performance: workerDb.performance
                    });
                }
            }
        });
        
        res.json({ success: true, workers: workers });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// User Management APIs (Admin only)
app.get('/api/users/pending', requireAuth, requireRole('superadmin'), (req, res) => {
    try {
        const userFiles = fs.readdirSync(PATHS.users);
        const pendingUsers = [];
        
        userFiles.forEach(file => {
            if (file.endsWith('.json')) {
                const user = JSON.parse(fs.readFileSync(path.join(PATHS.users, file), 'utf8'));
                if (user.status === 'pending') {
                    pendingUsers.push(user);
                }
            }
        });
        
        res.json({ success: true, users: pendingUsers });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/users/approve/:userId', requireAuth, requireRole('superadmin'), (req, res) => {
    try {
        const result = approveUser(req.params.userId, req.session.user.id);
        res.json(result);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== SYSTEM MAINTENANCE ====================

function startSystemMaintenance() {
    // Check for monthly archiving every hour
    setInterval(checkMonthlyArchiving, 60 * 60 * 1000);
    
    // Clean up old notifications weekly
    setInterval(cleanupOldData, 7 * 24 * 60 * 60 * 1000);
    
    console.log('✅ System maintenance started');
}

function cleanupOldData() {
    try {
        const mainDb = readMainDatabase();
        // Keep only last 3 months of activity logs
        const threeMonthsAgo = new Date();
        threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
        
        mainDb.activityLog = mainDb.activityLog.filter(activity => 
            new Date(activity.timestamp) > threeMonthsAgo
        );
        
        writeMainDatabase(mainDb);
        console.log('✅ Old data cleanup completed');
    } catch (error) {
        console.error('❌ Data cleanup error:', error);
    }
}

// ==================== START SERVER ====================

function startServer() {
    try {
        // Initialize database system
        initDatabaseSystem();
        
        // Start system maintenance
        startSystemMaintenance();
        
        // Start server
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Moadop Website System Started`);
            console.log(`🌐 Domain: ${SHORT_DOMAIN}`);
            console.log(`🔗 URL: ${RENDER_DOMAIN}`);
            console.log(`📊 Port: ${PORT}`);
            console.log(`💾 Database: ${DB_DIR}`);
            console.log(`👑 Default Admin: admin@moadop.com / admin123`);
            console.log(`✅ System ready for operation`);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

// Export for testing
module.exports = {
    app,
    readMainDatabase,
    createUser,
    authenticateUser,
    createOrder,
    sendMessage
};
