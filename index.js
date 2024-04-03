
const express = require('express');
const passport = require('passport');
const session = require("express-session");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const jwtStrategy = require("passport-jwt").Strategy;
const jwtExtract = require("passport-jwt").ExtractJwt;

const { body, validationResult } = require('express-validator');
const port = 8008;
const app = express();
app.use(
    session({
        name: "jwtcrud",
        secret: "jwtcrud",
        resave: true,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 100,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());

let tasks = [];
let users = [];

const validateAddTask = [
    body('title').notEmpty().withMessage('Task title is required'),
    body('content').notEmpty().withMessage('Task content is required'),
];

const validateRegister = [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').notEmpty().withMessage('Password is required'),
];

const validateLogin = [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').notEmpty().withMessage('Password is required'),
];

let userOpts = {
    jwtFromRequest: jwtExtract.fromAuthHeaderAsBearerToken(),
    secretOrKey: "JWT",
};

passport.use(
    "userLogin", new jwtStrategy(userOpts, async (record, done) => {
        return done(null, record);
    })
);

const generateToken = (user) => {
    return jwt.sign(user, userOpts.secretOrKey);
};

const authenticateJWT = (req, res, next) => {
    passport.authenticate('userLogin', { session: false }, (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(400).json({ message: 'Unauthorized', status: 0 });
        }
        req.user = user;
        next();
    })(req, res, next);
};

app.post('/register', validateRegister, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Validation error", errors: errors.array(), status: 0 });
    }

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { name, email, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: "User registered successfully", user: user, status: 1 });
});

app.post('/login', validateLogin, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: "Validation error", errors: errors.array(), status: 0 });
    }

    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(400).json({ message: "Invalid email or password", status: 0 });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ message: "Invalid email or password", status: 0 });
    }

    const token = generateToken({ email: user.email });
    res.json({ token });
});

app.post('/Add_Task', authenticateJWT, validateAddTask, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ mes: "Validation error", errors: errors.array(), status: 0 });
    }

    const { title, content } = req.body;
    const author = req.user.email;
    const task = { id: tasks.length + 1, title, content, author };
    tasks.push(task);
    res.status(201).json({ message: "Record inserted successfully", task, status: 1 });
});


app.get('/viewTasks', (req, res) => {
    res.json(tasks);
});

app.get("/singlepost/:id", (req, res) => {
    const taskId = parseInt(req.params.id);
    const singleTask = tasks.find(task => task.id === taskId);
    res.status(200).json({ message: "single Task is here", singleTask: singleTask, status: 1 });
});

app.delete('/deleteTasks/:id', (req, res) => {
    const taskId = parseInt(req.params.id);
    const deletedTask = tasks.find(task => task.id === taskId);
    tasks = tasks.filter(task => task.id !== taskId);
    res.status(200).json({ mes: "record delete sucessfully", deletedTask: deletedTask, status: 1 });
});

app.put('/updateTask/:id', (req, res) => {
    const { id } = req.params;
    const { title, content, author } = req.body;

    const taskIndex = tasks.findIndex(task => task.id === parseInt(id));

    if (taskIndex === -1)
        return res.status(400).json({ error: 'Task not found', status: 0 });

    tasks[taskIndex] = { id: parseInt(id), title, content, author };

    res.status(200).json({ message: "Record updated successfully", updatedTask: tasks[taskIndex], status: 1 });
});


app.listen(port, (err) => {
    err ? console.log("Listen error:", err) : console.log(`Server listening on ${port}`);
});

