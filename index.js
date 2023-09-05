if (process.env.Node_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const app = express();
const path = require('path');
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const session = require('express-session');
const User = require('./models/loginSchema');
const mongoose = require('mongoose');
const MongoDBStore = require('connect-mongo');

const dbUrl = process.env.DBURL || 'mongodb://0.0.0.0:27017/login';

mongoose.connect(dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'Connection error'));
db.once('open', () => {
    console.log('Database Connected')
})

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))
app.use(express.urlencoded({ extended: true }));
const secret = process.env.SECRET || 'secret!'

const store = new MongoDBStore({
    mongoUrl: dbUrl,
    secret,
    touchAfter: 24 * 60 * 60
})
store.on('error', function (e) {
    console.log('Session Store Error!!!', e)
})

app.use(session({
    secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 10 * 60 * 60 * 24 * 7,
        maxAge: 10 * 60 * 60 * 24 * 7
    }
}))

app.use(flash());
app.use((req, res, next) => {
    res.locals.error = req.flash("error");
    res.locals.success = req.flash('success');
    next();
})
const isLogin = (req, res, next) => {
    console.log(req.session);
    if (!req.session.user) {
        req.flash("error", "Please Sign in first!!!")
        return res.redirect('/');
    }
    next();
}
app.get("/", (req, res) => {
    console.log(req.session, req.sessionID);
    res.render("home")
})
app.get("/login", (req, res) => {
    if (req.session.user) {
        return res.redirect("/secret");
    }
    res.render('login');
})

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    let found = await User.findOne({ email: email });
    if (found) {
        const check = await bcrypt.compare(password, found.password);
        if (check) {
            req.session.user = found._id;
            req.flash('success', 'Welcome!!!')
            return res.redirect('/secret');
        }
        else {
            req.flash('error', 'Invalid email or password!!!');
            return res.redirect("/login");
        }
    }
    else {
        req.flash('error', 'Invalid email or password!!!');
        res.redirect('/login');
    }
})
app.get("/signup", (req, res) => {
    if (req.session.user) {
        return res.redirect("/secret");
    }
    res.render('signup');
})
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    let found = User.findOne({ email });
    if (!email || !password) {
        req.flash('error', 'Please fill the fields!!!')
        res.redirect('/signup');
    }
    else if (found) {
        req.flash('error', "Already Registered!!!");
        res.redirect("/signup");
    } else {
        const hash = await bcrypt.hash(password, 12);
        const user = new User({ email: email, password: hash });
        await user.save();
        req.flash('success', 'Welcome home!!!')
        req.session.user = user._id;
        res.redirect('/secret')
    }
});
app.get('/signout', (req, res) => {
    req.flash('success', 'Successfully log out!!!');
    req.session = null;
    res.redirect('/')

})
app.get("/secret", isLogin, (req, res) => {
    res.render("secured")
})
app.listen(3000, () => {
    console.log("Listening")
});