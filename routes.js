const passport = require('passport');
const bcrypt = require('bcrypt');

module.exports = function (app, myDataBase) {
  app.route('/').get((req, res) => {
    res.render('index', {
      title: 'Connected to Database',
      message: 'Please log in',
      showLogin: true,
      showRegistration: true,
      showSocialAuth: true
    });
  });

  app.route('/login').post(
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res) => {
      res.redirect('/profile');
    }
  );

  app.route('/profile').get(ensureAuthenticated, (req, res) => {
    res.render('profile', { username: req.user.username });
  });

  app.route('/logout').get((req, res) => {
    req.logout();
    res.redirect('/');
  });

  app.route('/register').post(
    (req, res, next) => {
      const hash = bcrypt.hashSync(req.body.password, 12);
      myDataBase.findOne({ username: req.body.username }, (err, user) => {
        if (err) return next(err);
        if (user) return res.redirect('/');
        myDataBase.insertOne(
          { username: req.body.username, password: hash },
          (err, doc) => {
            if (err) return res.redirect('/');
            next(null, doc.ops[0]);
          }
        );
      });
    },
    passport.authenticate('local', { failureRedirect: '/' }),
    (req, res) => {
      res.redirect('/profile');
    }
  );

  app.route('/auth/github').get(passport.authenticate('github'));

  app.route('/auth/github/callback').get(
    passport.authenticate('github', { failureRedirect: '/' }),
    (req, res) => {
      res.redirect('/chat');
    }
  );

  app.route('/chat').get(ensureAuthenticated, (req, res) => {
    res.render('chat', { user: req.user });
  });

  app.use((req, res) => {
    res.status(404).type('text').send('Not Found');
  });
};

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
}
