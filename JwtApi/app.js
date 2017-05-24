//Use nodemon to have your server restart on file changes.
//Install nodemon using npm install -g nodemon.
//Then start your server with nodemon start.js.
let http = require('http');
let express = require('express');
let app = express();
let bodyParser = require('body-parser');
let morgan = require('morgan');
let mongoose = require('mongoose');
let MongoClient = require('mongodb');
let assert = require('assert');
let jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
let config = require('./config'); // get our config file
let User = require('./model/user'); // get our mongoose model
let port = process.env.PORT || 3000; // used to create, sign, and verify tokens
let bcrypt = require('bcryptjs');
var fs = require('fs');
let apiRoutes = express.Router();
let allowCrossDomain = function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
    // intercept OPTIONS method
    if ('OPTIONS' == req.method)  res.send(200);
    else next();
};
mongoose.connect(config.database_cluster_atlas);
// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(allowCrossDomain); // This API will be fully accessible in yhe internet (CORS)
// use morgan to log requests to the console
app.use(morgan('dev'));
app.get('/hello', function(req, res) {
  res.send('Hello! The API is at working good on port ' + port );
});
// Here we create an user
app.get('/setup', function(req, res) {
  MongoClient.connect(config.database_cluster_atlas, function(err, db) {
    db.createCollection('userprofiles', function(err, collection) {
        assert.equal(null, err);
        bcrypt.hash('admin', 10, function(err, passwordhash) {
        collection.insert({username:'diego',password:passwordhash,isadmin:true}, function(err, result) {
          assert.equal(null, err);
          db.collection('userprofiles').find({}).toArray(function (err, doc) {res.json(doc); db.close();});
      });
     });
    });
  });
 });
apiRoutes.post('/authenticate', function(req, res) {

  if(!req.body.username || !req.body.password)
  {
    res.json({status:'no credentials provided'});
    return;
  }

  User.findOne({
     name: req.body.username
   }, function(err, user) {

     if(!user)
     {
       res.json({status:'user not found'});
       return;
     }

     if(!bcrypt.compareSync(req.body.password, user.password))
     {
       res.json({status:'password is not valid'});
       return;
     }

     let token = jwt.sign(user, config.secret, {
               expiresIn: "2 days"
             });
             res.json({
                       success: true,
                       message: 'JWT token created and signed!',
                       token: token
                     });
   })
});
apiRoutes.get('/flowers', function(req, res) {
  MongoClient.connect(config.database_cluster_atlas, function(err, db) {
    assert.equal(null, err);
    db.collection('BachFlowers').find({}).toArray(function (err, users) { res.json(users); db.close();});
  });
});
//We won't want to protect the /api/authenticate route so what we'll do
apiRoutes.use(function(req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers['x-access-token'];
  // decode token
  if (token) {
    // verifies secret and checks exp
    jwt.verify(token, config.secret, function(err, decoded) {
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });
      } else {
        // if everything is good, save to request for use in other routes
        req.decoded = decoded;
        next();
      }
    });

  } else {

    // if there is no token
    // return an error
    return res.status(403).send({
        success: false,
        message: 'No token provided.'
    });
  }
});
// is to place our middleware beneath that route. Order is important here.
// the following routes are protected
apiRoutes.get('/', function(req, res) {
  res.json({ message: 'This is a JWT api! It provides token authentication.' });
});
// Warning use mongoclient instead of mongoose here
apiRoutes.post('/users', function(req, res) {
  MongoClient.connect(config.database_cluster_atlas, function(err, db) {
    assert.equal(null, err);
    db.collection('users').find({}).toArray(function (err, users) { res.json(users); db.close();});
  });
});
apiRoutes.post('/createuser',function(req,res){
  if(!req.body.username || !req.body.password)
  {
    res.json({status:'no credentials provided'});
    return;
  }
  User.findOne({
     name: req.body.username
   }, function(err, user) {

     if(user)
     {
       res.json({status:'username already present please choose a different one'});
       return;
     }
     bcrypt.hash(req.body.password, 10, function(err, hash) {
       var newuser = new User({
         name: req.body.username,
         password: hash,
         admin: true
       });
       newuser.save(function(err) {
         if (err) throw err;
         console.log('User saved successfully');
         res.json({ success: `user ${req.body.username} created successfuly` });
       });
     });
   })
})
app.use('/api', apiRoutes);
// to serve static files at the end so that the API routes are free to go
app.use(express.static('public'));
let server = http.createServer(app).listen(process.env.NODE_PORT || 3000,process.env.NODE_IP || 'localhost', function () {
  console.log('Server express running at. ' + server.address().address +':'+ server.address().port + ' ' );
  console.log(`Application worker ${process.pid} started...`);
});
