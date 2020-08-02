require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
//for levle 5 security (sessions and cookies)
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); 
//for level 4 security (salting+hashing)
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
//for level 3 security (hashing)
//const md5 = require("md5");
//for level 2 security (encryption)
//const encrypt = require("mongoose-encryption")
//for level 6 security (oAuth using google)
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set("view engine","ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
	secret:"Our little secret",
	resave:false,
	saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});

const secretSchema = new mongoose.Schema({content:String,likes:Number,comments:[String],userId:String});
const userSchema = new mongoose.Schema({email:String,password:String,googleId:String,secrets:[secretSchema]});

//performing encryption
//for level 2 security (encryption)
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});
mongoose.set('useCreateIndex', true);
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User',userSchema);
const Secret = new mongoose.model("Secret",secretSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrl: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
	res.render("home");
});

app.get("/auth/google",
	passport.authenticate('google', { scope: ['profile'] }));
app.get("/login",function(req,res){
	res.render("login");
});

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/register",function(req,res){
	res.render("register");
});

app.get("/secrets",function(req,res){
	if(req.isAuthenticated()){
		User.find({secrets:{$ne:null}},function(err,users){
			if(err){
				console.log(err);
			}
			else{
				res.render("secrets",{userWithSecrets:users});
			}
		});
	}
	else{
		res.redirect("/")
	}
});

app.get("/logout",function(req,res){
	req.logout();
	res.redirect("/");
});

app.get("/submit",function(req,res){
	if(req.isAuthenticated()){
		res.render("submit");
	}
	else{
		res.redirect("/login");
	}
});
app.post("/register",function(req,res){

	// bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
 //    const newUser = new User({
	// 	email:req.body.username,
	// 	password:hash
	// });
	// newUser.save(function(err){
	// 	if(err){
	// 		console.log(err);
	// 	}
	// 	else{
	// 		res.render("secrets");
	// 	}
	// });
//});
User.register({username:req.body.username},req.body.password,function(err,user){
		if(err){
			console.log(err);
			res.redirect("/register");
		}
		else{
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			});
		}
	});
	
});
let flag;
app.post("/like",function(req,res){
	User.findById(req.body.userId,function(err,posts){
		if(err){
			console.log(err);
		}
		else{
			if(posts){

				posts.secrets.forEach(function(secret){
					if(secret.id == req.body.postId){
						secret.likes += 1;
						posts.save(function(){
						res.redirect("/secrets");	
				});	}
				});			
			}
			else{
				console.log("post not found");
			}
		}
	});
});

app.post("/comment",function(req,res){
	//User.findOne()
	//User.findOne({secrets.id:req.body.post},function(err,posts){

	//})
	User.findById(req.body.userId,function(err,posts){
		if(err){
			console.log(err);
		}
		else{
			if(posts){

				posts.secrets.forEach(function(secret){
					if(secret.id == req.body.postId){
						secret.comments.push(req.body.commentContent);
						posts.save(function(){
						res.redirect("/secrets");	
				});	}
				});			
			}
			else{
				console.log("post not found");
			}
		}
	});
});
app.post("/login",function(req,res){
	let username = req.body.username;
	let password = req.body.password;
	const user = new User({username:username,password:password});
	req.login(user,function(err){
		if(err){
			console.log(err);
		}
		else{
			passport.authenticate("local")(req,res,function(){
				res.redirect("/secrets");
			});
		}
	});
	// User.findOne({email:username},function(err,docs){
	// 	if(err){
	// 		console.log(err);
	// 	}
	// 	if(docs){
	// 		bcrypt.compare(password, docs.password, function(err, result) {
 //    			if(result == true){
	// 				res.render("secrets");
	// 			}
	// 			else{
	// 				res.send("<h1>incorrect password</h1>");
	// 			}
	// 		});
			
	// 	}
	// 	else{
	// 		res.send("<h1>incorrect username</h1>");
	// 	}
	// });
});

app.post("/submit",function(req,res){
	const newSecret = req.body.secret;
	var posts = new Secret({
		content:newSecret,
		likes:0,
		userId:req.user.id
	});
	posts.save();
	User.findById(req.user.id,function(err,foundUser){
		if(err){
			console.log(err);
		}
		else{
			if(foundUser){
				foundUser.secrets.push(posts);
				foundUser.save(function(){
					res.redirect("/secrets");
				});
			}
		}
	});
});

app.listen(3000,function(){
	console.log("server running at port 3000");
});