var User
, _ =               require('underscore')
, passport =        require('passport')
, LocalStrategy =   require('passport-local').Strategy
, TwitterStrategy = require('passport-twitter').Strategy
//, FacebookStrategy = require('passport-facebook').Strategy
, GoogleStrategy = require('passport-google').Strategy
, LinkedInStrategy = require('passport-linkedin').Strategy
, check =           require('validator').check
, userRoles =       require('../../client/js/routingConfig').userRoles
, crypto = require('crypto')
, mongoose = require('mongoose')
, colors = require('colors');


if (process.env.OPENSHIFT_APP_NAME !== undefined) {
	// open shift- connection
	var murl = "mongodb://" + process.env.OPENSHIFT_MONGODB_DB_USERNAME +
		":" + process.env.OPENSHIFT_MONGODB_DB_PASSWORD + "@" +
		process.env.OPENSHIFT_MONGODB_DB_HOST + ":" +
		process.env.OPENSHIFT_MONGODB_DB_PORT + "/" +
		process.env.OPENSHIFT_APP_NAME;
	mongoose.connect(murl);

} else { // local server
	mongoose.connect('mongodb://localhost/localauthmydb');
	console.log("[DB] Connection ok db localauthmydb ".yellow);
}

var UserSchema = mongoose.Schema({
	id: Number,
	username: String,
	password: String,
	role: Object,

});
var User = mongoose.model('User', UserSchema);
var db = mongoose.connection;
db.on('error', function(){});
db.once('open', function callback() {
console.log("[DB] Connection ok collection User ".yellow);
});
module.exports = {
    addUser: function (username, password, role, callback) {


        this.findByUsername(username, function (e, c_id) {

            //console.log("Dati da scrivere" + c_id);

            //console.log("Role*" + role + password);
            var user = {
                id: c_id,
                username: username,
                password: crypto.createHash('md5').update(password).digest("hex"),
                role: role
            };

            // db
            var dbuser = new User(user);
            dbuser.save(function (err, User) {

                if (err) {
                    console.log("Non salvato");
                } else {
                    console.log("Salvato");
                }

            });
            callback(null, user);

        }, function (e) {
            callback("UserAlreadyExists");
        }, password, role, callback, false);

    },

    findOrCreateOauthUser: function (provider, providerId) {
        var user = module.exports.findByProviderId(provider, providerId);
        //console.log("ricerco");
        if (!user) {
            user = {
                id: _.max(users, function (user) {
                    return user.id;
                }).id + 1,
                username: provider + '_user', // Should keep Oauth users anonymous on demo site
                role: userRoles.user,
                provider: provider
            };
            user[provider] = providerId;

            users.push(user);

        }
        //console.log("Return User");
        return user;

    },

    findAll: function (fError, fSuccess) {
       User.find({
		  // deleted: false
	   }, {
		   password: 0
	   }, function(err, db_art){
			if(err){
				console.log("[API] Fail to catch all users".red);
				fError(null);
			}  else {
				console.log("[API] OK  catched all users".green);
				fSuccess(db_art);
			}
	   });
    },
	
	delete: function (user , fSuccess, fError) {
       User.remove({
		  '_id': user.userID
	   }, function(err, db_art){
	   
			if(err){
				//console.log('err  - deleted');
				fError(null);
			}  else {
				//console.log('succ - deleted');
				fSuccess(db_art);
			}
	   });
   },

    findById: function (id, functionOnFinish) {

        User.find({
            id: id
        }, function (err, db_articles) {

            if (err) {
                //console.log("Error Query ");
                functionOnFinish(null);

            } else {

                if (db_articles[0] == undefined) {
                    functionOnFinish(null);

                } else {

                    //console.log("OK user readed" + db_articles[0]);
                    functionOnFinish(db_articles[0]);


                }
            }

        });

        //console.log("Fine query By ID");

        //  return _.clone(_.find(users, function(user) { return user.id === id }));

    },


    // Function for db user controll 
    findByUsername: function (username, functionOnSucces, functionOnError, password, role, callback, isLogin) {


        var idtoset = 0;

        //console.log("Lo username con cui stai cercando di accedere è : " + username + " con psw :" + password + " is login? " + isLogin);

        User.find({
            username: username
        }, function (err, db_users) {

            if (err) {
                //console.log("Error Query ");
                functionOnError(err);

            } else {

                if (db_users[0] !== undefined && role !== undefined) {
                    functionOnError("null");


                } else {

                    //console.log("Console.log" + isLogin);

                    if (isLogin === undefined) {

                        functionOnSucces(db_users[0], idtoset);

                    } else {
                        User.find({}, function (err, resp) {

                            var idtoset = 0;

                            if (!err && resp[0] !== undefined) {
                                var idtoset = getmax(resp) + 1;
                            }
                            functionOnSucces(db_users[0], idtoset);

                        }, functionOnSucces);
                    }
                }
            }

        });
       // console.log("Fine query by Usersname");
        //	return _.clone(_.find(users, function(user) { return user.username === username; }));

    },

    findByProviderId: function (provider, id) {
        //console.log("find by Provider id");
        return _.find(users, function (user) {
            return user[provider] === id;
        });
    },

    validate: function (user) {
        check(user.username, 'Username must be 1-20 characters long').len(1, 20);
        check(user.password, 'Password must be 5-60 characters long').len(5, 60);
        check(user.username, 'Invalid username').not(/((([A-Za-z]{3,9}:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)/);

        // TODO: Seems node-validator's isIn function doesn't handle Number arrays very well...
        // Till this is rectified Number arrays must be converted to string arrays
        // https://github.com/chriso/node-validator/issues/185
        var stringArr = _.map(_.values(userRoles), function (val) {
            return val.toString()
        });
        check(user.role, 'Invalid user role given').isIn(stringArr);
    },

    localStrategy: new LocalStrategy(
        function (username, password, done) {

            module.exports.findByUsername(username, function (user) {

                    if (!user) {
                        done(null, false, {
                            message: 'Incorrect username and password.'
                        });
                    } else if (user.password != crypto.createHash('md5').update(password).digest("hex")) {
                        done(null, false, {
                            message: 'Incorrect username and password2.'
                        });
                    } else {
                        return done(null, user);
                    }

                },
                function (e) {
                    console.log("Errore" + e);
                });

        }),

    twitterStrategy: function () {
        if (!process.env.TWITTER_CONSUMER_KEY) throw new Error('A Twitter Consumer Key is required if you want to enable login via Twitter.');
        if (!process.env.TWITTER_CONSUMER_SECRET) throw new Error('A Twitter Consumer Secret is required if you want to enable login via Twitter.');

        return new TwitterStrategy({
                consumerKey: process.env.TWITTER_CONSUMER_KEY,
                consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
                callbackURL: process.env.TWITTER_CALLBACK_URL || 'http://localhost:8000/auth/twitter/callback'
            },
            function (token, tokenSecret, profile, done) {
                var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
                done(null, user);
            });
    },

    facebookStrategy: function () {
        if (!process.env.FACEBOOK_APP_ID) throw new Error('A Facebook App ID is required if you want to enable login via Facebook.');
        if (!process.env.FACEBOOK_APP_SECRET) throw new Error('A Facebook App Secret is required if you want to enable login via Facebook.');

        return new FacebookStrategy({
                clientID: process.env.FACEBOOK_APP_ID,
                clientSecret: process.env.FACEBOOK_APP_SECRET,
                callbackURL: process.env.FACEBOOK_CALLBACK_URL || "http://localhost:8000/auth/facebook/callback"
            },
            function (accessToken, refreshToken, profile, done) {
                var user = module.exports.findOrCreateOauthUser(profile.provider, profile.id);
                done(null, user);
            });
    },

    googleStrategy: function () {

        return new GoogleStrategy({
                returnURL: process.env.GOOGLE_RETURN_URL || "http://localhost:8000/auth/google/return",
                realm: process.env.GOOGLE_REALM || "http://localhost:8000/"
            },
            function (identifier, profile, done) {
                var user = module.exports.findOrCreateOauthUser('google', identifier);
                done(null, user);
            });
    },

    linkedInStrategy: function () {
        if (!process.env.LINKED_IN_KEY) throw new Error('A LinkedIn App Key is required if you want to enable login via LinkedIn.');
        if (!process.env.LINKED_IN_SECRET) throw new Error('A LinkedIn App Secret is required if you want to enable login via LinkedIn.');

        return new LinkedInStrategy({
                consumerKey: process.env.LINKED_IN_KEY,
                consumerSecret: process.env.LINKED_IN_SECRET,
                callbackURL: process.env.LINKED_IN_CALLBACK_URL || "http://localhost:8000/auth/linkedin/callback"
            },
            function (token, tokenSecret, profile, done) {
                var user = module.exports.findOrCreateOauthUser('linkedin', profile.id);
                done(null, user);
            }
        );
    },
    serializeUser: function (user, done) {
        done(null, user.id);
    },

    deserializeUser: function (id, done) {
        var user = module.exports.findById(id, function (user) {

            if (user) {
                done(null, user);
            } else {
                done(null, false);
            }
        });

    }
};


var getmax = function (value) {
    var max = value[0].id;
    var len = value.length;
    for (var i = 1; i < len; i++) {
        if (value[i].id > max) {
            max = value[i].id;
        };
    }
    return max;
}