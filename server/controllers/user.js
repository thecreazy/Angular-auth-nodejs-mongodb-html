var _ =           require('underscore')
    , User =      require('../models/User.js')
    , userRoles = require('../../client/js/routingConfig').userRoles;

module.exports = {
    index: function(req, res) {
        var users = User.findAll(function(err){
		    res.writeHead(500,{'Content-Type':'application/json'});
			res.write(JSON.stringify(err));
			res.end();
		}, function(users){
			//console.log(JSON.stringify(users));
		    res.json(200,users);
		});
    }
};