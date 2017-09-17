'use strict';

const auth = require('basic-auth');
const jwt = require('jsonwebtoken');

const register = require('./functions/register');
const login = require('./functions/login');
const profile = require('./functions/profile');
const password = require('./functions/password');
const config = require('./config/config.json');

module.exports = router => {

	router.get('/', (req, res) => res.end(''));

	router.post('/authenticate', (req, res) => {

		//const credentials = req;
		var email = req.body.email;
		var password = req.body.password;
		console.log(email);
		console.log(password);

		if (!email && !password) {

			res.status(400).json({ code: 400, message: 'Invalid Request !' });

		} else {

			login.loginUser(email, password)

			.then(result => {

				if(result.status == 200){
					const token = jwt.sign(result, config.secret, { expiresIn: 14400 });

					res.status(result.status).json({ code: result.status, message: result.message, userid: result.userid, token: token });

				} else if(result.status == 202) {
					res.status(result.status).json({ code: result.status, message: result.message});
				} else if(result.status == 203) {
					res.status(result.status).json({ code: result.status, message: result.message});
				}
			})
			
		}
	});

	router.post('/users', (req, res) => {

		const name = req.body.name;
		const email = req.body.email;
		const phone = req.body.phone;
		const location = req.body.location;
		const signup_lat = req.body.signup_lat;
		const signup_long = req.body.signup_long;
		const password = req.body.password;

		if (!name || !email || !phone || !location || !signup_lat || !signup_long || !password || !name.trim() || !email.trim() || !phone.trim() || !location.trim() || !signup_lat.trim() || !signup_long.trim() || !password.trim()) {

			res.status(400).json({message: 'Invalid Request !'});

		} else {

			register.registerUser(name, email, phone, location, signup_lat, signup_long, password)

			.then(result => {

				res.setHeader('Location', '/users/'+email);
				res.status(result.status).json({ code: result.status, message: result.message })
			})

			.catch(err => res.status(err.status).json({ message: err.message }));
		}
	});

	router.get('/users/:id', (req,res) => {

		if (checkToken(req)) {

			profile.getProfile(req.params.id)

			.then(result => res.json(result))

			.catch(err => res.status(err.status).json({ message: err.message }));

		} else {

			res.status(401).json({ message: 'Invalid Token !' });
		}
	});

	router.post('/users/forgotpassword', (req,res) => {

			const email = req.body.email;
			const tempPass = req.body.temppass;
			const newPass = req.body.password;
			console.log(email);

			if (!email || !email.trim()) {

				res.status(400).json({ message: 'Invalid Request !' });

			} else {
				if (!tempPass || !newPass || !tempPass.trim() || !newPass.trim()) {

					password.forgotPassword(email)

					.then(result => res.status(result.status).json({ message: result.message }))

					.catch(err => res.status(err.status).json({ message: err.message }));
				} else {
					
					password.forgotPasswordFinish(email, tempPass, newPass)

					.then(result => res.status(result.status).json({ message: result.message }))

					.catch(err => res.status(err.status).json({ message: err.message }));
				}
			}		
	});

	router.put('/users/:id', (req,res) => {
			var xxx = checkToken(req);
			console.log("xxx", xxx, req.params.id)
		if (xxx) {

			const oldPassword = req.body.password;
			const newPassword = req.body.newPassword;
			//const email = req.body.email;

			if (!oldPassword || !newPassword || !oldPassword.trim() || !newPassword.trim()) {

				res.status(400).json({ message: 'Invalid Request !' });

			} else {

				password.changePassword(req.params.id, oldPassword, newPassword)

				.then(result => res.status(result.status).json({ message: result.message }))

				.catch(err => res.status(err.status).json({ message: err.message }));

			}
		} else {

			res.status(401).json({ message: 'Invalid Token !' });
		}
	});

	router.post('/users/:id/password', (req,res) => {

		const email = req.params.id;
		const token = req.body.token;
		const newPassword = req.body.password;

		if (!token || !newPassword || !token.trim() || !newPassword.trim()) {
			password.resetPasswordInit(email)

			.then(result => res.status(result.status).json({ message: result.message }))

			.catch(err => res.status(err.status).json({ message: err.message }));

		} else {

			password.resetPasswordFinish(email, token, newPassword)

			.then(result => res.status(result.status).json({ message: result.message }))

			.catch(err => res.status(err.status).json({ message: err.message }));
		}
	});

	function checkToken(req) {

		const token = req.headers['x-access-token'];
		console.log(token);

		if (token) {

			try {

  				var decoded = jwt.verify(token, config.secret);
             console.log("decode msg_id is here",decoded.message);
             console.log("id is here",req.params.id);

  				return decoded.message === req.params.id;


			} catch(err) {

				return false;
			}

		} else {

			return false;
		}
	}
}