'use strict';

const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = mongoose.Schema({ 

	name 			: String,
	email			: String,
	phone           : String,
	location        : String,
	signup_lat      : String,
	signup_long     : String,
	hashed_password	: String,
	created_at		: String,
	temp_password	: String,
	temp_password_time: String

});

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost:27017/appuser');

module.exports = mongoose.model('user', userSchema);
