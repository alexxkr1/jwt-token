// Importing modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken");
const User = require("./userModel");
const dotenv = require('dotenv').config();

const jwtSecret = process.env.mySecret;


const app = express();

app.use(express.json());

// Handling post request
app.post("/login", async (req, res, next) => {
let { email, password } = req.body;

let existingUser;
try {
	existingUser = await User.findOne({ email: email });
} catch {
	const error = new Error("Error! Something went wrong.", res.status(400));
	return next(error);
}
if (!existingUser || !await bcrypt.compare(req.body.password, existingUser.password)) {
	const error = Error("Wrong details please check at once", res.status(400));
	return next(error);
}
let token;
try {
	//Creating jwt token
	token = jwt.sign(
	{ userId: existingUser.id, email: existingUser.email },
	process.env.mySecret,
	{ expiresIn: "1h" }
	);
} catch (err) {
	console.log(err);
	const error = new Error("Error! Something went wrong.", res.status(400));
	return next(error);
}

res
	.status(200)
	.json({
	success: true,
	data: {
		userId: existingUser.id,
		email: existingUser.email,
		token: token,
	},
	});
});

// Handling post request
app.post("/signup", async (req, res, next) => {
const { name, email, password } = req.body;
const newUser = User({
	name,
	email,
	password,
});

try {
	await newUser.save();
} catch {
	const error = new Error("Error! Something went wrong.", res.status(400));
	return next(error);
}
let token;
try {
	token = jwt.sign(
	{ userId: newUser.id, email: newUser.email },
	process.env.mySecret,
	{ expiresIn: "1h" }
	);
} catch (err) {
	const error = new Error(err, res.status(400));
	return next(error);
}
res
	.status(201)
	.json({
	success: true,
	data: { userId: newUser.id,
		email: newUser.email, token: token },
	});
});

app.get('/accessResource', (req, res, next)=>{
	const token = req.headers.authorization.split(' ')[1];
	//Authorization: 'Bearer TOKEN'
        if(!token)
        {
            res.status(200).json({success:false, message: "Error Token was not provided."});
        }

	//Decoding the token
    try{
        const decodedToken = jwt.verify(token,process.env.mySecret );
        res.status(200).json({success:true, data:{userId:decodedToken.userId,
            email:decodedToken.email}});
    }
    catch{
        const error = new Error("The Token is invalid", res.status(400));
	return next(error);
    }
	

})


//Connecting to the database
mongoose
.connect("mongodb://localhost:27017/?readPreference=primary&appname=mongodb-vscode%200.6.10&ssl=false")
.then(() => {
	app.listen("3000", () => {
	console.log("Server is listening on port 3000");
	});
})
.catch((err) => {
	console.log("Error Occurred");
});
