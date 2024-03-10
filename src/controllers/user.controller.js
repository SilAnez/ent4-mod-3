const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require("bcrypt");
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const { captureRejectionSymbol } = require('events');
const jwt = require('jsonwebtoken');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const {email,password,firstName,lastName,country,image,frontBaseUrl} = req.body;
    const encriptedPassword = await bcrypt.hash(password,10)
    const result = await User.create({
        email,
        password:encriptedPassword,
        firstName,
        lastName,
        country,
        image,
    });

    const code = require('crypto').randomBytes(32).toString("hex")
    const link = `${frontBaseUrl}/${code}`;
    
    await EmailCode.create({
        code:code,
        userId:result.id
    })
    
    await sendEmail({
        to:email,
        subject:"Verificate email for user app",
        html:`
            <h1>Hello ${firstName} ${lastName}</h1>
            <p><a href = "${link}">${link}</a></p>
            <p><b>Code:</b> ${code}</p>
            <p>Thanks for sign up in user app</p>
            
        `
    })
    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const {email,firstName,lastName,country,image} = req.body
    const result = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyEmail = catchError(async(req,res)=>{
    const{code} = req.params;
    const emailcode = await EmailCode.findOne({where:{code:code}});
    if (!emailcode) return res.status(401).json({message:"Invalid"})
    await User.update(
        {isVerified :true},
        {where:{id:emailcode.userId}, 
        returning:true});
    await emailcode.destroy();
    return res.json({message:"verificated"})
})

const login = catchError(async(req,res)=>{
    const{email,password} = req.body;
    const user = await User.findOne({where:{email:email}});
    if(!user) return res.status(401).json({message:"Incorrect Credentials"});
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({message:"Incorrect Credentials"});
    if (user.isVerified === false) return res.status(401).json({message:"Usuario sin verificar"});
    
    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        {expiresIn:'1d'},
    );
    return res.json({user,token})
});

const getLoggedUser = catchError(async(req,res)=>{
    return res.json(req.user);
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    getLoggedUser,
}