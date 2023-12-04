const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer=require("multer");
const app = express();
app.use(express.json());
const path=require("path");
const dotenv=require('dotenv');
const { error, info } = require('console');
dotenv.config();
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());
mongoose.connect(process.env.MONGODB_URI,{
}).then((conn)=>{
    console.log("DB CONNECTED");
}).catch((error)=>{
    console.log("ERROR");
})
const userSchema=new mongoose.Schema({
    firstname:String,
    lastname:String,
    email:String,
    password:String,
    verified:{type:Boolean,default:false},
    verificationCode:String,
    verificationCodeExpiration:Date,
    role:{type:String,default:'user'},
    image:{type:String,default:""}
});
const User=mongoose.model('User',userSchema);
const jobSchema=new mongoose.Schema({
    jobname:String,
    jobDescription:String,
    tasks:[{type:mongoose.Schema.Types.ObjectId,ref:'Task'}],
    dueDate:Date,
    assignee:String,    
})
const Job=mongoose.model('Job',jobSchema);
const taskSchema=new mongoose.Schema({
    tasktitle:String,
    completionStatus:{type:Boolean,default:false},
    description:String,
    assignee:String
})
const Task=mongoose.model('Task',taskSchema);
const transporter=nodemailer.createTransport({
    service:'gmail',
    auth:{
        user: 'r7814474688@gmail.com', 
        pass: 'xmbs mtjf wjrx ixkk'
    }
});
app.post('/register',async(req,res)=>{
    try{
        const{firstname,lastname,email,password}=req.body;
        const existingUser=await User.findOne({email});
        if(existingUser){
            return res.status(400).json({error:"Email already registered"})
        }
        const verificationCode=Math.random().toString(36).substring(7);
        const verificationCodeExpiration=new Date();
        verificationCodeExpiration.setMinutes(verificationCodeExpiration.getMinutes()+45);
        const hashedPassword=await bcrypt.hash(password,8);
        const  user=new User({
            firstname,
            lastname,
            email,
            password:hashedPassword,
            verificationCode,
            verificationCodeExpiration,
        });
        await user.save();
        const mailOptions={
            from:"r7814474688@gmail.com",
            to:email,
            subject:"Email Verification",
            text:`Your verification code is ${verificationCode} . Code valid for 45 mins`
        };
        transporter.sendMail(mailOptions,async(error,info)=>{
            if(error){
                console.log(error);
                await User.deleteOne({ email });
                return res.status(500).json({ error: "Failed to send verification email. User data deleted." });
            }
            console.log("Email sent"+info.response);
        });
        res.status(201).json({message:"registration successful pls check your email for verification"});

    }catch(error){
        console.log(error);
        res.status(500).json({error:"Internal server error"});
    }
});
app.get('/verify/:email/:code',async(req,res)=>{
    try{
        const{email,code}=req.params;
        const user=await User.findOne({email,verificationCode:code});
        if(!user){
            return res.status(404).json({error:"User not found"});
        }
        if(user.verificationCodeExpiration<new Date()){
            await User.deleteOne({ email });
            return res.status(400).json({error:"Verification Code expired"});
        }
        user.verified=true;
        await user.save();
        res.status(200).json({message:"Email verification successful.You can now Login"})
    }catch(error){
        console.log(error);
        res.status(500).json({error:"Internal server error"})
    }
});
app.post('/login',async(req,res)=>{
    try{
        const{email,password}=req.body;
        const user=await User.findOne({email});
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        if(!user.verified){
            console.log(error);
            return res.status(401).json({ error: 'Account not verified. Please check your email for verification.' });
        }
        const token=jwt.sign({userId:user._id},'jwt_secret',{expiresIn:'12h'});
        res.status(200).json(token);
    }catch(error){
        console.log(error);
        res.status(500).json({error:"Internal server error"});
    }
});
app.post('/resetPassword',async(req,res)=>{
    try{
        const{email}=req.body;
        const user=await User.findOne({email});
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
        const newVerificationCode=Math.random().toString(36).substring(7);
        const newVerificationCodeExpiration=new Date();
        newVerificationCodeExpiration.setMinutes(newVerificationCodeExpiration.getMinutes()+45);
        user.verificationCode=newVerificationCode;
        user.verificationCodeExpiration=newVerificationCodeExpiration;
        await user.save();
        const resetlink=`http://localhost:8169/resetPassword/${email}/${newVerificationCode}`;
        const mailOptions={
            from:"r7814474688@gmail.com",
            to:email,
            subject:'Reset Password',
            text:`Click on follwoeing link to reset ypur password : ${resetlink}`
        };
        transporter.sendMail(mailOptions,(error,info)=>{
            if(error){
                console.error(error);
                return res.status(500).json({ error: 'Failed to send password reset email.' });
            }
            console.log("Email Sent :" +info.response);
        });
        res.status(200).json({ message: 'Password reset email sent. Please check your email.' });
    }catch(error){
        res.status(500).json({error:"Internal server error"});
    }
});
app.post('/resetPassword/:email/:code',async(req,res)=>{
    try{
        const{email,code}=req.params;
        const user=await User.findOne({email,verificationCode:code});
        if(!user){
            console.log("error");
            res.status(400).json({error:"User not found"});
        }
        if(user.verificationCodeExpiration< new Date()){
            res.status(400).json({error:"Verification code expired"})
        }
        const { password } = req.body;
        const hashedPasword=await bcrypt.hash(password,8);
        user.password=hashedPasword;
        await user.save();
        res.status(200).json({ message: 'Password updated successfully.' });
    }catch(error){
        console.log(error);
        res.status(500).json({error:"Internal server error"});
    }
});

const storage=multer.diskStorage({
    destination:function(req,file,cb){
        cb(null,'uploads/')
    },
        filename:function(req,file,cb){
            cb(null,Date.now()+'-'+file.originalname)
        }
    }
);
const upload=multer({storage:storage});
const uploadsDir=path.join(__dirname,'uploads');
app.use('/uploads',express.static(uploadsDir));
app.post('/upload-image',authenticateToken,upload.single('image'),async(req,res)=>{
    try{
        const imagePath=req.file?req.file.path:null;
        const userId=req.user.userId;
        await User.findByIdAndUpdate(userId,{image:imagePath});
        res.status(200).json({imagePath});
    }catch(error){
        console.log(error);
        res.status(500).json({error:"Internal server error"});
    }
});
app.post('/createJob',authenticateToken,async(req,res)=>{
    try{
        const{jobname,jobDescription,dueDate,assignee}=req.body;
        const job=new Job({
            jobname,jobDescription,
            dueDate,
            assignee
        });
        await job.save();
        res.status(201).json({ message: 'Job created successfully.', jobId: job._id });
    }catch(errro){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.get('/Jobs',async(req,res)=>{
    try{
        const jobs=await Job.find().populate('tasks');
        res.status(200).json(jobs);
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.delete('/deleteJob/:jobId',authenticateToken,async(req,res)=>{
    try{
        const jobId=req.params.jobId;
        const job=await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found.' });
        }
        if(!isAdminOrCreator){
            return res.status(403).json({ error: 'Permission denied. Either admin or the user who created can delete the post' });
        }
        await job.remove();
        res.status(200).json({message:"Job deleted Successfully"});

    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.patch('/updateJob/:jobId',authenticateToken,async(reeq,res)=>{
    try{
        const jobId=req.params.jobId;
        const{jobname,jobDescription,dueDate,assignee}=req.body;
        const job=await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found.' });
        }
        if(!isAdminOrCreator){
            return res.status(403).json({ error: 'Permission denied. Either admin or the user who created can UPDATE the post' });
        }
        job.jobname=jobname;
        job.jobDescription=jobDescription;
        job.dueDate=dueDate;
        job.assignee=assignee;
        await Job.save();
        res.status(200).json({ message: 'Job updated successfully.' });
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.post('/createTask/:jobId',authenticateToken,async(req,res)=>{
    try{
        const{tasktitle,description,assignee}=req.body;
        const jobId=Id=req.params.jobId;
        const task=new Task({
            tasktitle,
            description,
            assignee
        });
        const job=await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ error: 'Job not found.' });
        }
        const savedTask=await task.save();
        job.tasks.push(savedTask._id);
        await job.save();
        res.status(201).json({ message: 'Task created successfully.', taskId: savedTask._id });
        }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.get('/tasks/:jobId',authenticateToken,async(req,res)=>{
    try{
        const jobId=req.params.jobId;
        const job=await Job.findById(jobId).populate('tasks');
        if (!job) {
            return res.status(404).json({ error: 'Job not found.' });
        }
        res.status(200).json(job.tasks);
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.patch('/updateTask/:taskId',authenticateToken,async(req,res)=>{
    try{
        const taskId=req.params.taskId;
        const{completionStatus}=req.body;
        const task=await Task.findById(taskId).populate('job');
        if (!task) {
            return res.status(404).json({ error: 'Task not found.' });
        }
        if(!isAdminOrCreator){
            return res.status(403).json({ error: 'Permission denied.' });
        }
        task.completionStatus=completionStatus;
        await Task.save();
        res.status(200).json({ message: 'Task updated successfully.' });
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});
app.delete('/deleteTask/:taskId',authenticateToken,async(req,res)=>{
    try{
        const taskId=req.params.taskId;
        const task=await Task.findById(taskId).populate('job');
        if (!task) {
            return res.status(404).json({ error: 'Task not found.' });
        }
        if (!isAdminOrCreator(req.user, task.job)) {
            return res.status(403).json({ error: 'Permission denied.' });
        }
        await task.remove();
        res.status(200).json({ message: 'Task deleted successfully.' });
    }catch(error){
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

async function isAdminOrCreator(user, jobId) {
    const job = await Job.findById(jobId);
    return user.role === 'admin' || (job && job.creator.equals(user._id));
}
async function authenticateToken(req,res,next){
    const token=req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Unauthorized: Missing token.' });
    try{
        const decodedToken=await jwt.verify(token,'jwt_secret');
        req.user={userId:decodedToken.userId};
        next();
    }catch(error){
        return res.status(403).json({ error: 'Forbidden: Invalid token.' });
    }
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});