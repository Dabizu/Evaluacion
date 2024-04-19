const express=require("express");
const app=express();
const bcrypt = require('bcryptjs');
const MongoClient = require('mongodb').MongoClient;

const password="mT7ez.tx4pa7sMr";
const base="basedatos";
const url = "mongodb+srv://rootdavid:" + password + "@clusterazure.l92gg.mongodb.net/" + base + "?retryWrites=true&w=majority";

var jwt = require('jsonwebtoken');


app.listen(3000,()=>{console.log("servidor corriendo")});

app.use(express.static("public"));
app.use(express.static(__dirname+"/public"));

app.get("/",(req,res)=>{
    res.sendFile(__dirname+"/public/index.html")
});

app.post("/registroUsuario",(req,res)=>{
    var usuario=req.param("usuario");
    var correo=req.param("correo");
    var telefono=req.param("telefono");
    var password=req.param("password");
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db(base);
        var query = { $or:[{correo: correo},{telefono: telefono}]  };
        dbo.collection("usuario").find(query).toArray(function(err, result) {
          if (err) throw err;
          if(result.length==0){
            if(password.length<6){
                res.json({type:"error",text:"el numero de caracteres valido en password es de minimos 6 y maximo 12"});
            }else{
                if(password.length<=12){
                    const regexMayusculas = /[A-Z]/g;
                    const foundMayuscula = password.match(regexMayusculas);
                    
                    const regexMinusculas= /[a-z]/g;
                    const foundMinuscula= password.match(regexMinusculas);

                    const regexCaracteresEspeciales=/[@$?¡\-_]/g;
                    const foundCaracteresEspeciales=password.match(regexCaracteresEspeciales);
                    
                    const regexNumero=/[0-9]/g;
                    const foundNumero=password.match(regexNumero);

                    const regexCorreo=/^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i
                    const foundCorreo=correo.match(regexCorreo);
                    //console.log("mayusculas: "+foundMayuscula.length+"  minusculas: "+foundMinuscula.length)
                    if(foundMayuscula!=null && foundMinuscula!=null && foundCaracteresEspeciales!=null && foundNumero!=null && telefono.length==10 && foundCorreo!=null){
                        //var encriptar= bcrypt.hash(password);
                        var salt = bcrypt.genSaltSync(10);
                        var hash = bcrypt.hashSync(password, salt);
                        var token = jwt.sign({ password: hash }, 'shhhhh');
                        var myobj = { usuario:usuario, correo:correo, telefono:telefono, password:token };
                        dbo.collection("usuario").insertOne(myobj, function(err, ressult) {
                            if (err) throw err;
                            console.log("1 document inserted");
                            res.json({type:"success",text:"se registro con exito"});
                            db.close();
                        });
                    }else{
                        if(foundMayuscula==null && foundMinuscula==null){
                            res.json({type:"error",text:"no hay mayusculas ni minusculas en el password"});
                        }else if(foundMayuscula==null){
                            res.json({type:"error",text:"no hay mayusculas en el password"});
                        }else if(foundMinuscula==null){
                            res.json({type:"error",text:"no hay minusculas en el password"});
                        }else if(foundCaracteresEspeciales==null){
                            res.json({type:"error",text:"no hay caracteres espciales en el password"});
                        }else if(foundNumero==null){
                            res.json({type:"error",text:"no hay numeros en el password"});
                        }else if(telefono.length<10){
                            res.json({type:"error",text:"el telefono es menos de 10 digitos"});
                        }else if(foundCorreo==null){
                            res.json({type:"error",text:"correo no valido"});
                        }
                    }
                }
            }
          }else{
            res.json({type:"error",text:"el correo/telefono ya se encuentra registrado"});
          }
          console.log("este es el resultado")
          console.log(result);
        });
    });
});


app.post("/login",(req,res)=>{
    var usuarioCorreo=req.param("usuariocorreo");
    var password=req.param("password");
    MongoClient.connect(url, function(err, db) {
        if (err) throw err;
        var dbo = db.db(base);
        var query = { $or:[ {usuario:usuarioCorreo}, {correo:usuarioCorreo}]};
        dbo.collection("usuario").find(query).toArray(function(err, result) {
          if (err) throw err;
          console.log(result[0].password);
          
          var decoded = jwt.verify(result[0].password, 'shhhhh');
          console.log(decoded.password)
          if(bcrypt.compareSync(password, decoded.password)){
            res.json({type:"success",text:"Se logio"});
          }else{
            res.json({type:"error",text:"no se pudo logiar"});
          }
          //res.send(result)
          db.close();
        });
    });
});


//console.log("mi hast: "+hash)
