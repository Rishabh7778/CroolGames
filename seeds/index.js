const Games=require('../models/games')
const mongoose=require('mongoose');
const gm=require('./data')
mongoose.connect('mongodb://127.0.0.1:27017/CroolGames',{
    useNewUrlParser:true,
    useUnifiedTopology:true
})
.then(()=>{
    console.log("Success")
})
.catch(()=>{
    console.log("Error")
})

const gameDB = async () => {
    await Games.deleteMany({});
    // for (let i = 0; i < 8; i++) {
    //     const random10 = Math.floor(Math.random() * 8);
    //     const category = gm[random10].category; // Log the category
    //     console.log('Category:', category);
        
    //     const g = new Games({
    //         author: '655f6b594f344bd7c23210c2',
    //         title: `${gm[random10].title}`,
    //         description: `${gm[random10].description}`,
    //         category: `${category}`, // Assign the category
    //         image: [
    //             {
    //                 url: 'https://res.cloudinary.com/dnyuashia/image/upload/v1705928556/CroolGames/k5f12jxuyzfp7ss7en8t.png',
    //                 filename: 'CroolGames/k5f12jxuyzfp7ss7en8t',
    //             },
    //             {
    //                 url: 'https://res.cloudinary.com/dnyuashia/image/upload/v1705928556/CroolGames/k5f12jxuyzfp7ss7en8t.png',
    //                 filename: 'CroolGames/k5f12jxuyzfp7ss7en8t',
    //             }
    //         ]
    //     });
        // await g.save();
    // }
}

gameDB();