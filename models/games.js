const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { v4: uuidv4 } = require('uuid'); // Import UUID library

const ImageSchema = new Schema({
    url: String,
    filename: String
});

const GamesSchema = new Schema({
    gameId: {
        type: String,
        default: uuidv4 // Generate UUID by default
    },
    title: {
        type: String,
        required: [true, 'Title is required']
    },
    description: {
        type: String,
        required: [true, 'Description is required']
    },
    category: {
        type: String,
        required: [true, 'Category is required']
    },
    image: [ImageSchema],
    author: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    reviews: [{
        type: Schema.Types.ObjectId,
        ref: 'Review'
    }],
    gameFile: ImageSchema
});

module.exports = mongoose.model('Games', GamesSchema);






