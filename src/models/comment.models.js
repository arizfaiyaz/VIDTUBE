import mongoose, { Schema } from 'mongoose';

const commentSchema = new Schema({
    video: {
        type: Schema.Types.ObjectId,
        ref: 'Video'
    },
    owner: {
        type: Schema.Types.ObjectId,
        red: 'User'
    },
    content: {
        type: String,
        required: true
    }
}, { timestamps: true });

export const Comment = mongoose.model('Comment', commentSchema);