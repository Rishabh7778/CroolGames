const BaseJoi = require('joi');
const sanitizeHTML=require('sanitize-html');

const extension=(joi)=>({
    type:'string',
    base:joi.string(),
    messages:{
        'string.escapeHTML':'{{#label}} must not include Html'
    },
    rules:{
        escapeHTML:{
            validate(value,helpers){
                const clean=sanitizeHTML(value,{
                    allowedTags:[],
                    allowedAttributes:{},
                });
                if(clean!==value) return helpers.error('string.escapeHTML',{value})
                return clean;
            }
        }
    }
})
const Joi=BaseJoi.extend(extension);
module.exports.Rschema = Joi.object({
    review: Joi.object({
        body: Joi.string().required().escapeHTML(),
        rating: Joi.number().required().min(1).max(5),
    }).required()
});
module.exports.Gschema = Joi.object({
    games: Joi.object({
        title: Joi.string().required().escapeHTML(),
        description: Joi.string().required().escapeHTML(),
        category:Joi.string().required().escapeHTML()
    }).required(),
    deleteImages:Joi.array()
});