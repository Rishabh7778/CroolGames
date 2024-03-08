const Games=require('../models/games')
const Review=require('../models/review')
module.exports.storeR = (req, res, next) => {
    if (req.session.returnTo) {
        res.locals.returnTo = req.session.returnTo;
    }
    next();
}
module.exports.isloged = (req, res, next) => {
    if (!req.isAuthenticated()) {
        req.session.returnTo = req.originalUrl;
        req.flash('error', 'Login First')
        res.redirect('/login')
    }
    else {
        next();
    }
}
module.exports.isAuthor = async (req, res, next) => {
    const { id } = req.params;
    const g = await Games.findById(id);
    console.log("AdminA", req)
    if (!g || (!g.author.equals(req.user._id) && !req.user.isAdmin)) {
        req.flash('error', 'You are not authorized for that');
        return res.redirect(`/games/${id}`);
    }
    next();
};


module.exports.isReview = async (req, res, next) => {
    const {reviewid,id}=req.params;
    const r = await Review.findById(reviewid);
    if (!r || !r.author.equals(req.user._id)) {
        req.flash('error', 'You are not authorized for that');
        return res.redirect(`/games/${id}`);
    }
    next();
}

module.exports.isAdmin = (req, res, next) => {
    console.log('Usernn:', req.user);
    res.locals.Admin = req.isAuthenticated() && req.user.isAdmin;
    console.log('AdminM:', res.locals.Admin);
    next();
  };
  
  
