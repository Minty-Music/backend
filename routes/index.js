const auth = require('./auth');
const router = require('express').Router();
router.get('/is_up', (req, res) => { res.json({success: true})});
router.post('/signup', auth.signup);
router.post('/login', auth.login);

/********************
 * PROTECTED ROUTES *
 *********************/
router.use(auth.verifyToken);

module.exports = router;
