const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const router = express.Router();
const config = require('./config');
const utils = require('./utils');
const tokenList = {};
const app = express();

router.get('/', (req, res) => {
  res.send('Ok');
});


router.post('/login', (req, res) => {
  const postData = req.body;
  const user = {
    "name": postData.name
  }

  const token = jwt.sign(user, config.secret, {
    expiresIn: config.tokenLife,
  });

  const refreshToken = jwt.sign(user, config.refreshTokenSecret, {
    expiresIn: config.refreshTokenLife
  });

  tokenList[refreshToken] = user;

  const response = {
    token,
    refreshToken,
  }

  res.json(response);
})


router.post('/refresh_token', async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken && (refreshToken in tokenList)) {
    try {
      await utils.verifyJwtToken(refreshToken, config.refreshTokenSecret);

      const user = tokenList[refreshToken];

      // Tạo mã token mới
      const token = jwt.sign(user, config.secret, {
        expiresIn: config.tokenLife,
      });
      const response = {
        token,
      }
      res.status(200).json(response);
    } catch (err) {
      res.status(403).json({
        message: 'Invalid refresh token',
      });
    }
  } else {
    res.status(400).json({
      message: 'Invalid request',
    });
  }
});


const TokenCheckMiddleware = async (req, res, next) => {
  const token = req.headers['x-access-token'];

  if (token) {
    try {
      const decoded = await utils.verifyJwtToken(token, config.secret);

      // Lưu thông tin giã mã được vào đối tượng req, dùng cho các xử lý ở sau
      req.decoded = decoded;
      next();
    } catch (err) {
      // Giải mã gặp lỗi: Không đúng, hết hạn...
      console.error(err);
      return res.status(401).json({
        message: 'Unauthorized access.',
      });
    }
  } else {
    return res.status(403).send({
      message: 'No token provided.',
    });
  }
}

router.use(TokenCheckMiddleware);

router.get('/data', (req, res) => {
  // all secured routes goes here
  res.json({ data: 1 })
})

app.use(bodyParser.json());

app.use('/api', router);

app.listen(3000);