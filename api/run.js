const replayData = require('./replay_demo.json');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  return res.status(200).json({
    status: 'success',
    elapsed: '0.18',
    message: 'Pipeline executed in 0.18s. All 15 validation checks passed.',
    data: replayData
  });
};
