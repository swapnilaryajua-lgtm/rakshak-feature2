const replayData = require('./replay_demo.json');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  return res.status(200).json({
    validation_checks: replayData.validation_checks || [],
    matches_submitted_files: (replayData.summary && replayData.summary.matches_submitted_files) !== undefined ? replayData.summary.matches_submitted_files : true,
    mismatch_details: (replayData.summary && replayData.summary.mismatch_details) || [],
    all_checks_passed: (replayData.summary && replayData.summary.all_checks_passed) !== undefined ? replayData.summary.all_checks_passed : true
  });
};
