import { Router } from 'express';

const router = Router();

router.post('/', async (req: any, res: any) => {
  try {
    const { features } = req.body;
    if (!features) return res.status(400).json({ error: 'features required' });

    const attempt_count = features.attempt_count || 0;
    const failure_rate = features.failure_rate || 0;
    const velocity_score = features.velocity_score || 0;
    const brute_force_score = features.brute_force_score || 0;
    const suspicious_pattern_score = features.suspicious_pattern_score || 0;
    const regenerations = features.regenerations || 0;
    const attempts_after_regenerate = features.attempts_after_regenerate || 0;

    const threatScore = Math.min(1,
      (attempt_count * 0.10) +
      (failure_rate * 0.25) +
      (velocity_score * 0.20) +
      (brute_force_score * 0.25) +
      (suspicious_pattern_score * 0.10) +
      (regenerations * 0.05) +
      (attempts_after_regenerate * 0.05)
    );

    let recommendedAction = 'ALLOW';
    if (threatScore >= 0.8) recommendedAction = 'KILL';
    else if (threatScore >= 0.6) recommendedAction = 'REGENERATE';
    else if (threatScore >= 0.4) recommendedAction = 'LIE';

    const topFactors: string[] = [];
    if (velocity_score > 0.5) topFactors.push('High velocity (' + velocity_score.toFixed(2) + ')');
    if (brute_force_score > 0.5) topFactors.push('Brute force (' + brute_force_score.toFixed(2) + ')');
    if (failure_rate > 0.5) topFactors.push('High failure rate (' + failure_rate.toFixed(2) + ')');
    if (attempts_after_regenerate > 0) topFactors.push('Attempts after regenerate (' + attempts_after_regenerate + ')');

    res.json({
      threatScore,
      confidence: threatScore > 0.7 ? 'high' : threatScore > 0.4 ? 'medium' : 'low',
      recommendedAction,
      topFactors,
      inferenceTimeMs: 0,
      explanation: {
        base_score: threatScore,
        boosters_applied: topFactors,
        final_score: threatScore,
        reasoning: 'threatScore=' + threatScore.toFixed(3) + ' action=' + recommendedAction,
      },
    });
  } catch (err) {
    res.status(500).json({ error: 'Analysis failed' });
  }
});

export default router;
