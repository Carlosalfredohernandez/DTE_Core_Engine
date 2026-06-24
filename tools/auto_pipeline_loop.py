from __future__ import annotations

import runpy
from pathlib import Path
import shutil
import time

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'pipeline_run'
ITERS = OUT / 'iters'
ITERS.mkdir(parents=True, exist_ok=True)


def run_loop(max_iter: int = 10, pause: float = 0.2):
    prev_diff = None
    for i in range(1, max_iter + 1):
        print(f'Iteration {i}...')
        mod = runpy.run_path(str(ROOT / 'auto_pipeline.py'))
        # call run()
        if 'run' in mod:
            mod['run']()
        else:
            print('auto_pipeline.run not found')
            return 2

        diff_file = OUT / 'compare_normalized_diff_after_resign.txt'
        diff_text = ''
        if diff_file.exists():
            diff_text = diff_file.read_text(encoding='latin-1')

        # save iteration snapshot
        iter_dir = ITERS / f'iter_{i}'
        if iter_dir.exists():
            shutil.rmtree(iter_dir)
        iter_dir.mkdir(parents=True)
        for p in OUT.iterdir():
            if p.is_file():
                try:
                    shutil.copy(p, iter_dir / p.name)
                except Exception:
                    pass

        # check convergence
        if not diff_text.strip():
            summary = f'Converged: diff empty at iteration {i}\n'
            (OUT / 'loop_summary.txt').write_text(summary, encoding='utf-8')
            print(summary)
            return 0
        if prev_diff is not None and diff_text == prev_diff:
            summary = f'Stable (no change) at iteration {i}\n'
            (OUT / 'loop_summary.txt').write_text(summary, encoding='utf-8')
            print(summary)
            return 0

        prev_diff = diff_text
        time.sleep(pause)

    (OUT / 'loop_summary.txt').write_text('Reached max iterations without convergence\n', encoding='utf-8')
    print('Reached max iterations without convergence')
    return 0


if __name__ == '__main__':
    run_loop(10)
