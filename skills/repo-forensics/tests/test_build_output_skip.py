"""Framework build output is skipped only when .gitignore excludes it.

A local `next dev` leaves thousands of generated files under .next/ that drown
real findings. The same folder committed to a repo is attacker-chosen content,
so it is scanned unless a .gitignore at or above it lists it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import forensics_core as core  # noqa: E402


def _tree(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


def _walked(root, walker=core.walk_repo):
    return {rel.replace(os.sep, '/') for _, rel in walker(str(root))}


def test_gitignored_next_build_is_skipped(tmp_path):
    _tree(tmp_path, {'.gitignore': '/.next/\nnode_modules\n', 'app/page.js': 'x', '.next/dev/chunk.js': 'y'})
    walked = _walked(tmp_path)
    assert 'app/page.js' in walked
    assert not any(p.startswith('.next/') for p in walked)


def test_committed_build_folder_is_scanned(tmp_path):
    _tree(tmp_path, {'app/page.js': 'x', '.next/server/payload.js': 'y'})
    assert '.next/server/payload.js' in _walked(tmp_path)


def test_reincluded_build_folder_is_scanned(tmp_path):
    _tree(tmp_path, {'.gitignore': '.next\n!.next\n', '.next/a.js': 'y'})
    assert '.next/a.js' in _walked(tmp_path)


def test_nested_app_gitignore_covers_its_own_build(tmp_path):
    _tree(tmp_path, {'apps/web/.gitignore': '/.next/\n', 'apps/web/.next/dev/c.js': 'y',
                     'apps/web/app/page.js': 'x'})
    walked = _walked(tmp_path)
    assert 'apps/web/app/page.js' in walked
    assert not any('/.next/' in p for p in walked)


def test_anchored_root_pattern_does_not_reach_subfolders(tmp_path):
    _tree(tmp_path, {'.gitignore': '/.next/\n', 'apps/web/.next/c.js': 'y'})
    assert 'apps/web/.next/c.js' in _walked(tmp_path)


def test_unanchored_pattern_matches_any_depth(tmp_path):
    _tree(tmp_path, {'.gitignore': '.nuxt/\n**/.svelte-kit\n', 'a/.nuxt/x.js': 'y',
                     'b/c/.svelte-kit/z.js': 'y', 'a/real.js': 'x'})
    assert _walked(tmp_path) == {'.gitignore', 'a/real.js'}


def test_only_known_build_folder_names_are_eligible(tmp_path):
    _tree(tmp_path, {'.gitignore': 'payload/\n.cache/\n', 'payload/run.js': 'y', '.cache/x.js': 'y'})
    assert {'payload/run.js', '.cache/x.js'} <= _walked(tmp_path)


def test_aux_walker_matches(tmp_path):
    _tree(tmp_path, {'.gitignore': '/.next/\n', '.next/dev/big.bin': 'y', 'keep.js': 'x'})
    walked = _walked(tmp_path, core.walk_aux)
    assert 'keep.js' in walked and not any(p.startswith('.next/') for p in walked)


def test_symlinked_gitignore_is_not_trusted(tmp_path):
    (tmp_path / 'outside').mkdir()
    (tmp_path / 'outside' / 'ig').write_text('/.next/\n', encoding='utf-8')
    repo = tmp_path / 'repo'
    _tree(repo, {'.next/a.js': 'y'})
    try:
        os.symlink(tmp_path / 'outside' / 'ig', repo / '.gitignore')
    except (OSError, NotImplementedError):
        return
    assert '.next/a.js' in _walked(repo)
